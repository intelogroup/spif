"""
Key ceremony utilities for SIF — deterministic key derivation, rotation, and revocation.

All operations use only stdlib (hashlib) and the cryptography package already
required by SIF for ed25519 signature verification.
"""

from __future__ import annotations
import hashlib
import json
import os
import time
import warnings
from pathlib import Path

import base64
import struct

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_private_key as _load_pem_private_key,
)

from .format import cbor_deterministic
from .reader import SPIFSignatureError
from .types import SPIFDocument, Signature


# ---------------------------------------------------------------------------
# Weak (small-order) ed25519 keys
# ---------------------------------------------------------------------------
#
# A public key whose point has small order (order dividing the cofactor,
# 8) is never a legitimate signer, and cofactored verification — both
# OpenSSL's, behind the `cryptography` bindings, and ed25519-dalek's
# `verify` — can accept a forged signature under one for a fraction of
# messages (an all-zero key with an all-zero signature verifies against
# roughly one body in four). Every verify path in this package rejects
# weak keys before the cryptographic check; ed25519-dalek's `is_weak`
# is the Rust-side mirror. The check is the dalek definition: decode
# the point and test [8]P == identity, in pure Python (RFC 8032 math),
# memoized per key.

_ED_Q = 2**255 - 19
_ED_D = (-121665 * pow(121666, -1, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, -1, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if (x * x - xx) % _ED_Q != 0:
        raise ValueError("point is not on the curve")
    return x


def _ed_add(p: tuple, q: tuple) -> tuple:
    (x1, y1), (x2, y2) = p, q
    t = _ED_D * x1 * x2 * y1 * y2 % _ED_Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + t, -1, _ED_Q) % _ED_Q,
        (y1 * y2 + x1 * x2) * pow(1 - t, -1, _ED_Q) % _ED_Q,
    )


def _ed_scalarmult(p: tuple, e: int) -> tuple:
    out = (0, 1)
    while e > 0:
        if e & 1:
            out = _ed_add(out, p)
        p = _ed_add(p, p)
        e >>= 1
    return out


from functools import lru_cache as _lru_cache


@_lru_cache(maxsize=512)
def is_weak_ed25519_public_key(raw: bytes) -> bool:
    """True iff `raw` (32-byte compressed ed25519 public key) names a
    small-order point — or cannot be decoded as a point at all, in
    which case it is not a legitimate signer key either. Verify paths
    must reject weak keys; key *parsing* elsewhere is unaffected."""
    try:
        if len(raw) != 32:
            return False
        y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
        if y >= _ED_Q:
            return True  # non-canonical encoding: never a generated key
        x = _ed_xrecover(y)
        if (x & 1) != (raw[31] >> 7):
            x = (-x) % _ED_Q
        return _ed_scalarmult((x, y), 8) == (0, 1)
    except Exception:
        return True


def derive_key_from_mnemonic(mnemonic: str, passphrase: str = "") -> Ed25519PrivateKey:
    """
    Derive a deterministic ed25519 private key from a BIP39-style mnemonic phrase.

    Uses PBKDF2-HMAC-SHA512 with 600,000 iterations (OWASP 2026 minimum) to
    produce a 32-byte seed, then constructs an Ed25519PrivateKey from that seed.

    The same mnemonic + passphrase always produces the same key — callers are
    responsible for keeping mnemonics secret.

    .. warning::
        The iteration count was raised from 100,000 to 600,000 in v1.0.1 to
        meet OWASP 2026 guidance. Keys derived before this change will produce
        different bytes. Rotate via ``rotate_key()`` after re-deriving.

    **Empty passphrase warning**: The PBKDF2 salt is `b"sif-key-v1:" + passphrase`.
    When passphrase is empty (the default), the salt is the static string
    ``b"sif-key-v1:"``. All keys derived without a passphrase share this salt,
    which means an attacker with a precomputed table of common mnemonics and this
    fixed salt can recover keys without GPU resistance. The determinism is
    intentional (BIP39 design), but always supply a passphrase for high-value keys.
    """
    if not passphrase:
        warnings.warn(
            "derive_key_from_mnemonic called with empty passphrase. "
            "The PBKDF2 salt reduces to the static prefix b'sif-key-v1:'. "
            "An attacker with a precomputed table of common mnemonics and this salt "
            "can recover keys without GPU resistance (PBKDF2 at 600k iterations is "
            "CPU-bound only — use Argon2id for highest security). "
            "Always supply a passphrase for high-value signing keys.",
            UserWarning,
            stacklevel=2,
        )
    salt = b"sif-key-v1:" + passphrase.encode("utf-8")
    seed = hashlib.pbkdf2_hmac(
        hash_name="sha512",
        password=mnemonic.encode("utf-8"),
        salt=salt,
        iterations=600_000,
        dklen=32,
    )
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_pem_private_key(path: str | Path, password: bytes | None = None) -> Ed25519PrivateKey:
    """
    Load an ed25519 private key from a PEM file.

    Supports standard PKCS#8 PEM files as produced by:
        openssl genpkey -algorithm ed25519 -out private_key.pem

    Args:
        path: Path to the PEM file.
        password: Decryption password if the PEM is encrypted, else None.

    Returns:
        Ed25519PrivateKey ready for use with sign_document().
    """
    data = Path(path).read_bytes()
    key = _load_pem_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(
            f"PEM file contains a {type(key).__name__}, expected an Ed25519PrivateKey. "
            "Generate one with: openssl genpkey -algorithm ed25519 -out private_key.pem"
        )
    return key


def generate_key() -> Ed25519PrivateKey:
    """
    Generate a new random ed25519 private key.

    Use this for programmatic key creation. To persist, call export_pem_private_key().
    """
    return Ed25519PrivateKey.generate()


def export_pem_private_key(key: Ed25519PrivateKey, path: str | Path, password: bytes | None = None) -> None:
    """
    Write an ed25519 private key to a PEM file (PKCS#8 format).

    Args:
        key: The private key to export.
        path: Destination path (e.g. "signing_key.pem").
        password: Optional encryption password. If None, the file is unencrypted.
    """
    encryption = (
        NoEncryption() if password is None
        else __import__("cryptography.hazmat.primitives.serialization", fromlist=["BestAvailableEncryption"]).BestAvailableEncryption(password)
    )
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)
    # Write with 0o600 so only the owner can read the private key.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)


def export_pem_public_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    """
    Write the public key of an ed25519 keypair to a PEM file.

    Publish this at your signer_id URL so verifiers can check signatures.
    """
    pub = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    Path(path).write_bytes(pub)


def _rotation_payload(old_signer_id: str, new_signer_id: str, ts: int) -> bytes:
    return cbor_deterministic(
        {"old_signer": old_signer_id, "superseded_by": new_signer_id, "ts": ts}
    )


def rotate_key(
    old_key: Ed25519PrivateKey,
    new_key: Ed25519PrivateKey,
    old_signer_id: str,
    new_signer_id: str,
) -> dict:
    """
    Produce a signed rotation record: old key certifies that it is superseded by
    new key, AND new key counter-signs to prove it consents to receiving trust.

    Returns a JSON-serializable dict that callers can append to a rotation log.
    Both proof fields are base64-encoded ed25519 signatures over the canonical
    CBOR of {old_signer, superseded_by, ts} — verify with verify_rotation().
    """
    import base64

    ts = int(time.time() * 1000)
    payload_to_sign = _rotation_payload(old_signer_id, new_signer_id, ts)
    proof = old_key.sign(payload_to_sign)
    new_key_proof = new_key.sign(payload_to_sign)

    return {
        "old_signer": old_signer_id,
        "superseded_by": new_signer_id,
        "timestamp_ms": ts,
        "proof": base64.b64encode(proof).decode("ascii"),
        "new_key_proof": base64.b64encode(new_key_proof).decode("ascii"),
    }


def verify_rotation(
    record: dict,
    old_pubkey: Ed25519PublicKey,
    new_pubkey: Ed25519PublicKey,
) -> bool:
    """
    Verify a rotation record produced by rotate_key(): checks that both
    old_pubkey and new_pubkey signed the same {old_signer, superseded_by, ts}
    payload, proving mutual consent to the handoff.

    Returns True if both signatures check out, False otherwise (never raises
    on a bad signature — callers decide how to treat an unverified record).
    """
    import base64
    import binascii

    try:
        for pub in (old_pubkey, new_pubkey):
            raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            if is_weak_ed25519_public_key(raw):
                return False
        payload = _rotation_payload(
            record["old_signer"], record["superseded_by"], record["timestamp_ms"]
        )
        old_pubkey.verify(base64.b64decode(record["proof"]), payload)
        new_pubkey.verify(base64.b64decode(record["new_key_proof"]), payload)
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error):
        return False
    return True


def sign_document(
    doc: SPIFDocument,
    private_key: Ed25519PrivateKey,
    signer_id: str | None = None,
) -> bytes:
    """
    Sign a SPIFDocument with an ed25519 key and return the encoded bytes.

    signer_id defaults to the base64-encoded raw public key, which lets a
    verifier self-check the signature with no external key lookup via
    ``SPIFReader().verify_signature(data)``. Pass a URL to publish the key
    elsewhere instead (see export_pem_public_key()).

    Two-pass encode: the SIGNATURE chunk's position depends on document
    structure, so a dummy signature is written first to lock that structure
    in place, then the real signature covers exactly the bytes preceding it.
    """
    from .format import MAGIC as _MAGIC
    from .writer import SPIFWriter

    if signer_id is None:
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signer_id = base64.b64encode(pub_bytes).decode("ascii")

    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(_MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        chunk_type, length = struct.unpack_from(">BI", dummy, offset)
        if chunk_type == 0x07:  # CHUNK_SIGNATURE
            sig_offset = offset
            break
        if chunk_type == 0xFF:
            break
        offset += 5 + length
    if sig_offset is None:
        raise RuntimeError("could not locate SIGNATURE chunk in encoded document")

    body_to_sign = dummy[:sig_offset]
    doc.signature = Signature(
        algorithm="ed25519",
        signer=signer_id,
        signature=private_key.sign(body_to_sign),
    )
    return writer.encode(doc)


def load_revocation_list(path: str | Path) -> set[str]:
    """
    Load the set of revoked signer IDs from a JSON file.

    Expected format: {"revoked": ["signer_url_1", "signer_url_2", ...]}

    Returns an empty set if the file does not exist, so callers can always
    call this unconditionally without checking for the file first.
    """
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return set(data.get("revoked", []))


def check_revocation(signer_id: str, revocation_list: set[str]) -> None:
    """
    Raise SPIFSignatureError if signer_id appears in the revocation list.

    Call this before verifying a signature so that revoked keys are rejected
    even if their signature bytes are cryptographically valid.
    """
    if signer_id in revocation_list:
        raise SPIFSignatureError(
            f"Signer '{signer_id}' has been revoked and cannot be trusted"
        )
