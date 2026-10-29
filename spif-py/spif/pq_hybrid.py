"""
Post-quantum hybrid signing for SPIF (SPEC §7.5 / §7.9, v1.4).

Supported module implementing the registered hybrid algorithm
``ed25519+ml-dsa-65``: the 64-byte ed25519 signature and the 3309-byte
ML-DSA-65 signature (FIPS 204) concatenated, ed25519 first, both over
the same §7.2 signing body.

Normative design points (SPEC §7.9):

- **Signer encoding (§7.9.1, decided).** A hybrid entry's ``signer`` is
  base64 of the concatenated public keys (ed25519 32 B ‖ ML-DSA-65
  1952 B), so verification is self-contained and offline — no key
  lookup. A PQ-only entry's ``signer`` is base64 of the raw ML-DSA-65
  public key.
- **Gate modes (§7.9.2).** :func:`assess_pq_entry` is the single
  assessment used by the reader, the trust layer, and the keystore:
  classical mode verifies a hybrid entry's ed25519 component only;
  ``require_pq`` mode requires both components. A PQ-only entry is
  *unverifiable* in classical mode — invisible, not invalid — and is
  verified in require_pq mode when the backend is present. A
  wrong-length hybrid signature is malformed and invalid in both modes.
- **One identity, two components (§7.9.3).** Rotation records for a
  hybrid signer carry proofs from both components of the old and the
  new keypair (:func:`rotate_hybrid_key`).

Backend: `pqcrypto` (Backbone Technologies; Apache-2.0; compiled
wheels over the PQClean-style C implementations), an OPTIONAL
dependency (`pip install spif[pq]`). ML-DSA operations are isolated
behind three small wrappers so the backend can be swapped without
touching format logic. If the backend is not installed,
:func:`pq_available` is False, signing raises
:class:`PQBackendUnavailable`, and verification reports PQ entries as
unverifiable — it never silently degrades a hybrid signature to its
ed25519 component outside classical mode.

PQ-only *signing* is not implemented (SPEC §7.9.5): no public function
here emits an ``ml-dsa-65`` signature entry. Verification of PQ-only
entries in require_pq mode IS implemented, so artifacts from future
PQ-only writers are checkable.
"""

from __future__ import annotations

import base64
import binascii
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .format import CHUNK_SIGNATURE, MAGIC
from .reader import SPIFReader, _find_first_auth_chunk_offset
from .types import SPIFDocument, Signature
from .writer import SPIFWriter

__all__ = [
    "HYBRID_ALGORITHM",
    "PQ_ONLY_ALGORITHM",
    "ED25519_SIG_LEN",
    "ML_DSA_65_SIG_LEN",
    "ML_DSA_65_PUBLIC_KEY_LEN",
    "ML_DSA_65_SECRET_KEY_LEN",
    "HYBRID_SIG_LEN",
    "HYBRID_PUBLIC_KEY_LEN",
    "PQBackendUnavailable",
    "pq_available",
    "generate_ml_dsa_65_keypair",
    "ml_dsa_65_sign",
    "ml_dsa_65_verify",
    "hybrid_sign_message",
    "hybrid_verify_message",
    "hybrid_signer_id",
    "parse_hybrid_signer",
    "parse_pq_only_signer",
    "resolve_signer_keys",
    "HybridKeyPair",
    "generate_hybrid_keypair",
    "sign_document_hybrid",
    "PQAssessment",
    "assess_pq_entry",
    "verify_pq_entry",
    "verify_hybrid_signature",
    "HybridVerificationReport",
    "verify_hybrid_report",
    "rotate_hybrid_key",
    "verify_hybrid_rotation",
]

#: Registered algorithm ids (SPEC §7.5).
HYBRID_ALGORITHM = "ed25519+ml-dsa-65"
PQ_ONLY_ALGORITHM = "ml-dsa-65"

#: FIPS 204 ML-DSA-65 sizes (also asserted against the backend when it
#: is loaded, so a wrong-parameter-set library fails loudly).
ED25519_SIG_LEN = 64
ML_DSA_65_SIG_LEN = 3309
ML_DSA_65_PUBLIC_KEY_LEN = 1952
ML_DSA_65_SECRET_KEY_LEN = 4032
HYBRID_SIG_LEN = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN  # 3373

_ED25519_PK_LEN = 32
#: Raw length of the concatenated hybrid public keys (§7.9.1 encoding).
HYBRID_PUBLIC_KEY_LEN = _ED25519_PK_LEN + ML_DSA_65_PUBLIC_KEY_LEN  # 1984


class PQBackendUnavailable(RuntimeError):
    """The ML-DSA backend (`pqcrypto`) is not installed or does not
    expose FIPS 204 ML-DSA-65 with the expected parameter sizes."""


# ---------------------------------------------------------------------------
# ML-DSA-65 backend wrappers (the only pqcrypto touchpoints)
# ---------------------------------------------------------------------------

def _backend():
    try:
        from pqcrypto.sign import ml_dsa_65
    except Exception as e:  # ImportError or a broken native build
        raise PQBackendUnavailable(
            "pqcrypto with ML-DSA-65 support is required for PQ hybrid "
            "operations: pip install 'spif[pq]' (or pqcrypto directly)"
        ) from e
    sizes = (
        ml_dsa_65.PUBLIC_KEY_SIZE,
        ml_dsa_65.SECRET_KEY_SIZE,
        ml_dsa_65.SIGNATURE_SIZE,
    )
    expected = (ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIG_LEN)
    if sizes != expected:
        raise PQBackendUnavailable(
            f"pqcrypto ml_dsa_65 parameter sizes {sizes} do not match "
            f"FIPS 204 ML-DSA-65 {expected}; refusing to use it"
        )
    return ml_dsa_65


def pq_available() -> bool:
    """True iff the ML-DSA-65 backend is importable and sane."""
    try:
        _backend()
    except PQBackendUnavailable:
        return False
    return True


def generate_ml_dsa_65_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) raw bytes for ML-DSA-65."""
    return _backend().keygen()


def ml_dsa_65_sign(secret_key: bytes, message: bytes) -> bytes:
    """ML-DSA-65 signature (3309 bytes) over ``message``."""
    return _backend().sign(secret_key, message)


def ml_dsa_65_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid ML-DSA-65 signature.

    pqcrypto signals failure by raising; this wrapper normalizes to a
    boolean so call sites read like the ed25519 path.
    """
    backend = _backend()
    try:
        backend.verify(public_key, message, signature)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Signer encoding (SPEC §7.9.1) and key resolution
# ---------------------------------------------------------------------------

def hybrid_signer_id(ed_public_bytes: bytes, ml_public_bytes: bytes) -> str:
    """The self-describing hybrid signer id: base64 of the concatenated
    public keys (ed25519 first)."""
    return base64.b64encode(ed_public_bytes + ml_public_bytes).decode("ascii")


def _b64decode_or_none(text) -> bytes | None:
    if not isinstance(text, str):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_hybrid_signer(signer: str) -> tuple[bytes, bytes] | None:
    """Split a §7.9.1 hybrid signer field into (ed25519_pk, ml_dsa_pk).

    Returns None when the field is not the self-describing hybrid form
    (e.g. a URL or a bare ed25519 key).
    """
    raw = _b64decode_or_none(signer)
    if raw is None or len(raw) != HYBRID_PUBLIC_KEY_LEN:
        return None
    return raw[:_ED25519_PK_LEN], raw[_ED25519_PK_LEN:]


def parse_pq_only_signer(signer: str) -> bytes | None:
    """The ML-DSA-65 public key from a PQ-only signer field, or None."""
    raw = _b64decode_or_none(signer)
    if raw is None or len(raw) != ML_DSA_65_PUBLIC_KEY_LEN:
        return None
    return raw


def resolve_signer_keys(
    algorithm: str,
    signer: str,
    known_keys: dict[str, str] | None = None,
) -> tuple[bytes | None, bytes | None] | None:
    """Resolve an entry's key material to (ed25519_pk, ml_dsa_pk).

    Sources, in order: the caller's ``known_keys`` map (signer id ->
    base64 key material, the trust layer's out-of-band provisioning),
    then the signer field itself in its self-describing form. Either
    component may be None when only that component was provisioned;
    the pair is None when nothing usable resolves.
    """
    candidates: list[str] = []
    if known_keys and signer in known_keys:
        candidates.append(known_keys[signer])
    candidates.append(signer)
    for text in candidates:
        raw = _b64decode_or_none(text)
        if raw is None:
            continue
        if algorithm == HYBRID_ALGORITHM:
            if len(raw) == HYBRID_PUBLIC_KEY_LEN:
                return raw[:_ED25519_PK_LEN], raw[_ED25519_PK_LEN:]
            if len(raw) == _ED25519_PK_LEN:
                return raw, None  # ed25519 component provisioned only
        elif algorithm == PQ_ONLY_ALGORITHM:
            if len(raw) == ML_DSA_65_PUBLIC_KEY_LEN:
                return None, raw
    return None


# ---------------------------------------------------------------------------
# Hybrid message signing primitives (documents and statements alike)
# ---------------------------------------------------------------------------

def hybrid_sign_message(
    ed25519_private_key: Ed25519PrivateKey,
    ml_dsa_secret_key: bytes,
    message: bytes,
) -> bytes:
    """The concatenated hybrid signature (ed25519 ‖ ML-DSA-65) over
    ``message`` — the §7.5 construction, used for documents and for
    revocation statements signed by a hybrid signer (§7.9.4)."""
    if len(ml_dsa_secret_key) != ML_DSA_65_SECRET_KEY_LEN:
        raise ValueError("ml_dsa_secret_key must be 4032 bytes (ML-DSA-65)")
    ed_sig = ed25519_private_key.sign(message)
    ml_sig = ml_dsa_65_sign(ml_dsa_secret_key, message)
    return ed_sig + ml_sig


def hybrid_verify_message(
    ed_public_bytes: bytes,
    ml_public_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """True iff BOTH components of a hybrid signature verify."""
    if len(signature) != HYBRID_SIG_LEN:
        return False
    if not pq_available():
        return False
    try:
        Ed25519PublicKey.from_public_bytes(ed_public_bytes).verify(
            signature[:ED25519_SIG_LEN], message
        )
    except Exception:
        return False
    return ml_dsa_65_verify(
        ml_public_bytes, message, signature[ED25519_SIG_LEN:]
    )


# ---------------------------------------------------------------------------
# Hybrid keypairs
# ---------------------------------------------------------------------------

@dataclass
class HybridKeyPair:
    """One hybrid signer identity: an ed25519 keypair plus an ML-DSA-65
    keypair (§7.9.3 — one identity, two components)."""

    ed_private_key: Ed25519PrivateKey
    ml_public_key: bytes
    ml_secret_key: bytes

    @property
    def ed_public_bytes(self) -> bytes:
        return self.ed_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def signer_id(self) -> str:
        """The §7.9.1 self-describing signer id for this identity."""
        return hybrid_signer_id(self.ed_public_bytes, self.ml_public_key)

    def public_keys(self) -> tuple[bytes, bytes]:
        return self.ed_public_bytes, self.ml_public_key


def generate_hybrid_keypair(
    ed_private_key: Ed25519PrivateKey | None = None,
) -> HybridKeyPair:
    """Generate a fresh hybrid identity. The ed25519 component may be
    supplied (e.g. mnemonic-derived per §7.4); the ML-DSA component is
    always generated randomly — v1.4 defines no derivation for it
    (§7.9.3)."""
    ml_pk, ml_sk = generate_ml_dsa_65_keypair()
    return HybridKeyPair(
        ed_private_key=ed_private_key or Ed25519PrivateKey.generate(),
        ml_public_key=ml_pk,
        ml_secret_key=ml_sk,
    )


# ---------------------------------------------------------------------------
# Hybrid document signing
# ---------------------------------------------------------------------------

def sign_document_hybrid(
    doc: SPIFDocument,
    ed25519_private_key: Ed25519PrivateKey,
    ml_dsa_secret_key: bytes,
    ml_dsa_public_key: bytes,
    signer_id: str | None = None,
) -> bytes:
    """
    Sign ``doc`` with the hybrid ``ed25519+ml-dsa-65`` algorithm and
    return the encoded artifact bytes.

    Mirrors :func:`spif.crypto.sign_document`'s two-pass encode: a
    dummy hybrid signature of the correct length locks the document
    structure, then both real signatures are computed over the bytes
    preceding the SIGNATURE chunk (the §7.2 signing body) and
    concatenated, ed25519 first (SPEC §7.5).

    ``signer_id`` defaults to the §7.9.1 self-describing form (both
    public keys embedded), which keeps verification fully offline.
    ``doc`` is mutated in place (its ``signature`` is set), matching
    ``sign_document``'s behavior.
    """
    if len(ml_dsa_public_key) != ML_DSA_65_PUBLIC_KEY_LEN:
        raise ValueError("ml_dsa_public_key must be 1952 bytes (ML-DSA-65)")
    if len(ml_dsa_secret_key) != ML_DSA_65_SECRET_KEY_LEN:
        raise ValueError("ml_dsa_secret_key must be 4032 bytes (ML-DSA-65)")

    ed_public_bytes = ed25519_private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    if signer_id is None:
        signer_id = hybrid_signer_id(ed_public_bytes, ml_dsa_public_key)

    writer = SPIFWriter()
    doc.signature = Signature(
        algorithm=HYBRID_ALGORITHM,
        signer=signer_id,
        signature=b"\x00" * HYBRID_SIG_LEN,
    )
    dummy = writer.encode(doc)

    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        chunk_type, length = struct.unpack_from(">BI", dummy, offset)
        if chunk_type == CHUNK_SIGNATURE:
            sig_offset = offset
            break
        if chunk_type == 0xFF:
            break
        offset += 5 + length
    if sig_offset is None:
        raise RuntimeError("could not locate SIGNATURE chunk in encoded document")

    body_to_sign = dummy[:sig_offset]
    combined = hybrid_sign_message(
        ed25519_private_key, ml_dsa_secret_key, body_to_sign
    )
    assert len(combined) == HYBRID_SIG_LEN

    doc.signature = Signature(
        algorithm=HYBRID_ALGORITHM,
        signer=signer_id,
        signature=combined,
    )
    return writer.encode(doc)


# ---------------------------------------------------------------------------
# Gate-mode assessment (SPEC §7.9.2) — the one PQ entry check
# ---------------------------------------------------------------------------

@dataclass
class PQAssessment:
    """Tri-state outcome of assessing one PQ-bearing signature entry."""

    status: str       # "valid" | "invalid" | "unverifiable"
    detail: str = ""  # human-readable reason (for reports / errors)


def assess_pq_entry(
    algorithm: str,
    signer: str,
    signature: bytes,
    body: bytes,
    *,
    require_pq: bool = False,
    known_keys: dict[str, str] | None = None,
) -> PQAssessment:
    """Assess one hybrid or PQ-only signature entry under a gate mode.

    Hybrid entries: a signature that is not exactly 3373 bytes is
    malformed and **invalid in both modes** (it carries no classical
    component in the registered shape — the relabelled ed25519-only
    case). Otherwise classical mode verifies the ed25519 component
    only; require_pq mode additionally requires the ML-DSA component,
    and reports *unverifiable* (never a silent classical pass) when the
    ML-DSA key or backend is unavailable.

    PQ-only entries: **unverifiable in classical mode** regardless of
    keys or backend ("invisible, not invalid", §7.9.2); verified with
    ML-DSA-65 in require_pq mode when key and backend are available.
    """
    if algorithm == HYBRID_ALGORITHM:
        if len(signature) != HYBRID_SIG_LEN:
            return PQAssessment(
                "invalid",
                f"hybrid signature must be {HYBRID_SIG_LEN} bytes, "
                f"got {len(signature)} (malformed for the claimed algorithm)",
            )
        keys = resolve_signer_keys(algorithm, signer, known_keys)
        if keys is None:
            return PQAssessment(
                "unverifiable",
                "cannot resolve hybrid signer key material "
                "(signer is not the self-describing §7.9.1 form and no "
                "key was provisioned)",
            )
        ed_pk, ml_pk = keys
        try:
            Ed25519PublicKey.from_public_bytes(ed_pk).verify(
                signature[:ED25519_SIG_LEN], body
            )
        except InvalidSignature:
            return PQAssessment("invalid", "ed25519 component failed verification")
        except Exception as e:
            return PQAssessment("invalid", f"ed25519 component error: {e}")
        if not require_pq:
            return PQAssessment(
                "valid",
                "ed25519 component verified (classical gate mode; "
                "ML-DSA component not checked)",
            )
        if ml_pk is None:
            return PQAssessment(
                "unverifiable",
                "ML-DSA public key not available for this signer; "
                "PQ component cannot be checked under require_pq",
            )
        if not pq_available():
            return PQAssessment(
                "unverifiable",
                "ML-DSA backend (pqcrypto) not installed; PQ component "
                "cannot be checked under require_pq",
            )
        if not ml_dsa_65_verify(ml_pk, body, signature[ED25519_SIG_LEN:]):
            return PQAssessment("invalid", "ML-DSA-65 component failed verification")
        return PQAssessment("valid", "both hybrid components verified")

    if algorithm == PQ_ONLY_ALGORITHM:
        if not require_pq:
            return PQAssessment(
                "unverifiable",
                "ml-dsa-65 entries are not checked in classical gate "
                "mode (invisible, not invalid — SPEC §7.9.2)",
            )
        if len(signature) != ML_DSA_65_SIG_LEN:
            return PQAssessment(
                "invalid",
                f"ml-dsa-65 signature must be {ML_DSA_65_SIG_LEN} bytes, "
                f"got {len(signature)}",
            )
        keys = resolve_signer_keys(algorithm, signer, known_keys)
        if keys is None or keys[1] is None:
            return PQAssessment(
                "unverifiable",
                "cannot resolve ML-DSA public key for this signer",
            )
        if not pq_available():
            return PQAssessment(
                "unverifiable",
                "ML-DSA backend (pqcrypto) not installed; cannot check "
                "ml-dsa-65 entry under require_pq",
            )
        ok = ml_dsa_65_verify(keys[1], body, signature)
        return PQAssessment(
            "valid" if ok else "invalid",
            "ML-DSA-65 signature verified" if ok
            else "ML-DSA-65 signature failed verification",
        )

    return PQAssessment(
        "unverifiable", f"not a PQ algorithm: {algorithm!r}"
    )


def verify_pq_entry(
    algorithm: str,
    signer: str,
    signature: bytes,
    body: bytes,
    *,
    require_pq: bool = False,
    known_keys: dict[str, str] | None = None,
) -> str:
    """The status half of :func:`assess_pq_entry`:
    "valid" | "invalid" | "unverifiable"."""
    return assess_pq_entry(
        algorithm, signer, signature, body,
        require_pq=require_pq, known_keys=known_keys,
    ).status


# ---------------------------------------------------------------------------
# Strict hybrid verification of a whole artifact (primary signature)
# ---------------------------------------------------------------------------

def verify_hybrid_signature(data: bytes) -> bool:
    """
    True iff ``data`` is a SPIF artifact whose primary signature is a
    hybrid ``ed25519+ml-dsa-65`` entry with BOTH components valid over
    the signing body (the require_pq assessment of the primary entry).

    Returns False (never raises for content problems) when: the
    artifact does not decode, there is no primary signature, the
    algorithm is anything other than the hybrid id (an ed25519-only
    artifact presented to this verifier is rejected), the concatenated
    signature is not exactly 3373 bytes, the signer field is not the
    self-describing hybrid form, or either component fails. For full
    trust reporting (all entries, revocations, timestamps) use
    :func:`spif.trust.verify_artifact`.
    """
    try:
        doc = SPIFReader().decode(data)
    except Exception:
        return False

    sig = doc.signature
    if sig is None or sig.algorithm != HYBRID_ALGORITHM:
        return False

    auth_offset = _find_first_auth_chunk_offset(data)
    if auth_offset is None:
        return False
    body_to_sign = data[:auth_offset]

    return assess_pq_entry(
        sig.algorithm, sig.signer, sig.signature, body_to_sign,
        require_pq=True,
    ).status == "valid"


@dataclass
class HybridVerificationReport:
    """Report in the field shape the conformance runner asserts on
    (see vectors/run_conformance.py), so hybrid cases can live in the
    same manifest as the trust-layer cases."""

    trust_status: str       # "VALID" | "INVALID"
    signature_status: str   # "valid" | "invalid"
    timestamp_status: str = "absent"
    forged_revocations: int = 0
    references: list = field(default_factory=list)


def verify_hybrid_report(data: bytes) -> HybridVerificationReport:
    """Strict-hybrid view of :func:`verify_hybrid_signature`."""
    ok = verify_hybrid_signature(data)
    return HybridVerificationReport(
        trust_status="VALID" if ok else "INVALID",
        signature_status="valid" if ok else "invalid",
    )


# ---------------------------------------------------------------------------
# Hybrid key rotation (SPEC §7.9.3)
# ---------------------------------------------------------------------------

def rotate_hybrid_key(
    old: HybridKeyPair,
    new: HybridKeyPair,
    old_signer_id: str,
    new_signer_id: str,
) -> dict:
    """
    Produce a signed hybrid rotation record: the old identity certifies
    that it is superseded by the new identity, and the new identity
    counter-signs to prove consent — with **both** key components of
    each side signing the same rotation payload an ed25519 rotation
    uses (SPEC §7.9.3). Each proof field is base64 of the concatenated
    hybrid signature.

    Returns a JSON-serializable dict; verify with
    :func:`verify_hybrid_rotation`.
    """
    import time

    from .crypto import _rotation_payload

    ts = int(time.time() * 1000)
    payload = _rotation_payload(old_signer_id, new_signer_id, ts)
    proof = hybrid_sign_message(old.ed_private_key, old.ml_secret_key, payload)
    new_proof = hybrid_sign_message(
        new.ed_private_key, new.ml_secret_key, payload
    )
    return {
        "old_signer": old_signer_id,
        "superseded_by": new_signer_id,
        "timestamp_ms": ts,
        "algorithm": HYBRID_ALGORITHM,
        "proof": base64.b64encode(proof).decode("ascii"),
        "new_key_proof": base64.b64encode(new_proof).decode("ascii"),
    }


def verify_hybrid_rotation(
    record: dict,
    old_ed_public: bytes,
    old_ml_public: bytes,
    new_ed_public: bytes,
    new_ml_public: bytes,
) -> bool:
    """
    Verify a record produced by :func:`rotate_hybrid_key`: both
    components of the old keypair and both of the new must have signed
    the rotation payload. A record proven by only one component, or
    not labelled with the hybrid algorithm, is not a hybrid rotation
    (§7.9.3) and returns False. Never raises on bad input.
    """
    from .crypto import _rotation_payload

    try:
        if record.get("algorithm") != HYBRID_ALGORITHM:
            return False
        payload = _rotation_payload(
            record["old_signer"], record["superseded_by"],
            record["timestamp_ms"],
        )
        proof = base64.b64decode(record["proof"], validate=True)
        new_proof = base64.b64decode(record["new_key_proof"], validate=True)
    except Exception:
        return False
    return (
        hybrid_verify_message(old_ed_public, old_ml_public, payload, proof)
        and hybrid_verify_message(
            new_ed_public, new_ml_public, payload, new_proof
        )
    )
