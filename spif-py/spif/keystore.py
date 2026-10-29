"""
SPIFKeyStore — file-based public-key store for SPIF signature verification.

A keystore is a directory with the following layout::

    keystore/
        <key_id>.pub    — raw 32-byte ed25519 public key per signer
        <key_id>.hyb    — hybrid public keys (SPEC §7.9): the raw
                          concatenated ed25519 (32 B) + ML-DSA-65
                          (1952 B) public keys of one hybrid signer
        revoked.json    — {"revoked": {"<key_id>": <revoked_at_ms>}}
        roles.json      — {"roles": {"<role>": ["<authorized_key_id>", ...]}}
        rotation.jsonl  — newline-delimited rotation records (from crypto.rotate_key)

Usage::

    from spif.keystore import SPIFKeyStore

    ks = SPIFKeyStore("/path/to/keys")
    ks.add_key("alice", alice_public_key_bytes)

    # Verify a document's signature using the store
    ks.verify(data)           # verifies against the original signed bytes

    # Revoke a key
    ks.revoke("alice")

    # Use with the reader's verify_with_keystore helper
    from spif.keystore import verify_with_keystore
    verify_with_keystore(data, ks)
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from .reader import (
    SPIFReader,
    SPIFSignatureError,
    SPIFFormatError,
    _find_first_auth_chunk_offset,
)
from .types import SPIFDocument


class SPIFRevokedSignerError(SPIFSignatureError):
    """A cryptographically valid signature belongs to a revoked signer."""


@dataclass
class HybridKeyMaterial:
    """The private half of a hybrid signer identity (SPEC §7.9.3),
    returned by :meth:`SPIFKeyStore.generate_hybrid_key`. The keystore
    retains only the public components; the caller persists this
    material (the ML-DSA secret key is 4032 raw bytes with no PEM or
    mnemonic story in v1.4)."""

    ed_private_key: Ed25519PrivateKey
    ml_public_key: bytes
    ml_secret_key: bytes

    @property
    def signer_id(self) -> str:
        """The §7.9.1 self-describing signer id for this identity."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        from .pq_hybrid import hybrid_signer_id

        ed_public = self.ed_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        return hybrid_signer_id(ed_public, self.ml_public_key)


class SPIFKeyStore:
    """
    File-based store of ed25519 public keys for SPIF signature verification.

    Parameters
    ----------
    path :
        Directory to use as the key store.  Created if it does not exist.
    auto_create :
        If True (default), create the directory automatically.  Set False
        to raise FileNotFoundError if the directory is missing.
    """

    def __init__(self, path: Union[str, Path], *, auto_create: bool = True) -> None:
        self._root = Path(path)
        if auto_create:
            self._root.mkdir(parents=True, exist_ok=True)
        elif not self._root.exists():
            raise FileNotFoundError(f"Keystore directory not found: {self._root}")
        self._revocation_path = self._root / "revoked.json"
        self._roles_path = self._root / "roles.json"

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def add_key(self, key_id: str, public_key: bytes | Ed25519PublicKey) -> None:
        """
        Register a public key under the given key_id.

        Parameters
        ----------
        key_id :
            A stable identifier for this key (URL, email, short name).
            Stored as ``<key_id_slug>.pub`` — special chars are URL-encoded.
        public_key :
            Raw 32-byte ed25519 public key bytes, or an ``Ed25519PublicKey``
            object from the ``cryptography`` library.
        """
        if isinstance(public_key, Ed25519PublicKey):
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            raw = bytes(public_key)
        if len(raw) != 32:
            raise ValueError(f"ed25519 public key must be 32 bytes, got {len(raw)}")
        slug = _key_slug(key_id)
        (self._root / f"{slug}.pub").write_bytes(raw)

    def get_key(self, key_id: str) -> bytes | None:
        """Return the raw 32-byte public key for key_id, or None if not found."""
        slug = _key_slug(key_id)
        path = self._root / f"{slug}.pub"
        if not path.exists():
            return None
        return path.read_bytes()

    def has_key(self, key_id: str) -> bool:
        """Return True if a public key for key_id is registered."""
        return self.get_key(key_id) is not None

    def remove_key(self, key_id: str) -> bool:
        """Remove the public key(s) for key_id (classical and hybrid
        entries).  Returns True if any existed."""
        slug = _key_slug(key_id)
        removed = False
        for suffix in (".pub", ".hyb"):
            path = self._root / f"{slug}{suffix}"
            if path.exists():
                path.unlink()
                removed = True
        return removed

    def list_keys(self) -> list[str]:
        """Return a list of registered key IDs (unslugged names not preserved)."""
        stems = {p.stem for p in self._root.glob("*.pub")}
        stems |= {p.stem for p in self._root.glob("*.hyb")}
        return sorted(stems)

    # ------------------------------------------------------------------
    # Hybrid keys (SPEC §7.9) — one signer identity, two components.
    # The public halves are stored together in a single ``<id>.hyb``
    # file (raw ed25519 ‖ ML-DSA-65 public keys); revocation and role
    # authorization key off the same signer id as classical keys, so a
    # hybrid identity is revoked whole (§7.9.3).
    # ------------------------------------------------------------------

    def add_hybrid_key(
        self,
        key_id: str,
        ed_public_key: bytes | Ed25519PublicKey,
        ml_public_key: bytes,
    ) -> None:
        """
        Register a hybrid signer's public keys under the given key_id.

        Parameters
        ----------
        key_id :
            A stable identifier for the signer (URL, email, short name).
            Stored as ``<key_id_slug>.hyb`` — special chars are URL-encoded.
        ed_public_key :
            Raw 32-byte ed25519 public key bytes, or an
            ``Ed25519PublicKey`` object.
        ml_public_key :
            Raw 1952-byte ML-DSA-65 public key bytes.
        """
        from .pq_hybrid import ML_DSA_65_PUBLIC_KEY_LEN

        if isinstance(ed_public_key, Ed25519PublicKey):
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )
            ed_raw = ed_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            ed_raw = bytes(ed_public_key)
        if len(ed_raw) != 32:
            raise ValueError(f"ed25519 public key must be 32 bytes, got {len(ed_raw)}")
        ml_raw = bytes(ml_public_key)
        if len(ml_raw) != ML_DSA_65_PUBLIC_KEY_LEN:
            raise ValueError(
                f"ML-DSA-65 public key must be {ML_DSA_65_PUBLIC_KEY_LEN} "
                f"bytes, got {len(ml_raw)}"
            )
        slug = _key_slug(key_id)
        (self._root / f"{slug}.hyb").write_bytes(ed_raw + ml_raw)

    def get_hybrid_key(self, key_id: str) -> tuple[bytes, bytes] | None:
        """Return (ed25519_pk, ml_dsa_pk) raw bytes for key_id, or None."""
        from .pq_hybrid import HYBRID_PUBLIC_KEY_LEN

        slug = _key_slug(key_id)
        path = self._root / f"{slug}.hyb"
        if not path.exists():
            return None
        raw = path.read_bytes()
        if len(raw) != HYBRID_PUBLIC_KEY_LEN:
            return None
        return raw[:32], raw[32:]

    def has_hybrid_key(self, key_id: str) -> bool:
        """Return True if a hybrid public-key entry for key_id exists."""
        return self.get_hybrid_key(key_id) is not None

    def generate_hybrid_key(self, key_id: str) -> HybridKeyMaterial:
        """
        Generate a fresh hybrid signer identity, store its public keys
        under key_id, and return the private material.

        The ed25519 component is generated classically; the ML-DSA-65
        component is generated randomly by the PQ backend (§7.9.3 — no
        mnemonic derivation exists for it in v1.4). Raises
        PQBackendUnavailable if the `pqcrypto` backend is not installed.
        The caller owns the returned secret material — the store keeps
        only public keys, exactly as for classical keys.
        """
        from .pq_hybrid import generate_hybrid_keypair

        pair = generate_hybrid_keypair()
        ed_public, ml_public = pair.public_keys()
        self.add_hybrid_key(key_id, ed_public, ml_public)
        return HybridKeyMaterial(
            ed_private_key=pair.ed_private_key,
            ml_public_key=pair.ml_public_key,
            ml_secret_key=pair.ml_secret_key,
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(self, key_id: str, *, revoked_at_ms: int | None = None) -> None:
        """
        Mark a key as revoked.  Revoked keys will be rejected during verification
        even if their signature bytes are cryptographically valid.

        Parameters
        ----------
        key_id :
            The key identifier to revoke.
        revoked_at_ms :
            Optional explicit revocation timestamp.  Defaults to current time.
        """
        if revoked_at_ms is None:
            revoked_at_ms = int(time.time() * 1000)
        revoked = self._load_revoked()
        revoked[key_id] = revoked_at_ms
        self._save_revoked(revoked)

    def unrevoke(self, key_id: str) -> bool:
        """Remove a key from the revocation list.  Returns True if it was revoked."""
        revoked = self._load_revoked()
        if key_id in revoked:
            del revoked[key_id]
            self._save_revoked(revoked)
            return True
        return False

    def is_revoked(self, key_id: str) -> bool:
        """Return True if key_id appears in the revocation list."""
        return key_id in self._load_revoked()

    def revoked_keys(self) -> dict[str, int]:
        """Return a mapping of {key_id: revoked_at_ms} for all revoked keys."""
        return dict(self._load_revoked())

    # ------------------------------------------------------------------
    # Role authorization
    #
    # A document's ``signer_roles`` (see types.SPIFDocument) is a claim, bound
    # into the signed body, of the form {signer_id: role}. This section lets a
    # deployer restrict which signer_ids are actually allowed to make a given
    # role claim (e.g. only a designated human reviewer's key may sign as
    # "human_reviewer"). A role with no registered authorization list is not
    # enforced — this is opt-in per role, existing single-signer callers are
    # unaffected unless they explicitly call authorize_role.
    # ------------------------------------------------------------------

    def authorize_role(self, role: str, signer_id: str) -> None:
        """Grant signer_id permission to sign documents claiming the given role."""
        roles = self._load_roles()
        signers = roles.setdefault(role, [])
        if signer_id not in signers:
            signers.append(signer_id)
        self._save_roles(roles)

    def deauthorize_role(self, role: str, signer_id: str) -> bool:
        """Revoke signer_id's permission for role. Returns True if it was granted."""
        roles = self._load_roles()
        signers = roles.get(role, [])
        if signer_id not in signers:
            return False
        signers.remove(signer_id)
        self._save_roles(roles)
        return True

    def is_authorized_for_role(self, role: str, signer_id: str) -> bool:
        """Return True if signer_id may sign as role, or role has no registered list."""
        signers = self._load_roles().get(role)
        return signers is None or signer_id in signers

    def has_role_authorization_list(self, role: str) -> bool:
        """Return whether role has an explicitly configured authorization list.

        This lets application profiles that require explicit grants distinguish
        an unconfigured role from one whose configured list denies a signer,
        while preserving this keystore's default opt-in role semantics.
        """
        return role in self._load_roles()

    def check_roles(self, doc: SPIFDocument) -> None:
        """
        Verify every role claim in doc.signer_roles against this store's policy.

        Raises SPIFSignatureError if a signer_id claims a role it is not
        authorized for, or if the claimed signer_id is not among the document's
        declared signers (an unbound claim — anyone could attach that name).
        Roles with no registered authorization list are not enforced. Does not
        check signature validity or key revocation — call verify() for that;
        this is a separate, explicit policy check.
        """
        declared_signers = {s.signer for s in doc.signatures}
        if doc.signature:
            declared_signers.add(doc.signature.signer)

        for signer_id, role in doc.signer_roles.items():
            if signer_id not in declared_signers:
                raise SPIFSignatureError(
                    f"Role claim for {signer_id!r} does not match any declared "
                    f"signer on this document"
                )
            if not self.is_authorized_for_role(role, signer_id):
                raise SPIFSignatureError(
                    f"Signer {signer_id!r} is not authorized for role {role!r}"
                )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, doc_or_data: SPIFDocument | bytes) -> bool:
        """
        Verify the signature(s) on a SPIF document using keys in this store.

        ed25519 entries verify classically; hybrid
        (``ed25519+ml-dsa-65``, SPEC §7.9) entries verify strictly —
        both components — against the signer's stored hybrid keys (or
        the entry's self-describing signer keys). PQ-only entries are
        unsupported here and raise as unverifiable.

        Parameters
        ----------
        doc_or_data :
            Raw SPIF bytes, or an unsigned ``SPIFDocument``.

            Signed documents must be verified from raw bytes so the verifier can
            use the exact original signing body. A decoded ``SPIFDocument`` does
            not preserve enough wire-level information for byte-accurate
            verification.

        Returns
        -------
        bool
            True if at least one valid, non-revoked signature was found.
            False if the document has no signature chunks.

        Raises
        ------
        SPIFSignatureError
            If a signature is present but invalid, if the signer is revoked, if
            the signing key is not found in this store, or if a signed document
            is provided without the original raw bytes.
        SPIFFormatError
            If the raw bytes cannot be decoded.
        """
        raw_data: bytes | None = None
        if isinstance(doc_or_data, bytes):
            raw_data = doc_or_data
            doc = SPIFReader().decode(doc_or_data)
        else:
            doc = doc_or_data

        sigs = list(doc.signatures)
        if doc.signature:
            sigs.append(doc.signature)

        if not sigs:
            return False

        if raw_data is None:
            raise SPIFSignatureError(
                "SPIFKeyStore.verify() requires raw SPIF bytes for signed documents. "
                "Pass the original encoded bytes instead of a decoded SPIFDocument."
            )

        auth_offset = _find_first_auth_chunk_offset(raw_data)
        if auth_offset is None:
            raise SPIFSignatureError(
                "Document advertises signature data but no SIGNATURE/MULTISIG chunk "
                "was found before CHECKSUM"
            )
        body_to_sign = raw_data[:auth_offset]

        for sig in sigs:
            signer = sig.signer
            if sig.algorithm == "ed25519+ml-dsa-65":
                self._verify_hybrid(sig, signer, body_to_sign)
                continue
            # Key lookup
            raw_key = self.get_key(signer)
            if raw_key is None:
                raise SPIFSignatureError(
                    f"No public key for signer '{signer}' in keystore at {self._root}"
                )
            if sig.algorithm != "ed25519":
                raise SPIFSignatureError(
                    f"Unsupported signature algorithm '{sig.algorithm}'; only ed25519 is supported"
                )
            # Cryptographic verification
            pub = Ed25519PublicKey.from_public_bytes(raw_key)
            try:
                pub.verify(sig.signature, body_to_sign)
            except InvalidSignature:
                raise SPIFSignatureError(
                    f"Signature by '{signer}' is cryptographically invalid"
                )
            if self.is_revoked(signer):
                raise SPIFRevokedSignerError(
                    f"Signer '{signer}' is revoked as of "
                    f"{self._load_revoked()[signer]} ms"
                )

        return True

    def _verify_hybrid(self, sig, signer: str, body_to_sign: bytes) -> None:
        """Strictly verify one hybrid signature entry (SPEC §7.9): BOTH
        components must verify under the signer's stored hybrid keys —
        the keystore is a strict verifier and has no gate modes. Falls
        back to the entry's self-describing signer keys (§7.9.1) when
        the signer id is not a registered keystore id. Revocation is by
        signer id and revokes the whole hybrid identity (§7.9.3)."""
        from .pq_hybrid import (
            hybrid_verify_message,
            parse_hybrid_signer,
            pq_available,
        )

        keys = self.get_hybrid_key(signer)
        if keys is None:
            keys = parse_hybrid_signer(signer)
        if keys is None:
            raise SPIFSignatureError(
                f"No hybrid public key for signer '{signer}' in "
                f"keystore at {self._root}"
            )
        if not pq_available():
            raise SPIFSignatureError(
                f"Cannot verify hybrid signature by '{signer}': the "
                "ML-DSA backend (pqcrypto) is not installed — install "
                "the 'pq' extra to verify hybrid signatures"
            )
        ed_raw, ml_raw = keys
        ok = hybrid_verify_message(ed_raw, ml_raw, body_to_sign, sig.signature)
        if not ok:
            raise SPIFSignatureError(
                f"Signature by '{signer}' is cryptographically invalid"
            )
        if self.is_revoked(signer):
            raise SPIFRevokedSignerError(
                f"Signer '{signer}' is revoked as of "
                f"{self._load_revoked()[signer]} ms"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_revoked(self) -> dict[str, int]:
        if not self._revocation_path.exists():
            return {}
        try:
            data = json.loads(self._revocation_path.read_text())
            return dict(data.get("revoked", {}))
        except (json.JSONDecodeError, KeyError, AttributeError) as exc:
            raise SPIFSignatureError(
                f"Revocation file {self._revocation_path} is malformed: {exc}"
            ) from exc

    def _save_revoked(self, revoked: dict[str, int]) -> None:
        self._revocation_path.write_text(
            json.dumps({"revoked": revoked}, indent=2)
        )

    def _load_roles(self) -> dict[str, list[str]]:
        if not self._roles_path.exists():
            return {}
        try:
            data = json.loads(self._roles_path.read_text())
            roles = data.get("roles", {})
            if not isinstance(roles, dict):
                raise ValueError("'roles' must be an object")
            for role, signers in roles.items():
                if not isinstance(role, str):
                    raise ValueError(f"role key {role!r} must be a string")
                if not isinstance(signers, list) or not all(isinstance(s, str) for s in signers):
                    raise ValueError(f"role {role!r} value must be a list of strings")
            return roles
        except (json.JSONDecodeError, KeyError, AttributeError, ValueError) as exc:
            raise SPIFSignatureError(
                f"Roles file {self._roles_path} is malformed: {exc}"
            ) from exc

    def _save_roles(self, roles: dict[str, list[str]]) -> None:
        # Atomic write: a crash/interruption mid-write must never leave a
        # truncated or partially-written roles.json for _load_roles to trip on.
        fd, tmp_path = tempfile.mkstemp(dir=self._roles_path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"roles": roles}, f, indent=2)
            os.replace(tmp_path, self._roles_path)
        except BaseException:
            os.unlink(tmp_path)
            raise


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def verify_with_keystore(
    doc_or_data: SPIFDocument | bytes,
    keystore: SPIFKeyStore,
) -> bool:
    """
    Verify a SPIF document's signature using the given key store.

    Convenience wrapper around ``keystore.verify(doc_or_data)``.

    Returns True if signatures are valid, False if unsigned.
    Raises SPIFSignatureError on any verification failure.
    """
    return keystore.verify(doc_or_data)


def _key_slug(key_id: str) -> str:
    """Convert a key_id to a safe filename stem."""
    # URL-encode characters that are unsafe in filenames
    import urllib.parse
    return urllib.parse.quote(key_id, safe="-_~.")
