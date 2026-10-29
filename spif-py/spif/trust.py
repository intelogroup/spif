"""
SPIF v1.3 trust layer — revocation statements, timestamp anchors, and the
verification report.

Implements SPEC §7.7 (revocation), §7.8 (timestamp anchoring), and §8.1
(cross-document resolution policy). Everything here is offline by
construction: no function in this module performs network I/O. Revocations
arrive embedded in the artifact (REVOCATION chunk, 0x0B) or out-of-band in
a revocation-list file the caller supplies; cross-document references
resolve only from a caller-supplied local bundle.

Trust statuses (distinct from raw signature validity):

    VALID        signature valid, no valid revocation applies
    REVOKED      signature cryptographically valid, but a valid
                 signer-issued revocation applies — never reported as
                 VALID, never conflated with INVALID
    INVALID      a present signature fails, or the checksum fails
    UNSIGNED     no signature present
    UNVERIFIABLE a signature is present under an algorithm or key this
                 verifier cannot check
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .format import MAGIC, CHUNK_REVOCATION, CHUNK_TIMESTAMP, CHUNK_CHECKSUM
from .reader import (
    SPIFReader, SPIFError, SPIFChecksumError,
    _find_first_auth_chunk_offset, _iter_chunks,
)
from .types import RevocationStatement, TimestampAnchor, SPIFDocument

_CHUNK_STRUCT = struct.Struct(">BI")

REASON_CODES = frozenset({"compromised", "retracted", "superseded", "other"})

TRUST_VALID = "VALID"
TRUST_INVALID = "INVALID"
TRUST_REVOKED = "REVOKED"
TRUST_UNSIGNED = "UNSIGNED"
TRUST_UNVERIFIABLE = "UNVERIFIABLE"

TS_VERIFIED = "verified"
TS_UNVERIFIED = "unverified"
TS_ABSENT = "absent"


# ---------------------------------------------------------------------------
# Artifact identity
# ---------------------------------------------------------------------------

def signing_body_of(data: bytes) -> bytes:
    """The byte range covered by the artifact's signature(s).

    All bytes before the first SIGNATURE/MULTISIG chunk; for an unsigned
    document, all bytes before the CHECKSUM chunk. Stable under
    post-signature chunk attachment (REVOCATION / TIMESTAMP) and checksum
    recomputation.
    """
    auth_offset = _find_first_auth_chunk_offset(data)
    if auth_offset is not None:
        return data[:auth_offset]
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            break
        chunk_type, _length = _CHUNK_STRUCT.unpack_from(data, offset)
        if chunk_type == CHUNK_CHECKSUM:
            return data[:offset]
        offset += 5 + _length
    return data


def artifact_digest(data: bytes) -> str:
    """SHA-256 hex of the signing body — the digest revocations bind (SPEC §7.7)."""
    return hashlib.sha256(signing_body_of(data)).hexdigest()


def _pubkey_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(
        key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def _pubkey_from_b64(text: str) -> Ed25519PublicKey | None:
    """Parse a base64 raw ed25519 public key; None if `text` is not one."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Revocation statements
# ---------------------------------------------------------------------------

def _statement_signing_bytes(stmt: RevocationStatement) -> bytes:
    return cbor2.dumps(stmt.unsigned_dict(), canonical=True)


def create_revocation(
    artifact: bytes,
    private_key: Ed25519PrivateKey,
    *,
    reason: str = "retracted",
    signer_id: str | None = None,
    issued_ms: int | None = None,
) -> RevocationStatement:
    """Create a signed revocation statement for `artifact` (raw SPIF bytes).

    `signer_id` defaults to the base64 raw public key — the self-describing
    signer form used by crypto.sign_document(). Pass the artifact's
    Signature.signer value when it differs (e.g. a URL signer id whose key
    this is). The statement only takes effect if `signer_id` is one of the
    artifact's signers and the signature verifies under that signer's key.
    """
    if reason not in REASON_CODES:
        raise ValueError(
            f"reason must be one of {sorted(REASON_CODES)}, got {reason!r}"
        )
    if signer_id is None:
        signer_id = _pubkey_b64(private_key.public_key())
    stmt = RevocationStatement(
        artifact_digest=artifact_digest(artifact),
        signer=signer_id,
        issued_ms=issued_ms if issued_ms is not None else int(time.time() * 1000),
        reason=reason,
        signature=b"",
    )
    stmt.signature = private_key.sign(_statement_signing_bytes(stmt))
    return stmt


def _resolve_signer_key(
    signer_id: str,
    known_keys: dict[str, str] | None,
) -> Ed25519PublicKey | None:
    """Resolve a signer id to its public key: caller-supplied map first,
    then the self-describing form (the id itself is a base64 raw key)."""
    if known_keys and signer_id in known_keys:
        return _pubkey_from_b64(known_keys[signer_id])
    return _pubkey_from_b64(signer_id)


def statement_is_authoritative(
    stmt: RevocationStatement,
    artifact_signer_ids: set[str],
    known_keys: dict[str, str] | None = None,
) -> bool:
    """True iff the statement was issued by one of the artifact's signers
    and its signature verifies under that signer's key."""
    if not isinstance(stmt.signer, str) or stmt.signer not in artifact_signer_ids:
        return False
    key = _resolve_signer_key(stmt.signer, known_keys)
    if key is None:
        return False
    try:
        key.verify(stmt.signature, _statement_signing_bytes(stmt))
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def save_revocation_list(statements: list[RevocationStatement], path: str | Path) -> None:
    """Write statements as a distributable revocation-list file (JSON).

    Format: {"revocations": [<statement>, ...]} with signatures
    base64-encoded. This is the out-of-band distribution format of SPEC
    §7.7 — distinct from the legacy key-revocation list consumed by
    crypto.load_revocation_list(), which lists bare signer ids.
    """
    payload = {"revocations": [s.to_json_dict() for s in statements]}
    Path(path).write_text(json.dumps(payload, indent=2))


def load_revocation_statements(path: str | Path) -> list[RevocationStatement]:
    """Load statements from a revocation-list file written by
    save_revocation_list(). Returns an empty list if the file is absent."""
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return [RevocationStatement.from_json_dict(d) for d in data.get("revocations", [])]


# ---------------------------------------------------------------------------
# Post-signature chunk attach / extract (REVOCATION now; TIMESTAMP in §7.8)
# ---------------------------------------------------------------------------

def _chunk_bytes(chunk_type: int, payload: bytes) -> bytes:
    return _CHUNK_STRUCT.pack(chunk_type, len(payload)) + payload


def attach_chunk(data: bytes, chunk_type: int, payload: bytes) -> bytes:
    """Insert or replace a post-signature chunk before CHECKSUM and
    recompute the checksum. The signing body is untouched, so existing
    signatures remain valid."""
    offset = len(MAGIC) + 2
    parts: list[bytes] = [data[:offset]]
    inserted = False
    while offset < len(data):
        if offset + 5 > len(data):
            raise ValueError("truncated chunk header")
        ctype, length = _CHUNK_STRUCT.unpack_from(data, offset)
        chunk = data[offset: offset + 5 + length]
        if ctype == CHUNK_CHECKSUM:
            if not inserted:
                parts.append(_chunk_bytes(chunk_type, payload))
                inserted = True
            break
        if ctype == chunk_type:
            if not inserted:
                parts.append(_chunk_bytes(chunk_type, payload))
                inserted = True
            # drop any duplicate of the same chunk type
        else:
            parts.append(chunk)
        offset += 5 + length
    else:
        raise ValueError("no CHECKSUM chunk found")
    body = b"".join(parts)
    return body + _chunk_bytes(CHUNK_CHECKSUM, hashlib.sha256(body).digest())


def attach_revocations(data: bytes, statements: list[RevocationStatement]) -> bytes:
    """Return a copy of the artifact with `statements` embedded in its
    REVOCATION chunk (replacing any existing one)."""
    existing = extract_revocations(data)
    merged = existing + [s for s in statements if s not in existing]
    payload = cbor2.dumps([s.to_cbor_dict() for s in merged], canonical=True)
    return attach_chunk(data, CHUNK_REVOCATION, payload)


def extract_revocations(data: bytes) -> list[RevocationStatement]:
    """Statements embedded in the artifact's REVOCATION chunk (raw scan —
    does not require the document to decode cleanly)."""
    out: list[RevocationStatement] = []
    try:
        for chunk_type, chunk_data in _iter_chunks(data, len(MAGIC) + 2):
            if chunk_type == CHUNK_CHECKSUM:
                break
            if chunk_type == CHUNK_REVOCATION:
                raw = cbor2.loads(chunk_data)
                if isinstance(raw, list):
                    out.extend(RevocationStatement.from_cbor_dict(d) for d in raw)
    except Exception:
        return out
    return out


# ---------------------------------------------------------------------------
# Timestamp anchors (SPEC §6.13 / §7.8)
# ---------------------------------------------------------------------------

def _timestamp_token_body(digest: str, time_ms: int) -> bytes:
    return cbor2.dumps(
        {"artifact_digest": digest, "time_ms": time_ms}, canonical=True
    )


def create_timestamp_anchor(
    artifact: bytes,
    tsa_private_key: Ed25519PrivateKey,
    *,
    authority: str | None = None,
    time_ms: int | None = None,
) -> TimestampAnchor:
    """Create a TSA countersignature anchor for `artifact` (raw SPIF bytes).

    `authority` defaults to the base64 raw public key of the TSA key (the
    self-describing form). The token countersigns (artifact_digest,
    time_ms) — testable end-to-end with a locally generated TSA key; no
    network protocol is involved (SPEC §7.8).
    """
    if authority is None:
        authority = _pubkey_b64(tsa_private_key.public_key())
    t = time_ms if time_ms is not None else int(time.time() * 1000)
    token = tsa_private_key.sign(_timestamp_token_body(artifact_digest(artifact), t))
    return TimestampAnchor(authority=authority, time_ms=t, token=token)


def attach_timestamp(data: bytes, anchor: TimestampAnchor) -> bytes:
    """Return a copy of the artifact with `anchor` embedded in its
    TIMESTAMP chunk (replacing any existing one)."""
    payload = cbor2.dumps(anchor.to_cbor_dict(), canonical=True)
    return attach_chunk(data, CHUNK_TIMESTAMP, payload)


def extract_timestamp(data: bytes) -> TimestampAnchor | None:
    """The artifact's embedded TIMESTAMP anchor, or None (raw scan)."""
    try:
        for chunk_type, chunk_data in _iter_chunks(data, len(MAGIC) + 2):
            if chunk_type == CHUNK_CHECKSUM:
                break
            if chunk_type == CHUNK_TIMESTAMP:
                raw = cbor2.loads(chunk_data)
                if isinstance(raw, dict):
                    return TimestampAnchor.from_cbor_dict(raw)
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Verification report
# ---------------------------------------------------------------------------

@dataclass
class ReferenceResolution:
    ref: str                 # the NodeRef string as it appears in the document
    kind: str                # "local" | "cross-document"
    status: str              # "local" | "resolved" | "unresolved"
    content_id: str = ""     # cross-document only
    node_id: str = ""        # cross-document only


@dataclass
class VerificationReport:
    signature_status: str    # "valid" | "invalid" | "unsigned" | "unverifiable"
    trust_status: str        # VALID | INVALID | REVOKED | UNSIGNED | UNVERIFIABLE
    timestamp_status: str    # "verified" | "unverified" | "absent"
    artifact_digest: str
    content_id: str = ""
    signers: list[str] = field(default_factory=list)
    revocations_applied: list[RevocationStatement] = field(default_factory=list)
    forged_revocations: int = 0
    references: list[ReferenceResolution] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def unresolved_references(self) -> list[ReferenceResolution]:
        return [r for r in self.references if r.status == "unresolved"]


def _coerce_statements(items) -> tuple[list[RevocationStatement], int]:
    """Coerce out-of-band revocation entries to statements.

    Returns (statements, malformed_count). A dict entry that fails
    conversion (missing fields, wrong types, bad base64) is malformed
    untrusted input, not a programming error: it is counted, never
    raised. A non-dict, non-statement item is a caller bug and still
    raises TypeError.
    """
    out: list[RevocationStatement] = []
    malformed = 0
    for item in items or []:
        if isinstance(item, RevocationStatement):
            out.append(item)
        elif isinstance(item, dict):
            try:
                # JSON form carries a base64 signature; CBOR form raw bytes.
                if isinstance(item.get("signature"), str):
                    out.append(RevocationStatement.from_json_dict(item))
                else:
                    out.append(RevocationStatement.from_cbor_dict(item))
            except (KeyError, TypeError, ValueError):
                malformed += 1
        else:
            raise TypeError(
                f"revocation entries must be RevocationStatement or dict, got {type(item).__name__}"
            )
    return out, malformed


def _load_revocation_file_tolerant(
    path: str | Path,
) -> tuple[list[RevocationStatement], int, str | None]:
    """Load a revocation-list file for verify_artifact(): never raises.

    Returns (statements, malformed_count, error). An absent file is not
    an error (matches load_revocation_statements' contract). A file
    that cannot be parsed at all yields an error string and no
    statements; individually malformed entries are counted so the
    report can surface them.
    """
    p = Path(path)
    if not p.exists():
        return [], 0, None
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        return [], 0, f"revocation file unreadable: {e}"
    entries = data.get("revocations") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], 0, "revocation file malformed: expected {\"revocations\": [...]}"
    statements, malformed = [], 0
    for entry in entries:
        if not isinstance(entry, dict):
            malformed += 1
            continue
        try:
            statements.append(RevocationStatement.from_json_dict(entry))
        except (KeyError, TypeError, ValueError):
            malformed += 1
    return statements, malformed, None


def verify_artifact(
    data: bytes,
    *,
    revocations=None,
    revocation_file: str | Path | None = None,
    tsa_keys: dict[str, str] | None = None,
    bundle=None,
    known_keys: dict[str, str] | None = None,
) -> VerificationReport:
    """Verify an artifact end-to-end and report trust, not just signatures.

    Parameters
    ----------
    revocations : iterable of RevocationStatement/dict, optional
        Candidate revocation statements supplied out-of-band.
    revocation_file : path, optional
        A revocation-list file (see save_revocation_list()).
    tsa_keys : dict authority -> base64 raw public key, optional
        Pinned TSA keys for timestamp verification (SPEC §7.8).
    bundle : iterable of bytes or SPIFDocument, optional
        Local bundle for cross-document reference resolution (SPEC §8.1).
        Nothing is ever fetched.
    known_keys : dict signer_id -> base64 raw public key, optional
        Key resolution for non-self-describing (e.g. URL) signer ids.
    """
    digest = artifact_digest(data)
    report = VerificationReport(
        signature_status="invalid",
        trust_status=TRUST_INVALID,
        timestamp_status=TS_ABSENT,
        artifact_digest=digest,
    )

    # --- Parse -------------------------------------------------------------
    try:
        doc = SPIFReader().decode(data)
    except SPIFChecksumError as e:
        report.errors.append(f"checksum: {e}")
        return report
    except SPIFError as e:
        report.errors.append(f"parse: {e}")
        return report
    report.content_id = doc.content_id()

    sigs = ([doc.signature] if doc.signature is not None else []) + list(doc.signatures)
    report.signers = [s.signer for s in sigs]
    signer_ids = set(report.signers)

    # --- Signature validity -------------------------------------------------
    if not sigs:
        report.signature_status = "unsigned"
        report.trust_status = TRUST_UNSIGNED
    else:
        body = signing_body_of(data)
        any_invalid = False
        any_unverifiable = False
        verified = 0
        for sig in sigs:
            if sig.algorithm != "ed25519":
                any_unverifiable = True
                continue
            key = _resolve_signer_key(sig.signer, known_keys)
            if key is None:
                any_unverifiable = True
                continue
            try:
                key.verify(sig.signature, body)
                verified += 1
            except InvalidSignature:
                any_invalid = True
            except Exception:
                any_invalid = True
        if any_invalid:
            report.signature_status = "invalid"
            report.trust_status = TRUST_INVALID
        elif verified == len(sigs):
            report.signature_status = "valid"
            report.trust_status = TRUST_VALID
        else:
            report.signature_status = "unverifiable"
            report.trust_status = TRUST_UNVERIFIABLE

    # --- Revocations ---------------------------------------------------------
    supplied, malformed = _coerce_statements(revocations)
    candidates = list(doc.revocations) + supplied
    if revocation_file is not None:
        file_stmts, file_malformed, file_error = _load_revocation_file_tolerant(
            revocation_file)
        candidates += file_stmts
        malformed += file_malformed
        if file_error is not None:
            report.errors.append(file_error)
    if malformed:
        # Unparseable purported revocations: they can never apply, but
        # they are surfaced as forgeries seen (SPEC §7.7) plus a note.
        report.forged_revocations += malformed
        report.errors.append(
            f"ignored {malformed} malformed revocation statement(s)")
    # Identical statements (same signed fields + same signature) are one
    # statement however many times they are supplied: process each unique
    # statement once so duplicates cannot amplify verification cost or
    # inflate the forgery count.
    seen: set[bytes] = set()
    unique: list[RevocationStatement] = []
    for stmt in candidates:
        try:
            identity = _statement_signing_bytes(stmt) + b"|" + bytes(stmt.signature)
        except Exception:
            identity = None  # unencodable hand-built statement: never deduped
        if identity is not None:
            if identity in seen:
                continue
            seen.add(identity)
        unique.append(stmt)
    candidates = unique
    for stmt in candidates:
        if stmt.artifact_digest != digest:
            continue  # about a different artifact — not a forgery signal
        if statement_is_authoritative(stmt, signer_ids, known_keys):
            if stmt not in report.revocations_applied:
                report.revocations_applied.append(stmt)
        else:
            report.forged_revocations += 1
    if report.revocations_applied and report.trust_status == TRUST_VALID:
        report.trust_status = TRUST_REVOKED

    # --- Timestamp (SPEC §7.8) ------------------------------------------------
    report.timestamp_status = _timestamp_status(doc, digest, tsa_keys)

    # --- Cross-document references (SPEC §8.1) ---------------------------------
    report.references = _resolve_references(doc, bundle)

    return report


def _timestamp_status(doc: SPIFDocument, digest: str, tsa_keys) -> str:
    anchor = getattr(doc, "timestamp_anchor", None)
    if anchor is None:
        return TS_ABSENT
    if not isinstance(anchor.authority, str):
        return TS_UNVERIFIED
    if not tsa_keys or anchor.authority not in tsa_keys:
        return TS_UNVERIFIED
    key = _pubkey_from_b64(tsa_keys[anchor.authority])
    if key is None:
        return TS_UNVERIFIED
    try:
        key.verify(anchor.token, _timestamp_token_body(digest, anchor.time_ms))
    except Exception:
        return TS_UNVERIFIED
    return TS_VERIFIED


CROSS_DOC_PREFIX = "spif:sha256:"


def _resolve_references(doc: SPIFDocument, bundle) -> list[ReferenceResolution]:
    bundle_index: dict[str, SPIFDocument] = {}
    for item in bundle or []:
        try:
            bdoc = item if isinstance(item, SPIFDocument) else SPIFReader().decode(item)
        except SPIFError:
            continue  # an undecodable bundle entry resolves nothing
        bundle_index[bdoc.content_id()] = bdoc

    out: list[ReferenceResolution] = []
    for node in doc.payload:
        for ref in node.refs:
            text = ref.node_id
            if text.startswith(CROSS_DOC_PREFIX) and "#" in text:
                cid, _, node_id = text[len(CROSS_DOC_PREFIX):].partition("#")
                target = bundle_index.get(cid)
                if target is not None and any(n.id == node_id for n in target.payload):
                    status = "resolved"
                else:
                    status = "unresolved"
                out.append(ReferenceResolution(
                    ref=text, kind="cross-document", status=status,
                    content_id=cid, node_id=node_id,
                ))
            else:
                out.append(ReferenceResolution(ref=text, kind="local", status="local"))
    return out
