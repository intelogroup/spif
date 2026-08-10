"""SPIFReader — deserialize bytes or a file into a SPIFDocument."""

from __future__ import annotations
from functools import lru_cache
import hashlib
import hmac
import math
import os
import struct
import zlib
from collections import deque
import warnings
from pathlib import Path

import cbor2

from .format import (
    MAGIC,
    CHUNK_HEADER, CHUNK_PROVENANCE, CHUNK_SEMANTIC, CHUNK_TRACE,
    CHUNK_PAYLOAD, CHUNK_ALTS, CHUNK_DELTA, CHUNK_SIGNATURE, CHUNK_MULTISIG,
    CHUNK_TASK, CHUNK_ROLES, CHUNK_CHECKSUM,
    TAG_DISTRIBUTION, TAG_NODEREF, TAG_EMBEDDING,
    TRACE_POSTHOC, FLAG_COMPRESSED, FLAG_ZSTD,
)
from .types import (
    SPIFDocument, Distribution, NodeRef, Node, TraceStep,
    Provenance, SemanticLayer, Alternative, Delta, Signature, TaskInfo,
)

SUPPORTED_VERSIONS = {0x01, 0x02}
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # 10MB safety limit
MAX_PAYLOAD_NODES = 20_000  # ponytail: flat cap, raise if legit docs hit it

_CHUNK_STRUCT = struct.Struct(">BI")


class SPIFError(Exception):
    pass


class SPIFMagicError(SPIFError):
    pass


class SPIFVersionError(SPIFError):
    pass


class SPIFChecksumError(SPIFError):
    pass


class SPIFSignatureError(SPIFError):
    pass


class SPIFFormatError(SPIFError):
    pass


# ---------------------------------------------------------------------------
# CBOR tag resolution
# ---------------------------------------------------------------------------

def _tag_hook(decoder, tag: cbor2.CBORTag):
    """Called by cbor2 during decode — resolves SPIF tags in a single pass."""
    if tag.tag == TAG_DISTRIBUTION:
        return Distribution.from_dict(tag.value)
    if tag.tag == TAG_NODEREF:
        return NodeRef(tag.value)
    if tag.tag == TAG_EMBEDDING:
        return tag.value
    return tag  # unknown tag — return raw


def _decode_node(d: dict) -> Node:
    if not isinstance(d, dict):
        raise SPIFFormatError(f"Node entry must be a dict, got {type(d).__name__}")
    try:
        conf = d["confidence"]
        if not isinstance(conf, Distribution):
            if not isinstance(conf, dict):
                raise SPIFFormatError(
                    f"Node confidence must be a Distribution or dict, got {type(conf).__name__}"
                )
            conf = Distribution.from_dict(conf)
        refs = d.get("refs", [])
        if not isinstance(refs, list):
            raise SPIFFormatError(f"Node refs must be a list, got {type(refs).__name__}")
        return Node(
            id=d["id"],
            type=d["type"],
            value=d["value"],
            confidence=conf,
            refs=[r if isinstance(r, NodeRef) else NodeRef(r) for r in refs],
        )
    except SPIFFormatError:
        raise
    except (KeyError, TypeError, ValueError) as e:
        raise SPIFFormatError(f"Malformed Node entry: {e}") from e


def _decode_step(d: dict) -> TraceStep:
    if not isinstance(d, dict):
        raise SPIFFormatError(f"TraceStep entry must be a dict, got {type(d).__name__}")
    try:
        conf = d["confidence"]
        if not isinstance(conf, Distribution):
            if not isinstance(conf, dict):
                raise SPIFFormatError(
                    f"TraceStep confidence must be a Distribution or dict, got {type(conf).__name__}"
                )
            conf = Distribution.from_dict(conf)
        deps = d.get("deps", [])
        if not isinstance(deps, list):
            raise SPIFFormatError(f"TraceStep deps must be a list, got {type(deps).__name__}")
        alternatives = d.get("alternatives", [])
        if not isinstance(alternatives, list):
            raise SPIFFormatError(
                f"TraceStep alternatives must be a list, got {type(alternatives).__name__}"
            )
        return TraceStep(
            id=d["id"],
            type=d["type"],
            content=d["content"],
            confidence=conf,
            deps=deps,
            alternatives=alternatives,
        )
    except SPIFFormatError:
        raise
    except (KeyError, TypeError, ValueError) as e:
        raise SPIFFormatError(f"Malformed TraceStep entry: {e}") from e


# ---------------------------------------------------------------------------
# DAG validation
# ---------------------------------------------------------------------------

def _summarize_ids(ids: list[str], limit: int = 20) -> str:
    """Truncate long ID lists in error messages — a cycle over N nodes would
    otherwise dump all N IDs into the exception string/logs."""
    if len(ids) <= limit:
        return repr(ids)
    shown = ", ".join(repr(i) for i in ids[:limit])
    return f"[{shown}, ... {len(ids) - limit} more]"


def _validate_trace_dag(steps: list[TraceStep]) -> None:
    """Topological sort to detect cycles and dangling deps."""
    # Check for duplicate IDs first
    seen: set[str] = set()
    for s in steps:
        if s.id in seen:
            raise SPIFFormatError(f"Duplicate TraceStep id: '{s.id}'")
        seen.add(s.id)

    # Fast-path: if no steps have any dependencies, there can be no cycles or dangling deps!
    if not any(s.deps for s in steps):
        return

    ids = {s.id for s in steps}
    for s in steps:
        for dep in s.deps:
            if dep not in ids:
                raise SPIFFormatError(
                    f"TraceStep '{s.id}' references unknown dep '{dep}'"
                )

    # Kahn's algorithm
    in_degree: dict[str, int] = {s.id: 0 for s in steps}
    dependents: dict[str, list[str]] = {s.id: [] for s in steps}
    for s in steps:
        for dep in s.deps:
            in_degree[s.id] += 1
            dependents[dep].append(s.id)

    queue: deque[str] = deque(sid for sid, deg in in_degree.items() if deg == 0)
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for child in dependents[node]:
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    if visited != len(steps):
        cycle_members = [sid for sid, deg in in_degree.items() if deg > 0]
        raise SPIFFormatError(
            f"Cycle detected in trace DAG involving steps: {_summarize_ids(cycle_members)}"
        )


def _validate_payload_dag(nodes: list[Node]) -> None:
    """Topological sort over Node.refs to detect cycles and dangling references.

    Node.refs (``NodeRef`` objects) form a directed graph over payload node IDs.
    A cycle (e.g. A → B → A) would prevent safe traversal of the payload DAG
    and indicates a malformed or adversarially crafted document.
    """
    # Duplicate ID check
    seen: set[str] = set()
    for n in nodes:
        if n.id in seen:
            raise SPIFFormatError(f"Duplicate Node id: '{n.id}'")
        seen.add(n.id)

    # Fast-path: if no nodes have references, there can be no cycles or dangling refs!
    if not any(n.refs for n in nodes):
        return

    ids = {n.id for n in nodes}

    # Dangling reference check
    for n in nodes:
        for ref in (n.refs or []):
            if ref.node_id not in ids:
                raise SPIFFormatError(
                    f"Node '{n.id}' references unknown node_id '{ref.node_id}'"
                )

    # Kahn's algorithm for cycle detection
    in_degree: dict[str, int] = {n.id: 0 for n in nodes}
    dependents: dict[str, list[str]] = {n.id: [] for n in nodes}
    for n in nodes:
        for ref in (n.refs or []):
            in_degree[n.id] += 1
            dependents[ref.node_id].append(n.id)

    queue: deque[str] = deque(nid for nid, deg in in_degree.items() if deg == 0)
    visited = 0
    while queue:
        nid = queue.popleft()
        visited += 1
        for child in dependents[nid]:
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    if visited != len(nodes):
        cycle_members = [nid for nid, deg in in_degree.items() if deg > 0]
        raise SPIFFormatError(
            f"Cycle detected in payload Node refs involving nodes: {_summarize_ids(cycle_members)}"
        )


# ---------------------------------------------------------------------------
# Safe CBOR loader
# ---------------------------------------------------------------------------

def _cbor_load(data: bytes, chunk_name: str, *,
               compressed: bool = False, zstd_compressed: bool = False):
    """
    Deserialize CBOR bytes, raising SPIFFormatError on any failure.

    Uses tag_hook to resolve SPIF-specific CBORTags in a single decode pass,
    avoiding a separate _decode_tag() tree walk.

    cbor2 can return a 'break_marker_type' sentinel (not a dict/list) when
    given certain invalid byte sequences like 0xFF. We treat any non-standard
    result or exception as a format error.

    If ``compressed=True``, the bytes are first decompressed with zlib.
    If ``zstd_compressed=True``, the bytes are decompressed with zstd (v1.1+).
    """
    if zstd_compressed:
        try:
            import zstandard as zstd_mod  # type: ignore[import]
        except ImportError as exc:
            raise SPIFFormatError(
                f"zstandard package required to read zstd-compressed {chunk_name} chunk: "
                "pip install zstandard"
            ) from exc
        try:
            data = zstd_mod.ZstdDecompressor().decompress(data, max_output_size=MAX_DECOMPRESSED_SIZE)
        except Exception as e:
            raise SPIFFormatError(f"zstd decompression failed in {chunk_name} chunk: {e}") from e
    elif compressed:
        try:
            dobj = zlib.decompressobj()
            data = dobj.decompress(data, MAX_DECOMPRESSED_SIZE)
            if dobj.unconsumed_tail or dobj.unused_data:
                raise SPIFFormatError(
                    f"zlib decompression failed in {chunk_name} chunk: "
                    f"Decompressed data size exceeds safety limit of {MAX_DECOMPRESSED_SIZE} bytes"
                )
        except zlib.error as e:
            raise SPIFFormatError(f"zlib decompression failed in {chunk_name} chunk: {e}") from e
    try:
        result = cbor2.loads(data, tag_hook=_tag_hook)
    except SPIFFormatError:
        raise
    except Exception as e:
        raise SPIFFormatError(f"Malformed CBOR in {chunk_name} chunk: {e}") from e
    # cbor2 break_marker or other sentinel types are not valid SPIF payloads
    if not isinstance(result, (dict, list, str, int, float, bytes, bool, type(None),
                                Distribution, NodeRef)):
        raise SPIFFormatError(
            f"Unexpected CBOR type {type(result).__name__} in {chunk_name} chunk"
        )
    return result


# ---------------------------------------------------------------------------
# Chunk iterator
# ---------------------------------------------------------------------------

def _iter_chunks(data: bytes, offset: int):
    """Yield (chunk_type, chunk_data_bytes) from offset."""
    while offset < len(data):
        if offset + 5 > len(data):
            raise SPIFFormatError("Truncated chunk header")
        chunk_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
        offset += 5
        if offset + length > len(data):
            raise SPIFFormatError(
                f"Chunk 0x{chunk_type:02x} claims {length} bytes but only "
                f"{len(data) - offset} remain"
            )
        yield chunk_type, data[offset: offset + length]
        offset += length


def _find_first_auth_chunk_offset(data: bytes) -> int | None:
    """
    Return the byte offset of the first SIGNATURE or MULTISIG chunk.

    The signing body is defined as all bytes before the first authentication
    chunk. If neither auth chunk is present before CHECKSUM, returns None.
    """
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            break
        chunk_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
        if chunk_type in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            return offset
        if chunk_type == CHUNK_CHECKSUM:
            return None
        offset += 5 + length
    return None


# ---------------------------------------------------------------------------
# Main reader
# ---------------------------------------------------------------------------

@lru_cache(maxsize=256)
def _get_pub_key(signer_b64: str):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub_bytes = base64.b64decode(signer_b64)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


class SPIFReader:
    """
    Deserializes SPIF documents from bytes or files.

    Parameters
    ----------
    require_signature : bool
        When True, ``decode()`` raises ``SPIFSignatureError`` if the document
        carries no ed25519 signature.  Use this in production pipelines where
        tamper-proof provenance is mandatory.  Default False (backward-compatible).

    Security model reminder
    -----------------------
    SHA-256 checksums detect *accidental* corruption (bit rot, truncation, bad
    writes).  They do NOT protect against an attacker who modifies the content
    and recomputes the checksum.  Only an ed25519 signature over a known
    signing key provides tamper-evidence against intentional substitution.
    Set ``require_signature=True`` whenever the document origin matters.
    """

    def __init__(
        self,
        *,
        require_signature: bool = False,
        revocation_list_path: str | Path | None = None,
        max_signature_age_seconds: int | None = None,
    ) -> None:
        env_strict = os.environ.get("SPIF_REQUIRE_SIGNATURE", "").strip() in ("1", "true", "yes")
        self._require_signature = require_signature or env_strict
        self._revocation_list: set[str] = set()
        if revocation_list_path is not None:
            from .crypto import load_revocation_list
            self._revocation_list = load_revocation_list(revocation_list_path)
        self._max_signature_age_seconds = max_signature_age_seconds

    @classmethod
    def strict(cls) -> "SPIFReader":
        """Return a reader that rejects unsigned documents.

        Equivalent to ``SPIFReader(require_signature=True)``.  Mirrors the
        ``SPIFReader::strict()`` constructor in the Rust implementation.

        Production pipelines SHOULD use this instead of the default reader
        whenever document origin must be verifiable.
        """
        return cls(require_signature=True)

    def decode(self, data: bytes) -> SPIFDocument:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SPIFMagicError(
                f"decode() requires bytes-like input, got {type(data).__name__}"
            )
        # 1. Magic
        if len(data) < len(MAGIC) + 2:
            raise SPIFMagicError("File too short to be a SPIF document")
        if data[:len(MAGIC)] != MAGIC:
            raise SPIFMagicError(
                f"Bad magic bytes: {data[:len(MAGIC)].hex()} (expected {MAGIC.hex()})"
            )

        version = data[len(MAGIC)]
        if version not in SUPPORTED_VERSIONS:
            raise SPIFVersionError(f"Unsupported SPIF version: {version}")

        # v0.1 compat: warn about missing semantics fields
        is_v1 = (version == 0x01)

        # 2. Find terminal chunks — SIGNATURE (optional) then CHECKSUM (required)
        checksum_offset = None
        offset = len(MAGIC) + 2
        while offset < len(data):
            if offset + 5 > len(data):
                break
            chunk_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
            if chunk_type == CHUNK_CHECKSUM:
                checksum_offset = offset
                break
            offset += 5 + length

        if checksum_offset is None:
            raise SPIFFormatError("No CHECKSUM chunk found")

        # 3. Validate checksum
        body = data[:checksum_offset]
        _, csum_len = struct.unpack_from(">BI", data, checksum_offset)
        stored_checksum = data[checksum_offset + 5: checksum_offset + 5 + csum_len]
        computed = hashlib.sha256(body).digest()
        if not hmac.compare_digest(stored_checksum, computed):
            raise SPIFChecksumError(
                f"Checksum mismatch: stored={stored_checksum.hex()}, "
                f"computed={computed.hex()}"
            )

        # 4. Parse all chunks up to CHECKSUM
        chunks: dict[int, list[bytes]] = {}
        roles_offset = None
        auth_offset = None
        scan_offset = len(MAGIC) + 2
        for chunk_type, chunk_data in _iter_chunks(data, len(MAGIC) + 2):
            if chunk_type == CHUNK_CHECKSUM:
                break
            if chunk_type in chunks and (chunk_type <= 0x0F or chunk_type == CHUNK_CHECKSUM):
                raise SPIFFormatError(
                    f"Duplicate chunk of type 0x{chunk_type:02x} is not allowed"
                )
            if chunk_type == CHUNK_ROLES and roles_offset is None:
                roles_offset = scan_offset
            if chunk_type in (CHUNK_SIGNATURE, CHUNK_MULTISIG) and auth_offset is None:
                auth_offset = scan_offset
            chunks.setdefault(chunk_type, []).append(chunk_data)
            scan_offset += 5 + len(chunk_data)

        if roles_offset is not None and auth_offset is not None and roles_offset >= auth_offset:
            raise SPIFFormatError(
                "ROLES chunk must precede SIGNATURE/MULTISIG so role claims "
                "are covered by the signature"
            )

        # 4a. Detect compression from HEADER chunk (flags2 field)
        compressed = False
        zstd_compressed = False
        if CHUNK_HEADER in chunks:
            hdr = _cbor_load(chunks[CHUNK_HEADER][0], "HEADER")
            if isinstance(hdr, dict):
                flags2 = hdr.get("flags2", 0)
                compressed = bool(flags2 & FLAG_COMPRESSED)
                zstd_compressed = bool(flags2 & FLAG_ZSTD)

        # 5. PAYLOAD (required) — decompressed if needed
        if CHUNK_PAYLOAD not in chunks:
            raise SPIFFormatError("Missing required PAYLOAD chunk")

        raw_payload = _cbor_load(chunks[CHUNK_PAYLOAD][0], "PAYLOAD",
                                 compressed=compressed, zstd_compressed=zstd_compressed)
        if not isinstance(raw_payload, list):
            raise SPIFFormatError("PAYLOAD chunk must decode to a list")
        if len(raw_payload) > MAX_PAYLOAD_NODES:
            raise SPIFFormatError(
                f"Payload has {len(raw_payload)} nodes, exceeding the limit of {MAX_PAYLOAD_NODES}"
            )
        payload = [_decode_node(n) for n in raw_payload]
        if not payload:
            raise SPIFFormatError("PAYLOAD must contain at least one node")
        _validate_payload_dag(payload)

        # 6. PROVENANCE — never compressed
        provenance = None
        if CHUNK_PROVENANCE in chunks:
            p = _cbor_load(chunks[CHUNK_PROVENANCE][0], "PROVENANCE")
            if not isinstance(p, dict):
                raise SPIFFormatError("PROVENANCE chunk must decode to a dict")
            provenance = Provenance(
                source_model=p.get("source_model", ""),
                model_version=p.get("model_version", ""),
                temperature=p.get("temperature", 0.0),
                input_hash=p.get("input_hash", ""),
                context_ref=p.get("context_ref", ""),
                timestamp_ms=p.get("timestamp_ms", 0),
                attempt=p.get("attempt", 0),
                task_id=p.get("task_id", ""),
                risk_tier=p.get("risk_tier", ""),
                model_card=p.get("model_card", ""),
                training_data_hash=p.get("training_data_hash", ""),
                energy_wh=p.get("energy_wh", 0.0),
                human_oversight=p.get("human_oversight", ""),
                nonce=p.get("nonce", ""),
            )

        # 7. SEMANTIC — compressed if flag set
        semantic = None
        if CHUNK_SEMANTIC in chunks:
            s = _cbor_load(chunks[CHUNK_SEMANTIC][0], "SEMANTIC",
                           compressed=compressed, zstd_compressed=zstd_compressed)
            if not isinstance(s, dict):
                raise SPIFFormatError("SEMANTIC chunk must decode to a dict")
            emb = s.get("embedding", [])
            semantic = SemanticLayer(
                embedding=emb,
                embedding_model=s.get("embedding_model", ""),  # v0.1 compat: default ""
                covariance=s.get("covariance", []),
            )

        # 8. TRACE (v0.2: wrapped dict; v0.1: bare list) — compressed if flag set
        trace: list[TraceStep] = []
        trace_method = TRACE_POSTHOC
        if CHUNK_TRACE in chunks:
            raw = _cbor_load(chunks[CHUNK_TRACE][0], "TRACE",
                             compressed=compressed, zstd_compressed=zstd_compressed)
            if isinstance(raw, list):
                # v0.1 format: bare list of steps
                trace = [_decode_step(st) for st in raw]
                if is_v1:
                    warnings.warn(
                        "Reading v0.1 TRACE chunk: trace_method defaults to 'post-hoc'. "
                        "Re-encode with SPIFWriter to upgrade to v0.2.",
                        DeprecationWarning, stacklevel=3,
                    )
            else:
                if not isinstance(raw, dict):
                    raise SPIFFormatError("TRACE chunk must decode to a list or dict")
                # v0.2 format: {method, steps}
                trace_method = raw.get("method", TRACE_POSTHOC)
                if not isinstance(trace_method, str):
                    raise SPIFFormatError("TRACE method must be a string")
                steps = raw.get("steps", [])
                if not isinstance(steps, list):
                    raise SPIFFormatError("TRACE steps must be a list")
                trace = [_decode_step(st) for st in steps]

        # DAG validation (all versions)
        if trace:
            _validate_trace_dag(trace)

        # 9. ALTS (v0.2: wrapped dict; v0.1: bare list) — compressed if flag set
        alternatives: list[Alternative] = []
        if CHUNK_ALTS in chunks:
            raw = _cbor_load(chunks[CHUNK_ALTS][0], "ALTS",
                             compressed=compressed, zstd_compressed=zstd_compressed)
            if isinstance(raw, list):
                # v0.1 format
                for a in raw:
                    if not isinstance(a, dict):
                        raise SPIFFormatError(
                            f"Alternative entry must be a dict, got {type(a).__name__}"
                        )
                    alternatives.append(Alternative(
                        weight=a["weight"],
                        nodes=[_decode_node(n) for n in a["nodes"]],
                    ))
            else:
                if not isinstance(raw, dict):
                    raise SPIFFormatError("ALTS chunk must decode to a list or dict")
                # v0.2 format: {normalized, alts}
                normalized = raw.get("normalized", True)
                if not isinstance(normalized, bool):
                    raise SPIFFormatError("ALTS normalized must be a bool")
                alts = raw.get("alts", [])
                if not isinstance(alts, list):
                    raise SPIFFormatError("ALTS alts must be a list")
                for a in alts:
                    if not isinstance(a, dict):
                        raise SPIFFormatError(
                            f"Alternative entry must be a dict, got {type(a).__name__}"
                        )
                    alternatives.append(Alternative(
                        weight=a["weight"],
                        nodes=[_decode_node(n) for n in a["nodes"]],
                        normalized=normalized,
                    ))
                # Validate weights if normalized
                if normalized and alternatives:
                    total = sum(a.weight for a in alternatives)
                    if abs(total - 1.0) > 0.01:
                        raise SPIFFormatError(
                            f"ALTS normalized=True but weights sum to {total:.4f}, "
                            f"expected 1.0 ± 0.01"
                        )

            if alternatives and any(math.isnan(a.weight) for a in alternatives):
                raise SPIFFormatError("ALTS weight must not be nan")

        # 10. DELTA — compressed if flag set
        delta = None
        if CHUNK_DELTA in chunks:
            d = _cbor_load(chunks[CHUNK_DELTA][0], "DELTA",
                           compressed=compressed, zstd_compressed=zstd_compressed)
            if not isinstance(d, dict):
                raise SPIFFormatError("DELTA chunk must decode to a dict")
            delta = Delta(base_hash=d["base_hash"], changes=d.get("changes", []))

        # 11. SIGNATURE (v0.2)
        signature = None
        if CHUNK_SIGNATURE in chunks:
            s = _cbor_load(chunks[CHUNK_SIGNATURE][0], "SIGNATURE")
            if not isinstance(s, dict):
                raise SPIFFormatError("SIGNATURE chunk must decode to a dict")
            sig_bytes = s.get("signature", b"")
            if isinstance(sig_bytes, memoryview):
                sig_bytes = bytes(sig_bytes)
            signature = Signature(
                algorithm=s.get("algorithm", "ed25519"),
                signer=s.get("signer", ""),
                signature=sig_bytes,
                key_id=s.get("key_id", ""),
            )

        # 12. MULTISIG (v0.2+)
        signatures: list[Signature] = []
        if CHUNK_MULTISIG in chunks:
            raw = _cbor_load(chunks[CHUNK_MULTISIG][0], "MULTISIG")
            if not isinstance(raw, list):
                raise SPIFFormatError("MULTISIG chunk must decode to a list")
            for s in raw:
                sig_bytes = s.get("signature", b"")
                if isinstance(sig_bytes, memoryview):
                    sig_bytes = bytes(sig_bytes)
                signatures.append(Signature(
                    algorithm=s.get("algorithm", "ed25519"),
                    signer=s.get("signer", ""),
                    signature=sig_bytes,
                    key_id=s.get("key_id", ""),
                ))

        # 13. TASK chunk (v1.1+) — never compressed
        task_info = None
        if CHUNK_TASK in chunks:
            t = _cbor_load(chunks[CHUNK_TASK][0], "TASK")
            if not isinstance(t, dict):
                raise SPIFFormatError("TASK chunk must decode to a dict")
            task_info = TaskInfo(
                task_id=t.get("task_id", ""),
                attempt=t.get("attempt", 0),
                status=t.get("status", "ok"),
                total_ms=t.get("total_ms", 0),
                tool_count=t.get("tool_count", 0),
                error_count=t.get("error_count", 0),
            )

        # 14. ROLES chunk (v1.1+) — signer_id -> claimed role, never compressed
        signer_roles: dict[str, str] = {}
        if CHUNK_ROLES in chunks:
            r = _cbor_load(chunks[CHUNK_ROLES][0], "ROLES")
            if not isinstance(r, dict):
                raise SPIFFormatError("ROLES chunk must decode to a dict")
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in r.items()):
                raise SPIFFormatError("ROLES chunk keys and values must all be strings")
            signer_roles = dict(r)

        doc = SPIFDocument(
            payload=payload,
            provenance=provenance,
            semantic=semantic,
            trace=trace,
            trace_method=trace_method,
            alternatives=alternatives,
            delta=delta,
            signature=signature,
            signatures=signatures,
            task_info=task_info,
            signer_roles=signer_roles,
        )

        # Signature enforcement — must come after full parse so that the
        # signature/signatures fields are populated before we inspect them.
        if self._require_signature:
            if doc.signature is None and not doc.signatures:
                raise SPIFSignatureError(
                    "Document is unsigned. SPIFReader was created with "
                    "require_signature=True — sign the document with an ed25519 "
                    "key before distributing it, or use require_signature=False "
                    "if provenance guarantees are not needed."
                )
            # Cryptographically verify the signature — not just its presence.
            # A stale or forged signature chunk with a recomputed checksum would
            # otherwise pass decode() silently.
            self._verify_sig_inner(doc, data, self._revocation_list)

        # Time-bounded signature age limit check
        if self._max_signature_age_seconds is not None:
            import time
            if doc.provenance is None:
                raise SPIFSignatureError(
                    "Provenance chunk is missing, cannot verify signature age limit"
                )
            current_ms = int(time.time() * 1000)
            age_ms = current_ms - doc.provenance.timestamp_ms
            if age_ms < -5000:
                raise SPIFSignatureError(
                    f"Signature is post-dated (in the future) by {-age_ms / 1000:.1f} seconds"
                )
            if age_ms > self._max_signature_age_seconds * 1000:
                raise SPIFSignatureError(
                    f"Signature expired: age is {age_ms / 1000:.1f} seconds, "
                    f"maximum allowed is {self._max_signature_age_seconds} seconds"
                )

        return doc

    def read(self, path: str | Path) -> SPIFDocument:
        return self.decode(Path(path).read_bytes())

    @staticmethod
    def _verify_sig_inner(
        doc: "SPIFDocument",
        data: bytes,
        revocation_list: set[str],
    ) -> bool:
        """
        Core ed25519 verification. Takes an already-decoded doc and the raw bytes
        it was decoded from. Separated from decode() to avoid circular calls.

        Returns True if all signatures are valid.
        Returns False if no signatures are present.
        Raises SPIFSignatureError if any signature fails.
        """
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        def _check_revoked(signer_id: str) -> None:
            if signer_id in revocation_list:
                raise SPIFSignatureError(
                    f"Signer '{signer_id}' has been revoked"
                )

        def _verify_one(sig_obj, body_to_sign: bytes) -> None:
            _check_revoked(sig_obj.signer)
            if sig_obj.algorithm != "ed25519":
                raise SPIFSignatureError(
                    f"Unsupported signature algorithm '{sig_obj.algorithm}'; "
                    "only ed25519 is supported"
                )
            try:
                pub_key = _get_pub_key(sig_obj.signer)
                pub_key.verify(sig_obj.signature, body_to_sign)
            except InvalidSignature as e:
                raise SPIFSignatureError(
                    "Signature verification failed: invalid signature"
                ) from e
            except SPIFSignatureError:
                raise
            except Exception as e:
                raise SPIFSignatureError(
                    f"Signature verification failed: {e}"
                ) from e

        sigs = []
        if doc.signature is not None:
            sigs.append(doc.signature)
        sigs.extend(doc.signatures)

        if not sigs:
            return False

        auth_offset = _find_first_auth_chunk_offset(data)
        if auth_offset is None:
            raise SPIFSignatureError(
                "Document advertises signature data but no SIGNATURE/MULTISIG chunk "
                "was found before CHECKSUM"
            )

        body_to_sign = data[:auth_offset]
        for sig_obj in sigs:
            _verify_one(sig_obj, body_to_sign)
        return True

    def verify_signature(
        self,
        data: bytes,
        revocation_list_path: str | Path | None = None,
        max_signature_age_seconds: int | None = None,
    ) -> bool:
        """
        Verify the ed25519 signature(s) in a SPIF document.

        body_to_sign = all bytes before the first SIGNATURE or MULTISIG chunk
        in the file.
        The signer field must be a base64-encoded raw ed25519 public key (32 bytes).
        For URL-based signers, the caller must resolve the key externally.

        If both SIGNATURE and MULTISIG are present, every signature in both
        chunks is verified against the same signing body: the bytes before the
        first auth chunk.

        If revocation_list_path is given, revoked signer IDs are rejected before
        cryptographic verification via SPIFSignatureError.

        Returns True if all present signatures are valid.
        Returns False if no signature chunk is present.
        Raises SPIFSignatureError if any signature is present but invalid.
        """
        # Use a non-strict reader to parse without triggering crypto verification
        # a second time — _verify_sig_inner does the actual check below.
        doc = SPIFReader(require_signature=False).decode(data)

        revocation_list: set[str] = set()
        if revocation_list_path is not None:
            from .crypto import load_revocation_list
            revocation_list = load_revocation_list(revocation_list_path)

        # Crytographically verify signatures first
        has_sigs = self._verify_sig_inner(doc, data, revocation_list)
        if not has_sigs:
            return False

        # Time-bounded signature age limit check
        limit_sec = max_signature_age_seconds if max_signature_age_seconds is not None else self._max_signature_age_seconds
        if limit_sec is not None:
            if doc.provenance is None:
                raise SPIFSignatureError(
                    "Provenance chunk is missing, cannot verify signature age limit"
                )
            import time
            current_ms = int(time.time() * 1000)
            age_ms = current_ms - doc.provenance.timestamp_ms
            if age_ms < -5000:
                raise SPIFSignatureError(
                    f"Signature is post-dated (in the future) by {-age_ms / 1000:.1f} seconds"
                )
            if age_ms > limit_sec * 1000:
                raise SPIFSignatureError(
                    f"Signature expired: age is {age_ms / 1000:.1f} seconds, "
                    f"maximum allowed is {limit_sec} seconds"
                )

        return True
