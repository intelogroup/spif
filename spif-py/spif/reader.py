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
    CHUNK_TASK, CHUNK_ROLES, CHUNK_REVOCATION, CHUNK_TIMESTAMP, CHUNK_CHECKSUM,
    TAG_DISTRIBUTION, TAG_NODEREF, TAG_EMBEDDING,
    TRACE_POSTHOC, FLAG_COMPRESSED, FLAG_ZSTD,
)
from .types import (
    SPIFDocument, Distribution, NodeRef, Node, TraceStep,
    Provenance, SemanticLayer, Alternative, Delta, Signature, TaskInfo,
    RevocationStatement, TimestampAnchor,
)

SUPPORTED_VERSIONS = {0x01, 0x02}
MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # 10MB safety limit
MAX_PAYLOAD_NODES = 20_000  # ponytail: flat cap, raise if legit docs hit it
MAX_REVOCATION_STATEMENTS = 4_096  # ponytail: flat cap on embedded REVOCATION entries

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

    # Cross-document references (SPEC §8.1: "spif:sha256:<content_id>#<node_id>")
    # point outside this document by design. They are external: exempt from
    # the local dangling-reference check and the local cycle graph. Whether
    # they resolve is a verification-time question (spif.trust), never a
    # parse error.
    def _is_cross_doc(ref_id: str) -> bool:
        return ref_id.startswith("spif:")

    # Dangling reference check
    for n in nodes:
        for ref in (n.refs or []):
            if _is_cross_doc(ref.node_id):
                continue
            if ref.node_id not in ids:
                raise SPIFFormatError(
                    f"Node '{n.id}' references unknown node_id '{ref.node_id}'"
                )

    # Kahn's algorithm for cycle detection
    in_degree: dict[str, int] = {n.id: 0 for n in nodes}
    dependents: dict[str, list[str]] = {n.id: [] for n in nodes}
    for n in nodes:
        for ref in (n.refs or []):
            if _is_cross_doc(ref.node_id):
                continue
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

def _key_identity(span: bytes) -> bytes:
    """Identity of a map key for duplicate detection: the canonical
    re-encoding of the decoded key, so two byte-different encodings of
    the same key (short vs long-form length, f32 vs f64) still collide
    — cbor2 would collapse them into one dict entry. Falls back to the
    raw span when the key cannot be round-tripped."""
    try:
        return cbor2.dumps(cbor2.loads(span), canonical=True)
    except Exception:
        return span


def _scan_cbor(data: bytes, chunk_name: str, *, canonical: bool) -> None:
    """
    Walk one chunk's CBOR item, enforcing the SPEC §4.1 form rules.

    Always enforced (every document, signed or unsigned): no duplicate
    map keys. A duplicate key is *ambiguity*, not encoding variability —
    cbor2 resolves it last-wins while other conforming decoders resolve
    first-wins, so the chunk's meaning would depend on the decoder
    instead of the bytes.

    Additionally enforced when ``canonical`` is true (the caller passes
    this for every chunk of a document that carries a signature, which
    is what makes §12.4's writer rule — canonical CBOR for all chunks
    when a signature is present — reader-verifiable): definite lengths
    only and shortest-form arguments, the subset the SPIF writers emit
    (RFC 8949 §4.2 core deterministic encoding, minus key sorting, which
    the writers do not promise). Unsigned documents keep §4.1/§12.1's
    accept-both leniency for encoding *variability*: indefinite-length
    items and non-minimal forms decode normally.

    The scan is iterative so deeply nested inputs cannot hit the
    recursion limit here; cbor2 still performs the actual decode
    afterwards.
    """
    def fail(reason: str):
        if canonical:
            raise SPIFFormatError(
                f"Non-canonical CBOR in {chunk_name} chunk: {reason}")
        raise SPIFFormatError(f"Malformed CBOR in {chunk_name} chunk: {reason}")

    def fail_duplicate_key():
        if canonical:
            raise SPIFFormatError(
                f"Non-canonical CBOR in {chunk_name} chunk: duplicate map key")
        raise SPIFFormatError(
            f"Ambiguous CBOR in {chunk_name} chunk: duplicate map key")

    n = len(data)
    pos = 0
    # Container stack. Frame: [items_remaining, is_map, next_is_key,
    # seen_key_identities, frame_start]. items_remaining is None for an
    # indefinite-length container (closed by a break marker instead of
    # counting down); a map frame's count covers keys and values, so it
    # starts at 2 * pair_count.
    stack: list = []
    item_start: int | None = None  # start offset of the item being scanned
    root_done = False

    def complete_item(start: int, end: int) -> None:
        """Account one finished item (span data[start:end]) to its parent,
        cascading upward while containers complete."""
        nonlocal root_done
        while True:
            if not stack:
                root_done = True
                return
            frame = stack[-1]
            if frame[1] and frame[2]:  # map frame expecting a key
                identity = _key_identity(data[start:end])
                if identity in frame[3]:
                    fail_duplicate_key()
                frame[3].add(identity)
                frame[2] = False
            elif frame[1]:  # map frame expecting a value
                frame[2] = True
            if frame[0] is None:  # indefinite-length container: no countdown
                return
            frame[0] -= 1
            if frame[0] > 0:
                return
            # The container itself is now a completed item in its parent.
            stack.pop()
            start = frame[4]

    def read_argument(ai: int, major: int) -> int:
        """Consume the argument of an item whose additional-information
        value is 24..27, applying the shortest-form checks in canonical
        mode. Float payloads (major 7) are handled by the caller."""
        nonlocal pos
        if ai == 24:
            if pos + 1 > n:
                fail("unexpected end of data")
            arg = data[pos]
            pos += 1
            if canonical:
                if major == 7:
                    if arg < 32:
                        fail("non-minimal simple-value encoding")
                elif arg < 24:
                    fail("non-minimal argument encoding")
            return arg
        width = {25: 2, 26: 4, 27: 8}[ai]
        if pos + width > n:
            fail("unexpected end of data")
        arg = int.from_bytes(data[pos:pos + width], "big")
        pos += width
        if canonical and arg < (1 << (8 * (width // 2))):
            fail("non-minimal argument encoding")
        return arg

    while not root_done:
        if pos >= n:
            fail("unexpected end of data")
        if item_start is None:
            item_start = pos
        initial = data[pos]

        if initial == 0xFF:  # break marker: closes an indefinite item
            if canonical:
                fail("indefinite-length items are not canonical")
            pos += 1
            if not stack or stack[-1][0] is not None:
                fail("break marker outside an indefinite-length item")
            frame = stack[-1]
            if frame[1] and not frame[2]:
                fail("break marker after a map key with no value")
            stack.pop()
            complete_item(frame[4], pos)
            item_start = None
            continue

        pos += 1
        major = initial >> 5
        ai = initial & 0x1F

        if ai == 31:  # indefinite-length form
            if canonical:
                fail("indefinite-length items are not canonical")
            if major in (2, 3):
                # Indefinite-length string: definite-length chunks of
                # the same major type, closed by a break marker. The
                # whole sequence is one item with one span.
                while True:
                    if pos >= n:
                        fail("unexpected end of data")
                    if data[pos] == 0xFF:
                        pos += 1
                        break
                    chunk_head = data[pos]
                    if chunk_head >> 5 != major:
                        fail("indefinite-length string chunk of the wrong type")
                    chunk_ai = chunk_head & 0x1F
                    if chunk_ai == 31 or chunk_ai >= 28:
                        fail("malformed chunk inside an indefinite-length string")
                    pos += 1
                    chunk_len = (chunk_ai if chunk_ai < 24 else
                                 read_argument(chunk_ai, major))
                    if pos + chunk_len > n:
                        fail("unexpected end of data")
                    pos += chunk_len
                complete_item(item_start, pos)
                item_start = None
                continue
            if major == 4:
                stack.append([None, False, False, None, item_start])
                item_start = None
                continue
            if major == 5:
                stack.append([None, True, True, set(), item_start])
                item_start = None
                continue
            fail("indefinite-length form is only valid for strings, "
                 "arrays, and maps")
        if ai < 24:
            arg = ai
        elif ai == 24 or ai in (25, 26, 27):
            if major == 7 and ai in (25, 26, 27):
                # Float payload — its width is the encoding, no argument.
                width = {25: 2, 26: 4, 27: 8}[ai]
                if pos + width > n:
                    fail("unexpected end of data")
                pos += width
                complete_item(item_start, pos)
                item_start = None
                continue
            arg = read_argument(ai, major)
        else:  # 28..30 are reserved in every major type
            fail("reserved additional information")

        if major == 6:
            # A tag prefixes the following item: the span keeps the tag
            # bytes and the parent slot is consumed by the tagged item.
            continue
        if major in (0, 1, 7):
            complete_item(item_start, pos)
            item_start = None
        elif major in (2, 3):
            if pos + arg > n:
                fail("unexpected end of data")
            pos += arg
            complete_item(item_start, pos)
            item_start = None
        elif arg == 0:  # empty array or map completes immediately
            complete_item(item_start, pos)
            item_start = None
        elif major == 4:
            stack.append([arg, False, False, None, item_start])
            item_start = None
        else:  # major == 5
            stack.append([2 * arg, True, True, set(), item_start])
            item_start = None

    if pos != n:
        fail("trailing bytes after the CBOR item")


def _assert_canonical_cbor(data: bytes, chunk_name: str) -> None:
    """Reject non-canonical CBOR (full §4.1 canonical rule set)."""
    _scan_cbor(data, chunk_name, canonical=True)


def _assert_unambiguous_cbor(data: bytes, chunk_name: str) -> None:
    """Reject ambiguous CBOR (duplicate map keys) while accepting the
    encoding variability §4.1/§12.1 allow in unsigned documents."""
    _scan_cbor(data, chunk_name, canonical=False)


def _cbor_load(data: bytes, chunk_name: str, *,
               compressed: bool = False, zstd_compressed: bool = False,
               canonical_required: bool = False):
    """
    Deserialize CBOR bytes, raising SPIFFormatError on any failure.

    Uses tag_hook to resolve SPIF-specific CBORTags in a single decode pass,
    avoiding a separate _decode_tag() tree walk.

    cbor2 can return a 'break_marker_type' sentinel (not a dict/list) when
    given certain invalid byte sequences like 0xFF. We treat any non-standard
    result or exception as a format error.

    If ``compressed=True``, the bytes are first decompressed with zlib.
    If ``zstd_compressed=True``, the bytes are decompressed with zstd (v1.1+).

    Form enforcement (SPEC §4.1): duplicate map keys are always rejected
    (ambiguity is malformed in any document). If ``canonical_required``,
    the full canonical rule set is enforced as well — the reader passes
    it for every chunk when the document carries a signature. Unsigned
    documents may use non-canonical encodings (§4.1 / §12.1).
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
    if canonical_required:
        _assert_canonical_cbor(data, chunk_name)
    else:
        _assert_unambiguous_cbor(data, chunk_name)
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
        require_pq: bool = False,
    ) -> None:
        env_strict = os.environ.get("SPIF_REQUIRE_SIGNATURE", "").strip() in ("1", "true", "yes")
        self._require_signature = require_signature or env_strict
        # SPEC §7.9.2 gate mode: False = classical (a hybrid entry is
        # verified by its ed25519 component; PQ-only entries are
        # unverifiable), True = require_pq (both hybrid components must
        # verify; PQ-only entries are ML-DSA-verified when possible).
        self._require_pq = require_pq
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

        # 3a. CHECKSUM is the terminal chunk — anything after it is not
        # part of the document and must not be silently ignored into the
        # verdict for the bytes that precede it.
        if checksum_offset + 5 + csum_len != len(data):
            raise SPIFFormatError(
                f"{len(data) - (checksum_offset + 5 + csum_len)} trailing "
                f"byte(s) after CHECKSUM chunk"
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

        # One document, one attestation (SPEC §7.2): SIGNATURE and
        # MULTISIG are two encodings of the same claim — the signer set,
        # which is part of the document's meaning. If both were accepted,
        # their entries would union into a signer set no signer attested:
        # any holder of a signed envelope could append the *other* auth
        # chunk type carrying their own entry, signed over the public
        # signing body, and be reported as an attested signer — gaining
        # the authority signer-set membership confers, e.g. revocation
        # (SPIF-CROSSAUTH-SIGNER-EXPANSION-001). The writer never emits
        # both. A duplicate chunk of a single type is already rejected
        # in the scan above, so with this co-presence rejection a
        # decodable document carries at most one auth chunk in total.
        if CHUNK_SIGNATURE in chunks and CHUNK_MULTISIG in chunks:
            raise SPIFFormatError(
                "SIGNATURE and MULTISIG chunks must not both be present: "
                "a document carries exactly one attestation"
            )

        # SPEC §4.1 / §12.4: canonical CBOR is required for all chunks
        # when the document carries a signature. The chunk set is fully
        # collected at this point, so the presence of a SIGNATURE or
        # MULTISIG chunk decides the form enforcement for every load
        # below (duplicate keys are rejected either way).
        canonical_required = (CHUNK_SIGNATURE in chunks
                              or CHUNK_MULTISIG in chunks)

        # 4a. Detect compression from HEADER chunk (flags2 field)
        compressed = False
        zstd_compressed = False
        if CHUNK_HEADER in chunks:
            hdr = _cbor_load(chunks[CHUNK_HEADER][0], "HEADER",
                             canonical_required=canonical_required)
            if isinstance(hdr, dict):
                flags2 = hdr.get("flags2", 0)
                compressed = bool(flags2 & FLAG_COMPRESSED)
                zstd_compressed = bool(flags2 & FLAG_ZSTD)

        # 5. PAYLOAD (required) — decompressed if needed
        if CHUNK_PAYLOAD not in chunks:
            raise SPIFFormatError("Missing required PAYLOAD chunk")

        raw_payload = _cbor_load(chunks[CHUNK_PAYLOAD][0], "PAYLOAD",
                                 compressed=compressed, zstd_compressed=zstd_compressed,
                                 canonical_required=canonical_required)
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
            p = _cbor_load(chunks[CHUNK_PROVENANCE][0], "PROVENANCE",
                           canonical_required=canonical_required)
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
                           compressed=compressed, zstd_compressed=zstd_compressed,
                           canonical_required=canonical_required)
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
                             compressed=compressed, zstd_compressed=zstd_compressed,
                             canonical_required=canonical_required)
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
                             compressed=compressed, zstd_compressed=zstd_compressed,
                             canonical_required=canonical_required)
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
                           compressed=compressed, zstd_compressed=zstd_compressed,
                           canonical_required=canonical_required)
            if not isinstance(d, dict):
                raise SPIFFormatError("DELTA chunk must decode to a dict")
            delta = Delta(base_hash=d["base_hash"], changes=d.get("changes", []))

        # 11. SIGNATURE (v0.2)
        signature = None
        if CHUNK_SIGNATURE in chunks:
            s = _cbor_load(chunks[CHUNK_SIGNATURE][0], "SIGNATURE",
                           canonical_required=canonical_required)
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
            raw = _cbor_load(chunks[CHUNK_MULTISIG][0], "MULTISIG",
                             canonical_required=canonical_required)
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
            t = _cbor_load(chunks[CHUNK_TASK][0], "TASK",
                           canonical_required=canonical_required)
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
            r = _cbor_load(chunks[CHUNK_ROLES][0], "ROLES",
                           canonical_required=canonical_required)
            if not isinstance(r, dict):
                raise SPIFFormatError("ROLES chunk must decode to a dict")
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in r.items()):
                raise SPIFFormatError("ROLES chunk keys and values must all be strings")
            signer_roles = dict(r)

        # 15. REVOCATION chunk (v1.3+) — signed revocation statements,
        # post-signature chunk, never compressed. Parsing only: trust
        # semantics (REVOKED status, forgery detection) live in spif.trust.
        revocations: list[RevocationStatement] = []
        if CHUNK_REVOCATION in chunks:
            raw = _cbor_load(chunks[CHUNK_REVOCATION][0], "REVOCATION",
                             canonical_required=canonical_required)
            if not isinstance(raw, list):
                raise SPIFFormatError("REVOCATION chunk must decode to a list")
            if len(raw) > MAX_REVOCATION_STATEMENTS:
                raise SPIFFormatError(
                    f"REVOCATION chunk has {len(raw)} statements, exceeding "
                    f"the limit of {MAX_REVOCATION_STATEMENTS}"
                )
            for entry in raw:
                if not isinstance(entry, dict):
                    raise SPIFFormatError(
                        f"REVOCATION entry must be a dict, got {type(entry).__name__}"
                    )
                try:
                    revocations.append(RevocationStatement.from_cbor_dict(entry))
                except (KeyError, TypeError, ValueError) as e:
                    raise SPIFFormatError(f"Malformed REVOCATION entry: {e}") from e

        # 16. TIMESTAMP chunk (v1.3+) — TSA anchor, post-signature chunk,
        # never compressed. Parsing only; verified/unverified reporting
        # lives in spif.trust (SPEC §7.8).
        timestamp_anchor = None
        if CHUNK_TIMESTAMP in chunks:
            raw = _cbor_load(chunks[CHUNK_TIMESTAMP][0], "TIMESTAMP",
                             canonical_required=canonical_required)
            if not isinstance(raw, dict):
                raise SPIFFormatError("TIMESTAMP chunk must decode to a dict")
            try:
                timestamp_anchor = TimestampAnchor.from_cbor_dict(raw)
            except (KeyError, TypeError, ValueError) as e:
                raise SPIFFormatError(f"Malformed TIMESTAMP entry: {e}") from e

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
            revocations=revocations,
            timestamp_anchor=timestamp_anchor,
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
            self._verify_sig_inner(
                doc, data, self._revocation_list, require_pq=self._require_pq
            )

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
        require_pq: bool = False,
    ) -> bool:
        """
        Core signature verification. Takes an already-decoded doc and the raw bytes
        it was decoded from. Separated from decode() to avoid circular calls.

        ed25519 entries are verified classically. Hybrid
        (``ed25519+ml-dsa-65``) and PQ-only (``ml-dsa-65``) entries go
        through the SPEC §7.9.2 gate assessment in spif.pq_hybrid:
        classical mode (require_pq=False) checks a hybrid entry's
        ed25519 component only and treats PQ-only entries as
        unverifiable ("invisible, not invalid"); require_pq mode
        requires both hybrid components and ML-DSA-verifies PQ-only
        entries when the backend is available.

        Returns True if all signatures are valid.
        Returns False if no signatures are present.
        Raises SPIFSignatureError if any signature fails or cannot be
        verified under the active gate mode.
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
            if sig_obj.algorithm in ("ed25519+ml-dsa-65", "ml-dsa-65"):
                # SPEC §7.9.2 gate assessment (lazy import: pq_hybrid
                # imports this module).
                from .pq_hybrid import assess_pq_entry

                assessment = assess_pq_entry(
                    sig_obj.algorithm,
                    sig_obj.signer,
                    sig_obj.signature,
                    body_to_sign,
                    require_pq=require_pq,
                )
                if assessment.status == "valid":
                    return
                if assessment.status == "invalid":
                    raise SPIFSignatureError(
                        f"Signature verification failed: {assessment.detail}"
                    )
                raise SPIFSignatureError(
                    f"Signature cannot be verified: {assessment.detail}"
                )
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
        require_pq: bool | None = None,
    ) -> bool:
        """
        Verify the signature(s) in a SPIF document.

        body_to_sign = all bytes before the first SIGNATURE or MULTISIG chunk
        in the file.
        For ed25519 entries the signer field must be a base64-encoded raw
        ed25519 public key (32 bytes); hybrid and PQ-only entries carry
        their key material per the SPEC §7.9.1 encoding. For URL-based
        signers, the caller must resolve the key externally.

        ``require_pq`` selects the SPEC §7.9.2 gate mode for PQ-bearing
        entries (hybrid: both components required; PQ-only: ML-DSA
        verification). None (default) uses this reader's own gate mode
        (classical unless the reader was constructed with
        require_pq=True). In classical mode a hybrid entry is verified
        by its ed25519 component and a PQ-only entry raises
        SPIFSignatureError as unverifiable — invisible, not invalid.

        A document carries exactly one attestation: a SIGNATURE chunk or
        a MULTISIG chunk, never both. decode() rejects an envelope where
        both chunk types are present with SPIFFormatError, so every
        signature verified here comes from that single auth chunk and is
        checked against the same signing body: the bytes before the first
        auth chunk.

        If revocation_list_path is given, revoked signer IDs are rejected before
        cryptographic verification via SPIFSignatureError.

        Returns True if all present signatures are valid.
        Returns False if no signature chunk is present.
        Raises SPIFSignatureError if any signature is present but invalid
        or unverifiable under the active gate mode.
        """
        # Use a non-strict reader to parse without triggering crypto verification
        # a second time — _verify_sig_inner does the actual check below.
        doc = SPIFReader(require_signature=False).decode(data)

        revocation_list: set[str] = set()
        if revocation_list_path is not None:
            from .crypto import load_revocation_list
            revocation_list = load_revocation_list(revocation_list_path)

        effective_require_pq = self._require_pq if require_pq is None else require_pq

        # Crytographically verify signatures first
        has_sigs = self._verify_sig_inner(
            doc, data, revocation_list, require_pq=effective_require_pq
        )
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
