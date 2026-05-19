"""SPIFWriter — serialize a SPIFDocument to bytes or a file."""

from __future__ import annotations
import hashlib
import struct
import time
import zlib
from pathlib import Path

import cbor2

from .format import (
    MAGIC, FORMAT_VERSION,
    CHUNK_HEADER, CHUNK_PROVENANCE, CHUNK_SEMANTIC, CHUNK_TRACE,
    CHUNK_PAYLOAD, CHUNK_ALTS, CHUNK_DELTA, CHUNK_SIGNATURE, CHUNK_MULTISIG,
    CHUNK_TASK, CHUNK_CHECKSUM,
    FLAG_PROVENANCE, FLAG_SEMANTIC, FLAG_TRACE, FLAG_ALTS, FLAG_DELTA, FLAG_SIGNATURE,
    FLAG_MULTISIG, FLAG_COMPRESSED, FLAG_ZSTD, FLAG_HAS_TASK,
    TAG_DISTRIBUTION, TAG_NODEREF, TAG_EMBEDDING,
)
from .types import (
    SPIFDocument, Distribution, NodeRef, Node, TraceStep,
)


_CHUNK_STRUCT = struct.Struct(">BI")


def _cbor(data: object) -> bytes:
    """Canonical CBOR encoding (RFC 8949 §4.2) — required for valid signatures."""
    return cbor2.dumps(data, canonical=True)


def _cbor_fast(data: object) -> bytes:
    """Non-canonical CBOR — faster encode for unsigned documents."""
    return cbor2.dumps(data, canonical=False)


def _encode_distribution(d: Distribution) -> cbor2.CBORTag:
    return cbor2.CBORTag(TAG_DISTRIBUTION, d.to_dict())


def _encode_noderef(r: NodeRef) -> cbor2.CBORTag:
    return cbor2.CBORTag(TAG_NODEREF, r.node_id)


def _encode_embedding(v: list[float]) -> cbor2.CBORTag:
    return cbor2.CBORTag(TAG_EMBEDDING, v)


def _encode_value(v) -> object:
    if isinstance(v, Distribution):
        return _encode_distribution(v)
    if isinstance(v, NodeRef):
        return _encode_noderef(v)
    return v


def _encode_node(n: Node) -> dict:
    return {
        "id":         n.id,
        "type":       n.type,
        "value":      _encode_value(n.value),
        "confidence": _encode_distribution(n.confidence),
        "refs":       [_encode_noderef(r) for r in n.refs],
    }


def _encode_step(s: TraceStep) -> dict:
    return {
        "id":           s.id,
        "type":         s.type,
        "content":      _encode_value(s.content),
        "confidence":   _encode_distribution(s.confidence),
        "deps":         s.deps,
        "alternatives": [_encode_value(a) for a in s.alternatives],
    }


def _compress_bytes(data: bytes, *, method: str) -> bytes:
    """Compress bytes using the specified method ('zlib' or 'zstd')."""
    if method == "zstd":
        try:
            import zstandard as zstd  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "zstandard package is required for zstd compression: pip install zstandard"
            ) from exc
        return zstd.ZstdCompressor(level=10).compress(data)
    return zlib.compress(data, level=9)


def _chunk(chunk_type: int, data: object, *, fast: bool = False,
           compress: bool = False, compression: str = "zlib") -> bytes:
    payload = _cbor_fast(data) if fast else _cbor(data)
    if compress:
        payload = _compress_bytes(payload, method=compression)
    header = _CHUNK_STRUCT.pack(chunk_type, len(payload))
    return header + payload


def _raw_chunk(chunk_type: int, raw: bytes) -> bytes:
    header = _CHUNK_STRUCT.pack(chunk_type, len(raw))
    return header + raw


def compute_content_id(doc: SPIFDocument) -> str:
    """
    Compute a stable, content-addressed ID for a SIF document.

    The ID is SHA-256 of the canonical CBOR encoding of {payload, trace, provenance}.
    It is independent of framing bytes, signatures, embeddings, alternatives, and
    delta — only the semantically meaningful core content is hashed.

    This means two SPIF documents with identical payload+trace+provenance but different
    signatures or embeddings will have the same content_id.
    """
    prov_dict = None
    if doc.provenance:
        p = doc.provenance
        prov_dict = {
            "source_model":  p.source_model,
            "model_version": p.model_version,
            "temperature":   p.temperature,
            "input_hash":    p.input_hash,
            "context_ref":   p.context_ref,
            "timestamp_ms":  p.timestamp_ms,
            "attempt":       p.attempt,
            "task_id":       p.task_id,
        }
    content = {
        "payload":    [_encode_node(n) for n in doc.payload],
        "trace":      [_encode_step(s) for s in doc.trace],
        "provenance": prov_dict,
    }
    return hashlib.sha256(_cbor(content)).hexdigest()


class SPIFWriter:
    """
    Parameters
    ----------
    compress :
        If True, compress chunk payloads with zlib.  PROVENANCE and CHECKSUM
        are never compressed (they must be readable without decompression for
        routing / validation).  Reduces file size by ~40-70% for large payloads
        and trace-heavy documents.  Readers auto-detect compression from the
        HEADER chunk's ``flags2`` field.
    """

    def __init__(self, *, compress: bool = False, compression: str = "zlib") -> None:
        if compression not in ("zlib", "zstd"):
            raise ValueError(f"compression must be 'zlib' or 'zstd', got {compression!r}")
        self._compress = compress
        self._compression = compression

    def encode(self, doc: SPIFDocument) -> bytes:
        flags = 0
        if doc.provenance:
            flags |= FLAG_PROVENANCE
        if doc.semantic:
            flags |= FLAG_SEMANTIC
        if doc.trace:
            flags |= FLAG_TRACE
        if doc.alternatives:
            flags |= FLAG_ALTS
        if doc.delta:
            flags |= FLAG_DELTA
        if doc.signature:
            flags |= FLAG_SIGNATURE
        if doc.signatures:
            flags |= FLAG_MULTISIG

        flags2 = 0
        if self._compress:
            if self._compression == "zstd":
                flags2 |= FLAG_ZSTD
            else:
                flags2 |= FLAG_COMPRESSED
        if doc.task_info is not None:
            flags2 |= FLAG_HAS_TASK

        # Skip canonical CBOR when no signature is needed — ~10-15% faster encode
        fast = not (doc.signature or doc.signatures)
        compress = self._compress
        compression = self._compression

        parts: list[bytes] = []

        # Fixed header (11 bytes: magic + version + flags)
        parts.append(MAGIC)
        parts.append(bytes([FORMAT_VERSION, flags]))

        # HEADER chunk — never compressed (first thing readers parse)
        parts.append(_chunk(CHUNK_HEADER, {
            "version":    FORMAT_VERSION,
            "flags":      flags,
            "flags2":     flags2,
            "created_ms": doc.provenance.timestamp_ms if doc.provenance else 0,
        }, fast=fast))

        # TASK chunk — never compressed (envelope metadata, inspect without decompression)
        if doc.task_info is not None:
            ti = doc.task_info
            parts.append(_chunk(CHUNK_TASK, {
                "task_id":     ti.task_id,
                "attempt":     ti.attempt,
                "status":      ti.status,
                "total_ms":    ti.total_ms,
                "tool_count":  ti.tool_count,
                "error_count": ti.error_count,
            }, fast=fast))

        # PROVENANCE chunk — never compressed (routers may inspect without decompressing)
        if doc.provenance:
            p = doc.provenance
            parts.append(_chunk(CHUNK_PROVENANCE, {
                "source_model":  p.source_model,
                "model_version": p.model_version,
                "temperature":   p.temperature,
                "input_hash":    p.input_hash,
                "context_ref":   p.context_ref,
                "timestamp_ms":  p.timestamp_ms,
                "attempt":       p.attempt,
                "task_id":       p.task_id,
            }, fast=fast))

        # SEMANTIC chunk — compressed (embeddings are large)
        if doc.semantic:
            s = doc.semantic
            parts.append(_chunk(CHUNK_SEMANTIC, {
                "embedding_model": s.embedding_model,
                "dim":             s.dim,
                "embedding":       _encode_embedding(s.embedding),
                "covariance":      s.covariance,
            }, fast=fast, compress=compress, compression=compression))

        # TRACE chunk — compressed (thinking traces can be large)
        if doc.trace:
            parts.append(_chunk(CHUNK_TRACE, {
                "method": doc.trace_method,
                "steps":  [_encode_step(st) for st in doc.trace],
            }, fast=fast, compress=compress, compression=compression))

        # PAYLOAD chunk (required) — compressed
        parts.append(_chunk(CHUNK_PAYLOAD, [_encode_node(n) for n in doc.payload],
                            fast=fast, compress=compress, compression=compression))

        # ALTS chunk — compressed
        if doc.alternatives:
            if doc.alternatives and doc.alternatives[0].normalized:
                total = sum(a.weight for a in doc.alternatives)
                if abs(total - 1.0) > 0.01:
                    raise ValueError(
                        f"Alternative weights must sum to 1.0 ± 0.01 when normalized=True, "
                        f"got {total:.4f}. Set normalized=False for unnormalized scores."
                    )
            parts.append(_chunk(CHUNK_ALTS, {
                "normalized": doc.alternatives[0].normalized if doc.alternatives else True,
                "alts": [
                    {"weight": a.weight, "nodes": [_encode_node(n) for n in a.nodes]}
                    for a in doc.alternatives
                ],
            }, fast=fast, compress=compress, compression=compression))

        # DELTA chunk — compressed
        if doc.delta:
            parts.append(_chunk(CHUNK_DELTA, {
                "base_hash": doc.delta.base_hash,
                "changes":   doc.delta.changes,
            }, fast=fast, compress=compress, compression=compression))

        # SIGNATURE chunk — never compressed (always canonical, integrity-critical)
        if doc.signature:
            sig = doc.signature
            parts.append(_chunk(CHUNK_SIGNATURE, {
                "algorithm": sig.algorithm,
                "signer":    sig.signer,
                "signature": sig.signature,
                "key_id":    sig.key_id,
            }))

        # MULTISIG chunk — never compressed
        if doc.signatures:
            parts.append(_chunk(CHUNK_MULTISIG, [
                {
                    "algorithm": s.algorithm,
                    "signer":    s.signer,
                    "signature": s.signature,
                    "key_id":    s.key_id,
                }
                for s in doc.signatures
            ]))

        body = b"".join(parts)
        checksum = hashlib.sha256(body).digest()
        return body + _raw_chunk(CHUNK_CHECKSUM, checksum)

    def write(self, doc: SPIFDocument, path: str | Path) -> None:
        Path(path).write_bytes(self.encode(doc))
