"""
Generate deterministic SPIF conformance fixtures plus a manifest.

Usage:
    python compat/generate_compat_fixtures.py
    python compat/generate_compat_fixtures.py /tmp/spfx-fixtures
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import cbor2

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spfx import (
    Alternative,
    Distribution,
    Node,
    NodeRef,
    Provenance,
    SPIFDocument,
    SPIFWriter,
    Signature,
    TraceStep,
)
from spfx.crypto import derive_key_from_mnemonic
from spfx.format import CHUNK_CHECKSUM
from spfx.streaming import SPIFStreamWriter
from spfx.types import Delta


FIXED_TS = 1_712_000_000_000
DEFAULT_OUTPUT_DIR = Path(__file__).with_name("fixtures")


def _dist(mean: float, *, semantics: str = "epistemic", shape: str = "gaussian") -> Distribution:
    return Distribution(mean=mean, var=0.02, shape=shape, semantics=semantics)


def _pub_b64(private_key) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def _provenance() -> Provenance:
    return Provenance(
        source_model="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6",
        temperature=0.2,
        input_hash="ab" * 32,
        context_ref="sha256:fixture-context-0001",
        timestamp_ms=FIXED_TS,
    )


def _auth_offset(data: bytes) -> int | None:
    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    while offset < len(data):
        if offset + 5 > len(data):
            return None
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        if chunk_type in (0x07, 0x08):
            return offset
        if chunk_type == CHUNK_CHECKSUM:
            return None
        offset += 5 + length
    return None


def _sign_doc(doc: SPIFDocument, private_key, signer_id: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    auth_offset = _auth_offset(dummy)
    if auth_offset is None:
        raise RuntimeError("SIGNATURE chunk not found in dummy encoding")
    doc.signature = Signature(
        algorithm="ed25519",
        signer=signer_id,
        signature=private_key.sign(dummy[:auth_offset]),
    )
    return writer.encode(doc)


def _multisign_doc(doc: SPIFDocument, signers: list[tuple[object, str]]) -> bytes:
    writer = SPIFWriter()
    doc.signatures = [
        Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
        for _, signer_id in signers
    ]
    dummy = writer.encode(doc)
    auth_offset = _auth_offset(dummy)
    if auth_offset is None:
        raise RuntimeError("MULTISIG chunk not found in dummy encoding")
    body = dummy[:auth_offset]
    doc.signatures = [
        Signature(
            algorithm="ed25519",
            signer=signer_id,
            signature=private_key.sign(body),
        )
        for private_key, signer_id in signers
    ]
    return writer.encode(doc)


def _append_unknown_chunk(data: bytes) -> bytes:
    checksum_chunk = data[-37:]
    body = data[:-37]
    future_payload = cbor2.dumps({"future": True, "note": "unknown chunk fixture"}, canonical=True)
    future_chunk = struct.pack(">BI", 0x33, len(future_payload)) + future_payload
    new_body = body + future_chunk
    checksum = hashlib.sha256(new_body).digest()
    return new_body + struct.pack(">BI", CHUNK_CHECKSUM, len(checksum)) + checksum


def _stream_doc(doc: SPIFDocument, tokens: list[str]) -> bytes:
    writer = SPIFStreamWriter()
    parts = [writer.open(doc.provenance)]
    for token in tokens:
        parts.append(writer.partial_text(token, node_id=doc.payload[0].id))
    parts.append(writer.commit(doc))
    return b"".join(parts)


def _resumed_stream_doc(doc: SPIFDocument, tokens: list[str]) -> tuple[bytes, int]:
    first = SPIFStreamWriter()
    first.open(doc.provenance)
    first.partial_text(tokens[0], node_id=doc.payload[0].id)
    resume_token = first.resume_token()

    resumed = SPIFStreamWriter(resume_from=resume_token)
    parts = [resumed.open(doc.provenance)]
    for token in tokens:
        maybe_chunk = resumed.partial_text(token, node_id=doc.payload[0].id)
        if maybe_chunk:
            parts.append(maybe_chunk)
    parts.append(resumed.commit(doc))
    return b"".join(parts), 1


def _manifest_entry(name: str, filename: str, data: bytes, doc: SPIFDocument | None, **features: object) -> dict[str, object]:
    provenance = doc.provenance if doc is not None else None
    return {
        "name": name,
        "filename": filename,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "payload_count": len(doc.payload) if doc is not None else None,
        "trace_count": len(doc.trace) if doc is not None else None,
        "has_provenance": provenance is not None,
        "source_model": provenance.source_model if provenance else None,
        "features": features,
    }


def generate_fixtures(output_dir: str | Path | None = None) -> dict[str, object]:
    out_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    for path in out_dir.glob("*.spfx"):
        path.unlink()
    for path in out_dir.glob("*.ref.json"):
        path.unlink()
    manifest_path = out_dir / "manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()

    alpha = derive_key_from_mnemonic("compat alpha signer")
    beta = derive_key_from_mnemonic("compat beta signer")
    alpha_pub = _pub_b64(alpha)
    beta_pub = _pub_b64(beta)

    minimal_doc = SPIFDocument(
        payload=[Node(id="main", type="text", value="Minimal fixture", confidence=_dist(0.95))],
        provenance=_provenance(),
    )
    compressed_doc = SPIFDocument(
        payload=[Node(id="blob", type="text", value="x" * 4000, confidence=_dist(0.88))],
        provenance=_provenance(),
        trace=[
            TraceStep(id="t0", type="evidence", content="large payload", confidence=_dist(0.8)),
            TraceStep(id="t1", type="conclusion", content="compressed output", confidence=_dist(0.9), deps=["t0"]),
        ],
    )
    tool_doc = SPIFDocument(
        payload=[
            Node(
                id="call",
                type="tool_call",
                value={"name": "search", "arguments": {"q": "spfx"}, "call_id": "c1"},
                confidence=_dist(0.99),
            ),
            Node(
                id="result",
                type="tool_result",
                value={"call_id": "c1", "content": {"hits": 3}, "is_error": False},
                confidence=_dist(0.97),
                refs=[NodeRef("call")],
            ),
            Node(
                id="reply",
                type="text",
                value="Search returned three hits.",
                confidence=_dist(0.92, semantics="output_stability"),
                refs=[NodeRef("result")],
            ),
        ],
        provenance=_provenance(),
        delta=Delta(base_hash="00" * 32, changes=[{"op": "annotate", "target": "reply"}]),
    )
    stream_doc = SPIFDocument(
        payload=[Node(id="stream", type="text", value="hello streaming world", confidence=_dist(0.9))],
        provenance=_provenance(),
    )

    fixtures: list[tuple[str, bytes, SPIFDocument | None, dict[str, object]]] = [
        (
            "minimal_unsigned",
            SPIFWriter().encode(minimal_doc),
            minimal_doc,
            {"signed": False, "signatures": 0, "compressed": False, "streaming": False},
        ),
        (
            "signed_single",
            _sign_doc(
                SPIFDocument(payload=list(minimal_doc.payload), provenance=minimal_doc.provenance),
                alpha,
                alpha_pub,
            ),
            minimal_doc,
            {"signed": True, "signatures": 1, "compressed": False, "streaming": False},
        ),
        (
            "multisig",
            _multisign_doc(
                SPIFDocument(payload=list(minimal_doc.payload), provenance=minimal_doc.provenance),
                [(alpha, alpha_pub), (beta, beta_pub)],
            ),
            minimal_doc,
            {"signed": True, "signatures": 2, "compressed": False, "streaming": False},
        ),
        (
            "compressed",
            SPIFWriter(compress=True).encode(compressed_doc),
            compressed_doc,
            {"signed": False, "signatures": 0, "compressed": True, "streaming": False},
        ),
        (
            "unknown_chunk",
            _append_unknown_chunk(SPIFWriter().encode(minimal_doc)),
            minimal_doc,
            {"signed": False, "signatures": 0, "compressed": False, "streaming": False, "unknown_chunk": True},
        ),
        (
            "tool_chain",
            SPIFWriter().encode(tool_doc),
            tool_doc,
            {"signed": False, "signatures": 0, "compressed": False, "streaming": False, "tool_nodes": True},
        ),
    ]

    large_doc = SPIFDocument(
        payload=[Node(id="large", type="text", value="x" * (1024 * 1024), confidence=_dist(0.9))],
        provenance=_provenance(),
    )
    fixtures.append((
        "large_compressed_1mb",
        SPIFWriter(compress=True).encode(large_doc),
        large_doc,
        {"signed": False, "signatures": 0, "compressed": True, "streaming": False, "large_payload": True},
    ))

    stream_tokens = ["hello ", "streaming ", "world"]
    stream_bytes = _stream_doc(stream_doc, stream_tokens)
    fixtures.append((
        "streaming",
        stream_bytes,
        stream_doc,
        {"signed": False, "signatures": 0, "compressed": False, "streaming": True, "partial_tokens": len(stream_tokens)},
    ))

    resumed_bytes, resume_seq = _resumed_stream_doc(stream_doc, stream_tokens)
    fixtures.append((
        "resumed_streaming",
        resumed_bytes,
        stream_doc,
        {
            "signed": False,
            "signatures": 0,
            "compressed": False,
            "streaming": True,
            "resumed": True,
            "resume_seq": resume_seq,
        },
    ))

    manifest_entries: list[dict[str, object]] = []
    for name, data, doc, features in fixtures:
        filename = f"{name}.spfx"
        path = out_dir / filename
        path.write_bytes(data)
        ref_path = out_dir / f"{name}.ref.json"
        ref_path.write_text(json.dumps(_manifest_entry(name, filename, data, doc, **features), indent=2))
        manifest_entries.append(_manifest_entry(name, filename, data, doc, **features))

    manifest = {
        "version": 1,
        "generated_by": "compat/generate_compat_fixtures.py",
        "generated_at_ms": FIXED_TS,
        "fixtures": manifest_entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def main(argv: list[str]) -> int:
    output_dir = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUTPUT_DIR
    manifest = generate_fixtures(output_dir)
    print(f"Generated {len(manifest['fixtures'])} fixtures in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
