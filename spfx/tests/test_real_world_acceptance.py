"""Acceptance tests for realistic SPIF workflows.

These tests are intentionally broader than unit tests. They exercise the
operational story SPIF is meant to support:

1. stream an agent answer to a UI
2. persist the same answer as a signed audit artifact
3. export that artifact into observability / provenance systems
4. detect accidental corruption and malicious substitution
"""

from __future__ import annotations

import base64
import hashlib
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spfx import (
    Alternative,
    Delta,
    Distribution,
    Node,
    NodeRef,
    Provenance,
    SPIFDocument,
    SPIFReader,
    SPIFWriter,
    SemanticLayer,
    Signature,
    TraceStep,
)
from spfx.exporters.otel import to_otel_span
from spfx.exporters.prov import to_prov
from spfx.format import CHUNK_CHECKSUM, CHUNK_PROVENANCE, MAGIC
from spfx.reader import SPIFChecksumError, SPIFSignatureError
from spfx.streaming import SPIFStreamWriter, iter_events


FIXED_TS = 1_712_000_000_000
_CHUNK_STRUCT = struct.Struct(">BI")


def _dist(
    mean: float,
    *,
    var: float = 0.02,
    shape: str = "gaussian",
    semantics: str = "epistemic",
    p5: float | None = None,
    p95: float | None = None,
) -> Distribution:
    return Distribution(
        mean=mean,
        var=var,
        shape=shape,
        semantics=semantics,
        p5=p5,
        p95=p95,
    )


def _pub_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def _find_chunk_offset(data: bytes, chunk_type: int) -> int | None:
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            return None
        current_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
        if current_type == chunk_type:
            return offset
        offset += 5 + length
    return None


def _find_auth_offset(data: bytes) -> int | None:
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            return None
        chunk_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
        if chunk_type in (0x07, 0x08):
            return offset
        if chunk_type == CHUNK_CHECKSUM:
            return None
        offset += 5 + length
    return None


def _recompute_checksum(body: bytes) -> bytes:
    checksum = hashlib.sha256(body).digest()
    return body + _CHUNK_STRUCT.pack(CHUNK_CHECKSUM, len(checksum)) + checksum


def _replace_chunk_payload(data: bytes, chunk_type: int, new_payload: bytes) -> bytes:
    checksum_offset = _find_chunk_offset(data, CHUNK_CHECKSUM)
    assert checksum_offset is not None
    body = data[:checksum_offset]

    offset = len(MAGIC) + 2
    while offset < len(body):
        current_type, length = _CHUNK_STRUCT.unpack_from(body, offset)
        if current_type == chunk_type:
            chunk_end = offset + 5 + length
            header = _CHUNK_STRUCT.pack(chunk_type, len(new_payload))
            new_body = body[:offset] + header + new_payload + body[chunk_end:]
            return _recompute_checksum(new_body)
        offset += 5 + length

    raise AssertionError(f"Chunk 0x{chunk_type:02x} not found")


def _sign_doc(
    doc: SPIFDocument,
    private_key: Ed25519PrivateKey,
    signer_id: str,
    *,
    compress: bool = False,
) -> bytes:
    writer = SPIFWriter(compress=compress)

    # Pass 1: insert a dummy signature so the final body layout is stable.
    doc.signature = Signature(
        algorithm="ed25519",
        signer=signer_id,
        signature=b"\x00" * 64,
    )
    dummy = writer.encode(doc)
    auth_offset = _find_auth_offset(dummy)
    assert auth_offset is not None, "SIGNATURE chunk not found in dummy encoding"

    # Pass 2: sign the exact body prefix covered by the signature.
    doc.signature = Signature(
        algorithm="ed25519",
        signer=signer_id,
        signature=private_key.sign(dummy[:auth_offset]),
    )
    return writer.encode(doc)


def _baseline_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id="brief",
                type="text",
                value="Assess whether downtown office exposure should be escalated.",
                confidence=_dist(0.94, semantics="output_stability"),
            )
        ],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6",
            temperature=0.2,
            input_hash="ab" * 32,
            context_ref="",
            timestamp_ms=FIXED_TS,
        ),
    )


def _agent_doc(base_doc: SPIFDocument) -> SPIFDocument:
    base_hash = base_doc.content_id()
    recommendation = (
        "Treat the portfolio as high review priority; require human underwriting "
        "approval before issuing guidance."
    )

    return SPIFDocument(
        payload=[
            Node(
                id="call_search",
                type="tool_call",
                value={
                    "name": "search_market_filings",
                    "arguments": {"city": "San Francisco", "sector": "office"},
                    "call_id": "call-1",
                },
                confidence=_dist(0.99, semantics="output_stability", shape="point", var=0.0),
            ),
            Node(
                id="search_result",
                type="tool_result",
                value={
                    "call_id": "call-1",
                    "content": {
                        "vacancy_trend": "up",
                        "lease_rollover_risk": "high",
                        "source_count": 3,
                    },
                    "is_error": False,
                },
                confidence=_dist(0.96, semantics="factual_accuracy"),
                refs=[NodeRef("call_search")],
            ),
            Node(
                id="claim_vacancy",
                type="fact",
                value=(
                    "Recent source material indicates rising downtown vacancy and "
                    "elevated lease rollover risk."
                ),
                confidence=_dist(
                    0.82,
                    var=0.05,
                    semantics="factual_accuracy",
                    p5=0.60,
                    p95=0.94,
                ),
                refs=[NodeRef("search_result")],
            ),
            Node(
                id="recommendation",
                type="text",
                value=recommendation,
                confidence=_dist(
                    0.77,
                    var=0.08,
                    shape="bimodal",
                    semantics="output_stability",
                    p5=0.42,
                    p95=0.93,
                ),
                refs=[NodeRef("search_result"), NodeRef("claim_vacancy")],
            ),
        ],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6",
            temperature=0.2,
            input_hash="cd" * 32,
            context_ref=base_hash,
            timestamp_ms=FIXED_TS + 1_000,
        ),
        semantic=SemanticLayer(
            embedding=[0.12, -0.31, 0.44, 0.08, -0.27, 0.65, 0.11, -0.04],
            embedding_model="text-embedding-3-small",
            covariance=[[0.02, 0.0], [0.0, 0.03]],
        ),
        trace=[
            TraceStep(
                id="s1",
                type="evidence",
                content="Retrieved current office-market source material via a tool call.",
                confidence=_dist(0.97, semantics="factual_accuracy"),
            ),
            TraceStep(
                id="s2",
                type="inference",
                content="Downtown vacancy and rollover pressure jointly increase review risk.",
                confidence=_dist(0.84, semantics="epistemic"),
                deps=["s1"],
            ),
            TraceStep(
                id="s3",
                type="conclusion",
                content=recommendation,
                confidence=_dist(0.78, semantics="output_stability", var=0.07),
                deps=["s2"],
                alternatives=[
                    "Escalate to human underwriting review.",
                    "Keep automated guidance enabled with monitoring.",
                ],
            ),
        ],
        trace_method="live",
        alternatives=[
            Alternative(
                weight=0.70,
                normalized=True,
                nodes=[
                    Node(
                        id="alt_high_review",
                        type="text",
                        value="Escalate to human review because deterioration appears material.",
                        confidence=_dist(0.74, semantics="output_stability"),
                    )
                ],
            ),
            Alternative(
                weight=0.30,
                normalized=True,
                nodes=[
                    Node(
                        id="alt_monitor",
                        type="text",
                        value="Continue automated guidance but monitor for another quarter.",
                        confidence=_dist(0.51, semantics="output_stability"),
                    )
                ],
            ),
        ],
        delta=Delta(
            base_hash=base_hash,
            changes=[
                {"op": "replace", "target": "recommendation", "reason": "tool-backed escalation"},
                {"op": "annotate", "target": "claim_vacancy", "reason": "added confidence bounds"},
            ],
        ),
    )


def test_signed_streaming_agent_run_survives_full_lifecycle(tmp_path):
    base_doc = _baseline_doc()
    doc = _agent_doc(base_doc)
    final_text = doc.payload[-1].value
    tokens = [
        "Treat the portfolio as high review priority; ",
        "require human underwriting approval ",
        "before issuing guidance.",
    ]

    stream_writer = SPIFStreamWriter()
    stream_bytes = [stream_writer.open(doc.provenance)]
    for token in tokens:
        stream_bytes.append(stream_writer.partial_text(token, node_id="recommendation"))
    stream_bytes.append(stream_writer.commit(doc))
    streamed = b"".join(stream_bytes)

    events = list(iter_events(streamed))
    partials = [event for event in events if event.type == "partial_text"]
    assert [event.text for event in partials] == tokens

    verified = next(event for event in events if event.type == "verified")
    streamed_doc = verified.document
    assert streamed_doc is not None
    assert streamed_doc.payload[-1].value == final_text
    assert streamed_doc.provenance is not None
    assert streamed_doc.provenance.context_ref == base_doc.content_id()
    assert streamed_doc.delta is not None
    assert streamed_doc.delta.base_hash == base_doc.content_id()
    assert any(node.type == "tool_call" for node in streamed_doc.payload)
    assert any(node.type == "tool_result" for node in streamed_doc.payload)
    assert len(streamed_doc.alternatives) == 2
    assert streamed_doc.content_id() == doc.content_id()

    private_key = Ed25519PrivateKey.generate()
    signer_id = _pub_b64(private_key)
    artifact = _sign_doc(doc, private_key, signer_id, compress=True)
    artifact_path = tmp_path / "portfolio-review.spfx"
    artifact_path.write_bytes(artifact)

    restored = SPIFReader.strict().read(artifact_path)
    assert restored.signature is not None
    assert restored.content_id() == doc.content_id()
    assert restored.provenance is not None
    assert restored.provenance.context_ref == base_doc.content_id()
    assert SPIFReader().verify_signature(artifact) is True

    span = to_otel_span(restored)
    assert span["attributes"]["gen_ai.request.model"] == "claude-sonnet-4-6"
    assert span["attributes"]["sif.trace.method"] == "live"
    assert any(
        event["attributes"].get("sif.node.type") == "tool_result"
        for event in span["events"]
        if "attributes" in event
    )
    assert any("alternatives" in item.lower() for item in span["_sif_export_losses"])

    prov = to_prov(restored)
    assert "sif:dep/s2/s1" in prov["wasDerivedFrom"]
    assert "sif:dep/s3/s2" in prov["wasDerivedFrom"]
    assert any("alternatives" in item.lower() for item in prov["_sif_export_losses"])


def test_real_world_tampering_requires_checksum_and_signature_verification():
    doc = _agent_doc(_baseline_doc())
    private_key = Ed25519PrivateKey.generate()
    signer_id = _pub_b64(private_key)
    signed = _sign_doc(doc, private_key, signer_id)

    corrupted = bytearray(signed)
    corrupted[len(MAGIC) + 32] ^= 0x01
    with pytest.raises(SPIFChecksumError):
        SPIFReader().decode(bytes(corrupted))

    original = SPIFReader().decode(signed)
    assert original.provenance is not None

    tampered_provenance = {
        "source_model": "mallory-proxy-1",
        "model_version": original.provenance.model_version,
        "temperature": original.provenance.temperature,
        "input_hash": original.provenance.input_hash,
        "context_ref": original.provenance.context_ref,
        "timestamp_ms": original.provenance.timestamp_ms,
    }
    malicious = _replace_chunk_payload(
        signed,
        CHUNK_PROVENANCE,
        cbor2.dumps(tampered_provenance, canonical=True),
    )

    decoded = SPIFReader().decode(malicious)
    assert decoded.provenance is not None
    assert decoded.provenance.source_model == "mallory-proxy-1"

    with pytest.raises(SPIFSignatureError, match="invalid signature"):
        SPIFReader().verify_signature(malicious)

    unsigned = SPIFWriter().encode(_agent_doc(_baseline_doc()))
    with pytest.raises(SPIFSignatureError, match="unsigned"):
        SPIFReader.strict().decode(unsigned)
