"""Tests for lossless MsgPack export."""

from __future__ import annotations

import msgpack
import pytest

from spfx import (
    Alternative,
    Delta,
    Distribution,
    Node,
    NodeRef,
    Provenance,
    SPIFDocument,
    SemanticLayer,
    Signature,
    TraceStep,
    from_msgpack,
    to_msgpack,
)


def _doc_full() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id="img",
                type="multimodal",
                value=b"\x89PNG\x00demo",
                confidence=Distribution(mean=0.93, var=0.01, shape="gaussian",
                                        semantics="factual_accuracy"),
            ),
            Node(
                id="call",
                type="tool_call",
                value={"name": "lookup", "arguments": {"q": "spfx"}, "call_id": "c1"},
                confidence=Distribution(mean=0.99, var=0.0, shape="point",
                                        semantics="output_stability"),
            ),
            Node(
                id="reply",
                type="text",
                value="Tool returned an image and a lookup result.",
                confidence=Distribution(mean=0.88, var=0.04, shape="bimodal",
                                        semantics="output_stability", p5=0.5, p95=0.97),
                refs=[NodeRef("img"), NodeRef("call")],
            ),
        ],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6",
            temperature=0.2,
            input_hash="ab" * 32,
            context_ref="cd" * 32,
            timestamp_ms=1_712_000_000_000,
        ),
        semantic=SemanticLayer(
            embedding=[0.2, -0.1, 0.6],
            embedding_model="text-embedding-3-small",
            covariance=[[0.01, 0.0], [0.0, 0.02]],
        ),
        trace=[
            TraceStep(
                id="s1",
                type="evidence",
                content={"source": "tool", "ref": "c1"},
                confidence=Distribution(mean=0.95, var=0.01, shape="gaussian",
                                        semantics="factual_accuracy"),
            ),
            TraceStep(
                id="s2",
                type="conclusion",
                content="Tool output supports the final reply.",
                confidence=Distribution(mean=0.84, var=0.03, shape="gaussian",
                                        semantics="epistemic"),
                deps=["s1"],
                alternatives=[{"verdict": "insufficient"}, {"verdict": "strong"}],
            ),
        ],
        trace_method="live",
        alternatives=[
            Alternative(
                weight=0.75,
                normalized=True,
                nodes=[
                    Node(
                        id="alt1",
                        type="text",
                        value="High-confidence answer.",
                        confidence=Distribution(mean=0.81, var=0.05, shape="gaussian",
                                                semantics="output_stability"),
                    )
                ],
            ),
            Alternative(
                weight=0.25,
                normalized=True,
                nodes=[
                    Node(
                        id="alt2",
                        type="text",
                        value="Escalate to review.",
                        confidence=Distribution(mean=0.55, var=0.08, shape="gaussian",
                                                semantics="output_stability"),
                    )
                ],
            ),
        ],
        delta=Delta(base_hash="ef" * 32, changes=[{"op": "annotate", "target": "reply"}]),
        signature=Signature(
            algorithm="ed25519",
            signer="signer-a",
            signature=b"\x01" * 64,
            key_id="kid-a",
        ),
        signatures=[
            Signature(
                algorithm="ed25519",
                signer="signer-b",
                signature=b"\x02" * 64,
                key_id="kid-b",
            )
        ],
    )


def test_msgpack_roundtrip_preserves_binary_and_metadata():
    doc = _doc_full()
    raw = to_msgpack(doc)
    restored = from_msgpack(raw)

    assert restored.provenance is not None
    assert restored.provenance.source_model == "claude-sonnet-4-6"
    assert restored.provenance.context_ref == "cd" * 32
    assert restored.payload[0].value == b"\x89PNG\x00demo"
    assert restored.payload[2].refs[0].node_id == "img"
    assert restored.trace_method == "live"
    assert restored.trace[1].deps == ["s1"]
    assert restored.trace[1].alternatives[1]["verdict"] == "strong"
    assert restored.semantic is not None
    assert restored.semantic.embedding == [0.2, -0.1, 0.6]
    assert restored.delta is not None
    assert restored.delta.base_hash == "ef" * 32
    assert restored.signature is not None
    assert restored.signature.signature == b"\x01" * 64
    assert restored.signatures[0].signature == b"\x02" * 64


def test_msgpack_checksum_detects_tampered_body():
    raw = to_msgpack(_doc_full())
    envelope = msgpack.unpackb(raw, raw=False, strict_map_key=False)
    envelope["body"]["payload"][2]["value"] = "tampered"
    tampered = msgpack.packb(envelope, use_bin_type=True, strict_types=True)

    with pytest.raises(ValueError, match="checksum mismatch"):
        from_msgpack(tampered)


def test_msgpack_rejects_missing_checksum():
    raw = to_msgpack(_doc_full())
    envelope = msgpack.unpackb(raw, raw=False, strict_map_key=False)
    del envelope["cksum"]
    tampered = msgpack.packb(envelope, use_bin_type=True, strict_types=True)

    with pytest.raises(ValueError, match="body' and 'cksum"):
        from_msgpack(tampered)
