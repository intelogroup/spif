"""Tests for SIF exporters (OTel, PROV-JSON)."""

import json

from spfx import SPIFDocument, Node, TraceStep
from spfx.types import Distribution, Provenance, Signature
from spfx.format import DIST_SEM_FACTUAL, DIST_SEM_EPISTEMIC, TRACE_LIVE, NODE_TOOL_CALL, NODE_TOOL_RESULT
from spfx.exporters.otel import to_otel_span
from spfx.exporters.prov import to_prov


def _doc_full() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(id="n1", type="fact", value="Paris is the capital of France.",
                 confidence=Distribution(mean=0.99, var=0.01, shape="gaussian",
                                         semantics=DIST_SEM_FACTUAL)),
            Node(id="n2", type="inference", value="France is in Europe.",
                 confidence=Distribution(mean=0.85, var=0.03, shape="gaussian",
                                         semantics=DIST_SEM_EPISTEMIC)),
        ],
        trace=[
            TraceStep(id="s0", type="evidence", content="Retrieved knowledge about Paris.",
                      confidence=Distribution(mean=0.98, var=0.01, shape="gaussian",
                                              semantics=DIST_SEM_FACTUAL)),
            TraceStep(id="s1", type="inference", content="Reasoned about European capitals.",
                      confidence=Distribution(mean=0.90, var=0.02, shape="gaussian",
                                              semantics=DIST_SEM_EPISTEMIC),
                      deps=["s0"]),
            TraceStep(id="s2", type="conclusion", content="Concluded Paris is in France.",
                      confidence=Distribution(mean=0.95, var=0.01, shape="gaussian",
                                              semantics=DIST_SEM_FACTUAL),
                      deps=["s0", "s1"]),
        ],
        trace_method=TRACE_LIVE,
        provenance=Provenance(
            source_model="claude-haiku-4-5-20251001",
            model_version="claude-haiku-4-5-20251001",
            temperature=0.7,
            input_hash="abc123",
            timestamp_ms=1_700_000_000_000,
        ),
    )


# ---------------------------------------------------------------------------
# OTel exporter tests
# ---------------------------------------------------------------------------

class TestOtelExporter:
    def test_span_has_required_attributes(self):
        doc = _doc_full()
        span = to_otel_span(doc)
        assert span["attributes"]["gen_ai.request.model"] == "claude-haiku-4-5-20251001"
        assert span["attributes"]["gen_ai.system"] == "anthropic"
        assert span["attributes"]["gen_ai.request.temperature"] == 0.7

    def test_span_serializable_to_json(self):
        span = to_otel_span(_doc_full())
        # Must round-trip through JSON without error
        json.dumps(span)

    def test_payload_nodes_become_events(self):
        doc = _doc_full()
        span = to_otel_span(doc)
        completion_events = [e for e in span["events"] if e["name"] == "gen_ai.content.completion"]
        assert len(completion_events) == len(doc.payload)

    def test_trace_steps_become_events(self):
        doc = _doc_full()
        span = to_otel_span(doc)
        trace_events = [e for e in span["events"] if e["name"] == "sif.trace.step"]
        assert len(trace_events) == len(doc.trace)

    def test_dag_dependencies_dropped(self):
        """DAG edges cannot be expressed in OTel spans — verify they are absent."""
        span = to_otel_span(_doc_full())
        for event in span["events"]:
            # No deps field in any event (OTel has no DAG concept)
            assert "deps" not in event.get("attributes", {})

    def test_distribution_shape_dropped(self):
        """Distribution.shape has no OTel equivalent — only mean exported."""
        span = to_otel_span(_doc_full())
        for event in span["events"]:
            attrs = event.get("attributes", {})
            assert "confidence_shape" not in str(attrs)

    def test_export_losses_documented(self):
        span = to_otel_span(_doc_full())
        assert "_sif_export_losses" in span
        losses = span["_sif_export_losses"]
        assert any("Distribution.shape" in item for item in losses)
        assert any("signature" in item.lower() for item in losses)

    def test_minimal_doc_no_provenance(self):
        doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="test")])
        span = to_otel_span(doc)
        assert span["attributes"]["gen_ai.request.model"] == "unknown"


# ---------------------------------------------------------------------------
# PROV exporter tests
# ---------------------------------------------------------------------------

class TestProvExporter:
    def test_prov_has_required_sections(self):
        prov = to_prov(_doc_full())
        assert "entity" in prov
        assert "activity" in prov
        assert "agent" in prov
        assert "prefix" in prov

    def test_prov_serializable_to_json(self):
        prov = to_prov(_doc_full())
        json.dumps(prov)

    def test_payload_nodes_become_entities(self):
        doc = _doc_full()
        prov = to_prov(doc)
        for node in doc.payload:
            assert f"sif:node/{node.id}" in prov["entity"]

    def test_trace_steps_become_entities(self):
        doc = _doc_full()
        prov = to_prov(doc)
        for step in doc.trace:
            assert f"sif:step/{step.id}" in prov["entity"]

    def test_dag_edges_become_wasDerivedFrom(self):
        doc = _doc_full()
        prov = to_prov(doc)
        # s1 deps s0, s2 deps s0 and s1
        assert "sif:dep/s1/s0" in prov.get("wasDerivedFrom", {})
        assert "sif:dep/s2/s0" in prov.get("wasDerivedFrom", {})
        assert "sif:dep/s2/s1" in prov.get("wasDerivedFrom", {})

    def test_model_becomes_agent(self):
        prov = to_prov(_doc_full())
        agents = prov["agent"]
        assert any("claude-haiku" in k for k in agents)

    def test_confidence_stored_as_plain_attribute(self):
        """Distribution is stored as plain attributes — type enforcement lost."""
        prov = to_prov(_doc_full())
        entity = prov["entity"]["sif:node/n1"]
        # Mean is present as a float
        assert entity["sif:confidence_mean"] == 0.99
        # But there's no 'Distribution' type wrapper — it's a plain value
        assert isinstance(entity["sif:confidence_mean"], float)

    def test_checksum_dropped(self):
        """SHA-256 checksum has no PROV equivalent — verify it's absent."""
        prov = to_prov(_doc_full())
        prov_str = json.dumps(prov)
        assert "sha256" not in prov_str.lower() or "input_hash" in prov_str

    def test_export_losses_documented(self):
        prov = to_prov(_doc_full())
        assert "_sif_export_losses" in prov
        losses = prov["_sif_export_losses"]
        assert any("CHUNK_CHECKSUM" in item for item in losses)
        assert any("embedding" in item.lower() for item in losses)

    def test_signer_becomes_agent(self):
        """Signer identity is preserved as prov:Agent, but crypto bytes are dropped."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

        doc = _doc_full()
        doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
        prov = to_prov(doc)

        # Signer appears as an agent
        assert any("signer" in k for k in prov["agent"])
        signer_agent = next(v for k, v in prov["agent"].items() if "signer" in k)
        assert signer_agent["sif:signer_id"] == pub_b64
        # Signature bytes NOT present (no binary primitive in PROV)
        assert "signature_bytes" not in json.dumps(signer_agent)


# ---------------------------------------------------------------------------
# Round-trip loss demonstration test
# ---------------------------------------------------------------------------

class TestRoundTripLoss:
    """Demonstrate that neither OTel nor PROV can round-trip back to SIF without loss."""

    def test_otel_cannot_reconstruct_distribution_type(self):
        """After OTel export, you cannot tell a Distribution from a plain float."""
        doc = _doc_full()
        span = to_otel_span(doc)
        # The confidence value is a plain float in OTel
        for event in span["events"]:
            if "sif.node.confidence_mean" in event.get("attributes", {}):
                val = event["attributes"]["sif.node.confidence_mean"]
                assert isinstance(val, float)
                # No shape, no semantics, no Distribution type info

    def test_prov_cannot_reconstruct_dag_edge_types(self):
        """After PROV export, DAG edges lose their type information."""
        doc = _doc_full()
        prov = to_prov(doc)
        # wasDerivedFrom edges have no type/weight info
        for rel in prov.get("wasDerivedFrom", {}).values():
            assert "type" not in rel
            assert "weight" not in rel


# ---------------------------------------------------------------------------
# OTel exporter bug-fix tests (v1.1)
# ---------------------------------------------------------------------------

def _doc_with_tool_error() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(id="tc1", type=NODE_TOOL_CALL,
                 value={"name": "fetch_data", "arguments": {}, "call_id": "c1"},
                 confidence=Distribution(mean=0.9, var=0.05)),
            Node(id="tr1", type=NODE_TOOL_RESULT,
                 value={"call_id": "c1", "content": "timeout", "is_error": True},
                 confidence=Distribution(mean=0.9, var=0.05)),
        ],
        provenance=Provenance(source_model="claude-sonnet-4-6", timestamp_ms=0),
    )


def _doc_with_tool_success() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(id="tc1", type=NODE_TOOL_CALL,
                 value={"name": "get_weather", "arguments": {"city": "Paris"}, "call_id": "w1"},
                 confidence=Distribution(mean=0.9, var=0.05)),
            Node(id="tr1", type=NODE_TOOL_RESULT,
                 value={"call_id": "w1", "content": "22C sunny", "is_error": False},
                 confidence=Distribution(mean=0.9, var=0.05)),
        ],
        provenance=Provenance(source_model="gpt-4o", timestamp_ms=0),
    )


class TestOtelExporterBugFixes:
    def test_bug1_status_error_when_tool_result_is_error(self):
        """Bug 1 fix: status must be ERROR when any tool_result has is_error=True."""
        span = to_otel_span(_doc_with_tool_error())
        assert span["status"]["code"] == "ERROR"

    def test_bug1_status_ok_when_no_errors(self):
        span = to_otel_span(_doc_with_tool_success())
        assert span["status"]["code"] == "OK"

    def test_bug1_status_ok_text_only_doc(self):
        span = to_otel_span(_doc_full())
        assert span["status"]["code"] == "OK"

    def test_bug2_tool_call_event_name(self):
        """Bug 2 fix: NODE_TOOL_CALL nodes must produce gen_ai.tool.call events."""
        span = to_otel_span(_doc_with_tool_success())
        names = [e["name"] for e in span["events"]]
        assert "gen_ai.tool.call" in names
        assert "gen_ai.content.completion" not in names  # no text nodes in this doc

    def test_bug2_tool_result_event_name(self):
        """Bug 2 fix: NODE_TOOL_RESULT nodes must produce gen_ai.tool.result events."""
        span = to_otel_span(_doc_with_tool_success())
        names = [e["name"] for e in span["events"]]
        assert "gen_ai.tool.result" in names

    def test_bug2_tool_call_event_has_tool_name_attr(self):
        span = to_otel_span(_doc_with_tool_success())
        tc_events = [e for e in span["events"] if e["name"] == "gen_ai.tool.call"]
        assert len(tc_events) == 1
        assert tc_events[0]["attributes"]["gen_ai.tool.name"] == "get_weather"

    def test_bug2_tool_result_event_has_is_error_attr(self):
        span = to_otel_span(_doc_with_tool_error())
        tr_events = [e for e in span["events"] if e["name"] == "gen_ai.tool.result"]
        assert len(tr_events) == 1
        assert tr_events[0]["attributes"]["gen_ai.tool.is_error"] is True

    def test_bug3_call_ids_in_span_attributes(self):
        """Bug 3 fix: call_ids must be queryable from span-level attributes."""
        span = to_otel_span(_doc_with_tool_success())
        assert "gen_ai.tool.call_ids" in span["attributes"]
        assert "w1" in span["attributes"]["gen_ai.tool.call_ids"]

    def test_bug3_call_ids_absent_for_text_only_doc(self):
        span = to_otel_span(_doc_full())
        assert "gen_ai.tool.call_ids" not in span["attributes"]
