"""
Tests for spif.adapters.c2pa_adapter — C2PA manifest -> SPIFDocument import.
"""

from __future__ import annotations

import pytest

from spif.adapters.c2pa_adapter import import_c2pa_manifest
from spif.reader import SPIFReader
from spif.writer import SPIFWriter

_MANIFEST_STORE = {
    "active_manifest": "urn:uuid:abc123",
    "manifests": {
        "urn:uuid:abc123": {
            "claim_generator": "Claude/Fable5 c2pa-python/0.37.5",
            "title": "generated.docx",
            "format": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "signature_info": {"issuer": "Anthropic PBC", "time": "2026-08-11T12:00:00Z"},
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}}],
            "ingredients": [],
        }
    },
}


class TestActiveManifestSelection:
    def test_picks_active_manifest_by_label(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        assert doc.provenance.source_model == "Claude/Fable5 c2pa-python/0.37.5"

    def test_falls_back_to_first_manifest_when_active_label_missing(self):
        store = {"manifests": {"urn:uuid:only": _MANIFEST_STORE["manifests"]["urn:uuid:abc123"]}}
        doc = import_c2pa_manifest(store)
        assert doc.provenance.source_model == "Claude/Fable5 c2pa-python/0.37.5"

    def test_accepts_a_bare_manifest_dict_not_wrapped_in_a_store(self):
        bare = _MANIFEST_STORE["manifests"]["urn:uuid:abc123"]
        doc = import_c2pa_manifest(bare)
        assert doc.provenance.source_model == "Claude/Fable5 c2pa-python/0.37.5"

    def test_raises_on_empty_store(self):
        with pytest.raises(ValueError, match="no manifest found"):
            import_c2pa_manifest({})

    def test_accepts_json_string_matching_reader_json_output(self):
        """c2pa-python's Reader.json() returns a JSON string, not a dict."""
        import json

        doc = import_c2pa_manifest(json.dumps(_MANIFEST_STORE))
        assert doc.provenance.source_model == "Claude/Fable5 c2pa-python/0.37.5"
        assert doc.payload[0].value["title"] == "generated.docx"

    def test_raises_clear_error_on_non_dict_non_string_input(self):
        with pytest.raises(ValueError, match="dict or JSON string"):
            import_c2pa_manifest(12345)


class TestProvenanceMapping:
    def test_claim_generator_maps_to_source_model_and_version(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        assert doc.provenance.source_model == doc.provenance.model_version

    def test_signer_issuer_recorded_in_model_card_not_as_ed25519_signature(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        assert doc.provenance.model_card == "c2pa:Anthropic PBC"
        assert doc.signature is None
        assert doc.signatures == []

    def test_signature_time_parsed_to_epoch_ms(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        assert doc.provenance.timestamp_ms == 1786449600000

    def test_explicit_timestamp_override_wins(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE, timestamp_ms=42)
        assert doc.provenance.timestamp_ms == 42

    def test_unparseable_time_falls_back_to_zero(self):
        store = {
            "claim_generator": "x",
            "signature_info": {"time": "not-a-date"},
        }
        doc = import_c2pa_manifest(store)
        assert doc.provenance.timestamp_ms == 0

    def test_missing_signature_info_defaults_timestamp_to_zero(self):
        store = {"claim_generator": "x"}
        doc = import_c2pa_manifest(store)
        assert doc.provenance.timestamp_ms == 0
        assert doc.provenance.model_card == ""

    def test_context_ref_passthrough(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE, context_ref="deadbeef")
        assert doc.provenance.context_ref == "deadbeef"

    def test_input_hash_is_stable_sha256_of_manifest(self):
        doc1 = import_c2pa_manifest(_MANIFEST_STORE)
        doc2 = import_c2pa_manifest(_MANIFEST_STORE)
        assert doc1.provenance.input_hash == doc2.provenance.input_hash
        assert len(doc1.provenance.input_hash) == 64


class TestPayloadMapping:
    def test_single_fact_node_holds_manifest_contents(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        assert len(doc.payload) == 1
        node = doc.payload[0]
        assert node.id == "c2pa_manifest"
        assert node.type == "fact"
        assert node.value["title"] == "generated.docx"
        assert node.value["assertions"][0]["label"] == "c2pa.actions"

    def test_confidence_is_point_mass_certain_not_a_fabricated_distribution(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        confidence = doc.payload[0].confidence
        assert confidence.mean == 1.0
        assert confidence.var == 0.0
        assert confidence.shape == "point"


class TestRoundTrip:
    def test_encode_decode_preserves_manifest_derived_document(self):
        doc = import_c2pa_manifest(_MANIFEST_STORE)
        encoded = SPIFWriter().encode(doc)
        decoded = SPIFReader().decode(encoded)

        assert decoded.provenance.source_model == "Claude/Fable5 c2pa-python/0.37.5"
        assert decoded.payload[0].value["title"] == "generated.docx"
        assert decoded.payload[0].confidence.mean == 1.0
