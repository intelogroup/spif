import pytest

from spif import (
    EVENT_ROLE_BY_TYPE,
    EVENT_TYPES,
    GovernanceEvent,
    SPIFDocument,
    SPIFReader,
    SPIFWriter,
    build_event_document,
    event_from_document,
)


def _event(event_type="Review"):
    return GovernanceEvent(
        event_type=event_type,
        event_id="review-001",
        timestamp_ms=1700000000000,
        actor="hospital/reviewer/alice",
        payload={"decision": "approve", "override_flag": False},
        parent_ids=["decision-001", "policy-001"],
        policy_id="bed-placement-v1",
        credential_ref="credential://hospital/alice/clinical-ops",
    )


def test_event_vocabulary_and_roles_are_in_workflow_order():
    assert EVENT_TYPES == (
        "Decision", "Evidence", "PolicyEvaluation", "Review", "Action", "Outcome"
    )
    assert EVENT_ROLE_BY_TYPE == {
        "Decision": "model_provider",
        "Evidence": "evidence_service",
        "PolicyEvaluation": "policy_engine",
        "Review": "human_reviewer",
        "Action": "action_service",
        "Outcome": "outcome_source",
    }


def test_all_event_types_round_trip_through_node():
    for event_type in EVENT_TYPES:
        event = _event(event_type)
        assert GovernanceEvent.from_node(event.to_node()) == event


def test_unsupported_event_type_fails():
    with pytest.raises(ValueError, match="event_type"):
        _event("Unknown")


@pytest.mark.parametrize("kwargs", [
    {"event_id": ""},
    {"timestamp_ms": -1},
    {"actor": ""},
    {"parent_ids": "not-a-list"},
])
def test_event_fields_are_validated(kwargs):
    values = {
        "event_type": "Review",
        "event_id": "review-001",
        "timestamp_ms": 0,
        "actor": "reviewer",
        "payload": {},
        "parent_ids": [],
        "policy_id": "policy-v1",
        "credential_ref": "credential://hospital/reviewer",
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        GovernanceEvent(**values)


def test_document_contains_structured_node_and_actor_nonce_provenance():
    event = _event()
    doc = build_event_document(event, nonce="nonce-001")

    assert isinstance(doc, SPIFDocument)
    assert len(doc.payload) == 1
    assert doc.payload[0].value == {
        "profile": "spif-clinical-governance-v0",
        "event_type": "Review",
        "event_id": "review-001",
        "timestamp_ms": 1700000000000,
        "actor": "hospital/reviewer/alice",
        "payload": {"decision": "approve", "override_flag": False},
        "parent_ids": ["decision-001", "policy-001"],
        "policy_id": "bed-placement-v1",
        "credential_ref": "credential://hospital/alice/clinical-ops",
    }
    assert doc.provenance.source_model == event.actor
    assert doc.provenance.timestamp_ms == event.timestamp_ms
    assert doc.provenance.nonce == "nonce-001"


def test_document_round_trip_through_wire_serialization():
    event = _event("Outcome")
    encoded = SPIFWriter().encode(build_event_document(event, nonce="n"))
    restored = SPIFReader().decode(encoded)
    assert event_from_document(restored) == event
