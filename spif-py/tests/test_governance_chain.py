"""Trust-chain verification for signed clinical-governance events."""

from __future__ import annotations

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest
import tracemalloc

from spif import (
    EVENT_ROLE_BY_TYPE,
    GovernanceEvent,
    Provenance,
    SPIFKeyStore,
    SPIFReader,
    SPIFWriter,
    TrustDecision,
    sign_event,
    verify_chain,
    verify_event,
)
from spif.crypto import generate_key, sign_document
from spif.governance import build_event_document
import spif.governance as governance


ACTORS = {
    "Decision": "model-provider",
    "Evidence": "evidence-service",
    "PolicyEvaluation": "policy-engine",
    "Review": "clinical-reviewer",
    "Action": "action-service",
    "Outcome": "outcome-source",
}


def _event(
    event_type: str,
    *,
    actor: str | None = None,
    parent_ids: list[str] | None = None,
) -> GovernanceEvent:
    return GovernanceEvent(
        event_type=event_type,
        event_id=f"{event_type.lower()}-001",
        timestamp_ms=1_700_000_000_000,
        actor=actor or ACTORS[event_type],
        payload={"status": "recorded"},
        parent_ids=parent_ids or [],
        policy_id="bed-placement-v1",
        credential_ref=f"credential://hospital/{ACTORS[event_type]}",
    )


def _registered_keystore(tmp_path):
    keystore = SPIFKeyStore(tmp_path / "keys")
    keys = {event_type: generate_key() for event_type in ACTORS}
    for event_type, signer_id in ACTORS.items():
        keystore.add_key(
            signer_id,
            keys[event_type].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
        keystore.authorize_role(EVENT_ROLE_BY_TYPE[event_type], signer_id)
    return keystore, keys


def _signed_events(events: list[GovernanceEvent], keys: dict[str, object]) -> list[bytes]:
    return [
        governance.sign_event(event, keys[event.event_type], ACTORS[event.event_type])
        for event in events
    ]


def _tamper_signature(data: bytes) -> bytes:
    doc = SPIFReader().decode(data)
    assert doc.signature is not None
    signature = bytearray(doc.signature.signature)
    signature[-1] ^= 1
    doc.signature.signature = bytes(signature)
    return SPIFWriter().encode(doc)


def _tamper_signed_field(data: bytes, field: str, value: object) -> bytes:
    doc = SPIFReader().decode(data)
    doc.payload[0].value[field] = value
    return SPIFWriter().encode(doc)


def _signed_document_with_provenance(
    event: GovernanceEvent,
    private_key,
    signer_id: str,
    provenance,
) -> bytes:
    doc = build_event_document(event)
    doc.provenance = provenance
    doc.payload[0].value["signer_id"] = signer_id
    doc.signer_roles = {signer_id: EVENT_ROLE_BY_TYPE[event.event_type]}
    return sign_document(doc, private_key, signer_id)


def test_each_actor_signed_event_verifies_and_preserves_its_signer(tmp_path):
    """Fails if signing loses the event signer or bypasses the registered key."""
    keystore, keys = _registered_keystore(tmp_path)

    for event_type, signer_id in ACTORS.items():
        signed = governance.sign_event(_event(event_type), keys[event_type], signer_id)

        decoded = SPIFReader().decode(signed)
        assert decoded.signature is not None
        assert decoded.signature.signer == signer_id
        assert decoded.payload[0].value["signer_id"] == signer_id
        assert governance.verify_event(signed, keystore).valid is True


def test_governance_verification_is_available_from_the_top_level_api(tmp_path):
    """Fails if documented governance verification cannot be used via ``spif``."""
    keystore, keys = _registered_keystore(tmp_path)
    signed = sign_event(_event("Decision"), keys["Decision"], ACTORS["Decision"])

    event_result = verify_event(signed, keystore)
    chain_result = verify_chain([signed], keystore)

    assert isinstance(event_result, TrustDecision)
    assert (event_result.valid, event_result.reason) == (True, "verified")
    assert chain_result == [event_result]


def test_verify_event_reports_unknown_and_revoked_signers(tmp_path):
    """Fails if unknown or revoked signers are treated as valid trust roots."""
    keystore, keys = _registered_keystore(tmp_path)
    event = _event("Decision")

    unknown = governance.sign_event(
        _event("Decision", actor="unregistered-provider"),
        keys["Decision"],
        "unregistered-provider",
    )
    unknown_result = governance.verify_event(unknown, keystore)
    assert (unknown_result.valid, unknown_result.reason) == (False, "unknown_signer")

    signed = governance.sign_event(event, keys["Decision"], ACTORS["Decision"])
    keystore.revoke(ACTORS["Decision"], revoked_at_ms=1_700_000_000_001)
    revoked_result = governance.verify_event(signed, keystore)
    assert (revoked_result.valid, revoked_result.reason) == (False, "revoked_signer")
    assert governance.verify_chain([signed], keystore)[0].valid is False


def test_verify_event_rejects_tampered_signature_before_revoked_signer(tmp_path):
    """Fails if revocation masks signature tampering for a registered signer."""
    keystore, keys = _registered_keystore(tmp_path)
    signed = governance.sign_event(
        _event("Decision"), keys["Decision"], ACTORS["Decision"]
    )
    keystore.revoke(ACTORS["Decision"], revoked_at_ms=1_700_000_000_001)

    result = governance.verify_event(_tamper_signature(signed), keystore)

    assert (result.valid, result.reason) == (False, "invalid_signature")


def test_verify_event_rejects_expected_signer_tampering_and_role_mismatches(tmp_path):
    """Fails if identity, signature, or event-role binding can be substituted."""
    keystore, keys = _registered_keystore(tmp_path)
    review = _event("Review")
    signed = governance.sign_event(review, keys["Review"], ACTORS["Review"])

    assert governance.verify_event(
        signed, keystore, expected_signer="someone-else"
    ).valid is False
    assert governance.verify_event(_tamper_signature(signed), keystore).valid is False
    for field, value in (
        ("payload", {"status": "tampered"}),
        ("actor", "different-reviewer"),
        ("event_type", "Decision"),
    ):
        result = governance.verify_event(_tamper_signed_field(signed, field, value), keystore)
        assert (result.valid, result.reason) == (False, "invalid_signature")

    role_tamper = SPIFReader().decode(signed)
    role_tamper.signer_roles[ACTORS["Review"]] = EVENT_ROLE_BY_TYPE["Decision"]
    role_result = governance.verify_event(SPIFWriter().encode(role_tamper), keystore)
    assert (role_result.valid, role_result.reason) == (False, "invalid_signature")

    mismatched = build_event_document(review)
    mismatched.payload[0].value["signer_id"] = ACTORS["Review"]
    mismatched.signer_roles = {ACTORS["Review"]: EVENT_ROLE_BY_TYPE["Decision"]}
    wrong_role = sign_document(mismatched, keys["Review"], ACTORS["Review"])
    role_result = governance.verify_event(wrong_role, keystore)
    assert (role_result.valid, role_result.reason) == (False, "event_role_mismatch")


def test_verify_event_requires_signed_provenance_to_match_the_event(tmp_path):
    """Fails if profile provenance can be absent or disagree with signed event identity."""
    keystore, keys = _registered_keystore(tmp_path)
    event = _event("Review")
    signer_id = ACTORS["Review"]

    missing = _signed_document_with_provenance(event, keys["Review"], signer_id, None)
    actor_mismatch = _signed_document_with_provenance(
        event,
        keys["Review"],
        signer_id,
        Provenance(
            source_model="different-reviewer",
            timestamp_ms=event.timestamp_ms,
        ),
    )
    timestamp_mismatch = _signed_document_with_provenance(
        event,
        keys["Review"],
        signer_id,
        Provenance(
            source_model=event.actor,
            timestamp_ms=event.timestamp_ms + 1,
        ),
    )

    missing_result = governance.verify_event(missing, keystore)
    actor_result = governance.verify_event(actor_mismatch, keystore)
    timestamp_result = governance.verify_event(timestamp_mismatch, keystore)

    assert (missing_result.valid, missing_result.reason) == (False, "missing_provenance")
    assert (actor_result.valid, actor_result.reason) == (
        False,
        "provenance_actor_mismatch",
    )
    assert (timestamp_result.valid, timestamp_result.reason) == (
        False,
        "provenance_timestamp_mismatch",
    )


def test_sign_event_and_verify_event_bind_actor_to_signer(tmp_path):
    """Fails if a signer can create or verify an event attributed to another actor."""
    keystore, keys = _registered_keystore(tmp_path)
    mismatched_event = _event("Review", actor=ACTORS["Decision"])

    with pytest.raises(ValueError, match="event.actor must match signer_id"):
        governance.sign_event(mismatched_event, keys["Review"], ACTORS["Review"])

    decoded_mismatch = build_event_document(mismatched_event)
    decoded_mismatch.payload[0].value["signer_id"] = ACTORS["Review"]
    decoded_mismatch.signer_roles = {
        ACTORS["Review"]: EVENT_ROLE_BY_TYPE["Review"],
    }
    signed_mismatch = sign_document(
        decoded_mismatch, keys["Review"], ACTORS["Review"]
    )
    result = governance.verify_event(signed_mismatch, keystore)
    assert (result.valid, result.reason) == (False, "actor_signer_mismatch")


def test_verify_event_requires_configured_and_granted_role_authorization(tmp_path):
    """Fails if the governance role has no authorization list or denies its signer."""
    keystore = SPIFKeyStore(tmp_path / "keys")
    key = generate_key()
    signer_id = ACTORS["Decision"]
    keystore.add_key(
        signer_id,
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )
    signed = governance.sign_event(_event("Decision"), key, signer_id)

    missing = governance.verify_event(signed, keystore)
    assert (missing.valid, missing.reason) == (False, "role_authorization_missing")

    keystore.authorize_role(EVENT_ROLE_BY_TYPE["Decision"], "different-provider")
    denied = governance.verify_event(signed, keystore)
    assert (denied.valid, denied.reason) == (False, "unauthorized_role")


def test_verify_event_rejects_tampered_artifact_claiming_revoked_signer(tmp_path):
    """A revoked-signer reason must require a valid signature for that key."""
    keystore, keys = _registered_keystore(tmp_path)
    signer_id = ACTORS["Review"]
    signed = governance.sign_event(_event("Review"), keys["Review"], signer_id)
    keystore.revoke(signer_id, revoked_at_ms=1_700_000_000_001)

    forged = _tamper_signed_field(signed, "actor", "forged-reviewer")

    result = governance.verify_event(forged, keystore)

    assert (result.valid, result.reason) == (False, "invalid_signature")


def test_verify_chain_rejects_events_with_parents_not_already_present(tmp_path):
    """Fails if a chain accepts a governance event whose parent was not supplied first."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    action = _event("Action", parent_ids=[decision.event_id, "missing-policy-evaluation"])

    results = governance.verify_chain(
        [
            governance.sign_event(decision, keys["Decision"], ACTORS["Decision"]),
            governance.sign_event(action, keys["Action"], ACTORS["Action"]),
        ],
        keystore,
    )

    assert [result.valid for result in results] == [True, False]
    assert results[1].reason == "missing_parent"


def test_verify_chain_rejects_duplicate_event_ids_without_replacing_parent(tmp_path):
    """Fails if a later same-ID artifact can substitute for a verified parent."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    substituted_parent = _event("Evidence")
    substituted_parent.event_id = decision.event_id
    action = _event("Action", parent_ids=[decision.event_id])

    results = governance.verify_chain(
        [
            governance.sign_event(decision, keys["Decision"], ACTORS["Decision"]),
            governance.sign_event(
                substituted_parent, keys["Evidence"], ACTORS["Evidence"]
            ),
            governance.sign_event(action, keys["Action"], ACTORS["Action"]),
        ],
        keystore,
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (False, "duplicate_event_id"),
        (True, "verified"),
    ]


def test_verify_chain_rejects_duplicate_parent_ids(tmp_path):
    """A parent reference list must not contain the same event twice."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    evidence = _event("Evidence", parent_ids=[decision.event_id, decision.event_id])

    results = governance.verify_chain(
        _signed_events([decision, evidence], keys), keystore
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (False, "duplicate_parent"),
    ]


def test_verify_chain_rejects_disconnected_and_reverse_order_workflows(tmp_path):
    """Six signed stages are not a workflow unless their topology is connected and ordered."""
    keystore, keys = _registered_keystore(tmp_path)
    disconnected = [
        _event(event_type) for event_type in (
            "Decision", "Evidence", "PolicyEvaluation", "Review", "Action", "Outcome"
        )
    ]
    assert all(
        result.reason == ("verified" if event.event_type == "Decision" else "invalid_root")
        for event, result in zip(
            disconnected,
            governance.verify_chain(_signed_events(disconnected, keys), keystore),
        )
    )

    reverse = []
    for index, event_type in enumerate(
        ("Outcome", "Action", "Review", "PolicyEvaluation", "Evidence", "Decision")
    ):
        reverse.append(
            _event(
                event_type,
                parent_ids=[] if index == 0 else [reverse[index - 1].event_id],
            )
        )
    results = governance.verify_chain(_signed_events(reverse, keys), keystore)
    assert results[0].reason == "invalid_root"
    assert all(not result.valid for result in results)


def test_verify_chain_stress_fanout_preserves_parent_integrity(tmp_path):
    """A moderate fan-out remains bounded and verifies every signed child."""
    keystore, keys = _registered_keystore(tmp_path)
    root = _event("Decision")
    children = []
    for index in range(128):
        child = _event("Outcome", parent_ids=[root.event_id])
        child.event_id = f"outcome-{index:03d}"
        children.append(child)
    data = _signed_events([root] + children, keys)

    tracemalloc.start()
    results = governance.verify_chain(data, keystore)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(results) == 129
    assert all(result.valid for result in results)
    assert peak < 32 * 1024 * 1024


def test_verify_chain_rejects_decision_with_parents_as_invalid_root(tmp_path):
    """Fails if the only root event can declare a parent."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision", parent_ids=["earlier-event"])

    results = governance.verify_chain(_signed_events([decision], keys), keystore)

    assert [(result.valid, result.reason) for result in results] == [
        (False, "invalid_root"),
    ]


def test_verify_chain_rejects_non_decision_without_parent_as_invalid_root(tmp_path):
    """Fails if a non-root event starts an independent governance branch."""
    keystore, keys = _registered_keystore(tmp_path)
    evidence = _event("Evidence")

    results = governance.verify_chain(_signed_events([evidence], keys), keystore)

    assert [(result.valid, result.reason) for result in results] == [
        (False, "invalid_root"),
    ]


def test_verify_chain_rejects_second_decision_root(tmp_path):
    """Fails if a second Decision starts a disconnected root component."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    second_decision = _event("Decision")
    second_decision.event_id = "decision-002"

    results = governance.verify_chain(
        _signed_events([decision, second_decision], keys), keystore
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (False, "invalid_root"),
    ]


def test_verify_chain_rejects_duplicate_parent_ids(tmp_path):
    """Fails if a child repeats one verified parent identifier."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    evidence = _event(
        "Evidence", parent_ids=[decision.event_id, decision.event_id]
    )

    results = governance.verify_chain(
        _signed_events([decision, evidence], keys), keystore
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (False, "duplicate_parent"),
    ]


def test_verify_chain_requires_parent_event_type_to_precede_child(tmp_path):
    """Fails if an already verified later-stage event is a parent."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    action = _event("Action", parent_ids=[decision.event_id])
    policy = _event("PolicyEvaluation", parent_ids=[action.event_id])

    results = governance.verify_chain(
        _signed_events([decision, action, policy], keys), keystore
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (True, "verified"),
        (False, "parent_order"),
    ]


def test_verify_chain_rejects_disconnected_six_event_set(tmp_path):
    """Fails if six signed stages contain an independent non-Decision root."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    evidence = _event("Evidence")
    policy = _event("PolicyEvaluation", parent_ids=[evidence.event_id])
    review = _event("Review", parent_ids=[policy.event_id])
    action = _event("Action", parent_ids=[review.event_id])
    outcome = _event("Outcome", parent_ids=[action.event_id])

    results = governance.verify_chain(
        _signed_events([decision, evidence, policy, review, action, outcome], keys),
        keystore,
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (False, "invalid_root"),
        (False, "missing_parent"),
        (False, "missing_parent"),
        (False, "missing_parent"),
        (False, "missing_parent"),
    ]


def test_verify_chain_rejects_reverse_order_six_event_set(tmp_path):
    """Fails if a six-stage chain connects later event types to earlier children."""
    keystore, keys = _registered_keystore(tmp_path)
    decision = _event("Decision")
    outcome = _event("Outcome", parent_ids=[decision.event_id])
    action = _event("Action", parent_ids=[outcome.event_id])
    review = _event("Review", parent_ids=[action.event_id])
    policy = _event("PolicyEvaluation", parent_ids=[review.event_id])
    evidence = _event("Evidence", parent_ids=[policy.event_id])

    results = governance.verify_chain(
        _signed_events([decision, outcome, action, review, policy, evidence], keys),
        keystore,
    )

    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
        (True, "verified"),
        (False, "parent_order"),
        (False, "missing_parent"),
        (False, "missing_parent"),
        (False, "missing_parent"),
    ]
