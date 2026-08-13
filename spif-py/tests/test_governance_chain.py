"""Trust-chain verification for signed clinical-governance events."""

from __future__ import annotations

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from spif import EVENT_ROLE_BY_TYPE, GovernanceEvent, SPIFKeyStore, SPIFReader, SPIFWriter
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


def _tamper_signature(data: bytes) -> bytes:
    doc = SPIFReader().decode(data)
    assert doc.signature is not None
    signature = bytearray(doc.signature.signature)
    signature[-1] ^= 1
    doc.signature.signature = bytes(signature)
    return SPIFWriter().encode(doc)


def _tamper_event_content(data: bytes) -> bytes:
    doc = SPIFReader().decode(data)
    doc.payload[0].value["payload"] = {"status": "tampered"}
    return SPIFWriter().encode(doc)


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


def test_verify_event_rejects_expected_signer_tampering_and_role_mismatches(tmp_path):
    """Fails if identity, signature, or event-role binding can be substituted."""
    keystore, keys = _registered_keystore(tmp_path)
    review = _event("Review")
    signed = governance.sign_event(review, keys["Review"], ACTORS["Review"])

    assert governance.verify_event(
        signed, keystore, expected_signer="someone-else"
    ).valid is False
    assert governance.verify_event(_tamper_signature(signed), keystore).valid is False
    content_tamper = governance.verify_event(_tamper_event_content(signed), keystore)
    assert (content_tamper.valid, content_tamper.reason) == (False, "invalid_signature")

    mismatched = build_event_document(review)
    mismatched.payload[0].value["signer_id"] = ACTORS["Review"]
    mismatched.signer_roles = {ACTORS["Review"]: EVENT_ROLE_BY_TYPE["Decision"]}
    wrong_role = sign_document(mismatched, keys["Review"], ACTORS["Review"])
    role_result = governance.verify_event(wrong_role, keystore)
    assert (role_result.valid, role_result.reason) == (False, "event_role_mismatch")


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
