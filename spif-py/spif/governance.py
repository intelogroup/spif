"""Clinical-governance application profile for SPIF documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .crypto import sign_document
from .format import NODE_CONCEPT
from .keystore import SPIFKeyStore
from .reader import SPIFReader, SPIFSignatureError
from .types import Node, Provenance, SPIFDocument


EVENT_TYPES: tuple[str, ...] = (
    "Decision",
    "Evidence",
    "PolicyEvaluation",
    "Review",
    "Action",
    "Outcome",
)

EVENT_ROLE_BY_TYPE: dict[str, str] = {
    "Decision": "model_provider",
    "Evidence": "evidence_service",
    "PolicyEvaluation": "policy_engine",
    "Review": "human_reviewer",
    "Action": "action_service",
    "Outcome": "outcome_source",
}

PROFILE_NAME = "spif-clinical-governance-v0"


@dataclass
class GovernanceEvent:
    """One signed clinical-governance event encoded as an application node."""

    event_type: str
    event_id: str
    timestamp_ms: int
    actor: str
    payload: dict[str, Any]
    parent_ids: list[str]
    policy_id: str
    credential_ref: str

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"Unsupported event_type: {self.event_type!r}")
        for name, value in (
            ("event_id", self.event_id),
            ("actor", self.actor),
            ("policy_id", self.policy_id),
            ("credential_ref", self.credential_ref),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must not be empty")
        if not isinstance(self.timestamp_ms, int) or self.timestamp_ms < 0:
            raise ValueError("timestamp_ms must be a non-negative integer")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dictionary")
        if not isinstance(self.parent_ids, list):
            raise ValueError("parent_ids must be a list")
        if any(not isinstance(parent_id, str) or not parent_id for parent_id in self.parent_ids):
            raise ValueError("parent_ids must contain non-empty strings")

    def to_node(self) -> Node:
        return Node(
            id=self.event_id,
            type=NODE_CONCEPT,
            value={
                "profile": PROFILE_NAME,
                "event_type": self.event_type,
                "event_id": self.event_id,
                "timestamp_ms": self.timestamp_ms,
                "actor": self.actor,
                "payload": self.payload,
                "parent_ids": self.parent_ids,
                "policy_id": self.policy_id,
                "credential_ref": self.credential_ref,
            },
        )

    @classmethod
    def from_node(cls, node: Node) -> "GovernanceEvent":
        if not isinstance(node, Node) or node.type != NODE_CONCEPT:
            raise ValueError("node must be a clinical-governance concept node")
        value = node.value
        if not isinstance(value, dict) or value.get("profile") != PROFILE_NAME:
            raise ValueError("node does not contain the clinical-governance profile")
        try:
            event = cls(
                event_type=value["event_type"],
                event_id=value["event_id"],
                timestamp_ms=value["timestamp_ms"],
                actor=value["actor"],
                payload=value["payload"],
                parent_ids=value["parent_ids"],
                policy_id=value["policy_id"],
                credential_ref=value["credential_ref"],
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("malformed clinical-governance event node") from exc
        if event.event_id != node.id:
            raise ValueError("event_id must match node.id")
        return event


@dataclass(frozen=True)
class TrustDecision:
    """The verification outcome for one signed governance event."""

    event_id: str
    signer_id: str
    event_type: str
    valid: bool
    reason: str


def build_event_document(event: GovernanceEvent, *, nonce: str = "") -> SPIFDocument:
    """Build an unsigned SPIF document containing one governance event node."""
    if not isinstance(event, GovernanceEvent):
        raise TypeError("event must be a GovernanceEvent")
    return SPIFDocument(
        payload=[event.to_node()],
        provenance=Provenance(
            source_model=event.actor,
            timestamp_ms=event.timestamp_ms,
            nonce=nonce,
        ),
    )


def event_from_document(doc: SPIFDocument) -> GovernanceEvent:
    """Extract the single clinical-governance event from a SPIF document."""
    if not isinstance(doc, SPIFDocument) or len(doc.payload) != 1:
        raise ValueError("document must contain exactly one governance event node")
    return GovernanceEvent.from_node(doc.payload[0])


def sign_event(
    event: GovernanceEvent,
    private_key: Any,
    signer_id: str,
    *,
    nonce: str = "",
) -> bytes:
    """Sign one governance event with its actor's key.

    The signer ID and required event role are placed in signed document data,
    alongside the event type and parent IDs already represented by the event
    node.  Verification can therefore bind all three claims to the same raw
    signature without changing the SPIF wire format.
    """
    if not isinstance(signer_id, str) or not signer_id:
        raise ValueError("signer_id must not be empty")
    if event.actor != signer_id:
        raise ValueError("event.actor must match signer_id")

    doc = build_event_document(event, nonce=nonce)
    doc.payload[0].value["signer_id"] = signer_id
    doc.signer_roles = {signer_id: EVENT_ROLE_BY_TYPE[event.event_type]}
    return sign_document(doc, private_key, signer_id)


def _trust_fields(doc: SPIFDocument) -> tuple[str, str, str]:
    """Extract identifiers for a decision without trusting event validation."""
    if len(doc.payload) != 1 or not isinstance(doc.payload[0].value, dict):
        return "", "", ""
    value = doc.payload[0].value
    event_id = value.get("event_id", "")
    signer_id = value.get("signer_id", "")
    event_type = value.get("event_type", "")
    return (
        event_id if isinstance(event_id, str) else "",
        signer_id if isinstance(signer_id, str) else "",
        event_type if isinstance(event_type, str) else "",
    )


def _decision(
    doc: SPIFDocument,
    *,
    valid: bool,
    reason: str,
) -> TrustDecision:
    event_id, signer_id, event_type = _trust_fields(doc)
    return TrustDecision(event_id, signer_id, event_type, valid, reason)


def verify_event(
    data: bytes,
    keystore: SPIFKeyStore,
    *,
    expected_signer: str | None = None,
) -> TrustDecision:
    """Verify a signed governance event against a registered actor key.

    Malformed SPIF bytes raise the reader's format exceptions. Expected trust
    failures return an invalid :class:`TrustDecision`, preserving the decoded
    event identifiers whenever they are available. For a known, non-revoked
    signer, the raw signature is verified before any event profile claim is
    interpreted.
    """
    doc = SPIFReader().decode(data)

    if doc.signature is None or doc.signatures:
        return _decision(doc, valid=False, reason="missing_signature")

    event_id, signer_id, event_type = _trust_fields(doc)
    signature_signer = doc.signature.signer
    if not isinstance(signature_signer, str) or not signature_signer:
        return TrustDecision(event_id, signer_id, event_type, False, "missing_signer_binding")
    if keystore.is_revoked(signature_signer):
        return TrustDecision(event_id, signature_signer, event_type, False, "revoked_signer")
    if not keystore.has_key(signature_signer):
        return TrustDecision(event_id, signature_signer, event_type, False, "unknown_signer")

    try:
        keystore.verify(data)
    except SPIFSignatureError:
        return TrustDecision(event_id, signature_signer, event_type, False, "invalid_signature")

    try:
        event = event_from_document(doc)
    except ValueError:
        return _decision(doc, valid=False, reason="invalid_event")

    if not signer_id:
        return TrustDecision(event_id, signer_id, event_type, False, "missing_signer_binding")
    if signature_signer != signer_id:
        return TrustDecision(event_id, signer_id, event_type, False, "signer_mismatch")
    if event.actor != signer_id:
        return TrustDecision(event_id, signer_id, event_type, False, "actor_signer_mismatch")
    if expected_signer is not None and signer_id != expected_signer:
        return TrustDecision(event_id, signer_id, event_type, False, "expected_signer_mismatch")

    if doc.provenance is None:
        return TrustDecision(event_id, signer_id, event_type, False, "missing_provenance")
    if doc.provenance.source_model != event.actor:
        return TrustDecision(event_id, signer_id, event_type, False, "provenance_actor_mismatch")
    if doc.provenance.timestamp_ms != event.timestamp_ms:
        return TrustDecision(event_id, signer_id, event_type, False, "provenance_timestamp_mismatch")

    expected_role = EVENT_ROLE_BY_TYPE[event.event_type]
    if doc.signer_roles.get(signer_id) != expected_role:
        return TrustDecision(event_id, signer_id, event_type, False, "event_role_mismatch")
    if not keystore.has_role_authorization_list(expected_role):
        return TrustDecision(event_id, signer_id, event_type, False, "role_authorization_missing")
    if not keystore.is_authorized_for_role(expected_role, signer_id):
        return TrustDecision(event_id, signer_id, event_type, False, "unauthorized_role")

    try:
        keystore.check_roles(doc)
    except SPIFSignatureError:
        return TrustDecision(event_id, signer_id, event_type, False, "unauthorized_role")

    return TrustDecision(event_id, signer_id, event_type, True, "verified")


def verify_chain(
    events: list[bytes],
    keystore: SPIFKeyStore,
) -> list[TrustDecision]:
    """Verify event signatures and require declared parents to precede children."""
    decisions: list[TrustDecision] = []
    verified_events: dict[str, GovernanceEvent] = {}

    for data in events:
        decision = verify_event(data, keystore)
        if decision.valid:
            doc = SPIFReader().decode(data)
            event = event_from_document(doc)
            if event.event_id in verified_events:
                decision = TrustDecision(
                    decision.event_id,
                    decision.signer_id,
                    decision.event_type,
                    False,
                    "duplicate_event_id",
                )
            elif any(parent_id not in verified_events for parent_id in event.parent_ids):
                decision = TrustDecision(
                    decision.event_id,
                    decision.signer_id,
                    decision.event_type,
                    False,
                    "missing_parent",
                )
            else:
                verified_events[event.event_id] = event
        decisions.append(decision)

    return decisions


__all__ = [
    "EVENT_TYPES",
    "EVENT_ROLE_BY_TYPE",
    "GovernanceEvent",
    "TrustDecision",
    "build_event_document",
    "event_from_document",
    "sign_event",
    "verify_event",
    "verify_chain",
]
