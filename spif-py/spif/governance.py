"""Clinical-governance application profile for SPIF documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .format import NODE_CONCEPT
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


__all__ = [
    "EVENT_TYPES",
    "EVENT_ROLE_BY_TYPE",
    "GovernanceEvent",
    "build_event_document",
    "event_from_document",
]
