"""Synthetic cross-system clinical-governance evidence-chain walkthrough.

This example uses no patient data.  It demonstrates the profile and trust
chain APIs with six independently signed events produced by simulated systems.
"""

from __future__ import annotations

import tempfile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    EVENT_ROLE_BY_TYPE,
    EVENT_TYPES,
    GovernanceEvent,
    SPIFKeyStore,
    TrustDecision,
    sign_event,
    verify_chain,
)
from spif.crypto import generate_key


CASE_ID = "SYNTH-CASE-2026-042"

ACTORS = {
    "Decision": "recommendation-platform-sim:recommendation-service",
    "Evidence": "hospital-ehr-sim:evidence-service",
    "PolicyEvaluation": "policy-engine-sim:policy-evaluator",
    "Review": "hospital-ehr-sim:clinical-reviewer",
    "Action": "bed-management-sim:bed-assignment-service",
    "Outcome": "hospital-ehr-sim:outcome-recorder",
}


def _event(
    event_type: str,
    event_id: str,
    timestamp_ms: int,
    payload: dict[str, object],
    parent_ids: list[str],
) -> GovernanceEvent:
    return GovernanceEvent(
        event_type=event_type,
        event_id=event_id,
        timestamp_ms=timestamp_ms,
        actor=ACTORS[event_type],
        payload=payload,
        parent_ids=parent_ids,
        policy_id="synthetic-bed-placement-policy-v1",
        credential_ref=f"credential://synthetic/{ACTORS[event_type]}",
    )


def build_synthetic_chain() -> tuple[list[bytes], SPIFKeyStore]:
    """Build six signed, synthetic clinical-governance events and their trust store."""
    events = [
        _event(
            "Decision",
            "recommend-bed-placement",
            1_700_000_000_000,
            {
                "system": "recommendation-platform-sim",
                "case_id": CASE_ID,
                "recommendation": "prioritize-inpatient-bed-placement",
            },
            [],
        ),
        _event(
            "Evidence",
            "ehr-bed-and-acuity-evidence",
            1_700_000_000_001,
            {
                "system": "hospital-ehr-sim",
                "case_id": CASE_ID,
                "evidence": "synthetic-acuity-and-bed-availability",
            },
            ["recommend-bed-placement"],
        ),
        _event(
            "PolicyEvaluation",
            "bed-placement-policy-evaluation",
            1_700_000_000_002,
            {
                "system": "policy-engine-sim",
                "case_id": CASE_ID,
                "policy_result": "eligible-for-priority-placement",
            },
            ["recommend-bed-placement", "ehr-bed-and-acuity-evidence"],
        ),
        _event(
            "Review",
            "clinical-bed-placement-review",
            1_700_000_000_003,
            {
                "system": "hospital-ehr-sim",
                "case_id": CASE_ID,
                "approval_path": "clinical-review",
                "override_capable": True,
                "review_decision": "approved",
            },
            ["bed-placement-policy-evaluation"],
        ),
        _event(
            "Action",
            "assign-inpatient-bed",
            1_700_000_000_004,
            {
                "system": "bed-management-sim",
                "case_id": CASE_ID,
                "action": "assign-synthetic-inpatient-bed",
            },
            ["clinical-bed-placement-review"],
        ),
        _event(
            "Outcome",
            "bed-placement-outcome",
            1_700_000_000_005,
            {
                "system": "hospital-ehr-sim",
                "case_id": CASE_ID,
                "outcome": "synthetic-bed-placement-completed",
            },
            ["assign-inpatient-bed"],
        ),
    ]

    temporary_directory = tempfile.TemporaryDirectory(prefix="spif-clinical-governance-")
    keystore = SPIFKeyStore(temporary_directory.name)
    keystore._synthetic_demo_tempdir = temporary_directory
    keys = {event.event_type: generate_key() for event in events}
    signed_events = []
    for event in events:
        signer_id = ACTORS[event.event_type]
        key = keys[event.event_type]
        keystore.add_key(
            signer_id,
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        )
        keystore.authorize_role(EVENT_ROLE_BY_TYPE[event.event_type], signer_id)
        signed_events.append(sign_event(event, key, signer_id))

    return signed_events, keystore


def summarize_chain(results: list[TrustDecision]) -> dict[str, object]:
    """Return concise stakeholder-facing context and any trust failures."""
    by_type = {result.event_type: result for result in results}
    failures = [
        {
            "event_id": result.event_id,
            "signer_id": result.signer_id,
            "event_type": result.event_type,
            "reason": result.reason,
        }
        for result in results
        if not result.valid
    ]
    valid_results_by_type = {
        event_type: [
            result
            for result in results
            if result.valid and result.event_type == event_type
        ]
        for event_type in EVENT_TYPES
    }
    trust_valid = bool(results) and not failures
    complete = all(
        len(valid_results_by_type[event_type]) == 1 for event_type in EVENT_TYPES
    )
    decision = by_type.get("Decision")
    evidence = by_type.get("Evidence")
    policy = by_type.get("PolicyEvaluation")
    review = by_type.get("Review")
    action = by_type.get("Action")
    outcome = by_type.get("Outcome")
    return {
        "valid": trust_valid and complete,
        "trust_valid": trust_valid,
        "complete": complete,
        "recommendation": decision.event_id if decision else None,
        "evidence": evidence.event_id if evidence else None,
        "policy": policy.event_id if policy else None,
        "reviewer": review.signer_id if review else None,
        "action": action.event_id if action else None,
        "outcome": outcome.event_id if outcome else None,
        "failures": failures,
    }


def _decision_with_reason(
    results: list[TrustDecision], reason: str
) -> TrustDecision | None:
    return next((result for result in results if result.reason == reason), None)


def main() -> int:
    """Run a concise, synthetic stakeholder walkthrough."""
    chain, keystore = build_synthetic_chain()
    results = verify_chain(chain, keystore)
    summary = summarize_chain(results)

    print("Clinical governance synthetic chain")
    for result in results:
        print(
            f"  {result.event_type}: signer={result.signer_id} "
            f"state={result.reason}"
        )
    print(
        "Summary: "
        f"recommendation={summary['recommendation']} "
        f"evidence={summary['evidence']} policy={summary['policy']} "
        f"reviewer={summary['reviewer']} action={summary['action']} "
        f"outcome={summary['outcome']}"
    )

    unknown_signer = ACTORS["Decision"]
    keystore.remove_key(unknown_signer)
    unknown = _decision_with_reason(verify_chain(chain, keystore), "unknown_signer")
    print(
        "Trust failure: "
        f"unknown signer={unknown.signer_id if unknown else unknown_signer} "
        f"state={unknown.reason if unknown else 'not-observed'}"
    )

    revoked_chain, revoked_keystore = build_synthetic_chain()
    reviewer_id = ACTORS["Review"]
    revoked_keystore.revoke(reviewer_id, revoked_at_ms=1_700_000_000_007)
    revoked = _decision_with_reason(
        verify_chain(revoked_chain, revoked_keystore), "revoked_signer"
    )
    print(
        "Trust failure: "
        f"revoked reviewer={revoked.signer_id if revoked else reviewer_id} "
        f"state={revoked.reason if revoked else 'not-observed'}"
    )

    return 0 if summary["valid"] and unknown is not None and revoked is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
