"""End-to-end checks for the synthetic clinical-governance walkthrough."""

from __future__ import annotations

from spif import SPIFReader
from spif.governance import event_from_document, verify_chain


def _events(chain: list[bytes]):
    return [event_from_document(SPIFReader().decode(data)) for data in chain]


def test_synthetic_chain_contains_ordered_signed_artifacts_and_verifies():
    """Fails if the walkthrough no longer models six trusted governance steps."""
    from examples.clinical_governance_chain import build_synthetic_chain

    chain, keystore = build_synthetic_chain()
    events = _events(chain)
    results = verify_chain(chain, keystore)

    assert [event.event_type for event in events] == [
        "Decision",
        "Evidence",
        "PolicyEvaluation",
        "Review",
        "Action",
        "Outcome",
    ]
    assert len({event.actor for event in events}) == 6
    review = next(event for event in events if event.event_type == "Review")
    assert review.payload["approval_path"] == "clinical-review"
    assert review.payload["override_capable"] is True
    assert [(result.valid, result.reason) for result in results] == [
        (True, "verified"),
    ] * 6


def test_summary_reconstructs_cross_system_case_hand_offs():
    """Fails if the demo hides system boundaries or loses walkthrough context."""
    from examples.clinical_governance_chain import (
        build_synthetic_chain,
        summarize_chain,
    )

    chain, keystore = build_synthetic_chain()
    events = _events(chain)
    summary = summarize_chain(verify_chain(chain, keystore))

    assert {event.payload["system"] for event in events} == {
        "qventus-sim",
        "hospital-ehr-sim",
        "policy-engine-sim",
        "bed-management-sim",
    }
    assert summary == {
        "valid": True,
        "recommendation": "recommend-bed-placement",
        "evidence": "ehr-bed-and-acuity-evidence",
        "policy": "bed-placement-policy-evaluation",
        "reviewer": "hospital-ehr-sim:clinical-reviewer",
        "action": "assign-inpatient-bed",
        "outcome": "bed-placement-outcome",
        "failures": [],
    }


def test_summary_reports_unknown_signer_after_its_trust_root_is_removed():
    """Fails if removing a signer can be mistaken for a valid cross-system handoff."""
    from examples.clinical_governance_chain import (
        build_synthetic_chain,
        summarize_chain,
    )

    chain, keystore = build_synthetic_chain()
    assert keystore.remove_key("qventus-sim:recommendation-service") is True

    summary = summarize_chain(verify_chain(chain, keystore))

    assert summary["valid"] is False
    assert {
        "event_id": "recommend-bed-placement",
        "signer_id": "qventus-sim:recommendation-service",
        "event_type": "Decision",
        "reason": "unknown_signer",
    } in summary["failures"]


def test_summary_reports_revoked_reviewer_after_chain_creation():
    """Fails if a revoked reviewer remains trusted after signing the review."""
    from examples.clinical_governance_chain import (
        build_synthetic_chain,
        summarize_chain,
    )

    chain, keystore = build_synthetic_chain()
    reviewer_id = "hospital-ehr-sim:clinical-reviewer"
    keystore.revoke(reviewer_id, revoked_at_ms=1_700_000_000_007)

    summary = summarize_chain(verify_chain(chain, keystore))

    assert summary["valid"] is False
    assert {
        "event_id": "clinical-bed-placement-review",
        "signer_id": reviewer_id,
        "event_type": "Review",
        "reason": "revoked_signer",
    } in summary["failures"]


def test_cli_walkthrough_shows_chain_and_explicit_trust_failures(capsys):
    """Fails if stakeholders cannot see the successful chain and both trust boundaries."""
    from examples.clinical_governance_chain import main

    assert main() == 0

    output = capsys.readouterr().out
    for event_type in (
        "Decision",
        "Evidence",
        "PolicyEvaluation",
        "Review",
        "Action",
        "Outcome",
    ):
        assert event_type in output
    assert "qventus-sim:recommendation-service" in output
    assert "hospital-ehr-sim:clinical-reviewer" in output
    assert "unknown_signer" in output
    assert "revoked_signer" in output
