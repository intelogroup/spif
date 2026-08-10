"""Reference deployer envelope for Article 50 integrations.

These tests specify transport behavior, not legal compliance.  The profile
requires the deployer to provide the visible label and machine-readable mark;
SPIF supplies signed provenance evidence and an optional opaque C2PA handoff.
"""

from __future__ import annotations

import base64
import json

import pytest

from spif.eu_ai_act import DeployerOutput, build_deployer_output


def test_profile_requires_both_disclosure_surfaces_and_inline_spif():
    result = build_deployer_output(
        content="Generated answer",
        visible_label="AI-generated",
        machine_readable_mark="deployer-mark-v1",
        spif_bytes=b"signed-spif",
    )

    assert result == DeployerOutput(
        content="Generated answer",
        visible_label="AI-generated",
        machine_readable_mark="deployer-mark-v1",
        spif_bytes=b"signed-spif",
        c2pa_manifest=None,
    )


@pytest.mark.parametrize("field", ["visible_label", "machine_readable_mark"])
def test_profile_rejects_missing_disclosure_surface(field):
    values = {
        "content": "Generated answer",
        "visible_label": "AI-generated",
        "machine_readable_mark": "deployer-mark-v1",
        "spif_bytes": b"signed-spif",
    }
    values[field] = ""

    with pytest.raises(ValueError, match=field):
        build_deployer_output(**values)


def test_profile_rejects_empty_provenance():
    with pytest.raises(ValueError, match="spif_bytes"):
        build_deployer_output(
            content="Generated answer",
            visible_label="AI-generated",
            machine_readable_mark="deployer-mark-v1",
            spif_bytes=b"",
        )


def test_json_transport_preserves_disclosure_and_inline_provenance():
    result = build_deployer_output(
        content="Generated answer",
        visible_label="AI-generated",
        machine_readable_mark="deployer-mark-v1",
        spif_bytes=b"signed-spif",
    )

    transported = json.loads(json.dumps(result.to_transport()))
    restored = DeployerOutput.from_transport(transported)

    assert restored == result


def test_optional_c2pa_manifest_is_opaque_and_round_trips():
    result = build_deployer_output(
        content="Generated image description",
        visible_label="AI-generated",
        machine_readable_mark="deployer-mark-v1",
        spif_bytes=b"signed-spif",
        c2pa_manifest=b"manifest-generated-by-c2pa-tool",
    )

    transport = result.to_transport()
    assert transport["c2pa_manifest_b64"] == base64.b64encode(
        b"manifest-generated-by-c2pa-tool"
    ).decode("ascii")
    assert DeployerOutput.from_transport(transport) == result


def test_profile_does_not_claim_compliance():
    result = build_deployer_output(
        content="Generated answer",
        visible_label="AI-generated",
        machine_readable_mark="deployer-mark-v1",
        spif_bytes=b"signed-spif",
    )

    assert "compliant" not in result.to_transport()
    assert "c2pa_conformant" not in result.to_transport()
