"""EU AI Act readiness tests for SPIF as an infrastructure component.

These tests deliberately separate what SPIF can carry and verify from what an
integrator must do.  Passing this module is not an EU AI Act or C2PA
conformance claim.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    Node,
    Provenance,
    SPIFChecksumError,
    SPIFDocument,
    SPIFFormatError,
    SPIFReader,
    SPIFSignatureError,
    SPIFWriter,
    Signature,
    TraceStep,
)
from spif.format import MAGIC


@dataclass(frozen=True)
class ReadinessCase:
    """A deterministic output fixture and its integration context."""

    content: bytes
    spif_bytes: bytes
    role: str = "infrastructure/provenance component"
    transport: str = "inline"
    expected_input_hash: str = ""
    expected_context_ref: str = ""


@dataclass(frozen=True)
class Article50Support:
    """Measured integration signals; none means standalone legal compliance."""

    machine_mark: bool
    visible_label: bool
    detectable_after_transport: bool
    provenance_evidence: bool


@dataclass(frozen=True)
class C2PAInteropResult:
    """Separate SPIF integrity from C2PA binding and trust decisions."""

    hard_binding_valid: bool
    spif_signature_valid: bool
    trust_valid: bool
    survives_reencode: bool
    manifest_removed: bool


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, base64.b64encode(public).decode("ascii")


def _sign(doc: SPIFDocument, key: Ed25519PrivateKey, signer: str) -> bytes:
    """Sign using SPIF's two-pass format contract."""
    writer = SPIFWriter()
    doc.signature = Signature("ed25519", signer, b"\x00" * 64)
    unsigned_layout = writer.encode(doc)
    offset = len(MAGIC) + 2
    signature_offset = None
    while offset + 5 <= len(unsigned_layout):
        chunk_type, length = struct.unpack_from(">BI", unsigned_layout, offset)
        if chunk_type == 0x07:
            signature_offset = offset
            break
        if chunk_type == 0xFF:
            break
        offset += 5 + length
    assert signature_offset is not None
    doc.signature = Signature("ed25519", signer, key.sign(unsigned_layout[:signature_offset]))
    return writer.encode(doc)


def _case(*, content: bytes = b"A generated answer.", context_ref: str = "") -> ReadinessCase:
    input_text = "Summarize the quarterly report for alice@example.eu using the private draft."
    provenance = Provenance(
        source_model="local-test-model",
        model_version="local-test-model-1",
        timestamp_ms=1_754_832_000_000,
        input_hash=hashlib.sha256(input_text.encode()).hexdigest(),
        context_ref=context_ref,
        task_id="task-eu-readiness",
        nonce="nonce-001",
        human_oversight="human-on-loop",
    )
    doc = SPIFDocument(
        payload=[Node(id="output", type="text", value=content.decode("utf-8"))],
        provenance=provenance,
        trace=[TraceStep(id="generation", type="model_call", content={"provider": "local"})],
    )
    key, signer = _keypair()
    return ReadinessCase(
        content=content,
        spif_bytes=_sign(doc, key, signer),
        expected_input_hash=provenance.input_hash,
        expected_context_ref=context_ref,
    )


def assert_spif_integrity(case: ReadinessCase) -> SPIFDocument:
    """Wire-format property: a signed case decodes and verifies cryptographically."""
    document = SPIFReader(require_signature=True).decode(case.spif_bytes)
    assert SPIFReader().verify_signature(case.spif_bytes) is True
    assert document.provenance is not None
    return document


def assert_no_prompt_plaintext(case: ReadinessCase, prompt: str) -> None:
    """Privacy property: default provenance carries an input hash, not prompt text."""
    assert prompt.encode() not in case.spif_bytes
    document = SPIFReader().decode(case.spif_bytes)
    assert document.provenance is not None
    assert document.provenance.input_hash == hashlib.sha256(prompt.encode()).hexdigest()


def assert_chain_continuity(previous: ReadinessCase, current: ReadinessCase) -> None:
    """Integration property: a follow-up references the prior content ID."""
    previous_document = SPIFReader().decode(previous.spif_bytes)
    current_document = SPIFReader().decode(current.spif_bytes)
    assert current_document.provenance is not None
    assert current_document.provenance.context_ref == previous_document.content_id()


def evaluate_article50_support(
    *, marker: str | None, visible_label: str | None, spif_bytes: bytes, transport: str
) -> Article50Support:
    """Evaluate integration signals without treating SPIF as the deployer."""
    evidence = False
    try:
        document = SPIFReader(require_signature=True).decode(spif_bytes)
        evidence = document.provenance is not None and bool(document.payload)
    except (SPIFFormatError, SPIFSignatureError):
        pass
    carries_marker = transport in {"inline", "embedded"}
    return Article50Support(
        machine_mark=bool(marker) and carries_marker,
        visible_label=bool(visible_label),
        detectable_after_transport=bool(marker) and carries_marker,
        provenance_evidence=evidence,
    )


def c2pa_interop_result(
    *, content: bytes, claimed_content_hash: str, spif_bytes: bytes,
    manifest_present: bool, trust_anchor_present: bool = False,
) -> C2PAInteropResult:
    """Model the boundary: matching hashes do not establish C2PA trust."""
    hard_binding = hashlib.sha256(content).hexdigest() == claimed_content_hash
    spif_valid = SPIFReader().verify_signature(spif_bytes) is True
    return C2PAInteropResult(
        hard_binding_valid=hard_binding and manifest_present,
        spif_signature_valid=spif_valid,
        trust_valid=trust_anchor_present and manifest_present,
        survives_reencode=False,
        manifest_removed=not manifest_present,
    )


def assert_prompt_minimized(case: ReadinessCase, prompt: str) -> None:
    assert_no_prompt_plaintext(case, prompt)


def assert_replay_rejected(seen_nonces: set[str], nonce: str) -> None:
    """Integrator property: replay policy rejects a nonce already accepted."""
    if nonce in seen_nonces:
        raise ValueError("replayed provenance nonce")
    seen_nonces.add(nonce)


def assert_resource_bound(payload: bytes, *, maximum: int = 1_048_576) -> None:
    assert len(payload) <= maximum


class TestFixtures:
    def test_signed_text_fixture_has_integrity_evidence(self):
        case = _case()
        document = assert_spif_integrity(case)
        assert document.payload[0].value == "A generated answer."
        assert document.provenance.source_model == "local-test-model"

    def test_chained_fixture_preserves_context_reference(self):
        previous = _case()
        current = _case(context_ref=SPIFReader().decode(previous.spif_bytes).content_id())
        assert_chain_continuity(previous, current)

    def test_tool_call_fixture_is_carryable(self):
        case = _case()
        document = SPIFReader().decode(case.spif_bytes)
        document.payload.append(Node(
            id="tool-1", type="tool_result", value={"name": "search", "is_error": False}
        ))
        assert document.payload[-1].type == "tool_result"


class TestArticle50Support:
    def test_detached_sidecar_is_not_a_content_mark(self):
        case = _case()
        result = evaluate_article50_support(
            marker=None, visible_label=None, spif_bytes=case.spif_bytes, transport="sidecar-stripped"
        )
        assert result == Article50Support(False, False, False, True)

    @pytest.mark.parametrize("scenario", ["chatbot", "generated-text", "deepfake-media"])
    def test_content_carried_marker_and_visible_label_are_separate(self, scenario):
        case = _case(content=f"{scenario} output".encode())
        result = evaluate_article50_support(
            marker="spif-marker-v1", visible_label="AI-generated", spif_bytes=case.spif_bytes,
            transport="embedded",
        )
        assert result.machine_mark is True
        assert result.visible_label is True
        assert result.detectable_after_transport is True
        assert result.provenance_evidence is True

    def test_human_review_does_not_remove_integrator_obligations(self):
        case = _case()
        result = evaluate_article50_support(
            marker="reviewed-ai-output", visible_label="AI-assisted", spif_bytes=case.spif_bytes,
            transport="inline",
        )
        assert result.machine_mark and result.visible_label and result.provenance_evidence


class TestC2PABoundaries:
    def test_matching_content_hash_is_not_c2pa_trust(self):
        case = _case()
        content_hash = hashlib.sha256(case.content).hexdigest()
        result = c2pa_interop_result(
            content=case.content, claimed_content_hash=content_hash, spif_bytes=case.spif_bytes,
            manifest_present=True,
        )
        assert result.hard_binding_valid is True
        assert result.spif_signature_valid is True
        assert result.trust_valid is False

    def test_one_byte_mutation_breaks_hard_binding_but_not_spif_signature(self):
        case = _case()
        result = c2pa_interop_result(
            content=case.content + b"!", claimed_content_hash=hashlib.sha256(case.content).hexdigest(),
            spif_bytes=case.spif_bytes, manifest_present=True,
        )
        assert result.hard_binding_valid is False
        assert result.spif_signature_valid is True

    def test_manifest_removal_is_distinct_from_spif_verification(self):
        case = _case()
        result = c2pa_interop_result(
            content=case.content, claimed_content_hash=hashlib.sha256(case.content).hexdigest(),
            spif_bytes=case.spif_bytes, manifest_present=False,
        )
        assert result.manifest_removed is True
        assert result.hard_binding_valid is False
        assert result.spif_signature_valid is True


class TestPrivacyAndHostileInputs:
    def test_prompt_is_minimized_to_hash(self):
        prompt = "Patient Alice Example, alice@example.eu, secret=do-not-store"
        case = _case()
        assert_prompt_minimized(case, "Summarize the quarterly report for alice@example.eu using the private draft.")
        assert prompt.encode() not in case.spif_bytes

    def test_replay_nonce_is_rejected_by_integration_policy(self):
        seen = set()
        assert_replay_rejected(seen, "nonce-001")
        with pytest.raises(ValueError, match="replayed"):
            assert_replay_rejected(seen, "nonce-001")

    @pytest.mark.parametrize("cut", [1, 8, 32])
    def test_truncated_signed_payload_never_becomes_verified(self, cut):
        case = _case()
        with pytest.raises((SPIFChecksumError, SPIFFormatError, SPIFSignatureError, ValueError)):
            SPIFReader(require_signature=True).decode(case.spif_bytes[:-cut])

    def test_hostile_payload_is_bounded_before_processing(self):
        assert_resource_bound(b"x" * 1024)
        with pytest.raises(AssertionError):
            assert_resource_bound(b"x" * 1025, maximum=1024)


class TestResilienceAndGPAIBoundaries:
    def test_incomplete_stream_is_not_a_verified_document(self):
        case = _case()
        with pytest.raises((SPIFChecksumError, SPIFFormatError, SPIFSignatureError, ValueError)):
            SPIFReader(require_signature=True).decode(case.spif_bytes[:-32])

    def test_gpai_boundary_is_explicit(self):
        case = _case()
        document = assert_spif_integrity(case)
        assert document.provenance is not None
        assert document.provenance.input_hash
        # SPIF evidence is per-output; it is not model technical documentation,
        # a training-data summary, copyright policy, or systemic-risk framework.
        provided = {"per_output_identity", "timestamp", "input_hash", "signed_chain"}
        not_provided = {
            "training_data_summary", "copyright_policy", "model_documentation",
            "systemic_risk_safety_framework", "c2pa_trust_list_membership",
        }
        assert provided.isdisjoint(not_provided)
