"""
Tests for the supported post-quantum hybrid signing module
(spif.pq_hybrid) — SPEC §7.5 / §7.9, carried over from the Phase D
spike and adapted to the integrated v1.4 gate semantics.

Pinned contract:
- hybrid sign/verify round-trip over a real SPIF artifact;
- strict verification requires BOTH components (ed25519 AND ML-DSA-65);
- either component tampered -> invalid;
- an ed25519-only artifact presented to the hybrid verifier -> rejected;
- the reader's gate (§7.9.2): classical mode verifies a hybrid entry
  by its ed25519 component, require_pq mode requires both — so a
  tampered ML-DSA component passes classically and fails require_pq;
- the ML-DSA component is genuine FIPS 204: it verifies under the
  independent pure-Python reference implementation (dilithium_py).

The whole module skips when the `pqcrypto` backend is not installed.
"""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("pqcrypto", reason="PQ backend not installed")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spif import Node, Provenance, SPIFDocument, SPIFReader, SPIFWriter
from spif.crypto import derive_key_from_mnemonic, sign_document
from spif.pq_hybrid import (
    HYBRID_ALGORITHM,
    HYBRID_SIG_LEN,
    ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SECRET_KEY_LEN,
    ML_DSA_65_SIG_LEN,
    generate_ml_dsa_65_keypair,
    ml_dsa_65_verify,
    pq_available,
    sign_document_hybrid,
    verify_hybrid_report,
    verify_hybrid_signature,
)
from spif.reader import SPIFSignatureError, _find_first_auth_chunk_offset
from spif.types import Signature


@pytest.fixture(scope="module")
def ed_key() -> Ed25519PrivateKey:
    return derive_key_from_mnemonic("pq spike test key", passphrase="test-only")


@pytest.fixture(scope="module")
def ml_keys() -> tuple[bytes, bytes]:
    return generate_ml_dsa_65_keypair()  # (public, secret)


def _doc(text: str = "hybrid fact") -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=text)],
        provenance=Provenance(source_model="pq-test", timestamp_ms=1_700_000_000_000),
    )


@pytest.fixture(scope="module")
def hybrid_artifact(ed_key, ml_keys) -> bytes:
    ml_pk, ml_sk = ml_keys
    return sign_document_hybrid(_doc(), ed_key, ml_sk, ml_pk)


def _mutate_signature(data: bytes, mutate) -> bytes:
    """Decode, mutate the primary signature entry, re-encode.

    Re-encoding recomputes the file checksum, so the result is an
    internally consistent artifact whose *signature* is wrong — the
    attacker model the crypto layer (not the checksum) must catch.
    """
    doc = SPIFReader().decode(data)
    doc.signature = Signature(
        algorithm=doc.signature.algorithm,
        signer=doc.signature.signer,
        signature=mutate(doc.signature.signature),
        key_id=doc.signature.key_id,
    )
    return SPIFWriter().encode(doc)


def _flip(sig: bytes, offset: int) -> bytes:
    b = bytearray(sig)
    b[offset] ^= 0x01
    return bytes(b)


class TestBackend:
    def test_backend_available_and_sizes_match_fips_204(self, ml_keys):
        assert pq_available()
        ml_pk, ml_sk = ml_keys
        assert len(ml_pk) == ML_DSA_65_PUBLIC_KEY_LEN == 1952
        assert len(ml_sk) == ML_DSA_65_SECRET_KEY_LEN == 4032

    def test_sign_rejects_wrong_key_sizes(self, ed_key):
        with pytest.raises(ValueError):
            sign_document_hybrid(_doc(), ed_key, b"\x00" * 10, b"\x00" * 10)


class TestRoundTrip:
    def test_hybrid_round_trip(self, hybrid_artifact):
        doc = SPIFReader().decode(hybrid_artifact)
        assert doc.signature.algorithm == HYBRID_ALGORITHM
        assert len(doc.signature.signature) == HYBRID_SIG_LEN == 3373
        assert verify_hybrid_signature(hybrid_artifact) is True

    def test_report_shape_matches_conformance_fields(self, hybrid_artifact):
        report = verify_hybrid_report(hybrid_artifact)
        assert report.trust_status == "VALID"
        assert report.signature_status == "valid"
        assert report.timestamp_status == "absent"
        assert report.forged_revocations == 0
        assert report.references == []


class TestReaderGateModes:
    """The v1.3 reader hard-refused hybrid artifacts; v1.4 migrates
    that gate to the §7.9.2 modes instead (SPEC §7.9.2)."""

    def test_classical_reader_verifies_ed25519_component(self, hybrid_artifact):
        assert SPIFReader().verify_signature(hybrid_artifact) is True

    def test_require_pq_reader_verifies_both_components(self, hybrid_artifact):
        reader = SPIFReader(require_pq=True)
        assert reader.verify_signature(hybrid_artifact) is True
        # The per-call override reaches the same result from a
        # classical reader.
        assert SPIFReader().verify_signature(
            hybrid_artifact, require_pq=True
        ) is True

    def test_tampered_ml_component_passes_classically_fails_require_pq(
        self, hybrid_artifact
    ):
        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 64 + 1000))
        # Classical mode checks the ed25519 component only (§7.5
        # backward compatibility) — the tampered ML-DSA half is
        # exactly what require_pq exists to catch.
        assert SPIFReader().verify_signature(bad) is True
        with pytest.raises(SPIFSignatureError):
            SPIFReader(require_pq=True).verify_signature(bad)

    def test_tampered_ed_component_fails_both_modes(self, hybrid_artifact):
        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 10))
        with pytest.raises(SPIFSignatureError):
            SPIFReader().verify_signature(bad)
        with pytest.raises(SPIFSignatureError):
            SPIFReader(require_pq=True).verify_signature(bad)


class TestBothComponentsRequired:
    def test_tampered_ml_dsa_component_is_invalid(self, hybrid_artifact):
        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 64 + 1000))
        assert verify_hybrid_signature(bad) is False
        assert verify_hybrid_report(bad).trust_status == "INVALID"

    def test_tampered_ed25519_component_is_invalid(self, hybrid_artifact):
        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 10))
        assert verify_hybrid_signature(bad) is False

    def test_zeroed_ml_dsa_component_is_invalid(self, hybrid_artifact):
        bad = _mutate_signature(
            hybrid_artifact, lambda s: s[:64] + b"\x00" * ML_DSA_65_SIG_LEN
        )
        assert verify_hybrid_signature(bad) is False

    def test_wrong_ml_dsa_public_key_is_invalid(self, hybrid_artifact):
        other_pk, _ = generate_ml_dsa_65_keypair()
        doc = SPIFReader().decode(hybrid_artifact)
        raw = base64.b64decode(doc.signature.signer)
        doc.signature = Signature(
            algorithm=doc.signature.algorithm,
            signer=base64.b64encode(raw[:32] + other_pk).decode("ascii"),
            signature=doc.signature.signature,
        )
        bad = SPIFWriter().encode(doc)
        # ed25519 half still verifies; ML-DSA half must fail the artifact.
        assert verify_hybrid_signature(bad) is False


class TestEd25519OnlyPresentedAsHybrid:
    def test_plain_ed25519_artifact_is_rejected(self, ed_key):
        data = sign_document(_doc(), ed_key)
        assert SPIFReader().decode(data).signature.algorithm == "ed25519"
        assert verify_hybrid_signature(data) is False

    def test_hybrid_label_with_64_byte_signature_is_rejected(self, ed_key):
        data = sign_document(_doc(), ed_key)
        doc = SPIFReader().decode(data)
        doc.signature = Signature(
            algorithm=HYBRID_ALGORITHM,
            signer=doc.signature.signer,
            signature=doc.signature.signature,  # only 64 bytes
        )
        relabelled = SPIFWriter().encode(doc)
        assert verify_hybrid_signature(relabelled) is False

    def test_unsigned_artifact_is_rejected(self):
        data = SPIFWriter().encode(_doc())
        assert verify_hybrid_signature(data) is False


class TestCrossImplementation:
    def test_ml_component_verifies_under_reference_implementation(
        self, hybrid_artifact
    ):
        """The ML-DSA half of a pqcrypto-produced hybrid signature must
        verify under dilithium_py, an independent pure-Python FIPS 204
        implementation — evidence the bytes are the standard format,
        not a library-private dialect."""
        ref = pytest.importorskip("dilithium_py.ml_dsa")
        doc = SPIFReader().decode(hybrid_artifact)
        body = hybrid_artifact[: _find_first_auth_chunk_offset(hybrid_artifact)]
        raw = base64.b64decode(doc.signature.signer)
        ml_pk = raw[32:]
        ml_sig = doc.signature.signature[64:]
        assert len(ml_sig) == ML_DSA_65_SIG_LEN == 3309
        assert ref.ML_DSA_65.verify(ml_pk, body, ml_sig) is True
        assert ref.ML_DSA_65.verify(ml_pk, body + b"x", ml_sig) is False
        # And the wrapper agrees with the reference on the same inputs.
        assert ml_dsa_65_verify(ml_pk, body, ml_sig) is True
