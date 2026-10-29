"""
Integration tests for SPIF v1.4 post-quantum hybrid signing (SPEC §7.9).

Where test_pq_hybrid.py pins the pq_hybrid module itself, this file
pins the *integrated* behaviour across the surfaces a user touches:

- the gate-mode matrix through spif.trust.verify_artifact for
  classical / hybrid / PQ-only artifacts in both modes;
- `spif verify` through the CLI (plain, --trust, --trust --require-pq);
- SPIFKeyStore hybrid entries: generation, storage, strict verify,
  whole-identity revocation, and hybrid rotation records;
- revocation of a hybrid-sealed artifact (§7.9.4), out-of-band and
  embedded, plus the forgery shapes;
- the independent-implementation cross-check on the integrated path:
  an artifact whose ML-DSA component was produced by dilithium_py
  verifies through verify_artifact(require_pq=True);
- behaviour with the backend absent (subprocess): spif imports and
  verifies classically, PQ entries report UNVERIFIABLE, and signing
  raises PQBackendUnavailable instead of degrading.

The whole module skips when the `pqcrypto` backend is not installed
(except the backend-absent subprocess test, which constructs its own
absence and runs either way).
"""

from __future__ import annotations

import base64
import importlib.util
import struct
import subprocess
import sys
import textwrap

import pytest

from spif import Node, Provenance, SPIFDocument, SPIFReader, SPIFWriter
from spif.format import CHUNK_SIGNATURE, MAGIC
from spif.types import Signature

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("pqcrypto") is None,
    reason="PQ backend not installed",
)


# ---------------------------------------------------------------------------
# Fixtures and builders
# ---------------------------------------------------------------------------

def _doc(text: str = "v1.4 integration fact") -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=text)],
        provenance=Provenance(source_model="v14-test", timestamp_ms=1_700_000_000_000),
    )


@pytest.fixture(scope="module")
def hybrid_pair():
    from spif.pq_hybrid import generate_hybrid_keypair

    return generate_hybrid_keypair()


@pytest.fixture(scope="module")
def hybrid_artifact(hybrid_pair) -> bytes:
    from spif.pq_hybrid import sign_document_hybrid

    return sign_document_hybrid(
        _doc(),
        hybrid_pair.ed_private_key,
        hybrid_pair.ml_secret_key,
        hybrid_pair.ml_public_key,
    )


@pytest.fixture(scope="module")
def classical_artifact():
    from spif.crypto import generate_key, sign_document

    return sign_document(_doc(), generate_key())


def _signing_body_offset(data: bytes) -> int:
    offset = len(MAGIC) + 2
    while offset < len(data):
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        if chunk_type == CHUNK_SIGNATURE:
            return offset
        offset += 5 + length
    raise AssertionError("no SIGNATURE chunk")


def make_pq_only_artifact(ml_public: bytes, ml_secret: bytes, text="pq only") -> bytes:
    """Build an ml-dsa-65-signed artifact (test-local construction —
    the library deliberately ships no PQ-only writer, SPEC §7.9.5;
    readers must still handle such artifacts)."""
    from spif.pq_hybrid import ML_DSA_65_SIG_LEN, ml_dsa_65_sign

    doc = _doc(text)
    signer = base64.b64encode(ml_public).decode("ascii")
    writer = SPIFWriter()
    doc.signature = Signature(
        algorithm="ml-dsa-65", signer=signer, signature=b"\x00" * ML_DSA_65_SIG_LEN
    )
    dummy = writer.encode(doc)
    body = dummy[: _signing_body_offset(dummy)]
    doc.signature = Signature(
        algorithm="ml-dsa-65", signer=signer, signature=ml_dsa_65_sign(ml_secret, body)
    )
    return writer.encode(doc)


@pytest.fixture(scope="module")
def pq_only_artifact(hybrid_pair) -> bytes:
    return make_pq_only_artifact(
        hybrid_pair.ml_public_key, hybrid_pair.ml_secret_key
    )


def _mutate_signature(data: bytes, mutate) -> bytes:
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


# ---------------------------------------------------------------------------
# Gate-mode matrix through the trust layer (SPEC §7.9.2)
# ---------------------------------------------------------------------------

class TestGateMatrix:
    def test_classical_artifact_both_modes(self, classical_artifact):
        from spif.trust import verify_artifact

        assert verify_artifact(classical_artifact).trust_status == "VALID"
        assert verify_artifact(
            classical_artifact, require_pq=True
        ).trust_status == "VALID"

    def test_hybrid_artifact_both_modes(self, hybrid_artifact):
        from spif.trust import verify_artifact

        assert verify_artifact(hybrid_artifact).trust_status == "VALID"
        r = verify_artifact(hybrid_artifact, require_pq=True)
        assert r.trust_status == "VALID"
        assert r.signature_status == "valid"

    def test_hybrid_tampered_ml_component(self, hybrid_artifact):
        from spif.trust import verify_artifact

        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 64 + 500))
        # Classical: ed25519 component carries it (the §7.5 rule).
        assert verify_artifact(bad).trust_status == "VALID"
        # require_pq: the PQ failure is decisive.
        assert verify_artifact(bad, require_pq=True).trust_status == "INVALID"

    def test_hybrid_tampered_ed_component(self, hybrid_artifact):
        from spif.trust import verify_artifact

        bad = _mutate_signature(hybrid_artifact, lambda s: _flip(s, 3))
        assert verify_artifact(bad).trust_status == "INVALID"
        assert verify_artifact(bad, require_pq=True).trust_status == "INVALID"

    def test_hybrid_relabelled_ed_only_is_invalid_both_modes(self):
        from spif.crypto import generate_key, sign_document
        from spif.trust import verify_artifact

        data = sign_document(_doc(), generate_key())
        doc = SPIFReader().decode(data)
        doc.signature = Signature(
            algorithm="ed25519+ml-dsa-65",
            signer=doc.signature.signer,
            signature=doc.signature.signature,
        )
        relabelled = SPIFWriter().encode(doc)
        assert verify_artifact(relabelled).trust_status == "INVALID"
        assert verify_artifact(relabelled, require_pq=True).trust_status == "INVALID"

    def test_pq_only_artifact_status(self, pq_only_artifact):
        """Invisible, not invalid: classical reports UNVERIFIABLE and
        never INVALID/VALID; require_pq verifies the ML-DSA signature."""
        from spif.trust import verify_artifact

        r = verify_artifact(pq_only_artifact)
        assert r.trust_status == "UNVERIFIABLE"
        assert r.signature_status == "unverifiable"
        r = verify_artifact(pq_only_artifact, require_pq=True)
        assert r.trust_status == "VALID"
        assert r.signature_status == "valid"

    def test_pq_only_tampered(self, pq_only_artifact):
        from spif.trust import verify_artifact

        bad = _mutate_signature(pq_only_artifact, lambda s: _flip(s, 100))
        # Classical still refuses to judge it at all.
        assert verify_artifact(bad).trust_status == "UNVERIFIABLE"
        # require_pq judges — and the judgement is INVALID.
        assert verify_artifact(bad, require_pq=True).trust_status == "INVALID"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestCLI:
    def _run(self, *args):
        from typer.testing import CliRunner

        from spif.cli import app

        return CliRunner().invoke(app, [str(a) for a in args])

    def _write(self, tmp_path, name, data):
        p = tmp_path / name
        p.write_bytes(data)
        return p

    def test_plain_verify_hybrid(self, tmp_path, hybrid_artifact):
        p = self._write(tmp_path, "h.spif", hybrid_artifact)
        result = self._run("verify", p)
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_plain_verify_pq_only_is_unverifiable(self, tmp_path, pq_only_artifact):
        p = self._write(tmp_path, "pq.spif", pq_only_artifact)
        result = self._run("verify", p)
        assert result.exit_code == 1
        assert "UNVERIFIABLE" in result.output

    def test_trust_verify_hybrid(self, tmp_path, hybrid_artifact):
        p = self._write(tmp_path, "h.spif", hybrid_artifact)
        result = self._run("verify", "--trust", p)
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_trust_classical_vs_require_pq_on_tampered_ml(
        self, tmp_path, hybrid_artifact
    ):
        p = self._write(
            tmp_path, "bad.spif",
            _mutate_signature(hybrid_artifact, lambda s: _flip(s, 64 + 500)),
        )
        classical = self._run("verify", "--trust", p)
        assert classical.exit_code == 0
        assert "VALID" in classical.output
        strict = self._run("verify", "--trust", "--require-pq", p)
        assert strict.exit_code == 1
        assert "INVALID" in strict.output

    def test_trust_pq_only_both_modes(self, tmp_path, pq_only_artifact):
        p = self._write(tmp_path, "pq.spif", pq_only_artifact)
        classical = self._run("verify", "--trust", p)
        assert classical.exit_code == 1
        assert "UNVERIFIABLE" in classical.output
        strict = self._run("verify", "--trust", "--require-pq", p)
        assert strict.exit_code == 0
        assert "VALID" in strict.output


# ---------------------------------------------------------------------------
# Keystore hybrid entries (SPEC §7.9.3)
# ---------------------------------------------------------------------------

class TestKeystoreHybrid:
    def test_generate_store_verify_round_trip(self, tmp_path):
        from spif.keystore import SPIFKeyStore
        from spif.pq_hybrid import sign_document_hybrid

        ks = SPIFKeyStore(tmp_path / "ks")
        material = ks.generate_hybrid_key("alice")
        assert ks.has_hybrid_key("alice")
        assert "alice" in ks.list_keys()
        got = ks.get_hybrid_key("alice")
        assert got is not None
        ed_pk, ml_pk = got
        assert ml_pk == material.ml_public_key

        data = sign_document_hybrid(
            _doc(),
            material.ed_private_key,
            material.ml_secret_key,
            material.ml_public_key,
            signer_id="alice",
        )
        assert ks.verify(data) is True

    def test_named_signer_tamper_raises(self, tmp_path):
        from spif.keystore import SPIFKeyStore
        from spif.pq_hybrid import sign_document_hybrid
        from spif.reader import SPIFSignatureError

        ks = SPIFKeyStore(tmp_path / "ks")
        material = ks.generate_hybrid_key("alice")
        data = sign_document_hybrid(
            _doc(), material.ed_private_key, material.ml_secret_key,
            material.ml_public_key, signer_id="alice",
        )
        bad = _mutate_signature(data, lambda s: _flip(s, 64 + 42))
        with pytest.raises(SPIFSignatureError):
            ks.verify(bad)

    def test_self_describing_signer_verifies_without_registration(
        self, tmp_path, hybrid_artifact
    ):
        from spif.keystore import SPIFKeyStore

        ks = SPIFKeyStore(tmp_path / "ks")
        assert ks.verify(hybrid_artifact) is True

    def test_revocation_revokes_whole_identity(self, tmp_path):
        from spif.keystore import SPIFKeyStore, SPIFRevokedSignerError
        from spif.pq_hybrid import sign_document_hybrid

        ks = SPIFKeyStore(tmp_path / "ks")
        material = ks.generate_hybrid_key("alice")
        data = sign_document_hybrid(
            _doc(), material.ed_private_key, material.ml_secret_key,
            material.ml_public_key, signer_id="alice",
        )
        assert ks.verify(data) is True
        ks.revoke("alice")
        with pytest.raises(SPIFRevokedSignerError):
            ks.verify(data)

    def test_add_hybrid_key_validates_sizes(self, tmp_path):
        from spif.keystore import SPIFKeyStore

        ks = SPIFKeyStore(tmp_path / "ks")
        with pytest.raises(ValueError):
            ks.add_hybrid_key("bad", b"\x00" * 32, b"\x00" * 100)
        with pytest.raises(ValueError):
            ks.add_hybrid_key("bad", b"\x00" * 10, b"\x00" * 1952)

    def test_hybrid_rotation_record(self):
        """§7.9.3: rotation proofs must come from BOTH components of
        the old AND the new keypair."""
        from spif.pq_hybrid import (
            generate_hybrid_keypair,
            rotate_hybrid_key,
            verify_hybrid_rotation,
        )

        old = generate_hybrid_keypair()
        new = generate_hybrid_keypair()
        record = rotate_hybrid_key(old, new, old.signer_id, new.signer_id)
        assert verify_hybrid_rotation(
            record,
            old.ed_public_bytes, old.ml_public_key,
            new.ed_public_bytes, new.ml_public_key,
        ) is True
        # Wrong successor keys -> not a valid rotation.
        other = generate_hybrid_keypair()
        assert verify_hybrid_rotation(
            record,
            old.ed_public_bytes, old.ml_public_key,
            other.ed_public_bytes, other.ml_public_key,
        ) is False
        # An ed25519-only record (no hybrid label/proofs) is not a
        # hybrid rotation.
        stripped = dict(record)
        stripped.pop("algorithm")
        assert verify_hybrid_rotation(
            stripped,
            old.ed_public_bytes, old.ml_public_key,
            new.ed_public_bytes, new.ml_public_key,
        ) is False


# ---------------------------------------------------------------------------
# Revocation of hybrid-sealed artifacts (SPEC §7.9.4)
# ---------------------------------------------------------------------------

class TestHybridRevocation:
    def test_hybrid_revocation_applies(self, hybrid_pair, hybrid_artifact):
        from spif.trust import create_revocation_hybrid, verify_artifact

        stmt = create_revocation_hybrid(
            hybrid_artifact,
            hybrid_pair.ed_private_key,
            hybrid_pair.ml_secret_key,
            hybrid_pair.ml_public_key,
            reason="compromised",
        )
        r = verify_artifact(hybrid_artifact, revocations=[stmt])
        assert r.trust_status == "REVOKED"
        assert len(r.revocations_applied) == 1
        assert r.forged_revocations == 0

    def test_hybrid_revocation_embedded(self, hybrid_pair, hybrid_artifact):
        from spif.trust import (
            attach_revocations,
            create_revocation_hybrid,
            verify_artifact,
        )

        stmt = create_revocation_hybrid(
            hybrid_artifact,
            hybrid_pair.ed_private_key,
            hybrid_pair.ml_secret_key,
            hybrid_pair.ml_public_key,
        )
        r = verify_artifact(attach_revocations(hybrid_artifact, [stmt]))
        assert r.trust_status == "REVOKED"

    def test_hybrid_revocation_list_file_round_trip(
        self, tmp_path, hybrid_pair, hybrid_artifact
    ):
        from spif.trust import (
            create_revocation_hybrid,
            load_revocation_statements,
            save_revocation_list,
            verify_artifact,
        )

        stmt = create_revocation_hybrid(
            hybrid_artifact,
            hybrid_pair.ed_private_key,
            hybrid_pair.ml_secret_key,
            hybrid_pair.ml_public_key,
        )
        path = tmp_path / "revocations.json"
        save_revocation_list([stmt], path)
        loaded = load_revocation_statements(path)
        assert len(loaded) == 1
        r = verify_artifact(hybrid_artifact, revocation_file=path)
        assert r.trust_status == "REVOKED"

    def test_forged_hybrid_statement_wrong_ml_key(
        self, hybrid_pair, hybrid_artifact
    ):
        """Statement signed with the right ed25519 key but a DIFFERENT
        ML-DSA key: the hybrid check must reject it as a forgery."""
        from spif.pq_hybrid import generate_ml_dsa_65_keypair
        from spif.trust import create_revocation_hybrid, verify_artifact

        other_pk, other_sk = generate_ml_dsa_65_keypair()
        stmt = create_revocation_hybrid(
            hybrid_artifact,
            hybrid_pair.ed_private_key,
            other_sk,
            hybrid_pair.ml_public_key,  # signer id stays the artifact's
        )
        r = verify_artifact(hybrid_artifact, revocations=[stmt])
        assert r.trust_status == "VALID"
        assert r.forged_revocations == 1
        assert other_pk != hybrid_pair.ml_public_key

    def test_ed_only_statement_from_hybrid_signer_is_forgery(
        self, hybrid_pair, hybrid_artifact
    ):
        """§7.9.4: a hybrid signer must revoke hybridly. An ed25519-only
        statement — even from the signer's own ed25519 key — is forged."""
        from spif.trust import create_revocation, verify_artifact

        stmt = create_revocation(
            hybrid_artifact,
            hybrid_pair.ed_private_key,
            signer_id=hybrid_pair.signer_id,
        )
        r = verify_artifact(hybrid_artifact, revocations=[stmt])
        assert r.trust_status == "VALID"
        assert r.forged_revocations == 1
        assert r.revocations_applied == []


# ---------------------------------------------------------------------------
# Cross-implementation check on the integrated path
# ---------------------------------------------------------------------------

class TestCrossImplementationIntegrated:
    def test_dilithium_produced_ml_component_verifies(self, hybrid_pair):
        """Build a hybrid artifact whose ML-DSA component is produced
        by dilithium_py (independent FIPS 204 implementation); the
        integrated require_pq path (pqcrypto backend) must verify it —
        the bytes are the standard, not a library dialect."""
        ref = pytest.importorskip("dilithium_py.ml_dsa")
        from spif.pq_hybrid import HYBRID_ALGORITHM, ML_DSA_65_SIG_LEN
        from spif.trust import verify_artifact

        ml_pk, ml_sk = ref.ML_DSA_65.keygen()
        doc = _doc("dilithium-produced component")
        signer = base64.b64encode(
            hybrid_pair.ed_public_bytes + ml_pk
        ).decode("ascii")
        writer = SPIFWriter()
        doc.signature = Signature(
            algorithm=HYBRID_ALGORITHM, signer=signer,
            signature=b"\x00" * (64 + ML_DSA_65_SIG_LEN),
        )
        dummy = writer.encode(doc)
        body = dummy[: _signing_body_offset(dummy)]
        ed_sig = hybrid_pair.ed_private_key.sign(body)
        ml_sig = ref.ML_DSA_65.sign(ml_sk, body)
        doc.signature = Signature(
            algorithm=HYBRID_ALGORITHM, signer=signer,
            signature=ed_sig + ml_sig,
        )
        data = writer.encode(doc)
        r = verify_artifact(data, require_pq=True)
        assert r.trust_status == "VALID"


# ---------------------------------------------------------------------------
# Backend absent — subprocess with pqcrypto import blocked
# ---------------------------------------------------------------------------

class TestBackendAbsent:
    def test_no_backend_behaviour(self, tmp_path, hybrid_artifact, classical_artifact):
        stub = tmp_path / "blocker"
        stub.mkdir()
        (stub / "pqcrypto.py").write_text(
            "raise ImportError('blocked by test')\n"
        )
        hybrid_path = tmp_path / "hybrid.spif"
        hybrid_path.write_bytes(hybrid_artifact)
        classical_path = tmp_path / "classical.spif"
        classical_path.write_bytes(classical_artifact)

        script = textwrap.dedent(
            """
            import sys
            from spif import SPIFReader
            from spif.pq_hybrid import PQBackendUnavailable, pq_available
            from spif.trust import verify_artifact

            assert pq_available() is False

            # Classical artifacts are unaffected by the missing backend.
            classical = open(sys.argv[1], "rb").read()
            assert SPIFReader().verify_signature(classical) is True
            assert verify_artifact(classical).trust_status == "VALID"

            hybrid = open(sys.argv[2], "rb").read()
            # Classical mode still verifies the ed25519 component.
            assert SPIFReader().verify_signature(hybrid) is True
            # require_pq reports UNVERIFIABLE — never a silent
            # classical pass, never a crash.
            r = verify_artifact(hybrid, require_pq=True)
            assert r.trust_status == "UNVERIFIABLE", r.trust_status

            # Signing refuses loudly instead of degrading to ed25519.
            from spif import Node, Provenance, SPIFDocument
            from spif.crypto import generate_key
            from spif.pq_hybrid import sign_document_hybrid
            doc = SPIFDocument(
                payload=[Node(id="n1", type="fact", value="x")],
                provenance=Provenance(source_model="t", timestamp_ms=1),
            )
            try:
                sign_document_hybrid(doc, generate_key(), b"\\x00" * 4032, b"\\x00" * 1952)
            except PQBackendUnavailable:
                pass
            else:
                raise AssertionError("expected PQBackendUnavailable")
            print("backend-absent behaviour OK")
            """
        )
        env = dict(**__import__("os").environ)
        env["PYTHONPATH"] = str(stub) + ":" + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", script, str(classical_path), str(hybrid_path)],
            capture_output=True, text=True, env=env, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert "backend-absent behaviour OK" in proc.stdout
