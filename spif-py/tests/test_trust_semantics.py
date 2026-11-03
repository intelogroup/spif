"""Pinned trust semantics: gate modes and the pinned keystore.

These tests promote two adversarial-loop probes (cycles 2026-11-02-1616
and 2026-11-02-1722) into the shipped suite. Both pin *documented*
verification semantics whose risk lives entirely in consumers, so a
refactor that silently drifts them must fail here:

1. Gate modes (SPEC §7.9). A hybrid (ed25519+ml-dsa-65) entry never
   verifies on one leg alone under ``require_pq``: when the ML-DSA leg
   cannot be checked the verdict is *unverifiable*, never a silent
   classical pass. Classical gate mode's one-leg acceptance is the
   documented transitional behaviour, and it is explicit — the
   assessment's structured ``legs`` field states which components were
   verified, failed, left not-checked, or are unsupported, so a
   consumer gates on data instead of parsing prose.

2. The pinned keystore. ``known_keys`` is a resolution aid, not an
   allowlist: a signature validates only under the key identity it
   claims. A pinned named signer verifies VALID; a same-id attacker
   signature is INVALID in both gate modes; an unpinned named id is
   UNVERIFIABLE; and a self-describing attacker document verifies
   VALID but ``report.signers`` discloses the attacker's own identity,
   never the pinned one — VALID means "signature genuine", never
   "trusted signer".
"""
import base64
import importlib.util

import pytest

from spif import Node, Provenance, SPIFDocument
from spif.crypto import generate_key, sign_document
from spif.pq_hybrid import (
    HYBRID_ALGORITHM,
    PQ_ONLY_ALGORITHM,
    assess_pq_entry,
    generate_hybrid_keypair,
    hybrid_sign_message,
    hybrid_signer_id,
    ml_dsa_65_sign,
)
from spif.trust import verify_artifact

requires_pq_backend = pytest.mark.skipif(
    importlib.util.find_spec("pqcrypto") is None,
    reason="PQ backend not installed",
)


# ---------------------------------------------------------------------------
# Gate modes: the hybrid downgrade battery (loop cycle 2026-11-02-1616)
# ---------------------------------------------------------------------------

_BODY = b"trust-semantics synthetic signing body"


@pytest.fixture(scope="module")
def hybrid():
    pair = generate_hybrid_keypair()
    ed_pk = pair.ed_private_key.public_key().public_bytes_raw()
    ml_pk = pair.ml_public_key
    return {
        "ed_pk": ed_pk,
        "ml_pk": ml_pk,
        "signer": hybrid_signer_id(ed_pk, ml_pk),
        "sig": hybrid_sign_message(pair.ed_private_key, pair.ml_secret_key, _BODY),
        "ml_only_sig": ml_dsa_65_sign(pair.ml_secret_key, _BODY),
        "pq_signer": base64.b64encode(ml_pk).decode(),
    }


def _assess(alg, signer, sig, require_pq, known=None):
    return assess_pq_entry(alg, signer, sig, _BODY,
                           require_pq=require_pq, known_keys=known)


@requires_pq_backend
class TestHybridDowngradeGateModes:
    def test_control_both_legs_valid_require_pq(self, hybrid):
        a = _assess(HYBRID_ALGORITHM, hybrid["signer"], hybrid["sig"], True)
        assert a.status == "valid"
        # Both legs were actually checked — as data, not prose.
        assert a.legs == {"ed25519": "verified", "ml-dsa-65": "verified"}

    def test_ml_leg_zeroed_require_pq(self, hybrid):
        sig = hybrid["sig"]
        bad = sig[:64] + b"\x00" * (len(sig) - 64)
        a = _assess(HYBRID_ALGORITHM, hybrid["signer"], bad, True)
        assert a.status == "invalid"

    def test_ed_only_truncated_signature_both_modes(self, hybrid):
        truncated = hybrid["sig"][:64]
        assert _assess(HYBRID_ALGORITHM, hybrid["signer"], truncated, True).status == "invalid"
        assert _assess(HYBRID_ALGORITHM, hybrid["signer"], truncated, False).status == "invalid"

    def test_hybrid_signature_presented_as_pq_only(self, hybrid):
        a = _assess(PQ_ONLY_ALGORITHM, hybrid["pq_signer"], hybrid["sig"], True)
        assert a.status == "invalid"

    def test_pq_only_signature_presented_as_hybrid(self, hybrid):
        ml_only = hybrid["ml_only_sig"]
        assert _assess(HYBRID_ALGORITHM, hybrid["signer"], ml_only, True).status == "invalid"
        assert _assess(HYBRID_ALGORITHM, hybrid["signer"], ml_only, False).status == "invalid"

    def test_ed_only_provisioning_require_pq_must_not_pass(self, hybrid):
        # known_keys provisions ONLY the ed25519 component for a bare
        # signer id; the full hybrid signature is genuine. Under
        # require_pq the ML leg is uncheckable -> "unverifiable",
        # never a one-leg "valid".
        known = {"victim-id": base64.b64encode(hybrid["ed_pk"]).decode()}
        a = _assess(HYBRID_ALGORITHM, "victim-id", hybrid["sig"], True, known)
        assert a.status == "unverifiable", f"partial-hybrid acceptance: got {a.status}"
        # The legs show why: the ed25519 leg verified, the ML-DSA leg
        # could not be checked under require_pq.
        assert a.legs == {"ed25519": "verified", "ml-dsa-65": "not-checked"}

    def test_ed_only_provisioning_classical_mode_is_documented_valid(self, hybrid):
        # §7.9 classical gate mode accepts on the ed25519 leg alone —
        # and says so in the legs: the ML-DSA component is recorded
        # not-checked, so no consumer has to guess which legs ran.
        known = {"victim-id": base64.b64encode(hybrid["ed_pk"]).decode()}
        a = _assess(HYBRID_ALGORITHM, "victim-id", hybrid["sig"], False, known)
        assert a.status == "valid"
        assert a.legs == {"ed25519": "verified", "ml-dsa-65": "not-checked"}

    def test_pq_only_entry_classical_mode_legs_unsupported(self, hybrid):
        # A PQ-only entry in classical mode is unverifiable ("invisible,
        # not invalid"), and its only component reads unsupported —
        # this verifier in this mode cannot check it at all.
        a = _assess(PQ_ONLY_ALGORITHM, hybrid["pq_signer"],
                    hybrid["ml_only_sig"], False)
        assert a.status == "unverifiable"
        assert a.legs == {"ml-dsa-65": "unsupported"}

    def test_full_provisioning_garbage_ml_leg_require_pq(self, hybrid):
        full = base64.b64encode(hybrid["ed_pk"] + hybrid["ml_pk"]).decode()
        known = {"victim-id": full}
        sig = hybrid["sig"]
        bad = sig[:64] + b"\x00" * (len(sig) - 64)
        a = _assess(HYBRID_ALGORITHM, "victim-id", bad, True, known)
        assert a.status == "invalid"


# ---------------------------------------------------------------------------
# Pinned keystore: key identity through the trust layer
# (loop cycle 2026-11-02-1722)
# ---------------------------------------------------------------------------

PINNED_ID = "alice@example.test"
HYBRID_PINNED_ID = "alice-hybrid@example.test"


def _doc(text="pinned keystore fact"):
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=text)],
        provenance=Provenance(source_model="trust-semantics",
                              timestamp_ms=1_700_000_000_000),
    )


def _pub_b64(priv):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


class TestPinnedKeystoreTrust:
    def test_control_pinned_named_signer_valid(self):
        victim = generate_key()
        data = sign_document(_doc(), victim, signer_id=PINNED_ID)
        r = verify_artifact(data, known_keys={PINNED_ID: _pub_b64(victim)})
        assert r.trust_status == "VALID", r
        assert r.signers == [PINNED_ID]

    def test_same_named_id_attacker_signature_invalid_under_pin(self):
        victim = generate_key()
        attacker = generate_key()
        # Attacker signs their own document but claims the pinned identity.
        data = sign_document(_doc("attacker fact"), attacker, signer_id=PINNED_ID)
        r = verify_artifact(data, known_keys={PINNED_ID: _pub_b64(victim)})
        assert r.trust_status == "INVALID", r
        assert r.signature_status == "invalid"

    def test_named_id_without_pin_unverifiable(self):
        victim = generate_key()
        data = sign_document(_doc(), victim, signer_id=PINNED_ID)
        r = verify_artifact(data)  # no known_keys
        assert r.trust_status == "UNVERIFIABLE", r

    def test_signer_swap_to_attacker_self_describing_not_pinned_identity(self):
        victim = generate_key()
        attacker = generate_key()
        # Attacker signs under their OWN self-describing id (default).
        data = sign_document(_doc("attacker fact"), attacker)
        r = verify_artifact(data, known_keys={PINNED_ID: _pub_b64(victim)})
        # The document verifies on its own terms (known_keys resolves,
        # it does not allowlist) — but the report must disclose the
        # actual signer, never the pinned id.
        assert r.trust_status == "VALID", r
        assert r.signers == [_pub_b64(attacker)], r
        assert PINNED_ID not in r.signers

    @requires_pq_backend
    def test_hybrid_pinned_named_signer_and_attacker(self):
        from spif.pq_hybrid import generate_hybrid_keypair, sign_document_hybrid

        victim = generate_hybrid_keypair()
        attacker = generate_hybrid_keypair()
        victim_material = base64.b64encode(
            victim.ed_public_bytes + victim.ml_public_key
        ).decode("ascii")
        known = {HYBRID_PINNED_ID: victim_material}

        good = sign_document_hybrid(
            _doc(), victim.ed_private_key, victim.ml_secret_key,
            victim.ml_public_key, signer_id=HYBRID_PINNED_ID,
        )
        r = verify_artifact(good, known_keys=known, require_pq=True)
        assert r.trust_status == "VALID", r

        bad = sign_document_hybrid(
            _doc("attacker fact"), attacker.ed_private_key, attacker.ml_secret_key,
            attacker.ml_public_key, signer_id=HYBRID_PINNED_ID,
        )
        r = verify_artifact(bad, known_keys=known, require_pq=True)
        assert r.trust_status == "INVALID", r


# ---------------------------------------------------------------------------
# Structured verdict fields on the trust report: gate_mode,
# legs_verified, signer_trust — the §7.9.2 table and the pinned /
# resolved distinction as data a consumer can gate on.
# ---------------------------------------------------------------------------

class TestStructuredVerdictFields:
    def test_pinned_signer_trust_and_legs(self):
        victim = generate_key()
        data = sign_document(_doc(), victim, signer_id=PINNED_ID)
        r = verify_artifact(data, known_keys={PINNED_ID: _pub_b64(victim)})
        assert r.trust_status == "VALID", r
        assert r.gate_mode == "classical"
        assert r.signer_trust == {PINNED_ID: "pinned"}
        assert r.legs_verified == [{
            "signer": PINNED_ID,
            "algorithm": "ed25519",
            "legs": {"ed25519": "verified"},
        }]

    def test_self_describing_attacker_trust_is_resolved(self):
        victim = generate_key()
        attacker = generate_key()
        data = sign_document(_doc("attacker fact"), attacker)
        r = verify_artifact(data, known_keys={PINNED_ID: _pub_b64(victim)})
        assert r.trust_status == "VALID", r
        # The identity came from the document itself, not from a pin —
        # and the report discloses whose identity it actually is.
        assert r.signer_trust == {_pub_b64(attacker): "resolved"}
        assert r.signers == [_pub_b64(attacker)]

    @requires_pq_backend
    def test_hybrid_gate_modes_and_legs_on_report(self):
        from spif.pq_hybrid import sign_document_hybrid

        pair = generate_hybrid_keypair()
        data = sign_document_hybrid(
            _doc(), pair.ed_private_key, pair.ml_secret_key, pair.ml_public_key)
        signer = pair.signer_id

        r = verify_artifact(data)  # classical gate mode
        assert r.trust_status == "VALID", r
        assert r.gate_mode == "classical"
        assert r.legs_verified == [{
            "signer": signer,
            "algorithm": HYBRID_ALGORITHM,
            "legs": {"ed25519": "verified", "ml-dsa-65": "not-checked"},
        }]
        assert r.signer_trust == {signer: "resolved"}

        r = verify_artifact(data, require_pq=True)
        assert r.trust_status == "VALID", r
        assert r.gate_mode == "require_pq"
        assert r.legs_verified == [{
            "signer": signer,
            "algorithm": HYBRID_ALGORITHM,
            "legs": {"ed25519": "verified", "ml-dsa-65": "verified"},
        }]

    @requires_pq_backend
    def test_ed_only_provisioning_require_pq_report(self):
        from spif.pq_hybrid import sign_document_hybrid

        pair = generate_hybrid_keypair()
        data = sign_document_hybrid(
            _doc(), pair.ed_private_key, pair.ml_secret_key,
            pair.ml_public_key, signer_id="victim-id")
        known = {"victim-id": base64.b64encode(pair.ed_public_bytes).decode()}
        r = verify_artifact(data, known_keys=known, require_pq=True)
        # Unverifiable, and the legs say why: ed25519 verified, the
        # ML-DSA leg could not be checked with the provisioned key.
        assert r.trust_status == "UNVERIFIABLE", r
        assert r.gate_mode == "require_pq"
        assert r.signer_trust == {"victim-id": "pinned"}
        assert r.legs_verified == [{
            "signer": "victim-id",
            "algorithm": HYBRID_ALGORITHM,
            "legs": {"ed25519": "verified", "ml-dsa-65": "not-checked"},
        }]
