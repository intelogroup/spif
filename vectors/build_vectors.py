#!/usr/bin/env python3
"""
Deterministic builder for the SPIF v1.3 conformance vectors.

Regenerates every artifact, aux file, and manifest.json in this directory.
All keys are derived from fixed, published test seeds (TEST ONLY — these
keys are public by design and must never sign real artifacts), and ed25519
signatures are deterministic, so two runs of this script produce
byte-identical output.

Usage:  python build_vectors.py            (writes into ./artifacts, ./aux)
Requires the spif package (spif-py) on the path — run from the repo root
with the project venv, or set PYTHONPATH=spif-py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spif-py"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, NodeRef, Provenance, SPIFWriter
from spif.crypto import sign_document
from spif.format import MAGIC, CHUNK_CHECKSUM
from spif.trust import (
    create_revocation, attach_revocations, save_revocation_list,
    create_timestamp_anchor, attach_timestamp,
)

HERE = Path(__file__).resolve().parent
ART = HERE / "artifacts"
AUX = HERE / "aux"

TS0 = 1_700_000_000_000


def _test_key(label: str) -> Ed25519PrivateKey:
    """Deterministic TEST-ONLY key from a published seed string."""
    seed = hashlib.sha256(f"spif-v13-conformance-test-key:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _doc(text: str, *, refs=None, model="conformance-model") -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=text, refs=refs or [])],
        provenance=Provenance(source_model=model, timestamp_ms=TS0),
    )


def _fix_checksum(data: bytes) -> bytes:
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == CHUNK_CHECKSUM:
            body = data[:offset]
            return body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()
        offset += 5 + ln
    raise AssertionError("no CHECKSUM chunk")


def _tamper(data: bytes, old: bytes, new_first: bytes) -> bytes:
    b = bytearray(data)
    idx = data.find(old)
    assert idx > 0, old
    b[idx] = new_first[0]
    return _fix_checksum(bytes(b))


def main() -> None:
    ART.mkdir(exist_ok=True)
    AUX.mkdir(exist_ok=True)

    signer = _test_key("signer")
    tsa = _test_key("tsa")
    attacker = _test_key("attacker")

    cases: list[dict] = []

    def add(case: dict) -> None:
        cases.append(case)

    # 01 — valid, Python-produced -------------------------------------------
    valid = sign_document(_doc("conformance: valid signed artifact"), signer)
    (ART / "01_valid_py.spif").write_bytes(valid)
    add({
        "id": "01", "name": "valid_py",
        "description": "Signed artifact, no trust-layer extras. Must verify VALID.",
        "artifact": "artifacts/01_valid_py.spif",
        "inputs": {},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
    })

    # 02 — cross-implementation (Rust) ---------------------------------------
    add({
        "id": "02", "name": "cross_implementation_rust",
        "description": "Case 01's artifact verified by the Rust reader, and a "
                       "Rust-produced signed artifact verified by the Python "
                       "reader. Requires a Rust toolchain (cargo).",
        "artifact": "artifacts/01_valid_py.spif",
        "inputs": {},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
        # Executed by run_conformance.py's cross-implementation adapter
        # (Rust trust_conformance binary, both directions); the runner
        # reports it BLOCKED only when Rust is unavailable.
    })

    # 03 — tampered -----------------------------------------------------------
    tampered = _tamper(valid, b"conformance: valid", b"X")
    (ART / "03_tampered.spif").write_bytes(tampered)
    add({
        "id": "03", "name": "tampered",
        "description": "Payload byte flipped, checksum repaired. The signature "
                       "cannot be recomputed by the attacker: INVALID.",
        "artifact": "artifacts/03_tampered.spif",
        "inputs": {},
        "expected": {"trust_status": "INVALID", "signature_status": "invalid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
    })

    # 04 — unsigned -------------------------------------------------------------
    unsigned = SPIFWriter().encode(_doc("conformance: unsigned artifact"))
    (ART / "04_unsigned.spif").write_bytes(unsigned)
    add({
        "id": "04", "name": "unsigned",
        "description": "No signature chunk. Must report UNSIGNED, never VALID.",
        "artifact": "artifacts/04_unsigned.spif",
        "inputs": {},
        "expected": {"trust_status": "UNSIGNED", "signature_status": "unsigned",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
    })

    # 05 — revoked via out-of-band list -----------------------------------------
    stmt = create_revocation(valid, signer, reason="retracted", issued_ms=TS0 + 60_000)
    save_revocation_list([stmt], AUX / "revocations_05.json")
    add({
        "id": "05", "name": "revoked_list",
        "description": "Signer's signed revocation supplied as a revocation-list "
                       "file. Signature stays valid; trust status is REVOKED.",
        "artifact": "artifacts/01_valid_py.spif",
        "inputs": {"revocation_file": "aux/revocations_05.json"},
        "expected": {"trust_status": "REVOKED", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
    })

    # 06 — revoked via embedded chunk ---------------------------------------------
    embedded = attach_revocations(valid, [stmt])
    (ART / "06_revoked_embedded.spif").write_bytes(embedded)
    add({
        "id": "06", "name": "revoked_embedded",
        "description": "The same revocation embedded in the REVOCATION chunk. "
                       "REVOKED; the artifact's §7.2 signature still verifies.",
        "artifact": "artifacts/06_revoked_embedded.spif",
        "inputs": {},
        "expected": {"trust_status": "REVOKED", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": []},
    })

    # 07 — forged revocation -------------------------------------------------------
    forged = create_revocation(valid, attacker, reason="compromised",
                               issued_ms=TS0 + 60_000)
    save_revocation_list([forged], AUX / "revocations_07_forged.json")
    add({
        "id": "07", "name": "forged_revocation",
        "description": "Revocation statement for this artifact signed by a "
                       "non-signer key. Must be ignored for trust (artifact "
                       "stays VALID) and flagged: forged_revocations == 1.",
        "artifact": "artifacts/01_valid_py.spif",
        "inputs": {"revocation_file": "aux/revocations_07_forged.json"},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 1,
                     "references": []},
    })

    # 08 / 09 — timestamped ----------------------------------------------------------
    anchor = create_timestamp_anchor(valid, tsa, time_ms=TS0 + 30_000)
    stamped = attach_timestamp(valid, anchor)
    (ART / "08_timestamped.spif").write_bytes(stamped)
    (AUX / "tsa_pub.json").write_text(json.dumps(
        {anchor.authority: _b64(tsa)}, indent=2))
    add({
        "id": "08", "name": "timestamp_verified",
        "description": "TSA countersignature present; verifier has the TSA's "
                       "pinned key (aux/tsa_pub.json). Timestamp verified.",
        "artifact": "artifacts/08_timestamped.spif",
        "inputs": {"tsa_keys": "aux/tsa_pub.json"},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "verified", "forged_revocations": 0,
                     "references": []},
    })
    add({
        "id": "09", "name": "timestamp_unverified_authority",
        "description": "Same artifact as 08, but the verifier has no pinned "
                       "key for the TSA. Timestamp unverified — not a failure.",
        "artifact": "artifacts/08_timestamped.spif",
        "inputs": {},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "unverified", "forged_revocations": 0,
                     "references": []},
    })

    # 10 / 11 — cross-document ---------------------------------------------------------
    upstream = _doc("conformance: upstream evidence", model="retriever")
    upstream_bytes = SPIFWriter().encode(upstream)
    (ART / "10_upstream.spif").write_bytes(upstream_bytes)
    ref = f"spif:sha256:{upstream.content_id()}#n1"
    downstream = sign_document(
        _doc("conformance: derived claim", refs=[NodeRef(ref)], model="reasoner"),
        signer,
    )
    (ART / "10_downstream.spif").write_bytes(downstream)
    add({
        "id": "10", "name": "crossdoc_resolved",
        "description": "Downstream artifact references a node in the upstream "
                       "artifact; the upstream artifact is supplied in the "
                       "local bundle. Reference resolves.",
        "artifact": "artifacts/10_downstream.spif",
        "inputs": {"bundle": ["artifacts/10_upstream.spif"]},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": [{"kind": "cross-document",
                                     "status": "resolved"}]},
    })
    add({
        "id": "11", "name": "crossdoc_unresolved",
        "description": "Same downstream artifact, no bundle supplied. The "
                       "reference reports UNRESOLVED; the artifact's own "
                       "trust status is unaffected (VALID).",
        "artifact": "artifacts/10_downstream.spif",
        "inputs": {},
        "expected": {"trust_status": "VALID", "signature_status": "valid",
                     "timestamp_status": "absent", "forged_revocations": 0,
                     "references": [{"kind": "cross-document",
                                     "status": "unresolved"}]},
    })

    manifest = {
        "kit": "SPIF v1.3 conformance vectors",
        "spec": "docs/SPEC.md (v1.3 addendum: §6.12, §6.13, §7.7, §7.8, §8.1)",
        "note": "All signing keys are published TEST-ONLY keys derived from "
                "fixed seeds in build_vectors.py. Never sign real artifacts "
                "with them.",
        "cases": cases,
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"built {len(cases)} cases -> {ART}, {AUX}, manifest.json")


if __name__ == "__main__":
    main()
