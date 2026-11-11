#!/usr/bin/env python3
"""
Builder for the wire-0x03 conformance cases (SPIF v2.0 kit extension).

Appends cases 26-34 to the kit's manifest.json, pinning the
per-version canonical rule of SPEC §4.1 as amended by the CBOR
deterministic-encoding migration (docs/CBOR-DETERMINISTIC-MIGRATION.md):

  26  a signed construction stamped 0x02, its SIGNATURE chunk keys in
      an order satisfying neither canonical rule: VALID — the 0x02
      subset does not check key order at all.
  27  the identical construction stamped 0x03: INVALID — wire 0x03
      enforces deterministic key order on signed documents.
  28  an ordinary current-writer 0x03 document: VALID.
  29  a 0x03 document whose payload carries 0.5 as a float64 where
      float16 is exact: INVALID (non-shortest float form).
  30  the identical construction stamped 0x02: VALID — the legacy
      subset does not check float width.
  31  a 0x03 document whose payload carries a small integer as a
      tag-2 bignum: INVALID (non-minimal bignum).
  32  an integer-keyed map ({-1, 24}) in LEGACY order — the one
      construction where the legacy and bytewise orders differ —
      stamped 0x03: INVALID. Pins the 2026-11-07 decision for the
      IETF bytewise rule over the RFC 8949 §4.2.3 legacy rule.
  33  the identical construction stamped 0x02: VALID.
  34  the same map in BYTEWISE order ({24, -1}) stamped 0x03: VALID —
      the accepted order at 0x03 is the bytewise one.

      (For text-string keys the two canonical orders coincide — the
      encoded length head is monotone in key length — so no SPIF map
      of text keys can distinguish them; integer keys can, which is
      why cases 32-34 carry their probe map on a payload node's
      extension field, which decoders ignore.)

Each hand-built case carries a genuine signature over its own signing
body from the published TEST-ONLY key, so the ONLY property under
test is the form rule. Cases are byte-identical across builds
(ed25519 signing is deterministic). All keys are TEST-ONLY — never
sign a real artifact with them.

Usage:  python build_v2_vectors.py
Requires: the spif package.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spif-py"))

import cbor2

from spif.crypto import sign_document
from spif.format import (
    CHUNK_CHECKSUM,
    CHUNK_HEADER,
    CHUNK_PAYLOAD,
    CHUNK_SIGNATURE,
    MAGIC,
    TAG_DISTRIBUTION,
    cbor_deterministic,
)
from spif.types import SPIFDocument

HERE = Path(__file__).resolve().parent
ART = HERE / "artifacts"
CREATED_MS = 1779379200000


def _test_key(label: str):
    """Deterministic TEST-ONLY key — same published seeds as
    build_vectors.py."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    seed = hashlib.sha256(f"spif-v13-conformance-test-key:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _b64(key) -> str:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _chunk(tag: int, payload: bytes) -> bytes:
    return struct.pack(">BI", tag, len(payload)) + payload


def _assemble(version: int, header: bytes, payload: bytes, sig: bytes) -> bytes:
    doc = (
        MAGIC + bytes([version, 0])
        + _chunk(CHUNK_HEADER, header)
        + _chunk(CHUNK_PAYLOAD, payload)
    )
    if sig:
        doc += _chunk(CHUNK_SIGNATURE, sig)
    doc += _chunk(CHUNK_CHECKSUM, hashlib.sha256(doc).digest())
    return doc


def _header(version: int) -> bytes:
    return cbor_deterministic(
        {"version": version, "flags": 0, "flags2": 0, "created_ms": CREATED_MS}
    )


def _node_payload(text: str) -> bytes:
    node = {
        "id": "n1",
        "type": "text",
        "value": text,
        "confidence": cbor2.CBORTag(
            TAG_DISTRIBUTION,
            {"mean": 0.9, "var": 0.0, "shape": "point",
             "semantics": "epistemic"},
        ),
        "refs": [],
    }
    return cbor_deterministic([node])


def _sign(key, body: bytes) -> bytes:
    return key.sign(body)


def _sig_chunk(key, signature: bytes, *, disordered: bool) -> bytes:
    fields = {
        "algorithm": "ed25519",
        "signer": _b64(key),
        "signature": signature,
        "key_id": "",
    }
    if not disordered:
        return cbor_deterministic(fields)
    # An order satisfying NEITHER canonical rule (bytewise wants
    # algorithm, key_id, signature, signer; the legacy rule agrees on
    # text keys). Only a version whose rule checks order can object.
    ordered = {k: fields[k] for k in ("signature", "key_id", "algorithm", "signer")}
    return cbor2.dumps(ordered)


def _signed_doc(version: int, payload: bytes, key, *, disordered_sig: bool) -> bytes:
    body = (
        MAGIC + bytes([version, 0])
        + _chunk(CHUNK_HEADER, _header(version))
        + _chunk(CHUNK_PAYLOAD, payload)
    )
    sig = _sign(key, body)
    return _assemble(
        version, _header(version), payload,
        _sig_chunk(key, sig, disordered=disordered_sig),
    )


def _float_payload() -> bytes:
    """Payload whose distribution mean is 0.5 encoded as float64 —
    legal CBOR, deterministic everywhere except float width. Map keys
    are in bytewise order so the float is the ONLY 0x03 violation."""
    node = {
        "id": "n1",
        "refs": [],
        "type": "text",
        "value": "conformance: float width",
        "confidence": cbor2.CBORTag(
            TAG_DISTRIBUTION,
            {"var": 0.1, "mean": 0.5, "shape": "point",
             "semantics": "epistemic"},
        ),
    }
    raw = cbor2.dumps([node])
    assert b"\xfb\x3f\xe0\x00\x00\x00\x00\x00\x00" in raw  # f64 0.5 present
    return raw


def _probe_payload(*, bytewise: bool) -> bytes:
    """Payload carrying an integer-keyed probe map on a node extension
    field (decoders ignore unknown node fields; the form scan does
    not). {-1, 24} is the one key pair whose order differs between
    the legacy rule (shorter encoding first: -1 = 0x20 precedes
    24 = 0x1818) and the bytewise rule (0x18.. precedes 0x20).
    Everything else in the payload is deterministic-clean: the
    distribution floats (0.9, 0.1) are not representable at a smaller
    width, so their float64 form is the shortest exact one."""
    probe = {24: "pos", -1: "neg"} if bytewise else {-1: "neg", 24: "pos"}
    node = {
        "id": "n1",
        "refs": [],
        "type": "text",
        "value": "conformance: key order probe",
        "x-probe": probe,
        "confidence": cbor2.CBORTag(
            TAG_DISTRIBUTION,
            {"var": 0.1, "mean": 0.9, "shape": "point",
             "semantics": "epistemic"},
        ),
    }
    return cbor2.dumps([node])


def _bignum_payload() -> bytes:
    """Deterministic payload with the distribution `var` value replaced
    by a tag-2 bignum encoding of the integer 5 — a value that fits the
    standard major types and so must not use a bignum at 0x03."""
    raw = _node_payload("conformance: bignum minimality")
    needle = b"\x63var\xf9\x00\x00"          # "var": float16 0.0
    assert raw.count(needle) == 1
    return raw.replace(needle, b"\x63var\xc2\x41\x05")  # "var": tag(2) h'05'


EXPECTED_VALID = {
    "trust_status": "VALID", "signature_status": "valid",
    "timestamp_status": "absent", "forged_revocations": 0, "references": [],
}
EXPECTED_INVALID = {
    "trust_status": "INVALID", "signature_status": "invalid",
    "timestamp_status": "absent", "forged_revocations": 0, "references": [],
}


def main() -> None:
    ART.mkdir(exist_ok=True)
    signer = _test_key("signer")
    cases = []

    payload = _node_payload("conformance: key order enforcement")
    doc26 = _signed_doc(0x02, payload, signer, disordered_sig=True)
    (ART / "26_unordered_keys_v2.spif").write_bytes(doc26)
    cases.append({
        "id": "26", "name": "unordered_keys_accepted_v2",
        "artifact": "artifacts/26_unordered_keys_v2.spif", "inputs": {},
        "description": "Signed document at wire 0x02 whose SIGNATURE chunk "
                       "keys are in an order satisfying neither canonical "
                       "rule. SPEC §4.1: the 0x01/0x02 canonical subset "
                       "does not check map key order — must verify VALID.",
        "expected": EXPECTED_VALID,
    })

    doc27 = _signed_doc(0x03, payload, signer, disordered_sig=True)
    (ART / "27_unordered_keys_v3.spif").write_bytes(doc27)
    cases.append({
        "id": "27", "name": "unordered_keys_rejected_v3",
        "artifact": "artifacts/27_unordered_keys_v3.spif", "inputs": {},
        "description": "The case-26 construction stamped wire 0x03. SPEC "
                       "§4.1: signed 0x03 documents are serialization-"
                       "checked against IETF deterministic encoding, "
                       "which fixes map key order: must not verify VALID.",
        "expected": EXPECTED_INVALID,
    })

    from spif.types import Node, Provenance

    doc28 = sign_document(
        SPIFDocument(
            payload=[Node(id="n1", type="fact",
                          value="conformance: current writer at wire 0x03")],
            provenance=Provenance(
                source_model="conformance-model", timestamp_ms=CREATED_MS
            ),
        ),
        signer,
    )
    (ART / "28_valid_v3.spif").write_bytes(doc28)
    cases.append({
        "id": "28", "name": "valid_v3",
        "artifact": "artifacts/28_valid_v3.spif", "inputs": {},
        "description": "Ordinary document produced by the current writer "
                       "(wire 0x03, deterministic encoding). Must verify "
                       "VALID.",
        "expected": EXPECTED_VALID,
    })

    fpayload = _float_payload()
    doc29 = _signed_doc(0x03, fpayload, signer, disordered_sig=False)
    (ART / "29_neg_float_width_v3.spif").write_bytes(doc29)
    cases.append({
        "id": "29", "name": "neg_nonminimal_float_v3",
        "artifact": "artifacts/29_neg_float_width_v3.spif", "inputs": {},
        "description": "Signed 0x03 document whose payload encodes 0.5 as "
                       "float64 although float16 represents it exactly. "
                       "SPEC §4.1 / deterministic encoding: floats use the "
                       "shortest exact form: must not verify VALID.",
        "expected": EXPECTED_INVALID,
    })

    doc30 = _signed_doc(0x02, fpayload, signer, disordered_sig=False)
    (ART / "30_float_width_accepted_v2.spif").write_bytes(doc30)
    cases.append({
        "id": "30", "name": "float_width_accepted_v2",
        "artifact": "artifacts/30_float_width_accepted_v2.spif", "inputs": {},
        "description": "The case-29 construction stamped wire 0x02. The "
                       "legacy canonical subset does not check float "
                       "width — must verify VALID.",
        "expected": EXPECTED_VALID,
    })

    doc31 = _signed_doc(0x03, _bignum_payload(), signer, disordered_sig=False)
    (ART / "31_neg_bignum_v3.spif").write_bytes(doc31)
    cases.append({
        "id": "31", "name": "neg_nonminimal_bignum_v3",
        "artifact": "artifacts/31_neg_bignum_v3.spif", "inputs": {},
        "description": "Signed 0x03 document whose payload encodes the "
                       "small integer 5 as a tag-2 bignum. SPEC §4.1 / "
                       "deterministic encoding: values that fit the "
                       "standard major types must not use bignums: must "
                       "not verify VALID.",
        "expected": EXPECTED_INVALID,
    })

    legacy_probe = _probe_payload(bytewise=False)
    doc32 = _signed_doc(0x03, legacy_probe, signer, disordered_sig=False)
    (ART / "32_neg_legacy_intkey_order_v3.spif").write_bytes(doc32)
    cases.append({
        "id": "32", "name": "neg_legacy_intkey_order_v3",
        "artifact": "artifacts/32_neg_legacy_intkey_order_v3.spif", "inputs": {},
        "description": "Signed 0x03 document carrying an integer-keyed map "
                       "{-1, 24} in the legacy RFC 8949 §4.2.3 order "
                       "(shorter encoding first). The 2026-11-07 decision "
                       "adopted the IETF bytewise order for wire 0x03: "
                       "must not verify VALID.",
        "expected": EXPECTED_INVALID,
    })

    doc33 = _signed_doc(0x02, legacy_probe, signer, disordered_sig=False)
    (ART / "33_legacy_intkey_order_v2.spif").write_bytes(doc33)
    cases.append({
        "id": "33", "name": "legacy_intkey_order_accepted_v2",
        "artifact": "artifacts/33_legacy_intkey_order_v2.spif", "inputs": {},
        "description": "The case-32 construction stamped wire 0x02. The "
                       "legacy subset checks no key order — must verify "
                       "VALID.",
        "expected": EXPECTED_VALID,
    })

    doc34 = _signed_doc(0x03, _probe_payload(bytewise=True), signer,
                        disordered_sig=False)
    (ART / "34_bytewise_intkey_order_v3.spif").write_bytes(doc34)
    cases.append({
        "id": "34", "name": "bytewise_intkey_order_v3",
        "artifact": "artifacts/34_bytewise_intkey_order_v3.spif", "inputs": {},
        "description": "The case-32 map in bytewise order ({24, -1}) at "
                       "wire 0x03: the order the IETF deterministic rule "
                       "prescribes — must verify VALID.",
        "expected": EXPECTED_VALID,
    })

    manifest_path = HERE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    own = {c["id"] for c in cases}
    manifest["cases"] = [c for c in manifest["cases"] if c["id"] not in own] + cases
    manifest["cases"].sort(key=lambda c: int(c["id"]))
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(cases)} cases (26-34); manifest now has "
          f"{len(manifest['cases'])} cases")


if __name__ == "__main__":
    main()
