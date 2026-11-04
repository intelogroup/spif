#!/usr/bin/env python3
"""
Builder for the negative conformance cases (SPIF v1.5 kit extension).

Appends cases 16-25 to the kit's manifest.json: documents that must NOT
verify as plain VALID, each pinning one rejection rule. Seeded from the
adversarial loop's preserved probes for SPIF-NONCANONICAL-ACCEPT-001
(cycles 2026-11-02-2022 / 2026-11-02-2322), the SPEC §7.9.2 gate
table, and the probe for SPIF-CROSSAUTH-SIGNER-EXPANSION-001
(cycle 2026-11-03-2022). The v1.3 builder (build_vectors.py) owns
cases 01-11 and the PQ builder (build_pq_vectors.py) owns 12-15;
this script replaces only its own cases, so the builders can run in
any order.

Cases 16-21 mutate case 01's signed artifact (the SIGNATURE chunk lies
outside the signing body and the CHECKSUM is recomputable, so anyone
holding a valid envelope can produce them). Case 22 reuses case 15's
artifact under the classical gate. Case 23 is a PQ-only signed
artifact presented to a classical reader. Cases 24-25 carry BOTH
auth chunk types: the attacker's entry in the appended chunk is
genuinely signed over the public signing body, so only the SPEC §7.2
one-attestation rule (never the cryptography) rejects them.

Determinism note: cases 16-22 and 24-25 are byte-identical across
builds (same published TEST-ONLY ed25519 seeds as build_vectors.py;
ed25519 signing is deterministic). Case 23's artifact is not
byte-identical (ML-DSA key generation and hedged signing are
randomized, as with cases 12-15); its expected outcome is
deterministic, which is all the runner asserts. All keys are
TEST-ONLY — never sign a real artifact with them.

Usage:  python build_negative_vectors.py
Requires: the spif package; case 23 additionally requires the
`pqcrypto` backend (the 'pq' extra) at build time only — the runner
case itself executes through the classical adapter and needs no
backend.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import Node, Provenance, SPIFDocument, SPIFWriter
from spif.crypto import sign_document
from spif.format import (
    MAGIC, CHUNK_CHECKSUM, CHUNK_MULTISIG, CHUNK_PROVENANCE, CHUNK_SIGNATURE,
)
from spif.pq_hybrid import (
    ML_DSA_65_SIG_LEN, PQ_ONLY_ALGORITHM,
    generate_ml_dsa_65_keypair, ml_dsa_65_sign,
)
from spif.types import Signature

HERE = Path(__file__).resolve().parent
ART = HERE / "artifacts"
TS0 = 1_700_000_000_000
NEG_CASE_IDS = {"16", "17", "18", "19", "20", "21", "22", "23", "24", "25"}

_CHUNK = struct.Struct(">BI")


def _test_key(label: str) -> Ed25519PrivateKey:
    """Deterministic TEST-ONLY key from a published seed string
    (same scheme as build_vectors.py, so case 01 rebuilds exactly)."""
    seed = hashlib.sha256(f"spif-v13-conformance-test-key:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _doc(text: str) -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value=text)],
        provenance=Provenance(source_model="conformance-model", timestamp_ms=TS0),
    )


def _chunks(data: bytes):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _with_chunk(data: bytes, chunk_type: int, payload_bytes: bytes) -> bytes:
    """Replace one chunk's payload and recompute the checksum — the
    attacker's move: the envelope stays well-formed and checksummed."""
    parts = [(ct, payload_bytes if ct == chunk_type else p)
             for ct, p in _chunks(data) if ct != CHUNK_CHECKSUM]
    body = data[: len(MAGIC) + 2] + b"".join(
        _CHUNK.pack(ct, len(p)) + p for ct, p in parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _chunk_dict(data: bytes, chunk_type: int) -> dict:
    payload = [p for ct, p in _chunks(data) if ct == chunk_type][0]
    return cbor2.loads(payload)


def _insert_before_checksum(data: bytes, chunk_type: int, payload: bytes) -> bytes:
    """Append a new chunk just before CHECKSUM and recompute the
    checksum — the cross-auth attacker's move (cases 24-25)."""
    parts = [data[: len(MAGIC) + 2]]
    off = len(MAGIC) + 2
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        if ct != CHUNK_CHECKSUM:
            parts.append(data[off: off + 5 + ln])
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    parts.append(_CHUNK.pack(chunk_type, len(payload)) + payload)
    body = b"".join(parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _signing_body(data: bytes) -> bytes:
    """Bytes before the first auth chunk (SPEC §7.2)."""
    off = len(MAGIC) + 2
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        if ct in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            return data[:off]
        off += 5 + ln
    raise AssertionError("no auth chunk")


def _entry(key: Ed25519PrivateKey, signer_id: str, body: bytes) -> dict:
    return {"algorithm": "ed25519", "signer": signer_id,
            "signature": key.sign(body), "key_id": ""}


def _genuine_multisig(k1: Ed25519PrivateKey, k2: Ed25519PrivateKey) -> bytes:
    """A genuine two-signer MULTISIG artifact from the TEST-ONLY keys."""
    doc = _doc("conformance: genuine multisig artifact")
    dummy = Signature(algorithm="ed25519", signer="x", signature=b"\x00" * 64)
    doc.signatures = [dummy, dummy]
    body = _signing_body(SPIFWriter().encode(doc))
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(k1), signature=k1.sign(body)),
        Signature(algorithm="ed25519", signer=_b64(k2), signature=k2.sign(body)),
    ]
    return SPIFWriter().encode(doc)


def _kv(k, v) -> bytes:
    return cbor2.dumps(k) + cbor2.dumps(v)


def _expected(trust: str, sig: str) -> dict:
    return {
        "trust_status": trust,
        "signature_status": sig,
        "timestamp_status": "absent",
        "forged_revocations": 0,
        "references": [],
    }


def _sign_document_pq_only(doc: SPIFDocument, ml_sk: bytes, ml_pk: bytes) -> bytes:
    """Encode a PQ-only (ml-dsa-65) signed artifact. PQ-only *signing*
    is spec-only in spif-py (§7.9.5); this builder assembles the entry
    directly, the way a future PQ-only writer would emit it."""
    signer = base64.b64encode(ml_pk).decode()
    doc.signature = Signature(
        algorithm=PQ_ONLY_ALGORITHM, signer=signer,
        signature=b"\x00" * ML_DSA_65_SIG_LEN,
    )
    dummy = SPIFWriter().encode(doc)
    offset = len(MAGIC) + 2
    while offset < len(dummy):
        ct, ln = _CHUNK.unpack_from(dummy, offset)
        if ct == CHUNK_SIGNATURE:
            break
        offset += 5 + ln
    else:
        raise AssertionError("no SIGNATURE chunk in encoded document")
    body = dummy[:offset]  # §7.2 signing body: bytes before the auth chunk
    doc.signature = Signature(
        algorithm=PQ_ONLY_ALGORITHM, signer=signer,
        signature=ml_dsa_65_sign(ml_sk, body),
    )
    return SPIFWriter().encode(doc)


def main() -> None:
    ART.mkdir(exist_ok=True)
    signer = _test_key("signer")
    valid = sign_document(_doc("conformance: valid signed artifact"), signer)
    sd = _chunk_dict(valid, CHUNK_SIGNATURE)
    victim_id = _b64(signer)
    attacker_id = base64.b64encode(b"A" * 32).decode()

    cases: list[dict] = []

    def add(case: dict) -> None:
        cases.append(case)

    # 16 — duplicate `signer` key, victim value last -------------------------
    body = (_kv("algorithm", sd["algorithm"]) + _kv("signer", attacker_id)
            + _kv("signer", victim_id) + _kv("signature", sd["signature"])
            + _kv("key_id", sd.get("key_id", "")))
    dup_signer = _with_chunk(valid, CHUNK_SIGNATURE, b"\xa5" + body)
    (ART / "16_neg_duplicate_signer_key.spif").write_bytes(dup_signer)
    add({
        "id": "16", "name": "neg_duplicate_signer_key",
        "description": "SIGNATURE map carries the `signer` key twice "
                       "(attacker first, victim last). A last-wins decoder "
                       "attributes the document to the victim; a first-wins "
                       "decoder to the attacker. Ambiguous in any document: "
                       "must not verify VALID.",
        "artifact": "artifacts/16_neg_duplicate_signer_key.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 17 — duplicate `signature` key, garbage first --------------------------
    body = b"".join(_kv(k, sd[k]) for k in sd if k != "signature")
    body += _kv("signature", b"\x00" * 64)
    body += _kv("signature", sd["signature"])
    dup_sig = _with_chunk(valid, CHUNK_SIGNATURE,
                          bytes([0xA0 + len(sd) + 1]) + body)
    (ART / "17_neg_duplicate_signature_key.spif").write_bytes(dup_sig)
    add({
        "id": "17", "name": "neg_duplicate_signature_key",
        "description": "SIGNATURE map carries the `signature` key twice "
                       "(garbage first, genuine second). Whether the entry "
                       "verifies depends on the decoder's duplicate-key "
                       "rule: ambiguous, must not verify VALID.",
        "artifact": "artifacts/17_neg_duplicate_signature_key.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 18 — indefinite-length SIGNATURE map ------------------------------------
    pairs = b"".join(_kv(k, sd[k]) for k in sd)
    indefinite = _with_chunk(valid, CHUNK_SIGNATURE, b"\xbf" + pairs + b"\xff")
    (ART / "18_neg_indefinite_signature_map.spif").write_bytes(indefinite)
    add({
        "id": "18", "name": "neg_indefinite_signature_map",
        "description": "SIGNATURE chunk re-encoded as an indefinite-length "
                       "CBOR map. A signed document's chunks must be "
                       "canonical (SPEC §4.1 / §12.4): must not verify VALID.",
        "artifact": "artifacts/18_neg_indefinite_signature_map.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 19 — long-form (0xB8) SIGNATURE map header ------------------------------
    longform = _with_chunk(valid, CHUNK_SIGNATURE,
                           b"\xb8" + bytes([len(sd)]) + pairs)
    (ART / "19_neg_longform_signature_header.spif").write_bytes(longform)
    add({
        "id": "19", "name": "neg_longform_signature_header",
        "description": "SIGNATURE map header in the non-minimal long form "
                       "(0xB8) although the pair count fits the short form. "
                       "Non-canonical in a signed document: must not verify "
                       "VALID.",
        "artifact": "artifacts/19_neg_longform_signature_header.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 20 — trailing bytes after CHECKSUM ---------------------------------------
    trailing = valid + b"\x04\x00\x00\x00\x02\x80\xffTRAILING-GARBAGE"
    (ART / "20_neg_trailing_bytes_after_checksum.spif").write_bytes(trailing)
    add({
        "id": "20", "name": "neg_trailing_bytes_after_checksum",
        "description": "Bytes appended after the terminal CHECKSUM chunk "
                       "(SPEC §12.4: CHECKSUM is last). The extra bytes are "
                       "outside the document's identity and must not be "
                       "silently ignored into the same verdict: must not "
                       "verify VALID.",
        "artifact": "artifacts/20_neg_trailing_bytes_after_checksum.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 21 — duplicate key in a non-signature chunk -------------------------------
    pd = _chunk_dict(valid, CHUNK_PROVENANCE)
    body = _kv("source_model", "attacker") + b"".join(_kv(k, pd[k]) for k in pd)
    dup_prov = _with_chunk(valid, CHUNK_PROVENANCE,
                           bytes([0xA0 + len(pd) + 1]) + body)
    (ART / "21_neg_duplicate_key_provenance.spif").write_bytes(dup_prov)
    add({
        "id": "21", "name": "neg_duplicate_key_provenance",
        "description": "PROVENANCE map carries `source_model` twice. The "
                       "ambiguity rule is class-level, not SIGNATURE-only: "
                       "a duplicate key in any chunk of a signed document "
                       "must not verify VALID.",
        "artifact": "artifacts/21_neg_duplicate_key_provenance.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 22 — malformed hybrid length under the CLASSICAL gate ---------------------
    add({
        "id": "22", "name": "neg_hybrid_malformed_length_classical",
        "description": "Case 15's artifact (ed25519-only signature relabelled "
                       "ed25519+ml-dsa-65, 64 bytes) assessed under the "
                       "CLASSICAL gate (default adapter; case 15 pins the "
                       "require_pq gate). §7.9.2: a hybrid entry not exactly "
                       "3373 bytes is malformed and INVALID in BOTH modes — "
                       "the classical reader must not fall back to verifying "
                       "its ed25519 component.",
        "artifact": "artifacts/15_hybrid_ed25519_only_relabelled.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 23 — PQ-only signature presented to a classical reader ---------------------
    ml_pk, ml_sk = generate_ml_dsa_65_keypair()
    pq_only = _sign_document_pq_only(
        _doc("conformance: pq-only signed artifact"), ml_sk, ml_pk)
    (ART / "23_neg_pq_only_classical.spif").write_bytes(pq_only)
    add({
        "id": "23", "name": "neg_pq_only_classical_unverifiable",
        "description": "Genuinely ML-DSA-65-signed artifact read by a "
                       "classical reader. §7.9.2: a PQ-only entry is "
                       "invisible, not invalid, to a classical reader — "
                       "the verdict is UNVERIFIABLE, never VALID and "
                       "never INVALID.",
        "artifact": "artifacts/23_neg_pq_only_classical.spif",
        "inputs": {},
        "expected": _expected("UNVERIFIABLE", "unverifiable"),
    })

    # 24 — MULTISIG appended to a single-signature document -------------------
    # The attacker's entry is genuinely signed over the public signing
    # body: the cryptography is impeccable, only the one-attestation
    # rule (SPEC §7.2) rejects the union signer set.
    attacker = _test_key("attacker")
    forged24 = _insert_before_checksum(
        valid, CHUNK_MULTISIG,
        cbor2.dumps(
            [_entry(attacker, _b64(attacker), _signing_body(valid))],
            canonical=True))
    (ART / "24_neg_crossauth_multisig_appended.spif").write_bytes(forged24)
    add({
        "id": "24", "name": "neg_crossauth_multisig_appended",
        "description": "Single-signature artifact plus an appended MULTISIG "
                       "chunk carrying a second signer's entry, genuinely "
                       "signed over the public signing body with the "
                       "CHECKSUM recomputed. SPEC §7.2: one document, one "
                       "attestation — SIGNATURE and MULTISIG must not "
                       "co-exist, or their entries union into a signer set "
                       "no signer attested (SPIF-CROSSAUTH-SIGNER-"
                       "EXPANSION-001): must not verify VALID.",
        "artifact": "artifacts/24_neg_crossauth_multisig_appended.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    # 25 — SIGNATURE appended to a genuine multisig document -------------------
    second = _test_key("second")
    multi = _genuine_multisig(signer, second)
    forged25 = _insert_before_checksum(
        multi, CHUNK_SIGNATURE,
        cbor2.dumps(
            _entry(attacker, _b64(attacker), _signing_body(multi)),
            canonical=True))
    (ART / "25_neg_crossauth_signature_appended.spif").write_bytes(forged25)
    add({
        "id": "25", "name": "neg_crossauth_signature_appended",
        "description": "Genuine two-signer MULTISIG artifact plus an "
                       "appended SIGNATURE chunk carrying a third signer's "
                       "entry, genuinely signed over the public signing "
                       "body with the CHECKSUM recomputed. The reverse "
                       "direction of case 24: co-present auth chunk types "
                       "must not verify VALID (SPEC §7.2).",
        "artifact": "artifacts/25_neg_crossauth_signature_appended.spif",
        "inputs": {},
        "expected": _expected("INVALID", "invalid"),
    })

    manifest_path = HERE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    kept = [c for c in manifest["cases"] if c["id"] not in NEG_CASE_IDS]
    manifest["cases"] = kept + cases
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"built {len(cases)} negative cases -> {ART}, manifest.json updated")


if __name__ == "__main__":
    main()
