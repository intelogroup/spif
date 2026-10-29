"""Adversarial tests for the v1.3 trust layer (spif.trust).

Phase B: attack the revocation / timestamp / cross-document machinery with
replayed, duplicated, malformed, transplanted, poisoned, and oversized
inputs. The contract under attack:

- verify_artifact() NEVER raises on untrusted input — it returns a
  VerificationReport. The only statuses are VALID / REVOKED / INVALID /
  UNSIGNED / UNVERIFIABLE, and timestamps verified / unverified / absent.
- A mutation or forgery NEVER produces a false REVOKED or a false
  timestamp "verified".
- Resolution binds the exact referenced content_id, never "any artifact".

Helpers build artifacts the same way the v1.3 suites do, then hand-craft
chunk payloads with cbor2 and splice them in via trust.attach_chunk (which
repairs the checksum, so the document still parses and the trust layer —
not the checksum — is what is being tested).
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, Provenance, SPIFReader, SPIFFormatError
from spif.crypto import sign_document, generate_key
from spif.format import MAGIC, CHUNK_REVOCATION, CHUNK_TIMESTAMP, CHUNK_CHECKSUM
from spif.types import RevocationStatement
from spif.trust import (
    verify_artifact, create_revocation, attach_revocations, attach_timestamp,
    create_timestamp_anchor, attach_chunk, artifact_digest,
    extract_revocations, extract_timestamp,
    TRUST_VALID, TRUST_REVOKED, TRUST_INVALID, TRUST_UNSIGNED, TRUST_UNVERIFIABLE,
    TS_VERIFIED, TS_UNVERIFIED, TS_ABSENT,
)

ALL_TRUST = {TRUST_VALID, TRUST_REVOKED, TRUST_INVALID, TRUST_UNSIGNED, TRUST_UNVERIFIABLE}
ALL_TS = {TS_VERIFIED, TS_UNVERIFIED, TS_ABSENT}


def _b64(key) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _doc(text="hello world", ts=1_700_000_000_000):
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value=text)],
        provenance=Provenance(source_model="test-model", timestamp_ms=ts),
    )


def _signed(text="hello world", ts=1_700_000_000_000):
    key = generate_key()
    return key, sign_document(_doc(text, ts), key)


def _chunk_payload(data: bytes, want: int) -> bytes:
    """Raw payload bytes of the first chunk of type `want` in `data`."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == want:
            return data[offset + 5: offset + 5 + ln]
        offset += 5 + ln
    raise AssertionError(f"chunk 0x{want:02x} not found")


def _splice_chunk(data: bytes, chunk_type: int, payload: bytes) -> bytes:
    """Insert an EXTRA chunk of `chunk_type` before CHECKSUM and repair the
    checksum — builds artifacts with duplicate chunk types, which
    attach_chunk() refuses to produce."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == CHUNK_CHECKSUM:
            body = data[:offset] + struct.pack(">BI", chunk_type, len(payload)) + payload
            return body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()
        offset += 5 + ln
    raise AssertionError("no CHECKSUM chunk")


def _rev_entry(digest, signer, *, issued_ms=1_700_000_100_000, reason="retracted",
               signature=b"\x00" * 64):
    return {
        "artifact_digest": digest, "signer": signer, "issued_ms": issued_ms,
        "reason": reason, "signature": signature,
    }


# ---------------------------------------------------------------------------
# (c) Malformed chunk payloads: clean reports, never a crash, never
#     VALID-by-accident. Regression tests for the type-confusion crashes
#     where unhashable signer/authority values escaped verify_artifact()
#     as TypeError (fixed by type validation in types.from_cbor_dict).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_signer", [["evil"], {"a": 1}, 42, None])
def test_revocation_signer_wrong_type_is_clean_parse_error(bad_signer):
    _key, data = _signed()
    payload = cbor2.dumps(
        [_rev_entry(artifact_digest(data), bad_signer)], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert any("parse" in e for e in report.errors)
    assert report.revocations_applied == []


@pytest.mark.parametrize("bad_authority", [["tsa"], {"a": 1}, 42, None])
def test_timestamp_authority_wrong_type_is_clean_parse_error(bad_authority):
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": bad_authority, "time_ms": 1, "token": b"\x00" * 64},
        canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"someone": _b64(key)})
    assert report.trust_status == TRUST_INVALID
    assert any("parse" in e for e in report.errors)


def test_statement_object_with_unhashable_signer_is_forged_not_crash():
    _key, data = _signed()
    stmt = RevocationStatement(
        artifact_digest=artifact_digest(data), signer=["x"],  # type: ignore[arg-type]
        issued_ms=1, reason="retracted", signature=b"\x00" * 64)
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


@pytest.mark.parametrize("field,bad", [
    ("artifact_digest", 123), ("issued_ms", "soon"), ("issued_ms", {"x": 1}),
    ("reason", ["retracted"]), ("signature", "not-bytes"), ("signature", 7),
])
def test_revocation_entry_field_types_validated(field, bad):
    _key, data = _signed()
    entry = _rev_entry(artifact_digest(data), "whoever")
    entry[field] = bad
    payload = cbor2.dumps([entry], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status in ALL_TRUST
    assert report.trust_status != TRUST_REVOKED
    # Either the entry is rejected at parse (INVALID report) or it parses
    # and is classified forged (VALID artifact, forgery counted).
    assert report.trust_status == TRUST_INVALID or report.forged_revocations == 1


def test_timestamp_time_and_token_types_validated():
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": "tsa", "time_ms": "noon", "token": b"\x00" * 64},
        canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"tsa": _b64(key)})
    assert report.trust_status == TRUST_INVALID  # parse error, clean report
    assert report.timestamp_status == TS_ABSENT


# ---------------------------------------------------------------------------
# (c) Truncated / structurally malformed chunk payloads
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    b"",                                        # empty
    b"\x81",                                    # truncated CBOR array
    b"\x81\xa1\x61\x61",                        # truncated mid-entry
    cbor2.dumps({"not": "a list"}),             # wrong top-level type
    cbor2.dumps([1, 2, 3]),                     # entries not dicts
    cbor2.dumps([{"artifact_digest": "x"}]),    # entry missing fields
])
def test_malformed_revocation_payloads_clean_report(payload):
    _key, data = _signed()
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.revocations_applied == []


@pytest.mark.parametrize("payload", [
    b"",
    b"\xa1\x61\x61",                            # truncated CBOR map
    cbor2.dumps(["not", "a", "dict"]),          # wrong top-level type
    cbor2.dumps({"authority": "tsa"}),          # missing fields
])
def test_malformed_timestamp_payloads_clean_report(payload):
    _key, data = _signed()
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.timestamp_status == TS_ABSENT


def test_revocation_entry_missing_signature_counts_forged():
    key, data = _signed()
    entry = _rev_entry(artifact_digest(data), _b64(key))
    del entry["signature"]  # defaults to b"" -> cannot verify -> forged
    payload = cbor2.dumps([entry], canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(mutated)
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


def test_timestamp_entry_missing_token_is_unverified():
    key, data = _signed()
    payload = cbor2.dumps(
        {"authority": "tsa", "time_ms": 1_700_000_100_000}, canonical=True)
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    report = verify_artifact(mutated, tsa_keys={"tsa": _b64(key)})
    assert report.trust_status == TRUST_VALID
    assert report.timestamp_status == TS_UNVERIFIED


@pytest.mark.parametrize("cut", [15, 30, 60])
def test_truncated_artifact_is_clean_report(cut):
    _key, data = _signed()
    stmt = create_revocation(data, _key)
    embedded = attach_revocations(data, [stmt])
    report = verify_artifact(embedded[:cut])  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert report.errors


# ---------------------------------------------------------------------------
# (c) Malformed OUT-OF-BAND revocation inputs (revocations= dicts and
#     revocation-list files). Regression tests: bad base64, missing keys,
#     and invalid JSON used to escape verify_artifact() as binascii.Error
#     / KeyError / JSONDecodeError. They are untrusted input: count them
#     as forgeries seen, note them, and keep verifying.
# ---------------------------------------------------------------------------

def test_revocations_arg_bad_base64_counted_not_raised():
    key, data = _signed()
    bad = _rev_entry(artifact_digest(data), _b64(key))
    bad["signature"] = "!!!not-base64!!!"
    report = verify_artifact(data, revocations=[bad])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1
    assert any("malformed" in e for e in report.errors)


def test_revocations_arg_missing_keys_counted_not_raised():
    _key, data = _signed()
    report = verify_artifact(data, revocations=[{"artifact_digest": "x"}, {}])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 2


def test_revocations_arg_bad_item_type_still_typeerror():
    _key, data = _signed()
    with pytest.raises(TypeError):
        verify_artifact(data, revocations=["not-a-statement"])


def test_revocation_file_invalid_json_is_error_not_crash(tmp_path):
    _key, data = _signed()
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    report = verify_artifact(data, revocation_file=path)
    assert report.trust_status == TRUST_VALID
    assert any("revocation file" in e for e in report.errors)


def test_revocation_file_malformed_entries_counted(tmp_path):
    import json as _json
    key, data = _signed()
    good = create_revocation(data, key, reason="retracted")
    path = tmp_path / "mixed.json"
    path.write_text(_json.dumps(
        {"revocations": [good.to_json_dict(), {"bogus": 1}, 42]}))
    report = verify_artifact(data, revocation_file=path)
    assert report.trust_status == TRUST_REVOKED  # the good one still applies
    assert report.forged_revocations == 2        # the two malformed ones
    assert any("malformed" in e for e in report.errors)


def test_revocation_file_wrong_shape_is_error_not_crash(tmp_path):
    import json as _json
    _key, data = _signed()
    path = tmp_path / "shape.json"
    path.write_text(_json.dumps(["not", "a", "dict"]))
    report = verify_artifact(data, revocation_file=path)
    assert report.trust_status == TRUST_VALID
    assert any("revocation file" in e for e in report.errors)


# ---------------------------------------------------------------------------
# (b) Duplicates: defined and safe at every level.
# - Duplicate chunk types: the reader rejects them (SPIFFormatError) —
#   verify_artifact reports a clean parse failure.
# - Duplicate statements: one statement, however many times supplied —
#   applied once, forged once (dedupe in verify_artifact).
# ---------------------------------------------------------------------------

def test_duplicate_revocation_chunks_rejected_cleanly():
    key, data = _signed()
    stmt = create_revocation(data, key)
    embedded = attach_revocations(data, [stmt])
    payload = _chunk_payload(embedded, CHUNK_REVOCATION)
    doubled = _splice_chunk(embedded, CHUNK_REVOCATION, payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(doubled)
    report = verify_artifact(doubled)  # must not raise
    assert report.trust_status == TRUST_INVALID
    assert any("Duplicate" in e or "parse" in e for e in report.errors)


def test_duplicate_timestamp_chunks_rejected_cleanly():
    key, data = _signed()
    tsa = generate_key()
    stamped = attach_timestamp(data, create_timestamp_anchor(data, tsa))
    payload = _chunk_payload(stamped, CHUNK_TIMESTAMP)
    doubled = _splice_chunk(stamped, CHUNK_TIMESTAMP, payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(doubled)
    report = verify_artifact(doubled)
    assert report.trust_status == TRUST_INVALID


def test_duplicate_valid_statement_applied_once():
    key, data = _signed()
    stmt = create_revocation(data, key)
    payload = cbor2.dumps([stmt.to_cbor_dict()] * 3, canonical=True)
    embedded = attach_chunk(data, CHUNK_REVOCATION, payload)
    report = verify_artifact(embedded, revocations=[stmt, stmt])
    assert report.trust_status == TRUST_REVOKED
    assert report.revocations_applied == [stmt]
    assert report.forged_revocations == 0


def test_duplicate_forged_statement_counted_once():
    _key, data = _signed()
    attacker = generate_key()
    forged = create_revocation(data, attacker, reason="compromised")
    report = verify_artifact(data, revocations=[forged, forged, forged])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


# ---------------------------------------------------------------------------
# (g) Resource bounds.
# - Embedded statements are capped by the reader
#   (MAX_REVOCATION_STATEMENTS): beyond the cap the document is a clean
#   parse failure, never a slow accept.
# - Within the cap, verification cost is linear: duplicates collapse
#   before any signature work, and each unique forged statement costs
#   one signature check.
# ---------------------------------------------------------------------------

def test_revocation_chunk_over_cap_rejected():
    from spif.reader import MAX_REVOCATION_STATEMENTS
    _key, data = _signed()
    entry = _rev_entry(artifact_digest(data), "whoever")
    payload = cbor2.dumps(
        [entry] * (MAX_REVOCATION_STATEMENTS + 1), canonical=True)
    mutated = attach_chunk(data, CHUNK_REVOCATION, payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(mutated)
    report = verify_artifact(mutated)
    assert report.trust_status == TRUST_INVALID


def test_many_statements_bounded_time_and_exact_counts():
    key, data = _signed()
    digest = artifact_digest(data)
    valid = create_revocation(data, key, reason="retracted")
    attacker = generate_key()
    forged = []
    for i in range(1500):
        stmt = RevocationStatement(
            artifact_digest=digest, signer=_b64(key),
            issued_ms=1_700_000_000_000 + i, reason="retracted", signature=b"")
        stmt.signature = attacker.sign(
            cbor2.dumps(stmt.unsigned_dict(), canonical=True))
        forged.append(stmt)
    entries = [valid.to_cbor_dict()] * 500 + [s.to_cbor_dict() for s in forged]
    embedded = attach_chunk(
        data, CHUNK_REVOCATION, cbor2.dumps(entries, canonical=True))
    start = time.monotonic()
    report = verify_artifact(embedded)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0
    assert report.trust_status == TRUST_REVOKED
    assert report.revocations_applied == [valid]  # 500 duplicates -> one
    assert report.forged_revocations == 1500


def test_large_revocation_file_filtered_by_digest(tmp_path):
    from spif.trust import save_revocation_list
    key, data = _signed()
    valid = create_revocation(data, key, reason="retracted")
    filler = [
        RevocationStatement(
            artifact_digest=f"{i:064x}", signer=_b64(key),
            issued_ms=i, reason="other", signature=b"\x00" * 64)
        for i in range(5000)
    ]
    path = tmp_path / "big-list.json"
    save_revocation_list(filler + [valid], path)
    start = time.monotonic()
    report = verify_artifact(data, revocation_file=path)
    assert time.monotonic() - start < 5.0
    assert report.trust_status == TRUST_REVOKED
    assert report.revocations_applied == [valid]
    assert report.forged_revocations == 0  # other digests are not forgeries


# ---------------------------------------------------------------------------
# (a) Replay: a statement binds (artifact_digest, signer) under the
#     signer's signature. Replaying it onto any other artifact — via
#     list, via attach, or as a raw transplanted chunk — must do
#     nothing. Rebinding the digest field breaks the statement
#     signature: forged.
# ---------------------------------------------------------------------------

def test_replay_raw_chunk_transplant_onto_other_artifact():
    key_a, data_a = _signed("artifact A")
    _key_b, data_b = _signed("artifact B")
    embedded_a = attach_revocations(data_a, [create_revocation(data_a, key_a)])
    payload = _chunk_payload(embedded_a, CHUNK_REVOCATION)
    transplanted = attach_chunk(data_b, CHUNK_REVOCATION, payload)
    report = verify_artifact(transplanted)
    assert report.trust_status == TRUST_VALID
    assert report.revocations_applied == []
    assert report.forged_revocations == 0  # about A, not B: not a forgery


def test_replay_same_signer_other_artifact_no_effect():
    key = generate_key()
    data_a = sign_document(_doc("artifact A"), key)
    data_b = sign_document(_doc("artifact B"), key)
    stmt_a = create_revocation(data_a, key)
    report = verify_artifact(attach_revocations(data_b, [stmt_a]))
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 0


def test_rebind_digest_breaks_statement_signature():
    key = generate_key()
    data_a = sign_document(_doc("artifact A"), key)
    data_b = sign_document(_doc("artifact B"), key)
    stmt = create_revocation(data_a, key)
    stmt.artifact_digest = artifact_digest(data_b)  # rebind after signing
    report = verify_artifact(data_b, revocations=[stmt])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations == 1


# ---------------------------------------------------------------------------
# (d) issued_ms semantics. SPEC §7.7's verification procedure checks
#     digest, signer membership, and the statement signature — it never
#     compares issued_ms against the artifact's timestamps. That is the
#     safer reading and is pinned here: issued_ms is signer-asserted
#     (and covered by the statement signature, so it cannot be altered
#     post-hoc), but it is produced by a different clock than the
#     artifact's provenance timestamp. Gating applicability on it would
#     let ordinary clock skew silently suppress a legitimate revocation
#     and leave a retracted artifact reporting VALID — the unsafe
#     direction. SPEC-CLARIFICATION CANDIDATE: §7.7 should state
#     explicitly that issued_ms is informational and MUST NOT gate
#     applicability.
# ---------------------------------------------------------------------------

def test_predated_revocation_still_applies():
    key, data = _signed(ts=1_700_000_000_000)
    stmt = create_revocation(
        data, key, issued_ms=1_700_000_000_000 - 86_400_000)  # a day earlier
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_REVOKED


def test_future_dated_revocation_still_applies():
    key, data = _signed()
    stmt = create_revocation(data, key, issued_ms=4_102_444_800_000)  # year 2100
    report = verify_artifact(data, revocations=[stmt])
    assert report.trust_status == TRUST_REVOKED


# ---------------------------------------------------------------------------
# (e) Timestamp transplants: the token countersigns (artifact_digest,
#     time_ms) under the TSA key and the authority field only selects
#     which pinned key to check. Moving an anchor across artifacts,
#     editing its time, or relabeling its authority can never produce
#     "verified".
# ---------------------------------------------------------------------------

def test_timestamp_raw_chunk_transplant_does_not_verify():
    _k, data_a = _signed("artifact A")
    _k2, data_b = _signed("artifact B")
    tsa = generate_key()
    stamped_a = attach_timestamp(data_a, create_timestamp_anchor(data_a, tsa))
    payload = _chunk_payload(stamped_a, CHUNK_TIMESTAMP)
    transplanted = attach_chunk(data_b, CHUNK_TIMESTAMP, payload)
    anchor = extract_timestamp(transplanted)
    report = verify_artifact(transplanted, tsa_keys={anchor.authority: _b64(tsa)})
    assert report.timestamp_status == TS_UNVERIFIED
    assert report.trust_status == TRUST_VALID


def test_timestamp_time_tamper_does_not_verify():
    _k, data = _signed()
    tsa = generate_key()
    anchor = create_timestamp_anchor(data, tsa, time_ms=1_700_000_100_000)
    forged = {"authority": anchor.authority,
              "time_ms": anchor.time_ms + 1, "token": anchor.token}
    mutated = attach_chunk(
        data, CHUNK_TIMESTAMP, cbor2.dumps(forged, canonical=True))
    report = verify_artifact(mutated, tsa_keys={anchor.authority: _b64(tsa)})
    assert report.timestamp_status == TS_UNVERIFIED
    assert report.trust_status == TRUST_VALID


def test_timestamp_authority_relabel_does_not_verify():
    _k, data = _signed()
    tsa, other = generate_key(), generate_key()
    anchor = create_timestamp_anchor(data, tsa)
    relabeled = {"authority": _b64(other), "time_ms": anchor.time_ms,
                 "token": anchor.token}
    mutated = attach_chunk(
        data, CHUNK_TIMESTAMP, cbor2.dumps(relabeled, canonical=True))
    # The pinned key for the relabeled authority is the OTHER key — which
    # never signed this token.
    report = verify_artifact(mutated, tsa_keys={_b64(other): _b64(other)})
    assert report.timestamp_status == TS_UNVERIFIED
    assert report.trust_status == TRUST_VALID


# ---------------------------------------------------------------------------
# (f) Bundle poisoning. Resolution binds content_id() — SHA-256 over
#     {payload, trace, provenance} — plus node presence (§8.1). A bundle
#     entry that merely looks similar (same node id, different content
#     or different provenance) has a different content_id and MUST NOT
#     resolve. Per §8.1 resolution is content identity only: the trust
#     state of bundle entries is not consulted, so a revoked copy of
#     the exact upstream still resolves (its content is bit-identical);
#     pinned here as the spec'd semantics.
# ---------------------------------------------------------------------------

from spif import NodeRef, SPIFWriter  # noqa: E402


def _upstream(node_id="n7", value="upstream evidence", ts=1_700_000_000_000):
    return SPIFDocument(
        payload=[Node(id=node_id, type="fact", value=value)],
        provenance=Provenance(source_model="retriever", timestamp_ms=ts),
    )


def _downstream_bytes(ref: str) -> bytes:
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="derived claim",
                      refs=[NodeRef(ref)])],
        provenance=Provenance(source_model="reasoner", timestamp_ms=1_700_000_100_000),
    )
    return SPIFWriter().encode(doc)


def _xref(doc) -> str:
    return f"spif:sha256:{doc.content_id()}#n7"


def test_bundle_same_node_different_provenance_does_not_resolve():
    up = _upstream()
    lookalike = _upstream(ts=1_700_000_999_999)  # same payload, new provenance
    assert lookalike.content_id() != up.content_id()
    report = verify_artifact(
        _downstream_bytes(_xref(up)), bundle=[SPIFWriter().encode(lookalike)])
    assert report.references[0].status == "unresolved"


def test_bundle_revoked_copy_of_exact_upstream_resolves():
    up = _upstream()
    up_key = generate_key()
    up_signed = sign_document(up, up_key)
    up_revoked = attach_revocations(
        up_signed, [create_revocation(up_signed, up_key)])
    report = verify_artifact(
        _downstream_bytes(_xref(up)), bundle=[up_revoked])
    assert report.references[0].status == "resolved"


def test_bundle_garbage_entries_resolve_nothing_but_do_not_crash():
    up = _upstream()
    garbage = [b"", b"not a spif file", b"\x00" * 64]
    report = verify_artifact(_downstream_bytes(_xref(up)), bundle=garbage)
    assert report.references[0].status == "unresolved"
    # ... and a good entry alongside the garbage still resolves.
    report = verify_artifact(
        _downstream_bytes(_xref(up)),
        bundle=garbage + [SPIFWriter().encode(up)])
    assert report.references[0].status == "resolved"


def test_bundle_document_object_form_resolves():
    up = _upstream()
    report = verify_artifact(_downstream_bytes(_xref(up)), bundle=[up])
    assert report.references[0].status == "resolved"


# ---------------------------------------------------------------------------
# (h) Mutation fuzzing of the new chunk parsers. Structured byte
#     mutations (deterministic seed) of valid revocation / timestamp
#     chunk payloads, spliced back with a repaired checksum so the
#     trust layer — not the checksum — decides. Invariants:
#       * verify_artifact always returns a report (nothing escapes),
#       * statuses stay within the defined sets,
#       * starting from a FORGED revocation, no mutation mints REVOKED;
#         starting from a VALID revocation, no mutation preserves
#         REVOKED (any content change breaks the statement signature);
#       * starting from an unverifiable anchor, no mutation mints a
#         "verified" timestamp.
# ---------------------------------------------------------------------------

import random  # noqa: E402

_FUZZ_SEED = 20261029
_FUZZ_ITERS = 1200


def _mutate(rng: random.Random, payload: bytes) -> bytes:
    """A mutated copy of `payload`, guaranteed to differ from it (an
    identity 'mutation' would legitimately preserve REVOKED)."""
    b = bytearray(payload)
    if rng.random() < 0.25 and len(b) > 1:
        return bytes(b[: rng.randrange(len(b))])  # strict truncation
    for _ in range(rng.randrange(1, 9)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    if bytes(b) == payload:
        b[0] ^= 0xFF
    return bytes(b)


def _fuzz_base(kind: str):
    key, data = _signed(f"fuzz base {kind}")
    tsa = generate_key()
    if kind == "forged-revocation":
        attacker = generate_key()
        stmt = create_revocation(data, attacker, reason="compromised")
        return data, attach_revocations(data, [stmt]), CHUNK_REVOCATION, {}
    if kind == "valid-revocation":
        stmt = create_revocation(data, key, reason="retracted")
        return data, attach_revocations(data, [stmt]), CHUNK_REVOCATION, {}
    anchor = create_timestamp_anchor(data, tsa)
    bad = {"authority": anchor.authority, "time_ms": anchor.time_ms,
           "token": b"\x00" * 64}
    mutated = attach_chunk(data, CHUNK_TIMESTAMP, cbor2.dumps(bad, canonical=True))
    return data, mutated, CHUNK_TIMESTAMP, {anchor.authority: _b64(tsa)}


@pytest.mark.parametrize("kind,forbidden", [
    ("forged-revocation", TRUST_REVOKED),
    ("valid-revocation", TRUST_REVOKED),
])
def test_fuzz_revocation_chunk_mutations(kind, forbidden):
    _data, base, chunk_type, _kw = _fuzz_base(kind)
    payload = _chunk_payload(base, chunk_type)
    rng = random.Random(_FUZZ_SEED)
    for i in range(_FUZZ_ITERS):
        mutated = attach_chunk(base, chunk_type, _mutate(rng, payload))
        report = verify_artifact(mutated)  # any escape fails the test
        assert report.trust_status in ALL_TRUST, (kind, i)
        assert report.trust_status != forbidden, (kind, i)


def test_fuzz_timestamp_chunk_mutations():
    _data, base, chunk_type, tsa_keys = _fuzz_base("bad-timestamp")
    payload = _chunk_payload(base, chunk_type)
    rng = random.Random(_FUZZ_SEED + 1)
    for i in range(_FUZZ_ITERS):
        mutated = attach_chunk(base, chunk_type, _mutate(rng, payload))
        report = verify_artifact(mutated, tsa_keys=tsa_keys)
        assert report.trust_status in ALL_TRUST, i
        assert report.timestamp_status in ALL_TS, i
        assert report.timestamp_status != TS_VERIFIED, i


def test_fuzz_whole_file_mutations_without_checksum_repair():
    _key, data = _signed("fuzz whole file")
    stmt = create_revocation(data, _key)
    base = attach_revocations(data, [stmt])
    rng = random.Random(_FUZZ_SEED + 2)
    for i in range(300):
        b = bytearray(base)
        for _ in range(rng.randrange(1, 9)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        report = verify_artifact(bytes(b))  # checksum fails: clean report
        assert report.trust_status in ALL_TRUST, i


def test_fuzz_extractors_never_raise():
    _k, data = _signed("fuzz extractors")
    stmt = create_revocation(data, _k)
    tsa = generate_key()
    base = attach_timestamp(
        attach_revocations(data, [stmt]),
        create_timestamp_anchor(data, tsa))
    rev_payload = _chunk_payload(base, CHUNK_REVOCATION)
    ts_payload = _chunk_payload(base, CHUNK_TIMESTAMP)
    rng = random.Random(_FUZZ_SEED + 3)
    for _ in range(600):
        m = attach_chunk(base, CHUNK_REVOCATION, _mutate(rng, rev_payload))
        assert isinstance(extract_revocations(m), list)
        m = attach_chunk(base, CHUNK_TIMESTAMP, _mutate(rng, ts_payload))
        extract_timestamp(m)  # None or an anchor; never an exception
