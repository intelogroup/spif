"""Regression tests for SPIF-TRUST-CBOR-AMBIGUITY-001 (converted
verbatim from the 2026-11-15-0822 adversarial-loop probe): duplicate
post-signature chunks.

Trigger: a downstream consumer reads embedded revocations / timestamps
through the public raw extractors extract_revocations / extract_timestamp
on an artifact carrying TWO REVOCATION chunks or TWO TIMESTAMP chunks
(checksum recomputed; post-signature chunks are not covered by the
signature, so any holder of a signed artifact can do this).

Invariant: the same bytes must not yield a concrete revocation statement
or timestamp anchor from a raw extractor when the strict document reader
rejects those bytes as a duplicate chunk -- extraction must fail closed
(no statement/anchor, or a raised error), never silently merge both
REVOCATION chunks or silently first-win a TIMESTAMP chunk. Cross-surface
agreement: one document, one post-signature attestation set.

Actor: holder of a signed artifact who can insert post-signature chunks.
Cluster: canonicalization and encoding divergence.
"""
import hashlib
import struct

import cbor2
import pytest

from spif import SPIFDocument, Node, Provenance, SPIFReader
from spif.crypto import sign_document, generate_key
from spif.format import MAGIC, CHUNK_CHECKSUM, CHUNK_REVOCATION, CHUNK_TIMESTAMP
from spif.reader import SPIFFormatError
from spif.trust import (
    create_revocation, attach_revocations, extract_revocations,
    create_timestamp_anchor, attach_timestamp, extract_timestamp,
)

_CHUNK = struct.Struct(">BI")


def _doc():
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello world")],
        provenance=Provenance(source_model="test-model",
                              timestamp_ms=1_700_000_000_000))


def _signed():
    key = generate_key()
    return key, sign_document(_doc(), key)


def _chunks(data):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _payload_of(data, want):
    for ct, p in _chunks(data):
        if ct == want:
            return p
    raise AssertionError("chunk not found")


def _insert_duplicate(data, chunk_type, extra_payload):
    """Insert a second chunk of chunk_type before CHECKSUM, rechecksum."""
    parts = [data[:len(MAGIC) + 2]]
    for ct, p in _chunks(data):
        if ct == CHUNK_CHECKSUM:
            parts.append(_CHUNK.pack(chunk_type, len(extra_payload)) + extra_payload)
            break
        parts.append(_CHUNK.pack(ct, len(p)) + p)
    body = b"".join(parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _extract_rev(doc):
    try:
        return extract_revocations(doc)
    except Exception:
        return []  # a raised error is a fail-closed outcome


def _extract_ts(doc):
    try:
        return extract_timestamp(doc)
    except Exception:
        return None


def test_control_single_revocation_surfaces_agree():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    embedded = attach_revocations(data, [stmt])
    assert SPIFReader().decode(embedded).revocations == [stmt]
    assert extract_revocations(embedded) == [stmt]


def test_control_single_timestamp_surfaces_agree():
    key, data = _signed()
    anchor = create_timestamp_anchor(data, key, time_ms=1_700_000_100_000)
    stamped = attach_timestamp(data, anchor)
    assert SPIFReader().decode(stamped).timestamp_anchor == anchor
    assert extract_timestamp(stamped) == anchor


def test_duplicate_revocation_second_chunk_not_silently_merged():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    embedded = attach_revocations(data, [stmt])
    # second REVOCATION chunk carries a second (empty) list; strict reader
    # must reject the duplicate, so the extractor must fail closed too
    dup = _insert_duplicate(embedded, CHUNK_REVOCATION, cbor2.dumps([]))
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(dup)
    got = _extract_rev(dup)
    assert got == [], f"raw extractor silently merged duplicate REVOCATION chunks: {got}"


def test_duplicate_revocation_first_empty_second_real_not_merged():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="compromised")
    # base artifact with an empty REVOCATION chunk, then a second chunk
    # carrying the real statement inserted after it
    from spif.trust import attach_chunk
    empty = attach_chunk(data, CHUNK_REVOCATION, cbor2.dumps([]))
    real_payload = cbor2.dumps([stmt.to_cbor_dict()])
    dup = _insert_duplicate(empty, CHUNK_REVOCATION, real_payload)
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(dup)
    got = _extract_rev(dup)
    assert got == [], f"raw extractor silently merged duplicate REVOCATION chunks: {got}"


def test_duplicate_timestamp_forged_first_not_silently_returned():
    key, data = _signed()
    tsa2 = generate_key()
    genuine = create_timestamp_anchor(data, key, time_ms=1_700_000_100_000)
    forged = create_timestamp_anchor(data, tsa2, time_ms=1_800_000_000_000)
    stamped = attach_timestamp(data, genuine)
    # forged anchor chunk inserted AFTER the genuine one; an attacker who
    # rebuilds chunk order can equally place it first -- extractor is
    # order-dependent (first-win) while the strict reader rejects both
    dup = _insert_duplicate(stamped, CHUNK_TIMESTAMP,
                            _payload_of(attach_timestamp(data, forged), CHUNK_TIMESTAMP))
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(dup)
    got = _extract_ts(dup)
    assert got is None, f"raw extractor silently first-won duplicate TIMESTAMP chunks: {got}"


def test_duplicate_timestamp_second_not_silently_ignored_or_returned():
    key, data = _signed()
    genuine = create_timestamp_anchor(data, key, time_ms=1_700_000_100_000)
    stamped = attach_timestamp(data, genuine)
    dup = _insert_duplicate(stamped, CHUNK_TIMESTAMP,
                            _payload_of(stamped, CHUNK_TIMESTAMP))
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(dup)
    got = _extract_ts(dup)
    assert got is None, f"raw extractor silently resolved duplicate TIMESTAMP chunks: {got}"
