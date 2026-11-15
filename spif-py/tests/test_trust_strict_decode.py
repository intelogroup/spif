"""Regression tests for SPIF-TRUST-CBOR-AMBIGUITY-001 (converted
verbatim from the 2026-11-14-1422 adversarial-loop probe): trust.py's
raw extractors must not decode REVOCATION / TIMESTAMP chunks with bare
cbor2.loads while the document reader decodes the same chunks via
reader._cbor_load, which rejects duplicate map keys and trailing bytes.

Trigger: a downstream consumer (or attach_revocations merging) reads
embedded revocations/timestamps through the public raw extractors
extract_revocations / extract_timestamp on an artifact whose post-
signature chunks were crafted with ambiguous CBOR.
Invariant: the same chunk bytes must not yield a concrete revocation
statement or timestamp anchor from the raw extractor when the strict
document path rejects those bytes as ambiguous/malformed -- extraction
must fail closed (no statement/anchor, or a raised error a caller
cannot mistake for a result), never silently resolve duplicate keys
last-wins or ignore trailing garbage.
Actor: holder of a signed artifact who can attach post-signature
chunks (attach_* recomputes only the checksum; signatures stay valid).
"""
import struct

import cbor2
import pytest

from spif import SPIFDocument, Node, Provenance, SPIFReader
from spif.crypto import sign_document, generate_key
from spif.format import MAGIC, CHUNK_REVOCATION, CHUNK_TIMESTAMP
from spif.reader import _cbor_load, SPIFFormatError
from spif.trust import (
    create_revocation, attach_revocations, extract_revocations,
    create_timestamp_anchor, attach_timestamp, extract_timestamp,
    attach_chunk,
)


def _doc():
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello world")],
        provenance=Provenance(source_model="test-model",
                              timestamp_ms=1_700_000_000_000))


def _signed():
    key = generate_key()
    return key, sign_document(_doc(), key)


# --- minimal CBOR encoders that can emit duplicate map keys ---
def _t(s):
    b = s.encode()
    if len(b) < 24:
        return bytes([0x60 + len(b)]) + b
    if len(b) < 256:
        return b"\x78" + bytes([len(b)]) + b
    return b"\x79" + struct.pack(">H", len(b)) + b


def _u(n):
    if n < 24:
        return bytes([n])
    if n < 256:
        return b"\x18" + bytes([n])
    if n < 65536:
        return b"\x19" + struct.pack(">H", n)
    return b"\x1a" + struct.pack(">I", n)


def _bigint(n):  # epoch-ms needs 64-bit head
    return b"\x1b" + struct.pack(">Q", n)


def _bytes(b):
    if len(b) < 24:
        return bytes([0x40 + len(b)]) + b
    if len(b) < 256:
        return b"\x58" + bytes([len(b)]) + b
    return b"\x59" + struct.pack(">H", len(b)) + b


def _map(pairs):
    assert len(pairs) < 24
    out = bytes([0xA0 + len(pairs)])
    for k, v in pairs:
        out += _t(k) + v
    return out


def _chunk_payload(data, want):
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == want:
            return data[offset + 5: offset + 5 + ln]
        offset += 5 + ln
    raise AssertionError("chunk not found")


def _rev_pairs(stmt, digest_override=None):
    return [
        ("artifact_digest", _t(digest_override or stmt.artifact_digest)),
        ("signer", _t(stmt.signer)),
        ("issued_ms", _bigint(stmt.issued_ms)),
        ("reason", _t(stmt.reason)),
        ("signature", _bytes(stmt.signature)),
    ]


def test_control_honest_chunks_extract_and_strict_agree():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    embedded = attach_revocations(data, [stmt])
    assert extract_revocations(embedded) == [stmt]
    payload = _chunk_payload(embedded, CHUNK_REVOCATION)
    assert isinstance(_cbor_load(payload, "REVOCATION"), list)  # no raise
    anchor = create_timestamp_anchor(embedded, key, time_ms=1_700_000_100_000)
    stamped = attach_timestamp(embedded, anchor)
    assert extract_timestamp(stamped) == anchor


def test_duplicate_key_revocation_not_silently_resolved():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="retracted")
    pairs = _rev_pairs(stmt)
    # duplicate artifact_digest: real digest first, benign digest last
    dup_pairs = [pairs[0], ("artifact_digest", _t("00" * 32))] + pairs[1:]
    payload = b"\x81" + _map(dup_pairs)  # array(1) of the ambiguous map
    doc = attach_chunk(data, CHUNK_REVOCATION, payload)
    with pytest.raises(SPIFFormatError):
        _cbor_load(payload, "REVOCATION")  # strict path rejects same bytes
    try:
        got = extract_revocations(doc)
    except Exception:
        got = []  # a raised error is a fail-closed outcome
    assert got == [], f"raw extractor silently resolved duplicate key: {got}"


def test_trailing_bytes_revocation_not_silently_accepted():
    key, data = _signed()
    stmt = create_revocation(data, key, reason="compromised")
    good = cbor2.dumps([stmt.to_cbor_dict()])
    payload = good + b"\xff\xfftrailing-garbage"
    doc = attach_chunk(data, CHUNK_REVOCATION, payload)
    with pytest.raises(SPIFFormatError):
        _cbor_load(payload, "REVOCATION")
    try:
        got = extract_revocations(doc)
    except Exception:
        got = []
    assert got == [], f"raw extractor ignored trailing bytes: {got}"


def test_duplicate_key_timestamp_not_silently_resolved():
    key, data = _signed()
    anchor = create_timestamp_anchor(data, key, time_ms=1_700_000_100_000)
    pairs = [
        ("authority", _t(anchor.authority)),
        ("time_ms", _bigint(anchor.time_ms)),
        ("time_ms", _bigint(1_800_000_000_000)),  # duplicate, last wins
        ("token", _bytes(anchor.token)),
    ]
    payload = _map(pairs)
    doc = attach_chunk(data, CHUNK_TIMESTAMP, payload)
    with pytest.raises(SPIFFormatError):
        _cbor_load(payload, "TIMESTAMP")
    try:
        got = extract_timestamp(doc)
    except Exception:
        got = None
    assert got is None, f"raw extractor silently resolved duplicate key: {got}"
