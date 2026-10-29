"""v1.3 timestamp anchors: TSA countersignature, verified/unverified/absent.

Covers SPEC §6.13 / §7.8. Absence never invalidates; an unverifiable or
unconfigured authority is reported, never treated as an artifact failure.
"""

import base64

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, Provenance, SPIFReader
from spif.crypto import sign_document, generate_key
from spif.trust import (
    verify_artifact, create_timestamp_anchor, attach_timestamp,
    extract_timestamp, artifact_digest,
    TRUST_VALID, TS_VERIFIED, TS_UNVERIFIED, TS_ABSENT,
)


def _signed():
    key = generate_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="timestamped claim")],
        provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
    )
    return sign_document(doc, key)


def _b64(key) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def test_absent_anchor_reports_absent_and_stays_valid():
    report = verify_artifact(_signed())
    assert report.timestamp_status == TS_ABSENT
    assert report.trust_status == TRUST_VALID


def test_anchor_verified_with_pinned_tsa_key():
    data = _signed()
    tsa = generate_key()
    anchor = create_timestamp_anchor(data, tsa, time_ms=1_700_000_100_000)
    stamped = attach_timestamp(data, anchor)

    # Post-signature attachment must not disturb §7.2 verification.
    assert SPIFReader().verify_signature(stamped) is True
    assert extract_timestamp(stamped) == anchor
    assert SPIFReader().decode(stamped).timestamp_anchor == anchor

    report = verify_artifact(stamped, tsa_keys={anchor.authority: _b64(tsa)})
    assert report.timestamp_status == TS_VERIFIED
    assert report.trust_status == TRUST_VALID


def test_anchor_unverified_without_configured_key():
    data = _signed()
    tsa = generate_key()
    stamped = attach_timestamp(data, create_timestamp_anchor(data, tsa))
    report = verify_artifact(stamped)  # no tsa_keys configured
    assert report.timestamp_status == TS_UNVERIFIED
    assert report.trust_status == TRUST_VALID  # reported, not a failure


def test_anchor_unverified_with_wrong_pinned_key():
    data = _signed()
    tsa, other = generate_key(), generate_key()
    anchor = create_timestamp_anchor(data, tsa)
    stamped = attach_timestamp(data, anchor)
    report = verify_artifact(stamped, tsa_keys={anchor.authority: _b64(other)})
    assert report.timestamp_status == TS_UNVERIFIED
    assert report.trust_status == TRUST_VALID


def test_anchor_for_other_artifact_does_not_verify():
    data = _signed()
    tsa = generate_key()
    other = sign_document(
        SPIFDocument(
            payload=[Node(id="n1", type="text", value="someone else")],
            provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
        ),
        generate_key(),
    )
    foreign_anchor = create_timestamp_anchor(other, tsa)
    stamped = attach_timestamp(data, foreign_anchor)
    report = verify_artifact(stamped, tsa_keys={foreign_anchor.authority: _b64(tsa)})
    assert report.timestamp_status == TS_UNVERIFIED  # digest mismatch
    assert report.trust_status == TRUST_VALID


def test_writer_emitted_anchor_roundtrip():
    key = generate_key()
    tsa = generate_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="writer stamped")],
        provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
    )
    anchor = create_timestamp_anchor(sign_document(doc, key), tsa)
    doc.timestamp_anchor = anchor
    data = sign_document(doc, key)
    assert artifact_digest(data) == artifact_digest(sign_document(
        SPIFDocument(
            payload=[Node(id="n1", type="text", value="writer stamped")],
            provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
        ),
        key,
    ))
    report = verify_artifact(data, tsa_keys={anchor.authority: _b64(tsa)})
    assert report.timestamp_status == TS_VERIFIED
