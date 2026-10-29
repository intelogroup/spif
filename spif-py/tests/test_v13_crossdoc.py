"""v1.3 cross-document references: local-bundle-only resolution, UNRESOLVED
reporting, and the reader fix that treats `spif:` refs as external.

Covers SPEC §8.1 + the v1.3 resolution policy. Verification never fetches:
resolution happens exclusively against the caller-supplied bundle.
"""

import pytest

from spif import (
    SPIFDocument, Node, NodeRef, Provenance, SPIFWriter, SPIFReader,
    SPIFFormatError,
)
from spif.crypto import sign_document, generate_key
from spif.trust import verify_artifact, TRUST_VALID


def _upstream(node_id="n7", value="upstream evidence"):
    return SPIFDocument(
        payload=[Node(id=node_id, type="fact", value=value)],
        provenance=Provenance(source_model="retriever", timestamp_ms=1_700_000_000_000),
    )


def _downstream(ref: str, *, signed_key=None):
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="derived claim",
                      refs=[NodeRef(ref)])],
        provenance=Provenance(source_model="reasoner", timestamp_ms=1_700_000_100_000),
    )
    if signed_key is not None:
        return sign_document(doc, signed_key)
    return SPIFWriter().encode(doc)


def _cross_ref(upstream_doc: SPIFDocument, node_id="n7") -> str:
    return f"spif:sha256:{upstream_doc.content_id()}#{node_id}"


def test_cross_doc_ref_parses_as_external():
    up = _upstream()
    data = _downstream(_cross_ref(up))
    doc = SPIFReader().decode(data)  # previously raised SPIFFormatError
    assert doc.payload[0].refs[0].node_id == _cross_ref(up)


def test_unresolved_without_bundle():
    up = _upstream()
    report = verify_artifact(_downstream(_cross_ref(up)))
    assert len(report.references) == 1
    ref = report.references[0]
    assert ref.kind == "cross-document"
    assert ref.status == "unresolved"
    assert ref.content_id == up.content_id()
    assert ref.node_id == "n7"
    assert report.unresolved_references == [ref]


def test_resolved_with_bundle():
    up = _upstream()
    up_bytes = SPIFWriter().encode(up)
    report = verify_artifact(_downstream(_cross_ref(up)), bundle=[up_bytes])
    assert report.references[0].status == "resolved"
    assert report.unresolved_references == []


def test_unresolved_when_bundle_has_wrong_content():
    up = _upstream()
    stranger = _upstream(node_id="n7", value="different content entirely")
    report = verify_artifact(
        _downstream(_cross_ref(up)), bundle=[SPIFWriter().encode(stranger)]
    )
    assert report.references[0].status == "unresolved"


def test_unresolved_when_node_missing_in_bundle_doc():
    up = _upstream()
    up_bytes = SPIFWriter().encode(up)
    report = verify_artifact(_downstream(_cross_ref(up, "nope")), bundle=[up_bytes])
    assert report.references[0].status == "unresolved"


def test_unresolved_ref_does_not_fail_signature():
    up = _upstream()
    key = generate_key()
    data = _downstream(_cross_ref(up), signed_key=key)
    report = verify_artifact(data)
    assert report.trust_status == TRUST_VALID
    assert report.references[0].status == "unresolved"


def test_local_refs_reported_as_local():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="fact", value="base"),
        Node(id="n2", type="fact", value="derived", refs=[NodeRef("n1")]),
    ])
    report = verify_artifact(SPIFWriter().encode(doc))
    assert [(r.kind, r.status) for r in report.references] == [("local", "local")]


def test_dangling_local_ref_still_rejected():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="fact", value="x", refs=[NodeRef("ghost")]),
    ])
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(SPIFWriter().encode(doc))
