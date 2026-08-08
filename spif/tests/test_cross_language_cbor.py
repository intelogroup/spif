"""Roadmap item: validate CBOR tagging across languages for interoperability.

Encodes a document with the SPIF custom CBOR tags (1000 Distribution,
1001 NodeRef, 1002 Embedding) using the Python writer. Cross-language decode
coverage lives in test_compat_fixtures.py, which round-trips fixtures through
the TypeScript reader in compat/sif_reader.ts — there is no native Rust
viewer binary anymore (removed with the desktop app; browser-based
verification lives at verify/, spif.dev/verify).
"""

from spif import (
    SPIFDocument, Node, NodeRef, TraceStep, Distribution, SPIFWriter, SPIFReader,
)


def _tagged_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(id="root", type="fact", value="v", confidence=Distribution(mean=0.5)),
            Node(
                id="n2", type="fact", value="v",
                confidence=Distribution(mean=0.87),
                refs=[NodeRef(node_id="root")],  # CBOR Tag(1001)
            ),
        ],
        trace=[TraceStep(id="s1", type="evidence", content="a")],
    )


def test_python_encoded_tags_still_decode_in_python():
    """Sanity control: the same document must round-trip in Python too."""
    data = SPIFWriter().encode(_tagged_doc())
    restored = SPIFReader().decode(data)
    assert restored.payload[1].refs[0].node_id == "root"
    assert abs(restored.payload[1].confidence.mean - 0.87) < 1e-6
