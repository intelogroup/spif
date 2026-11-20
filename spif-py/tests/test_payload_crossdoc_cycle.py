"""Permanent regression suite for SPIF-PAYLOAD-CROSSDOC-CYCLE-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-20-1122: payload cycle smuggled via spif:-prefixed local node ids.
Invariant: a cycle among payload Node.refs must fail closed with SPIFError at decode.
The reader exempts refs starting with 'spif:' from dangling/cycle checks (SPEC 8.1
cross-document refs). A LOCAL node whose id itself starts with 'spif:' makes every
edge touching it 'cross-document', so a cycle through that node escapes detection.
Controls: plain local cycle rejected; genuine cross-doc ref (no local node with that
id) decodes; acyclic local graph decodes.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, Provenance, SPIFDocument
from spif.format import CHUNK_CHECKSUM, CHUNK_PAYLOAD, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
CONF = {"mean": 0.9, "var": 0.05, "shape": "gaussian", "semantics": "epistemic"}
def _doc():
    return SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test", timestamp_ms=1700000000000, nonce="n1"))
def _chunks(data):
    off = len(MAGIC) + 2; out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off); out.append((ct, data[off+5:off+5+ln])); off += 5 + ln
        if ct == CHUNK_CHECKSUM: break
    return out
def _with_payload(nodes):
    data = SPIFWriter().encode(_doc())
    parts = [(ct, cbor2.dumps(nodes) if ct == CHUNK_PAYLOAD else p) for ct, p in _chunks(data) if ct != CHUNK_CHECKSUM]
    body = data[:len(MAGIC)+2] + b"".join(_CHUNK.pack(ct, len(p)) + p for ct, p in parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()
def _node(nid, refs):
    return {"id": nid, "type": "fact", "value": "v", "confidence": dict(CONF), "refs": refs}
def _closed(nodes):
    with pytest.raises(SPIFError):
        SPIFReader().decode(_with_payload(nodes))
def _open(nodes):
    doc = SPIFReader().decode(_with_payload(nodes))
    assert len(doc.payload) == len(nodes)

def test_control_genuine_decodes():
    doc = SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.payload[0].value == "canonical fact"
def test_control_plain_cycle_rejected():
    _closed([_node("a", ["b"]), _node("b", ["a"])])
def test_control_crossdoc_ref_decodes():
    _open([_node("a", ["spif:sha256:deadbeef#n9"])])
def test_control_acyclic_local_decodes():
    _open([_node("a", ["b"]), _node("b", [])])
# Hostile: cycle routed through a local node whose id starts with 'spif:'
def test_cycle_via_spif_prefixed_node_rejected():
    _closed([_node("spif:x", ["b"]), _node("b", ["spif:x"])])
def test_self_loop_spif_prefixed_node_rejected():
    _closed([_node("spif:x", ["spif:x"])])
def test_two_node_cycle_both_spif_prefixed_rejected():
    _closed([_node("spif:a", ["spif:b"]), _node("spif:b", ["spif:a"])])
