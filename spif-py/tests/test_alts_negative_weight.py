"""Permanent regression suite for SPIF-ALTS-NEGATIVE-WEIGHT-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-19-0522: hostile negative ALTS weights (normalized).
Invariant: when normalized=True, ALTS weights are probabilities -- each must
lie in [0,1]. The reader checks finiteness (all weights) and the SUM (1.0
+-0.01, normalized only) but never the sign, so [-0.5, 1.5] sums to 1.0 and
decodes. A negative or >1 normalized weight must fail closed with SPIFError.
"""
import hashlib, struct, cbor2, pytest
from spif import Alternative, Node, Provenance, SPIFDocument
from spif.format import CHUNK_ALTS, CHUNK_CHECKSUM, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _node(i, v):
    return {"id": f"a{i}", "type": "fact", "value": v, "refs": [], "confidence": cbor2.CBORTag(1000, {"mean": 1.0, "var": 0.0, "shape": "point", "semantics": "epistemic"})}
def _doc():
    return SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test", timestamp_ms=1_700_000_000_000, nonce="n1"),
        alternatives=[Alternative(weight=1.0, nodes=[Node(id="a1", type="fact", value="alt fact")], normalized=True)])
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with_alts(obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==CHUNK_ALTS else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _alts(weights, normalized=True):
    return {"normalized": normalized, "alts": [{"weight": w, "nodes": [_node(i+1, f"alt {i+1}")]} for i, w in enumerate(weights)]}
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.alternatives[0].weight==1.0
def test_control_pair_decodes():
    doc=SPIFReader().decode(_with_alts(_alts([0.5, 0.5]))); assert [a.weight for a in doc.alternatives]==[0.5, 0.5]
def test_control_sum_mismatch_rejected(): _closed(_with_alts(_alts([0.5, 0.6])))
def test_control_inf_weight_rejected(): _closed(_with_alts(_alts([float("inf"), 0.0])))
def test_negative_and_over_one_rejected(): _closed(_with_alts(_alts([-0.5, 1.5])))
def test_over_one_and_negative_rejected(): _closed(_with_alts(_alts([1.5, -0.5])))
def test_two_and_negative_one_rejected(): _closed(_with_alts(_alts([2.0, -1.0])))
def test_small_negative_three_way_rejected(): _closed(_with_alts(_alts([-0.1, 0.6, 0.5])))
def test_v01_bare_list_negative_rejected(): _closed(_with_alts([{"weight": -0.5, "nodes": [_node(1, "alt 1")]}, {"weight": 1.5, "nodes": [_node(2, "alt 2")]}]))


# --- Legs added at conversion: writer path + unnormalized control ---

def test_writer_rejects_normalized_negative_weights():
    doc = _doc()
    doc.alternatives = [
        Alternative(weight=-0.5, nodes=[Node(id="a1", type="fact", value="alt 1")], normalized=True),
        Alternative(weight=1.5, nodes=[Node(id="a2", type="fact", value="alt 2")], normalized=True),
    ]
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)

def test_writer_accepts_unnormalized_negative_score():
    # normalized=False weights are scores, not probabilities: a
    # finite negative score stays valid on both legs.
    doc = _doc()
    doc.alternatives = [
        Alternative(weight=-2.5, nodes=[Node(id="a1", type="fact", value="alt 1")], normalized=False),
    ]
    data = SPIFWriter().encode(doc)
    assert SPIFReader().decode(data).alternatives[0].weight == -2.5

def test_reader_rejects_unnormalized_spelling_of_range_via_v02_normalized():
    # The v0.2 wrapper with normalized=True is the reader leg already
    # covered above; a >1 single normalized weight is rejected even
    # though its sum is also wrong (range fires, not just sum).
    _closed(_with_alts(_alts([1.5])))
