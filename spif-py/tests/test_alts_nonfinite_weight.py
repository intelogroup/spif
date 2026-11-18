"""Permanent regression suite for SPIF-ALTS-NONFINITE-WEIGHT-001.

Converted from the loop probe test_loop_alts_shape_probe.py
(cycle 2026-11-18-0522; preserved under the loop goal's
hidden_files/evidence/2026-11-18-0522/spif/). Probe legs are
verbatim after this docstring; the final legs were added at
conversion for the writer path and the finite-extreme controls.

Invariant: an ALTS weight must be a finite number. The reader
rejects NaN via a finiteness gate (SPIFError) and the writer
refuses non-finite weights (ValueError) -- +Inf/-Inf under
normalized=False previously decoded unrejected because the gate
was isnan-only and the sum check runs only when normalized=True.

Fix: reader and writer gates changed from math.isnan(w) to
not math.isfinite(w); the Rust reader/writer gained the same
finiteness gate (tests/alts_nonfinite.rs).
"""

import hashlib, math, struct, cbor2, pytest
from spif import Alternative, Node, Provenance, SPIFDocument
from spif.format import CHUNK_ALTS, CHUNK_CHECKSUM, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
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
def _alt(**over):
    a={"weight":1.0,"nodes":[{"id":"a1","type":"fact","value":"alt fact","refs":[],"confidence":1.0}]}
    a.update(over); return {"normalized":True,"alts":[a]}
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc())); assert doc.alternatives[0].weight==1.0
def test_root_string_rejected(): _closed(_with_alts("not-alts"))
def test_root_int_rejected(): _closed(_with_alts(42))
def test_normalized_string_rejected(): _closed(_with_alts({"normalized":"true","alts":[]}))
def test_normalized_int_rejected(): _closed(_with_alts({"normalized":1,"alts":[]}))
def test_alts_string_rejected(): _closed(_with_alts({"normalized":True,"alts":"x"}))
def test_alts_dict_rejected(): _closed(_with_alts({"normalized":True,"alts":{"weight":1.0}}))
def test_entry_string_rejected(): _closed(_with_alts({"normalized":True,"alts":["x"]}))
def test_entry_missing_weight_rejected():
    _closed(_with_alts({"normalized":True,"alts":[{"nodes":[]}]}))
def test_entry_missing_nodes_rejected():
    _closed(_with_alts({"normalized":True,"alts":[{"weight":1.0}]}))
def test_weight_string_rejected(): _closed(_with_alts(_alt(weight="1.0")))
def test_weight_bool_rejected(): _closed(_with_alts(_alt(weight=True)))
def test_weight_list_rejected(): _closed(_with_alts(_alt(weight=[1.0])))
def test_weight_nan_normalized_rejected(): _closed(_with_alts(_alt(weight=float("nan"))))
def test_weight_nan_unnormalized_rejected():
    _closed(_with_alts({"normalized":False,"alts":[{"weight":float("nan"),"nodes":[]}]}))
def test_weight_inf_normalized_rejected(): _closed(_with_alts(_alt(weight=float("inf"))))
def test_weight_inf_unnormalized_rejected():
    _closed(_with_alts({"normalized":False,"alts":[{"weight":float("inf"),"nodes":[]}]}))
def test_weight_neginf_unnormalized_rejected():
    _closed(_with_alts({"normalized":False,"alts":[{"weight":float("-inf"),"nodes":[]}]}))
def test_nodes_string_rejected(): _closed(_with_alts(_alt(nodes="x")))
def test_nodes_dict_rejected(): _closed(_with_alts(_alt(nodes={"id":"a1"})))
def test_v01_bare_list_entry_shape_rejected():
    _closed(_with_alts([{"weight":"1.0","nodes":[]}]))


# --- Legs added at conversion: finite extremes + writer path ---

def test_weight_finite_extremes_unnormalized_decode():
    for w in (1e308, -1e308, 0.0):
        doc = SPIFReader().decode(
            _with_alts({"normalized": False, "alts": [{"weight": w, "nodes": []}]}))
        assert doc.alternatives[0].weight == w

def test_writer_rejects_nonfinite_weights():
    for w in (float("inf"), float("-inf"), float("nan")):
        doc = _doc()
        doc.alternatives = [Alternative(
            weight=w,
            nodes=[Node(id="a1", type="fact", value="alt fact")],
            normalized=False)]
        with pytest.raises(ValueError):
            SPIFWriter().encode(doc)

def test_writer_accepts_finite_extreme_weights():
    doc = _doc()
    doc.alternatives = [Alternative(
        weight=1e308,
        nodes=[Node(id="a1", type="fact", value="alt fact")],
        normalized=False)]
    data = SPIFWriter().encode(doc)
    assert SPIFReader().decode(data).alternatives[0].weight == 1e308
