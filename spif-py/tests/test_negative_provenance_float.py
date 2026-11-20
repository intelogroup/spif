"""Permanent regression suite for SPIF-NEGATIVE-INT-001 (negative PROVENANCE float extension).

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-18-2322: hostile negative PROVENANCE float fields.
Invariant: temperature (sampling parameter) and energy_wh (energy consumed)
are >= 0 by meaning; Provenance.__post_init__ enforces only timestamp_ms>=0.
A negative finite temperature/energy_wh must fail closed with SPIFError.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, Provenance, SPIFDocument, TaskInfo
from spif.format import CHUNK_CHECKSUM, CHUNK_PROVENANCE, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _doc():
    d = SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test", timestamp_ms=1700000000000, nonce="n1", attempt=1, temperature=0.5, energy_wh=1.0))
    return d
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with(obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==CHUNK_PROVENANCE else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def _prov(**over):
    p={"source_model":"canonical-test","timestamp_ms":1700000000000,"nonce":"n1","attempt":1,"temperature":0.5,"energy_wh":1.0}
    p.update(over); return p
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc()))
    assert doc.provenance.temperature==0.5 and doc.provenance.energy_wh==1.0
def test_control_prov_timestamp_negative_rejected(): _closed(_with(_prov(timestamp_ms=-1)))
def test_temperature_negative_rejected(): _closed(_with(_prov(temperature=-0.7)))
def test_temperature_large_negative_rejected(): _closed(_with(_prov(temperature=-273.15)))
def test_energy_negative_rejected(): _closed(_with(_prov(energy_wh=-1.0)))
def test_energy_huge_negative_rejected(): _closed(_with(_prov(energy_wh=-1e9)))
def test_both_negative_rejected(): _closed(_with(_prov(temperature=-1.0, energy_wh=-5.0)))


# --- Legs added at conversion: construction path ---

def test_provenance_negative_float_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        Provenance(source_model="m", timestamp_ms=1, temperature=-0.5)
    with pytest.raises((TypeError, ValueError)):
        Provenance(source_model="m", timestamp_ms=1, energy_wh=-1.0)
