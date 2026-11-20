"""Permanent regression suite for SPIF-NEGATIVE-INT-001.

Converted from the adversarial-loop probe of the same name
(preserved under the loop goal's hidden_files/evidence/).
Probe legs are verbatim after this docstring; writer/construction
legs, where present, were added at conversion.

Loop probe 2026-11-18-1722: hostile negative integer fields.
Invariant: counts, durations and attempt numbers are >= 0 by meaning;
Provenance.__post_init__ already enforces timestamp_ms >= 0, proving the
discipline. A negative TASK attempt/total_ms/tool_count/error_count or a
negative PROVENANCE attempt must fail closed with SPIFError -- never decoded.
"""
import hashlib, struct, cbor2, pytest
from spif import Node, Provenance, SPIFDocument, TaskInfo
from spif.format import CHUNK_CHECKSUM, CHUNK_PROVENANCE, CHUNK_TASK, MAGIC
from spif.reader import SPIFError, SPIFReader
from spif.trust import verify_artifact
from spif.writer import SPIFWriter
_CHUNK = struct.Struct(">BI")
def _doc():
    d = SPIFDocument(payload=[Node(id="n1", type="fact", value="canonical fact")],
        provenance=Provenance(source_model="canonical-test", timestamp_ms=1700000000000, nonce="n1", attempt=1))
    d.task_info = TaskInfo(task_id="t1", attempt=1, status="ok", total_ms=4200, tool_count=3, error_count=1)
    return d
def _chunks(data):
    off=len(MAGIC)+2; out=[]
    while off < len(data):
        ct,ln=_CHUNK.unpack_from(data,off); out.append((ct,data[off+5:off+5+ln])); off+=5+ln
        if ct==CHUNK_CHECKSUM: break
    return out
def _with(chunk_type, obj):
    data=SPIFWriter().encode(_doc())
    parts=[(ct, cbor2.dumps(obj) if ct==chunk_type else p) for ct,p in _chunks(data) if ct!=CHUNK_CHECKSUM]
    body=data[:len(MAGIC)+2]+b"".join(_CHUNK.pack(ct,len(p))+p for ct,p in parts)
    return body+_CHUNK.pack(CHUNK_CHECKSUM,32)+hashlib.sha256(body).digest()
def _closed(evil):
    with pytest.raises(SPIFError): SPIFReader().decode(evil)
    assert verify_artifact(evil).trust_status != "VALID"
def _task(**over):
    t={"task_id":"t1","attempt":1,"status":"ok","total_ms":4200,"tool_count":3,"error_count":1}
    t.update(over); return t
def _prov(**over):
    p={"source_model":"canonical-test","timestamp_ms":1700000000000,"nonce":"n1","attempt":1,"temperature":0.5,"energy_wh":1.0}
    p.update(over); return p
def test_control_genuine_decodes():
    doc=SPIFReader().decode(SPIFWriter().encode(_doc()))
    assert doc.task_info.total_ms==4200 and doc.provenance.attempt==1
def test_control_prov_timestamp_negative_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(timestamp_ms=-1)))
# TASK negative legs
def test_task_attempt_negative_rejected(): _closed(_with(CHUNK_TASK,_task(attempt=-1)))
def test_task_total_ms_negative_rejected(): _closed(_with(CHUNK_TASK,_task(total_ms=-1)))
def test_task_tool_count_negative_rejected(): _closed(_with(CHUNK_TASK,_task(tool_count=-1)))
def test_task_error_count_negative_rejected(): _closed(_with(CHUNK_TASK,_task(error_count=-1)))
def test_task_total_ms_huge_negative_rejected(): _closed(_with(CHUNK_TASK,_task(total_ms=-10**12)))
def test_task_error_gt_tool_negative_combo_rejected(): _closed(_with(CHUNK_TASK,_task(tool_count=-5,error_count=-9)))
# PROVENANCE negative attempt
def test_prov_attempt_negative_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(attempt=-1)))
def test_prov_attempt_huge_negative_rejected(): _closed(_with(CHUNK_PROVENANCE,_prov(attempt=-10**9)))


# --- Legs added at conversion: construction + writer paths ---

def test_taskinfo_negative_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        TaskInfo(task_id="t1", attempt=-1)
    with pytest.raises((TypeError, ValueError)):
        TaskInfo(task_id="t1", total_ms=-5)

def test_provenance_attempt_negative_construction_rejected():
    with pytest.raises((TypeError, ValueError)):
        Provenance(source_model="m", timestamp_ms=1, attempt=-1)

def test_writer_rejects_mutated_negative_task():
    doc = _doc()
    doc.task_info.total_ms = -1
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)

def test_writer_rejects_mutated_negative_provenance_attempt():
    doc = _doc()
    doc.provenance.attempt = -2
    with pytest.raises(ValueError):
        SPIFWriter().encode(doc)
