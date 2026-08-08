"""
Protobuf message definitions for SPIF benchmarks — no protoc required.

Builds message classes at import time using google.protobuf descriptor API.
Sets HAVE_PROTOBUF = False and no-ops all functions if protobuf is not installed
or the descriptor API differs from what we expect.

Install: pip install protobuf
"""
from __future__ import annotations

HAVE_PROTOBUF = False
_err_msg = ""

try:
    from google.protobuf import descriptor_pb2
    from google.protobuf.descriptor_pb2 import FieldDescriptorProto as _FDP

    _O = _FDP.LABEL_OPTIONAL
    _R = _FDP.LABEL_REPEATED
    _SF = _FDP.TYPE_STRING
    _FL = _FDP.TYPE_FLOAT
    _I64 = _FDP.TYPE_INT64
    _MSG = _FDP.TYPE_MESSAGE

    def _field(msg_proto, name: str, number: int, ftype: int, label: int,
               type_name: str = "") -> None:
        f = msg_proto.field.add()
        f.name = name
        f.number = number
        f.type = ftype
        f.label = label
        if type_name:
            f.type_name = type_name

    fp = descriptor_pb2.FileDescriptorProto()
    fp.name = "spif_bench.proto"
    fp.package = "spifbench"
    fp.syntax = "proto3"

    # Distribution
    _dm = fp.message_type.add()
    _dm.name = "Distribution"
    _field(_dm, "mean",      1, _FL,  _O)
    _field(_dm, "var",       2, _FL,  _O)
    _field(_dm, "shape",     3, _SF,  _O)
    _field(_dm, "semantics", 4, _SF,  _O)

    # Node
    _nm = fp.message_type.add()
    _nm.name = "Node"
    _field(_nm, "id",         1, _SF,  _O)
    _field(_nm, "type",       2, _SF,  _O)
    _field(_nm, "value",      3, _SF,  _O)
    _field(_nm, "confidence", 4, _MSG, _O, ".spfxbench.Distribution")
    _field(_nm, "refs",       5, _SF,  _R)

    # TraceStep
    _tm = fp.message_type.add()
    _tm.name = "TraceStep"
    _field(_tm, "id",           1, _SF,  _O)
    _field(_tm, "type",         2, _SF,  _O)
    _field(_tm, "content",      3, _SF,  _O)
    _field(_tm, "confidence",   4, _MSG, _O, ".spfxbench.Distribution")
    _field(_tm, "deps",         5, _SF,  _R)
    _field(_tm, "alternatives", 6, _SF,  _R)

    # Provenance
    _pm = fp.message_type.add()
    _pm.name = "Provenance"
    _field(_pm, "source_model",  1, _SF,  _O)
    _field(_pm, "model_version", 2, _SF,  _O)
    _field(_pm, "temperature",   3, _FL,  _O)
    _field(_pm, "input_hash",    4, _SF,  _O)
    _field(_pm, "timestamp_ms",  5, _I64, _O)

    # SemanticLayer
    _sm = fp.message_type.add()
    _sm.name = "SemanticLayer"
    _field(_sm, "embedding",       1, _FL,  _R)
    _field(_sm, "embedding_model", 2, _SF,  _O)

    # Alternative
    _am = fp.message_type.add()
    _am.name = "Alternative"
    _field(_am, "weight", 1, _FL,  _O)
    _field(_am, "nodes",  2, _MSG, _R, ".spfxbench.Node")

    # SPIFDocument
    _docm = fp.message_type.add()
    _docm.name = "SPIFDocument"
    _field(_docm, "payload",      1, _MSG, _R, ".spfxbench.Node")
    _field(_docm, "provenance",   2, _MSG, _O, ".spfxbench.Provenance")
    _field(_docm, "semantic",     3, _MSG, _O, ".spfxbench.SemanticLayer")
    _field(_docm, "trace",        4, _MSG, _R, ".spfxbench.TraceStep")
    _field(_docm, "alternatives", 5, _MSG, _R, ".spfxbench.Alternative")

    # Add to pool and build message classes
    _messages: dict = {}

    try:
        # protobuf >= 4.21: GetMessages accepts FileDescriptorProto objects
        from google.protobuf.message_factory import GetMessages as _GetMessages
        _messages = _GetMessages([fp])
    except (ImportError, TypeError):
        # protobuf 3.x: MessageFactory with pool
        from google.protobuf import descriptor_pool, message_factory
        _pool = descriptor_pool.DescriptorPool()
        _pool.Add(fp)
        _factory = message_factory.MessageFactory(pool=_pool)
        _messages = _factory.GetMessages([fp.name])

    _pkg = "spifbench."
    Proto_Distribution = _messages[_pkg + "Distribution"]
    Proto_Node         = _messages[_pkg + "Node"]
    Proto_TraceStep    = _messages[_pkg + "TraceStep"]
    Proto_Provenance   = _messages[_pkg + "Provenance"]
    Proto_SemanticLayer = _messages[_pkg + "SemanticLayer"]
    Proto_Alternative  = _messages[_pkg + "Alternative"]
    Proto_SPIFDocument = _messages[_pkg + "SPIFDocument"]

    HAVE_PROTOBUF = True

except Exception as _e:
    _err_msg = str(_e)
    # Provide no-op stubs so imports don't break
    Proto_Distribution = None
    Proto_Node         = None
    Proto_TraceStep    = None
    Proto_Provenance   = None
    Proto_SemanticLayer = None
    Proto_Alternative  = None
    Proto_SPIFDocument = None


def to_proto_raw(doc) -> bytes | None:
    """Serialize a SPIFDocument to protobuf bytes. Returns None if protobuf unavailable."""
    if not HAVE_PROTOBUF:
        return None
    try:
        pb = Proto_SPIFDocument()

        for n in doc.payload:
            pb_n = pb.payload.add()
            pb_n.id = n.id
            pb_n.type = n.type
            pb_n.value = str(n.value)
            if n.confidence:
                pb_n.confidence.mean = float(n.confidence.mean)
                pb_n.confidence.var = float(n.confidence.var)
                pb_n.confidence.shape = n.confidence.shape or ""
                pb_n.confidence.semantics = n.confidence.semantics or ""

        if doc.provenance:
            p = doc.provenance
            pb.provenance.source_model = p.source_model or ""
            pb.provenance.model_version = p.model_version or ""
            pb.provenance.temperature = float(p.temperature or 0.0)
            pb.provenance.input_hash = p.input_hash or ""
            pb.provenance.timestamp_ms = int(p.timestamp_ms or 0)

        if doc.semantic:
            pb.semantic.embedding_model = doc.semantic.embedding_model or ""
            pb.semantic.embedding[:] = [float(x) for x in doc.semantic.embedding]

        for s in (doc.trace or []):
            pb_s = pb.trace.add()
            pb_s.id = s.id
            pb_s.type = s.type
            pb_s.content = str(s.content)
            if s.confidence:
                pb_s.confidence.mean = float(s.confidence.mean)
                pb_s.confidence.var = float(s.confidence.var)

        for alt in (doc.alternatives or []):
            pb_a = pb.alternatives.add()
            pb_a.weight = float(alt.weight)
            for n in alt.nodes:
                pb_n = pb_a.nodes.add()
                pb_n.id = n.id
                pb_n.type = n.type
                pb_n.value = str(n.value)

        return pb.SerializeToString()
    except Exception:
        return None
