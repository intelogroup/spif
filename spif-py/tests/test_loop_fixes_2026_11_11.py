"""Regression tests for the 2026-11-11 SPIF loop-fix lane — all 22 open
cards, in four groups:

- Reader strictness (16 cards): SPIF-SEMANTIC-TYPE-001,
  SPIF-PROVENANCE-TYPE-001, SPIF-TASK-TYPE-001, SPIF-DELTA-TYPE-001,
  SPIF-ALTS-WEIGHT-TYPE-001, SPIF-HEADER-FLAGS2-TYPE-001,
  SPIF-ALTS-NODES-TYPE-001, SPIF-SIGNATURE-TYPE-001,
  SPIF-MULTISIG-TYPE-001, SPIF-PAYLOAD-NODE-TYPE-001,
  SPIF-TRACE-STEP-TYPE-001, SPIF-NODE-REFS-TYPE-001,
  SPIF-CONFIDENCE-TYPE-001, SPIF-SIGALG-DEFAULT-001,
  SPIF-STREAMING-TYPE-001, SPIF-RESUME-TYPE-001. One discipline: a
  present field must carry its declared type; wrong types fail closed
  as SPIFError, no silent defaults (an omitted signature algorithm
  least of all), and Distribution numerics reject bool explicitly.
- Revocation fail-closed (3 cards): SPIF-REVOCATION-FAILOPEN-001,
  SPIF-TRUST-REVOCATION-FILE-FAILOPEN-001,
  SPIF-INLINE-REVOCATION-TYPE-001. An explicitly supplied revocation
  source that is missing, corrupt, or wrong-typed fails closed.
- Replay identity (2 cards): SPIF-REPLAY-SIGNER-COLLISION-001,
  SPIF-REPLAY-SIGNERSET-INCOMPLETE-001. The ReplayGuard key encodes
  the full attested signer set injectively.
- CLI parity (1 card): SPIF-CLI-MULTISIG-DIVERGENCE-001. Legacy
  verify, inspect --json, and SPIFRenderer agree with the reader on
  multisig envelopes.

Distilled from the loop's preserved probe artifacts (cycles
2026-11-07-1722 through 2026-11-11-1122). Synthetic keys only.
"""
import base64
import hashlib
import json
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typer.testing import CliRunner

from spif import (
    Distribution, Node, Provenance, SPIFDocument, SPIFError, SPIFWriter,
    TraceStep,
)
from spif.cli import app
from spif.crypto import generate_key, load_revocation_list, sign_document
from spif.format import (
    CHUNK_ALTS, CHUNK_CHECKSUM, CHUNK_DELTA, CHUNK_HEADER, CHUNK_MULTISIG,
    CHUNK_PAYLOAD, CHUNK_PARTIAL_TEXT, CHUNK_PROVENANCE, CHUNK_SEMANTIC,
    CHUNK_SIGNATURE, CHUNK_STREAM_RESUME, CHUNK_TASK, CHUNK_TRACE, MAGIC,
)
from spif.reader import SPIFReader
from spif.renderer import SPIFRenderer
from spif.replay import ReplayGuard, SPIFReplayError
from spif.streaming import SPIFStreamReader
from spif.trust import (
    TRUST_REVOKED, TRUST_UNVERIFIABLE, TRUST_VALID, create_revocation,
    save_revocation_list, verify_artifact,
)
from spif.types import Signature

_CHUNK = struct.Struct(">BI")
TS = 1_700_000_000_000


def _b64(key):
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _chunks(data):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _rewrite(data, target, new_payload):
    parts = [data[:len(MAGIC) + 2]]
    for ct, p in _chunks(data):
        if ct == CHUNK_CHECKSUM:
            continue
        if ct == target:
            p = new_payload
        parts.append(_CHUNK.pack(ct, len(p)) + p)
    body = b"".join(parts)
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _chunk(data, target):
    for ct, p in _chunks(data):
        if ct == target:
            return cbor2.loads(p)
    raise AssertionError("chunk missing")


def _mutate(data, target, fn):
    payload = _chunk(data, target)
    fn(payload)
    return _rewrite(data, target, cbor2.dumps(payload, canonical=True))


def _plain_doc():
    return SPIFWriter().encode(SPIFDocument(
        payload=[Node(id="n1", type="fact", value="x")],
        provenance=Provenance(source_model="m", timestamp_ms=TS, nonce="n"),
        trace=[TraceStep(id="s1", type="reason", content="c")],
    ))


def _signed_doc():
    key = generate_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello")],
        provenance=Provenance(source_model="m", timestamp_ms=TS))
    return sign_document(doc, key), _b64(key)


def _assert_rejected(forged, **reader_kw):
    with pytest.raises(SPIFError):
        SPIFReader(**reader_kw).decode(forged)


# ---------------------------------------------------------------------------
# Reader strictness — chunk field types
# ---------------------------------------------------------------------------

def test_provenance_field_types_rejected():
    data = _plain_doc()
    for field, bad in [("source_model", 7), ("temperature", "hot"),
                       ("timestamp_ms", "now"), ("timestamp_ms", -5),
                       ("attempt", "1"), ("nonce", 42), ("input_hash", 3)]:
        forged = _mutate(data, CHUNK_PROVENANCE,
                         lambda p, f=field, b=bad: p.__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
    forged = _rewrite(data, CHUNK_PROVENANCE, cbor2.dumps([1, 2], canonical=True))
    _assert_rejected(forged, require_signature=False)


def test_task_field_types_rejected():
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="x")])
    from spif.types import TaskInfo
    doc.task_info = TaskInfo(task_id="t1", attempt=1, total_ms=5)
    data = SPIFWriter().encode(doc)
    for field, bad in [("task_id", 7), ("attempt", "1"), ("status", 3),
                       ("total_ms", "5"), ("tool_count", "2"),
                       ("error_count", 1.5)]:
        forged = _mutate(data, CHUNK_TASK,
                         lambda p, f=field, b=bad: p.__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
    forged = _rewrite(data, CHUNK_TASK, cbor2.dumps([], canonical=True))
    _assert_rejected(forged, require_signature=False)


def test_delta_field_types_rejected():
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="x")])
    from spif.types import Delta
    doc.delta = Delta(base_hash="abc", changes=[])
    data = SPIFWriter().encode(doc)
    for field, bad in [("base_hash", 7), ("base_hash", ["x"]),
                       ("changes", "x"), ("changes", {"a": 1}),
                       ("changes", 3)]:
        forged = _mutate(data, CHUNK_DELTA,
                         lambda p, f=field, b=bad: p.__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
    forged = _rewrite(data, CHUNK_DELTA, cbor2.dumps([], canonical=True))
    _assert_rejected(forged, require_signature=False)


def _alts_doc():
    from spif.types import Alternative
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="x")])
    doc.alternatives = [Alternative(
        weight=1.0, nodes=[Node(id="a1", type="fact", value="y")])]
    return SPIFWriter().encode(doc)


def test_alts_weight_and_nodes_types_rejected_both_forms():
    data = _alts_doc()
    # v0.2 wrapped form
    for field, bad in [("weight", "1.0"), ("weight", [1.0]), ("weight", None),
                       ("nodes", 3), ("nodes", 1.5), ("nodes", None),
                       ("nodes", {"id": "a1"}), ("nodes", "a1")]:
        def mut(p, f=field, b=bad):
            p["alts"][0][f] = b
        _assert_rejected(_mutate(data, CHUNK_ALTS, mut), require_signature=False)
    # v0.1 bare-list form
    wrapped = _chunk(data, CHUNK_ALTS)
    bare = _rewrite(data, CHUNK_ALTS, cbor2.dumps(wrapped["alts"], canonical=True))
    for field, bad in [("weight", "1.0"), ("weight", None), ("nodes", 3)]:
        def mut(p, f=field, b=bad):
            p[0][f] = b
        _assert_rejected(_mutate(bare, CHUNK_ALTS, mut), require_signature=False)
    # ALTS as a bare string is not an alts chunk at all
    forged = _rewrite(data, CHUNK_ALTS, cbor2.dumps("nope", canonical=True))
    _assert_rejected(forged, require_signature=False)


def test_header_flags2_types_rejected():
    data = _plain_doc()
    for bad in ["3", 1.5, [3], {"x": 1}, None]:
        forged = _mutate(data, CHUNK_HEADER,
                         lambda p, b=bad: p.__setitem__("flags2", b))
        _assert_rejected(forged, require_signature=False)
    forged = _rewrite(data, CHUNK_HEADER, cbor2.dumps("hdr", canonical=True))
    _assert_rejected(forged, require_signature=False)


def test_semantic_types_rejected():
    from spif.types import SemanticLayer
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="x")])
    doc.semantic = SemanticLayer(
        embedding=[0.1, 0.2], embedding_model="m", covariance=[[0.1, 0.0]])
    data = SPIFWriter().encode(doc)
    cases = [
        lambda p: p.__setitem__("embedding", "vec"),
        lambda p: p.__setitem__("embedding", ["0.1", 0.2]),
        lambda p: p.__setitem__("embedding", [True, 0.2]),
        lambda p: p.__setitem__("embedding", [[0.1], 0.2]),
        lambda p: p.__setitem__("embedding_model", 7),
        lambda p: p.__setitem__("covariance", "cov"),
        lambda p: p.__setitem__("covariance", [0.1, 0.2]),
        lambda p: p.__setitem__("covariance", [["x"]]),
    ]
    for mut in cases:
        _assert_rejected(_mutate(data, CHUNK_SEMANTIC, mut),
                         require_signature=False)
    forged = _rewrite(data, CHUNK_SEMANTIC, cbor2.dumps([], canonical=True))
    _assert_rejected(forged, require_signature=False)


def test_node_and_step_identity_types_rejected():
    data = _plain_doc()
    for field, bad in [("id", 7), ("id", ["n1"]), ("type", 7), ("type", ["fact"])]:
        forged = _mutate(data, CHUNK_PAYLOAD,
                         lambda p, f=field, b=bad: p[0].__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
        forged = _mutate(data, CHUNK_TRACE,
                         lambda p, f=field, b=bad: p["steps"][0].__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)


def test_node_refs_element_types_rejected():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="fact", value="x"),
        Node(id="n2", type="fact", value="y", refs=[]),
    ])
    data = SPIFWriter().encode(doc)
    for bad in [7, ["n1"], {"node_id": "n1"}, 1.5]:
        forged = _mutate(data, CHUNK_PAYLOAD,
                         lambda p, b=bad: p[1].__setitem__("refs", [b]))
        _assert_rejected(forged, require_signature=False)


def test_trace_step_deps_element_types_rejected():
    data = _plain_doc()
    forged = _mutate(data, CHUNK_TRACE,
                     lambda p: p["steps"][0].__setitem__("deps", [["s0"]]))
    _assert_rejected(forged, require_signature=False)


# ---------------------------------------------------------------------------
# Reader strictness — Distribution
# ---------------------------------------------------------------------------

def _conf(**over):
    d = {"mean": 0.5, "var": 0.1, "shape": "gaussian",
         "semantics": "epistemic", "p5": 0.1, "p95": 0.9}
    d.update(over)
    return d


def test_confidence_field_types_rejected():
    data = _plain_doc()
    for over in [dict(semantics=7), dict(semantics=["epistemic"]),
                 dict(shape=7), dict(shape=["gaussian"])]:
        forged = _mutate(data, CHUNK_PAYLOAD,
                         lambda p, o=over: p[0].__setitem__("confidence", _conf(**o)))
        _assert_rejected(forged, require_signature=False)
        forged = _mutate(data, CHUNK_TRACE,
                         lambda p, o=over: p["steps"][0].__setitem__("confidence", _conf(**o)))
        _assert_rejected(forged, require_signature=False)


def test_confidence_numeric_types_rejected():
    data = _plain_doc()
    for over in [dict(mean=True), dict(mean="0.5"), dict(mean=[0.5]),
                 dict(var=True), dict(var="wide"), dict(p5=True),
                 dict(p95="high")]:
        forged = _mutate(data, CHUNK_PAYLOAD,
                         lambda p, o=over: p[0].__setitem__("confidence", _conf(**o)))
        _assert_rejected(forged, require_signature=False)
    # A well-formed plain-dict confidence still decodes (control).
    forged = _mutate(data, CHUNK_PAYLOAD,
                     lambda p: p[0].__setitem__("confidence", _conf()))
    doc = SPIFReader(require_signature=False).decode(forged)
    assert doc.payload[0].confidence.mean == 0.5


def test_distribution_type_validation_direct():
    with pytest.raises(TypeError):
        Distribution(mean=True)
    with pytest.raises(TypeError):
        Distribution(mean=0.5, semantics=7)
    with pytest.raises(TypeError):
        Distribution(mean=0.5, shape=["gaussian"])
    with pytest.raises(TypeError):
        Distribution.from_dict(_conf(var="wide"))


# ---------------------------------------------------------------------------
# Reader strictness — signature entries (types + no algorithm default)
# ---------------------------------------------------------------------------

def test_signature_field_types_rejected():
    data, _signer = _signed_doc()
    for field, bad in [("signer", 7), ("signer", ["x"]), ("signature", "sig"),
                       ("signature", 7), ("key_id", 7), ("algorithm", 7)]:
        forged = _mutate(data, CHUNK_SIGNATURE,
                         lambda p, f=field, b=bad: p.__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
    # A genuine signed envelope still decodes (control).
    SPIFReader(require_signature=False).decode(data)


def test_signature_algorithm_omitted_rejected():
    data, _signer = _signed_doc()
    forged = _mutate(data, CHUNK_SIGNATURE, lambda p: p.pop("algorithm"))
    _assert_rejected(forged, require_signature=True)
    _assert_rejected(forged, require_signature=False)


def _multisig_doc(keys):
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="multi")],
        provenance=Provenance(source_model="m", timestamp_ms=TS))
    doc.signatures = [Signature(algorithm="ed25519", signer="x",
                                signature=b"\x00" * 64)]
    dummy = SPIFWriter().encode(doc)
    off = len(MAGIC) + 2
    body = None
    while off < len(dummy):
        ct, ln = _CHUNK.unpack_from(dummy, off)
        if ct in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            body = dummy[:off]
            break
        off += 5 + ln
    assert body is not None
    doc.signatures = [Signature(algorithm="ed25519", signer=_b64(k),
                                signature=k.sign(body)) for k in keys]
    return SPIFWriter().encode(doc)


def test_multisig_field_types_and_algorithm_omission_rejected():
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    data = _multisig_doc([k1, k2])
    for field, bad in [("signer", 7), ("signature", "sig"), ("key_id", 7),
                       ("algorithm", 7)]:
        forged = _mutate(data, CHUNK_MULTISIG,
                         lambda p, f=field, b=bad: p[0].__setitem__(f, b))
        _assert_rejected(forged, require_signature=False)
    forged = _mutate(data, CHUNK_MULTISIG, lambda p: p[0].pop("algorithm"))
    _assert_rejected(forged, require_signature=True)
    forged = _mutate(data, CHUNK_MULTISIG,
                     lambda p: [e.pop("algorithm") for e in p])
    _assert_rejected(forged, require_signature=True)
    # Control: the genuine multisig verifies.
    assert SPIFReader().verify_signature(data) is True


# ---------------------------------------------------------------------------
# Streaming strictness
# ---------------------------------------------------------------------------

def _stream(chunk_type, payload_dict):
    p = cbor2.dumps(payload_dict, canonical=True)
    return MAGIC + bytes([0x02, 0x00]) + _CHUNK.pack(chunk_type, len(p)) + p


def test_partial_text_field_types_fail_closed():
    good = SPIFStreamReader().feed(_stream(
        CHUNK_PARTIAL_TEXT, {"node_id": "main", "seq": 1, "text": "hello"}))
    assert [e.type for e in good].count("partial_text") == 1
    for payload in [dict(node_id="main", seq=1, text=["x"]),
                    dict(node_id="main", seq=1, text=42),
                    dict(node_id=123, seq=1, text="hi")]:
        evs = SPIFStreamReader().feed(_stream(CHUNK_PARTIAL_TEXT, payload))
        assert not any(e.type == "partial_text" for e in evs)
        assert any(e.type == "error" for e in evs)


def test_stream_resume_field_types_fail_closed():
    from spif.streaming import _parse_resume_token
    good = SPIFStreamReader().feed(_stream(
        CHUNK_STREAM_RESUME, {"seq": 3, "body_hash": b"\x01" * 32}))
    resumed = [e for e in good if e.type == "resumed"]
    assert len(resumed) == 1
    assert _parse_resume_token(resumed[0].resume_token) == (3, b"\x01" * 32)
    for payload in [dict(seq=3, body_hash=32),
                    dict(seq=3, body_hash=[0] * 32),
                    dict(seq=3, body_hash=b"\x01" * 3),
                    dict(seq=True, body_hash=b"\x01" * 32)]:
        evs = SPIFStreamReader().feed(_stream(CHUNK_STREAM_RESUME, payload))
        assert not any(e.type == "resumed" for e in evs)
        assert any(e.type == "error" for e in evs)


# ---------------------------------------------------------------------------
# Revocation fail-closed
# ---------------------------------------------------------------------------

def test_load_revocation_list_corrupt_and_wrong_shape_raise(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SPIFError):
        load_revocation_list(bad)
    shape = tmp_path / "shape.json"
    shape.write_text(json.dumps(["not", "a", "dict"]))
    with pytest.raises(SPIFError):
        load_revocation_list(shape)
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"revoked": "signer-a"}))
    with pytest.raises(SPIFError):
        load_revocation_list(wrong)
    # Documented legacy contract: absent file loads as the empty set.
    assert load_revocation_list(tmp_path / "absent.json") == set()


def test_reader_revocation_source_fails_closed(tmp_path):
    data, signer = _signed_doc()
    missing = str(tmp_path / "does-not-exist.json")
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=True,
                   revocation_list_path=missing).decode(data)
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=True).verify_signature(
            data, revocation_list_path=missing)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=True,
                   revocation_list_path=str(bad)).decode(data)
    # Controls: present file — revoked signer rejected, other accepted.
    present = tmp_path / "rev.json"
    present.write_text(json.dumps({"revoked": [signer]}))
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=True,
                   revocation_list_path=str(present)).decode(data)
    present.write_text(json.dumps({"revoked": ["someone-else"]}))
    SPIFReader(require_signature=True,
               revocation_list_path=str(present)).decode(data)


def test_trust_revocation_file_fails_closed(tmp_path):
    key = generate_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello world")],
        provenance=Provenance(source_model="test-model", timestamp_ms=TS))
    signed = sign_document(doc, key)
    assert verify_artifact(signed).trust_status == TRUST_VALID
    # Missing explicitly supplied file: not VALID.
    report = verify_artifact(signed, revocation_file=tmp_path / "absent.json")
    assert report.trust_status == TRUST_UNVERIFIABLE
    # Corrupt file: not VALID, error surfaced.
    stmt = create_revocation(signed, key, reason="compromised")
    path = tmp_path / "revocations.json"
    save_revocation_list([stmt], path)
    path.write_text(path.read_text()[:20])
    report = verify_artifact(signed, revocation_file=path)
    assert report.errors
    assert report.trust_status != TRUST_VALID
    # Wrong-shape file: not VALID.
    path.write_text(json.dumps({"unexpected": []}))
    report = verify_artifact(signed, revocation_file=path)
    assert report.trust_status != TRUST_VALID
    # Control: a valid revocation file still marks the artifact REVOKED.
    save_revocation_list([stmt], path)
    report = verify_artifact(signed, revocation_file=path)
    assert report.trust_status == TRUST_REVOKED


def test_inline_revocations_wrong_types_counted_not_raised():
    _data_key = generate_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello")],
        provenance=Provenance(source_model="m", timestamp_ms=TS))
    signed = sign_document(doc, _data_key)
    for bad in ["not-a-statement", 12345, None]:
        report = verify_artifact(signed, revocations=[bad])
        assert report.forged_revocations >= 1
        assert report.errors
    report = verify_artifact(signed, revocations=[{"bogus": True}])
    assert report.trust_status == TRUST_VALID
    assert report.forged_revocations >= 1


# ---------------------------------------------------------------------------
# Replay identity
# ---------------------------------------------------------------------------

def _replay_doc(nonce, multisig):
    doc = SPIFDocument(
        payload=[Node(id="r", type="text", value="hi",
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce))
    doc.signatures = [Signature(algorithm="ed25519", signer=s,
                                signature=b"\x00" * 64) for s in multisig]
    return doc


def test_replay_signer_set_collision_pairs_are_distinct():
    guard = ReplayGuard()
    guard.check(_replay_doc("n1", ["alice+bob"]))
    guard.check(_replay_doc("n1", ["alice", "bob"]))  # must NOT raise
    guard = ReplayGuard()
    guard.check(_replay_doc("n2", ["a+b", "c"]))
    guard.check(_replay_doc("n2", ["a", "b+c"]))      # must NOT raise


def test_replay_same_set_any_order_still_raises():
    guard = ReplayGuard()
    guard.check(_replay_doc("n-ctl", ["alice", "bob"]))
    with pytest.raises(SPIFReplayError):
        guard.check(_replay_doc("n-ctl", ["bob", "alice"]))


# ---------------------------------------------------------------------------
# CLI / renderer parity on multisig envelopes
# ---------------------------------------------------------------------------

def test_cli_verify_multisig_parity(tmp_path):
    runner = CliRunner()
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    genuine = tmp_path / "multi.spif"
    genuine.write_bytes(_multisig_doc([k1, k2]))
    result = runner.invoke(app, ["verify", str(genuine)])
    assert result.exit_code == 0
    assert "VALID" in result.output

    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="multi")],
        provenance=Provenance(source_model="m", timestamp_ms=TS))
    body_holder = _multisig_doc([k1])
    decoded = SPIFReader(require_signature=False).decode(body_holder)
    body = None
    off = len(MAGIC) + 2
    while off < len(body_holder):
        ct, ln = _CHUNK.unpack_from(body_holder, off)
        if ct in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            body = body_holder[:off]
            break
        off += 5 + ln
    attacker = Ed25519PrivateKey.generate()
    doc.signatures = [
        Signature(algorithm="ed25519", signer=_b64(k1), signature=k1.sign(body)),
        Signature(algorithm="ed25519", signer=_b64(attacker),
                  signature=b"\x00" * 64),
    ]
    forged = tmp_path / "forged.spif"
    forged.write_bytes(SPIFWriter().encode(doc))
    result = runner.invoke(app, ["verify", str(forged)])
    assert result.exit_code == 1
    assert "INVALID" in result.output
    assert decoded is not None  # (decode premise used above)


def test_cli_inspect_and_renderer_multisig_parity(tmp_path):
    runner = CliRunner()
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    data = _multisig_doc([k1, k2])
    path = tmp_path / "multi.spif"
    path.write_bytes(data)

    result = runner.invoke(app, ["inspect", "--json", str(path)])
    assert result.exit_code == 0
    info = json.loads(result.output)
    assert info["signed"] is True
    assert info["signer"]

    result = runner.invoke(app, ["inspect", "--layer", "signature", str(path)])
    assert result.exit_code == 0
    assert "SIGNATURE  none" not in result.output
    assert _b64(k1)[:16] in result.output

    rendered = SPIFRenderer().render(
        SPIFReader(require_signature=False).decode(data))
    assert "SIGNATURE unsigned" not in rendered
    assert "present" in rendered
    assert _b64(k1) in rendered and _b64(k2) in rendered
