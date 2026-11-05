"""Reader validation rules — regression tests for the scoped adversarial
learning loop cards closed by the 2026-11-05 reader-validation change:

- Position binding (SPIF-TASK-GRAFT-001, SPIF-PROV-GRAFT-001, incl. the
  SEMANTIC/TRACE/ALTS/DELTA legs): a content chunk is attested only inside
  the signing body. Any content chunk after the SIGNATURE/MULTISIG chunk
  is a format error at decode, for every content type — one general rule,
  not per-type guards.
- Entry validation (SPIF-DUPMULTISIG-ENTRY-001,
  SPIF-MULTISIG-ENTRYTYPE-001, SPIF-ALTSDELTA-MISSINGKEY-001): MULTISIG
  entries must be dicts and each signer may appear at most once; ALTS
  entries must carry weight/nodes; DELTA must carry base_hash. Violations
  raise SPIFFormatError — never a bare AttributeError/KeyError.

Built from the loop's preserved probe artifacts (cycles 2026-11-04-1722,
-2022, -2322, 2026-11-05-0222, -0522, -0822). Synthetic keys only.
"""
import base64
import hashlib
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    Alternative, Delta, Node, Provenance, SPIFDocument, SemanticLayer,
    SPIFError, SPIFWriter, TraceStep,
)
from spif.crypto import generate_key, sign_document
from spif.format import (
    CHUNK_ALTS, CHUNK_CHECKSUM, CHUNK_DELTA, CHUNK_PROVENANCE, CHUNK_ROLES,
    CHUNK_SEMANTIC, CHUNK_SIGNATURE, CHUNK_MULTISIG, CHUNK_TASK, CHUNK_TRACE,
    MAGIC,
)
from spif.reader import SPIFFormatError, SPIFReader
from spif.trust import verify_artifact
from spif.types import Signature, TaskInfo

_CHUNK = struct.Struct(">BI")
TS = 1_700_000_000_000
VICTIM = generate_key()
ATTACKER = generate_key()
SECOND = generate_key()


def _b64(key):
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _chunks(data):
    off = len(MAGIC) + 2
    out = []
    while off < len(data):
        ct, ln = _CHUNK.unpack_from(data, off)
        out.append((ct, off, data[off + 5: off + 5 + ln]))
        off += 5 + ln
        if ct == CHUNK_CHECKSUM:
            break
    return out


def _raw_chunk(data, ctype):
    for ct, _off, payload in _chunks(data):
        if ct == ctype:
            return _CHUNK.pack(ct, len(payload)) + payload
    return None


def _seal(body):
    return body + _CHUNK.pack(CHUNK_CHECKSUM, 32) + hashlib.sha256(body).digest()


def _graft_after_auth(data, chunk_bytes):
    """Insert chunk_bytes just before CHECKSUM (i.e. after the auth chunk
    of a signed document), recomputing the plain SHA-256 checksum."""
    csum_off = next(off for ct, off, _ in _chunks(data) if ct == CHUNK_CHECKSUM)
    return _seal(data[:csum_off] + chunk_bytes)


def _rewrite_chunk(data, target, new_payload):
    parts = [data[:len(MAGIC) + 2]]
    for ct, _off, p in _chunks(data):
        if ct == CHUNK_CHECKSUM:
            continue
        if ct == target:
            p = new_payload
        parts.append(_CHUNK.pack(ct, len(p)) + p)
    return _seal(b"".join(parts))


def _assert_not_valid(data):
    try:
        rep = verify_artifact(data)
    except SPIFError:
        return
    assert rep.trust_status != "VALID"


# ── Position binding ────────────────────────────────────────────────────

def _bare_doc():
    return SPIFDocument(payload=[Node(id="n1", type="fact", value="victim")])


def _donor_doc():
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value="attacker")],
        provenance=Provenance(source_model="attacker-model-x",
                              timestamp_ms=TS, human_oversight="board-certified-reviewer"),
        semantic=SemanticLayer(embedding=[0.11, 0.22],
                               embedding_model="attacker-model"),
        trace=[TraceStep(id="s1", type="reasoning",
                         content="attacker-fabricated-step")],
        alternatives=[Alternative(weight=1.0, nodes=[
            Node(id="a1", type="fact", value="attacker-alt")])],
        delta=Delta(base_hash="attacker-base-hash",
                    changes=[{"op": "replace", "value": "attacker"}]),
        task_info=TaskInfo(task_id="attacker-run-1", attempt=9, status="ok",
                           total_ms=999, tool_count=99, error_count=0),
        signer_roles={_b64(ATTACKER): "admin"},
    )


GRAFT_TYPES = [CHUNK_PROVENANCE, CHUNK_SEMANTIC, CHUNK_TRACE, CHUNK_ALTS,
               CHUNK_DELTA, CHUNK_TASK, CHUNK_ROLES]


def test_graft_controls_genuine_documents_valid():
    bare = sign_document(_bare_doc(), VICTIM)
    assert verify_artifact(bare).trust_status == "VALID"
    donor = sign_document(_donor_doc(), ATTACKER)
    assert verify_artifact(donor).trust_status == "VALID"
    dec = SPIFReader().decode(donor)
    assert dec.provenance.source_model == "attacker-model-x"
    assert dec.task_info.task_id == "attacker-run-1"
    for ct in GRAFT_TYPES:
        assert _raw_chunk(donor, ct) is not None, f"donor lacks 0x{ct:02x}"
        assert _raw_chunk(bare, ct) is None, f"bare doc carries 0x{ct:02x}"


@pytest.mark.parametrize("ctype", GRAFT_TYPES,
                         ids=[f"0x{ct:02x}" for ct in GRAFT_TYPES])
def test_post_signature_content_graft_rejected(ctype):
    bare = sign_document(_bare_doc(), VICTIM)
    donor = sign_document(_donor_doc(), ATTACKER)
    forged = _graft_after_auth(bare, _raw_chunk(donor, ctype))
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    _assert_not_valid(forged)


def test_post_signature_graft_rejected_for_multisig_doc():
    doc = _genuine_multisig([VICTIM])
    donor = sign_document(_donor_doc(), ATTACKER)
    forged = _graft_after_auth(doc, _raw_chunk(donor, CHUNK_TASK))
    with pytest.raises(SPIFFormatError):
        SPIFReader().decode(forged)
    _assert_not_valid(forged)


def test_revocation_and_timestamp_still_allowed_post_signature():
    # By design: REVOCATION/TIMESTAMP live after the signature and carry
    # their own signed statements. A genuine document using the writer's
    # post-signature chunks must keep decoding (covered by the suite's
    # revocation/timestamp tests); here a signed doc with a revocation
    # for an unrelated signer still decodes without a format error.
    from spif.trust import create_revocation
    doc = sign_document(_bare_doc(), VICTIM)
    rev = create_revocation(doc, VICTIM, reason="retracted")
    d = SPIFReader().decode(doc)
    d.revocations = [rev]
    data = SPIFWriter().encode(d)
    dec = SPIFReader().decode(data)
    assert len(dec.revocations) == 1


# ── MULTISIG entry validation ───────────────────────────────────────────

def _body_of(data):
    for ct, off, _p in _chunks(data):
        if ct in (CHUNK_SIGNATURE, CHUNK_MULTISIG):
            return data[:off]
    raise AssertionError("no auth chunk")


def _genuine_multisig(keys):
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="multi")],
        provenance=Provenance(source_model="m", timestamp_ms=TS))
    doc.signatures = [Signature(algorithm="ed25519", signer="x",
                                signature=b"\x00" * 64)]
    body = _body_of(SPIFWriter().encode(doc))
    doc.signatures = [Signature(algorithm="ed25519", signer=_b64(k),
                                signature=k.sign(body)) for k in keys]
    return SPIFWriter().encode(doc)


def _multisig_entries(data):
    for ct, _off, p in _chunks(data):
        if ct == CHUNK_MULTISIG:
            return cbor2.loads(p)
    raise AssertionError("no multisig chunk")


def test_control_genuine_multisig_two_signers_valid():
    data = _genuine_multisig([VICTIM, SECOND])
    rep = verify_artifact(data)
    assert rep.trust_status == "VALID"
    assert sorted(rep.signers) == sorted([_b64(VICTIM), _b64(SECOND)])


@pytest.mark.parametrize("bad_entry", ["attacker-string", 12345, ["x"]],
                         ids=["string-entry", "int-entry", "list-entry"])
def test_wrong_typed_multisig_entry_fails_closed(bad_entry):
    forged = _rewrite_chunk(_genuine_multisig([VICTIM]), CHUNK_MULTISIG,
                            cbor2.dumps([bad_entry], canonical=True))
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=False).decode(forged)
    _assert_not_valid(forged)


def test_duplicate_multisig_entry_rejected():
    data = _genuine_multisig([VICTIM])
    entries = _multisig_entries(data)
    forged = _rewrite_chunk(data, CHUNK_MULTISIG,
                            cbor2.dumps(entries + entries, canonical=True))
    with pytest.raises(SPIFFormatError):
        SPIFReader(require_signature=False).decode(forged)
    _assert_not_valid(forged)


def test_duplicate_signer_with_altered_signature_rejected():
    data = _genuine_multisig([VICTIM])
    entries = _multisig_entries(data)
    altered = dict(entries[0])
    altered["signature"] = b"\x01" * 64
    forged = _rewrite_chunk(data, CHUNK_MULTISIG,
                            cbor2.dumps(entries + [altered], canonical=True))
    with pytest.raises(SPIFFormatError):
        SPIFReader(require_signature=False).decode(forged)
    _assert_not_valid(forged)


# ── ALTS / DELTA missing keys ───────────────────────────────────────────

def _alts_doc():
    return SPIFWriter().encode(SPIFDocument(
        payload=[Node(id="n1", type="fact", value="x")],
        alternatives=[Alternative(weight=1.0, nodes=[
            Node(id="a1", type="fact", value="alt")])]))


def _delta_doc():
    return SPIFWriter().encode(SPIFDocument(
        payload=[Node(id="n1", type="fact", value="x")],
        delta=Delta(base_hash="abc123", changes=[])))


def test_control_alts_and_delta_decode():
    dec_a = SPIFReader(require_signature=False).decode(_alts_doc())
    dec_d = SPIFReader(require_signature=False).decode(_delta_doc())
    assert len(dec_a.alternatives) == 1
    assert dec_d.delta.base_hash == "abc123"


@pytest.mark.parametrize("payload", [
    cbor2.dumps([{"nodes": []}], canonical=True),
    cbor2.dumps([{"weight": 1.0}], canonical=True),
    cbor2.dumps({"normalized": True, "alts": [{"nodes": []}]}, canonical=True),
], ids=["alts-v1-missing-weight", "alts-v1-missing-nodes",
        "alts-v2-missing-weight"])
def test_alts_missing_key_fails_closed(payload):
    forged = _rewrite_chunk(_alts_doc(), CHUNK_ALTS, payload)
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=False).decode(forged)
    _assert_not_valid(forged)


def test_delta_missing_base_hash_fails_closed():
    forged = _rewrite_chunk(_delta_doc(), CHUNK_DELTA,
                            cbor2.dumps({"changes": []}, canonical=True))
    with pytest.raises(SPIFError):
        SPIFReader(require_signature=False).decode(forged)
    _assert_not_valid(forged)
