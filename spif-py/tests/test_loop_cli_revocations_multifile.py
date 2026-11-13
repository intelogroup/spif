"""Loop probe 2026-11-11-2322 (NEW): CLI --revocations multi-file composition.

Trigger: an operator's verify script passes several --revocations files
(team lists concatenated by automation); one path is typo'd/missing or in
the legacy {"revoked": [...]} shape, while another file loads fine but
does not revoke this signer.
Actor: downstream consumer scripting the CLI; no key needed.
Preconditions: a genuine signed envelope that verifies VALID; one
well-formed non-revoking revocation file.
Hostile steps: invoke the CLI with (valid non-revoking + missing) and
(valid non-revoking + legacy-shape) file pairs, in both orders.
Invariant: if ANY explicitly supplied revocation source cannot be loaded
as a well-formed trust revocation list, the CLI must fail closed
(non-zero exit, non-VALID verdict) -- a sibling file loading fine must
not mask the broken one.
Observable evidence: CLI exit code + verdict text per leg.
Primary cluster: authority.
Scores: realism 4, impact 3, novelty 3, cost 1.
"""
import json

from typer.testing import CliRunner

from spif import SPIFDocument, Node, Provenance, SPIFReader
from spif.cli import app
from spif.crypto import sign_document, generate_key
from spif.trust import create_revocation, save_revocation_list

runner = CliRunner()
TS = 1_700_000_000_000


def _setup(tmp_path):
    key = generate_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="text", value="hello")],
                       provenance=Provenance(source_model="m", timestamp_ms=TS))
    data = sign_document(doc, key)
    f = tmp_path / "doc.spif"
    f.write_bytes(data)
    signer = SPIFReader().decode(data).signature.signer
    empty = tmp_path / "empty.json"
    save_revocation_list([], empty)
    revoking = tmp_path / "revoking.json"
    save_revocation_list([create_revocation(data, key)], revoking)
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"revoked": [signer]}))
    missing = tmp_path / "does-not-exist.json"
    return f, empty, revoking, legacy, missing


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


def _must_fail_closed(r):
    assert r.exit_code != 0, f"broken revocation source masked by sibling file: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r) or "UNVERIFIABLE" in _out(r), _out(r)


def test_control_two_valid_files_valid(tmp_path):
    f, empty, *_ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(empty),
                            "--revocations", str(empty), str(f)])
    assert r.exit_code == 0 and "VALID" in _out(r), _out(r)


def test_control_revoking_plus_empty_revoked(tmp_path):
    f, empty, revoking, *_ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(empty),
                            "--revocations", str(revoking), str(f)])
    assert r.exit_code == 1 and "REVOKED" in _out(r), _out(r)


def test_valid_plus_missing_must_fail_closed(tmp_path):
    f, empty, _, _, missing = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(empty),
                            "--revocations", str(missing), str(f)])
    _must_fail_closed(r)


def test_missing_first_must_fail_closed(tmp_path):
    f, empty, _, _, missing = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(missing),
                            "--revocations", str(empty), str(f)])
    _must_fail_closed(r)


def test_valid_plus_legacy_shape_must_fail_closed(tmp_path):
    f, empty, _, legacy, _ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(empty),
                            "--revocations", str(legacy), str(f)])
    _must_fail_closed(r)
