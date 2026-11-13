"""Loop probe 2026-11-11-2022 (NEW): CLI --revocations wrong-shape file fail-open.

Trigger: an operator scripts `spif verify --trust --revocations <path>` and
points it at the wrong file: a directory, a JSON file in the legacy
crypto.load_revocation_list format ({"revoked": [signer ids]} -- the other
revocation format this codebase ships), or any JSON object that lacks the
trust format's "revocations" list.
Actor: downstream consumer scripting the CLI; no key needed.
Preconditions: a genuine signed envelope that verifies VALID, and a trust
revocation file that revokes its signer when actually loaded.
Hostile steps: invoke the CLI with each wrong-shape revocation source.
Invariant: an explicitly supplied revocation source that does not load as a
well-formed trust revocation list must fail closed (non-zero exit,
non-VALID verdict) -- never silently verify as if no revocations exist.
Sibling of SPIF-CLI-REVOCATION-MISSING-001 (absent file); this probe covers
present-but-wrong-shape sources, which an existence check alone cannot fix.
Observable evidence: CLI exit code + verdict text per leg.
Primary cluster: authority.
Scores: realism 4, impact 3, novelty 4, cost 1.
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
    return f, empty, revoking, signer


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


def _must_fail_closed(r):
    assert r.exit_code != 0, f"wrong-shape revocation source silently accepted: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r) or "UNVERIFIABLE" in _out(r), _out(r)


def test_control_no_revocations_valid(tmp_path):
    f, *_ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", str(f)])
    assert r.exit_code == 0 and "VALID" in _out(r), _out(r)


def test_control_empty_revocation_file_valid(tmp_path):
    f, empty, *_ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(empty), str(f)])
    assert r.exit_code == 0 and "VALID" in _out(r), _out(r)


def test_control_revoking_file_revoked(tmp_path):
    f, _, revoking, _ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(revoking), str(f)])
    assert r.exit_code == 1 and "REVOKED" in _out(r), _out(r)


def test_directory_revocation_source_must_fail_closed(tmp_path):
    f, *_ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(tmp_path), str(f)])
    _must_fail_closed(r)


def test_top_level_array_revocation_file_must_fail_closed(tmp_path):
    f, *_ = _setup(tmp_path)
    bad = tmp_path / "array.json"
    bad.write_text("[]")
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(bad), str(f)])
    _must_fail_closed(r)


def test_legacy_format_revocation_file_must_fail_closed(tmp_path):
    f, _, _, signer = _setup(tmp_path)
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"revoked": [signer]}))
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(legacy), str(f)])
    _must_fail_closed(r)


def test_object_without_revocations_key_must_fail_closed(tmp_path):
    f, *_ = _setup(tmp_path)
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"something_else": []}))
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(other), str(f)])
    _must_fail_closed(r)
