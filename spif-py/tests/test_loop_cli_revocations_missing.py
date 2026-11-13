"""Loop probe 2026-11-11-1722 (NEW): CLI --revocations missing-file fail-open.

Trigger: an operator scripts `spif verify --trust --revocations <path>` (or
--revocations alone, which implies the trust path) with a mistyped, moved, or
never-mounted revocation file path.
Actor: downstream consumer scripting the CLI; no key needed.
Preconditions: a genuine signed envelope that verifies VALID, and a
revocation file that revokes its signer when actually loaded.
Hostile steps: invoke the CLI with the revocation path pointing at a file
that does not exist.
Invariant: an explicitly supplied revocation source that cannot be loaded
must fail closed (non-zero exit, non-VALID verdict) -- never silently verify
as if no revocations exist. This is the same fail-closed rule PR #108 applied
to verify_artifact(revocation_file=...) and SPIFReader(revocation_list_path).
Observable evidence: CLI exit code + verdict text per leg.
Primary cluster: authority.
Scores: realism 4, impact 3, novelty 4, cost 1.
"""
from typer.testing import CliRunner

from spif import SPIFDocument, Node, Provenance
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
    empty = tmp_path / "empty.json"
    save_revocation_list([], empty)
    revoking = tmp_path / "revoking.json"
    save_revocation_list([create_revocation(data, key)], revoking)
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json")
    return f, empty, revoking, corrupt


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


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


def test_control_corrupt_file_fails_closed(tmp_path):
    f, _, _, corrupt = _setup(tmp_path)
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(corrupt), str(f)])
    assert r.exit_code == 1, _out(r)


def test_missing_revocation_file_must_fail_closed(tmp_path):
    f, *_ = _setup(tmp_path)
    missing = tmp_path / "does-not-exist.json"
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(missing), str(f)])
    assert r.exit_code != 0, f"missing revocation file silently accepted: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r) or "UNVERIFIABLE" in _out(r), _out(r)
