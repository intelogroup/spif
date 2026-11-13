"""Loop probe 2026-11-12-1722 (NEW): CLI --revocations value wrong TYPE.

Trigger: an operator scripts `spif verify --trust --revocations <path>`;
the file is valid JSON and has the "revocations" key, but its VALUE is the
wrong type -- a hand-edited or wrongly generated file: an empty/non-empty
string, an object, a number, or null, instead of a list of statements.
Actor: downstream consumer scripting the CLI; no key needed.
Preconditions: a genuine signed envelope that verifies VALID, and a trust
revocation file that revokes its signer when actually loaded.
Hostile steps: invoke the CLI with each wrong-typed revocation value.
Invariant: an explicitly supplied revocation source whose "revocations"
value is not a list of statements must fail closed (non-zero exit,
non-VALID verdict) -- never silently verify as if no revocations exist.
Sibling of SPIF-CLI-REVOCATION-WRONGSHAPE-001 (key absent / legacy key);
this probe covers the key present with a wrong-typed value, which a
missing-key check alone cannot fix. Loader analysis: trust.py:288 does
`[from_json_dict(d) for d in data.get("revocations", [])]` -- a non-empty
string/dict iterates into from_json_dict and should raise (fail closed via
the CLI wrapper), but an EMPTY string or EMPTY dict iterates zero times
and silently loads as zero statements.
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
    return f, empty, revoking, signer


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


def _must_fail_closed(r):
    assert r.exit_code != 0, f"wrong-typed revocation value silently accepted: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r) or "UNVERIFIABLE" in _out(r), _out(r)


def _run_with_value(tmp_path, value):
    f, *_ = _setup(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"revocations": value}))
    return runner.invoke(app, ["verify", "--trust", "--revocations", str(bad), str(f)])


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


def test_empty_string_value_must_fail_closed(tmp_path):
    _must_fail_closed(_run_with_value(tmp_path, ""))


def test_empty_object_value_must_fail_closed(tmp_path):
    _must_fail_closed(_run_with_value(tmp_path, {}))


def test_nonempty_string_value_must_fail_closed(tmp_path):
    f, _, _, signer = _setup(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"revocations": signer}))
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(bad), str(f)])
    _must_fail_closed(r)


def test_number_value_must_fail_closed(tmp_path):
    _must_fail_closed(_run_with_value(tmp_path, 123))


def test_null_value_must_fail_closed(tmp_path):
    _must_fail_closed(_run_with_value(tmp_path, None))


def test_object_with_signer_value_must_fail_closed(tmp_path):
    f, _, _, signer = _setup(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"revocations": {"signer": signer}}))
    r = runner.invoke(app, ["verify", "--trust", "--revocations", str(bad), str(f)])
    _must_fail_closed(r)
