"""Loop probe 2026-11-13-1122 (NEW): CLI output destinations that cannot be
written must fail closed cleanly, without corrupting the input.

Trigger: an operator scripts `spif export` / `spif sign` in a pipeline; the
--output path is a directory by mistake, or its parent directory does not
exist (typo, unmounted share, not-yet-created results folder).
Actor: downstream consumer / signing operator scripting the CLI; no hostile
key needed -- the failure is a crash on a routine operational error.
Preconditions: a genuine synthetic envelope; export to a real file and sign
to a real output file both succeed (controls).
Hostile steps: export --lossless-json and export --msgpack with --output
pointing at an existing directory; export --lossless-json with --output
under a missing parent; sign with --output pointing at a directory; sign
with --output under a missing parent.
Invariant: an explicitly supplied output destination that cannot be written
must fail closed with a clean rejection (non-zero exit, no unhandled
exception) -- never a crash -- and the input file must remain byte-identical.
Observable evidence: CLI exit code, output, result.exception type, and the
input file's bytes before/after per leg.
Primary cluster: other (malformed-input / output handling robustness).
Scores: realism 4, impact 2, novelty 3, cost 1.
"""
import os
from typer.testing import CliRunner
from spif import SPIFDocument, Node, Provenance
from spif.cli import app
from spif.crypto import sign_document, generate_key

runner = CliRunner()
TS = 1_700_000_000_000


def _setup(tmp_path):
    doc = SPIFDocument(payload=[Node(id="n1", type="text", value="hello")],
                       provenance=Provenance(source_model="m", timestamp_ms=TS))
    f = tmp_path / "doc.spif"
    f.write_bytes(sign_document(doc, generate_key()))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    key = Ed25519PrivateKey.generate()
    k = tmp_path / "key.bin"
    k.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    return f, k


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


def _clean_fail(r):
    assert r.exit_code != 0, f"accepted exit={r.exit_code} out={_out(r)}"
    assert r.exception is None or isinstance(r.exception, SystemExit), \
        f"unhandled {type(r.exception).__name__}: {r.exception}"


# Controls
def test_control_export_json_to_file(tmp_path):
    f, _ = _setup(tmp_path)
    out = tmp_path / "out.json"
    r = runner.invoke(app, ["export", "--lossless-json", "--output", str(out), str(f)])
    assert r.exit_code == 0 and out.exists(), _out(r)


def test_control_export_msgpack_to_file(tmp_path):
    f, _ = _setup(tmp_path)
    out = tmp_path / "out.msgpack"
    r = runner.invoke(app, ["export", "--msgpack", "--output", str(out), str(f)])
    assert r.exit_code == 0 and out.exists(), _out(r)


def test_control_sign_to_output_file(tmp_path):
    f, k = _setup(tmp_path)
    out = tmp_path / "signed.spif"
    r = runner.invoke(app, ["sign", str(f), "--key", str(k), "--output", str(out)])
    assert r.exit_code == 0 and out.exists(), _out(r)
    v = runner.invoke(app, ["verify", str(out)])
    assert v.exit_code == 0 and "VALID" in _out(v), _out(v)


# Hostile legs: output is a directory
def test_export_json_output_is_directory(tmp_path):
    f, _ = _setup(tmp_path)
    before = f.read_bytes()
    d = tmp_path / "adir"; d.mkdir()
    _clean_fail(runner.invoke(app, ["export", "--lossless-json", "--output", str(d), str(f)]))
    assert f.read_bytes() == before


def test_export_msgpack_output_is_directory(tmp_path):
    f, _ = _setup(tmp_path)
    before = f.read_bytes()
    d = tmp_path / "adir"; d.mkdir()
    _clean_fail(runner.invoke(app, ["export", "--msgpack", "--output", str(d), str(f)]))
    assert f.read_bytes() == before


def test_sign_output_is_directory(tmp_path):
    f, k = _setup(tmp_path)
    before = f.read_bytes()
    d = tmp_path / "adir"; d.mkdir()
    _clean_fail(runner.invoke(app, ["sign", str(f), "--key", str(k), "--output", str(d)]))
    assert f.read_bytes() == before


# Hostile legs: output parent does not exist
def test_export_json_output_missing_parent(tmp_path):
    f, _ = _setup(tmp_path)
    before = f.read_bytes()
    out = tmp_path / "no-such-dir" / "out.json"
    _clean_fail(runner.invoke(app, ["export", "--lossless-json", "--output", str(out), str(f)]))
    assert f.read_bytes() == before


def test_sign_output_missing_parent(tmp_path):
    f, k = _setup(tmp_path)
    before = f.read_bytes()
    out = tmp_path / "no-such-dir" / "signed.spif"
    _clean_fail(runner.invoke(app, ["sign", str(f), "--key", str(k), "--output", str(out)]))
    assert f.read_bytes() == before
