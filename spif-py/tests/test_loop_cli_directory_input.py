"""Loop probe 2026-11-13-1422 (NEW): a directory passed where a SPIF file is
expected must fail closed cleanly on every CLI surface.

Trigger: an operator or pipeline script passes a directory instead of a file
(a glob that expands to a folder, a mount-point path, a mistyped output dir
reused as input).
Actor: downstream consumer / signing operator; no key needed.
Preconditions: a genuine synthetic signed envelope verifying VALID, a real
sign key file, and a directory containing a copy of the envelope.
Hostile steps: invoke verify (plain and --trust), render, export
--lossless-json, validate, inspect, hexdump with the directory as the file
argument; sign with the directory as input; sign with the directory as --key.
Invariant: an unreadable input (here: a directory) fails closed with a clean
rejection (non-zero exit, no VALID/OK success, no unhandled exception) --
never a crash a caller could mistake for a verdict. This is the same
fail-closed rule the guarded bundle read (cli.py, OSError -> ERROR/Exit(1))
already implements.
Observable evidence: CLI exit code + verdict text + result.exception type.
Primary cluster: other (malformed-input robustness).
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
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="claim")],
                       provenance=Provenance(source_model="m", timestamp_ms=TS))
    f = tmp_path / "good.spif"
    f.write_bytes(sign_document(doc, generate_key()))
    k = tmp_path / "key.bin"
    k.write_bytes(os.urandom(32))
    d = tmp_path / "adir"
    d.mkdir()
    (d / "inner.spif").write_bytes(f.read_bytes())
    return f, k, d


def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")


def _clean(r):
    assert r.exit_code != 0, f"accepted: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r) and not _out(r).startswith("OK"), _out(r)
    assert r.exception is None or isinstance(r.exception, SystemExit), \
        f"unhandled {type(r.exception).__name__}: {r.exception}"


def test_control_verify_valid(tmp_path):
    f, _, _ = _setup(tmp_path)
    r = runner.invoke(app, ["verify", str(f)])
    assert r.exit_code == 0 and "VALID" in _out(r), _out(r)


def test_control_validate_ok(tmp_path):
    f, _, _ = _setup(tmp_path)
    r = runner.invoke(app, ["validate", str(f)])
    assert r.exit_code == 0, _out(r)


def test_control_sign_ok(tmp_path):
    f, k, _ = _setup(tmp_path)
    out = tmp_path / "signed.spif"
    r = runner.invoke(app, ["sign", str(f), "--key", str(k), "--output", str(out)])
    assert r.exit_code == 0 and out.exists(), _out(r)


def test_dir_verify(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["verify", str(d)]))


def test_dir_verify_trust(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["verify", "--trust", str(d)]))


def test_dir_render(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["render", str(d)]))


def test_dir_export(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["export", "--lossless-json", str(d)]))


def test_dir_validate(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["validate", str(d)]))


def test_dir_inspect(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["inspect", str(d)]))


def test_dir_hexdump(tmp_path):
    _, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["hexdump", str(d)]))


def test_dir_sign_input(tmp_path):
    _, k, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["sign", str(d), "--key", str(k)]))


def test_dir_sign_key(tmp_path):
    f, _, d = _setup(tmp_path)
    _clean(runner.invoke(app, ["sign", str(f), "--key", str(d)]))
