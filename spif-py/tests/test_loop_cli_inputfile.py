"""Loop probe 2026-11-12-2322 (NEW): CLI verify on a missing or truncated
input file must fail closed cleanly.
Trigger: an operator scripts `spif verify <path>` in a pipeline; the file
is a typo/unmounted path (missing) or a partial download/copy (truncated).
Actor: downstream consumer scripting the CLI; no key needed.
Preconditions: a genuine synthetic signed envelope verifying VALID.
Hostile steps: verify a missing path (plain and --trust) and a truncated
copy (first half of the genuine bytes).
Invariant: malformed/unreadable inputs fail closed with a clean rejection
(non-zero exit, non-VALID, no unhandled exception/traceback a caller could
mistake for a crash) -- never VALID, never an unhandled raise.
Observable evidence: CLI exit code, output text, and result.exception type.
Primary cluster: other (malformed-input robustness).
Scores: realism 4, impact 3, novelty 4, cost 1.
"""
from typer.testing import CliRunner
from spif import SPIFDocument, Node, Provenance, SPIFWriter
from spif.cli import app
from spif.crypto import sign_document, generate_key

runner = CliRunner()
TS = 1_700_000_000_000

def _setup(tmp_path):
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="claim")],
                       provenance=Provenance(source_model="m", timestamp_ms=TS))
    f = tmp_path / "good.spif"
    f.write_bytes(sign_document(doc, generate_key()))
    return f

def _out(r):
    return (r.output or "") + (getattr(r, "stderr", "") or "")

def _clean_failure(r):
    # Clean rejection: non-zero, not VALID, and no unhandled exception
    # (Typer Exit surfaces as SystemExit/None in CliRunner, not the raw error).
    assert r.exit_code != 0, f"accepted: exit={r.exit_code} out={_out(r)}"
    assert "VALID" not in _out(r), _out(r)
    assert r.exception is None or isinstance(r.exception, SystemExit), \
        f"unhandled exception {type(r.exception).__name__}: {r.exception}"

def test_control_genuine_valid(tmp_path):
    f = _setup(tmp_path)
    r = runner.invoke(app, ["verify", str(f)])
    assert r.exit_code == 0 and "VALID" in _out(r), _out(r)

def test_missing_input_plain_fails_closed_cleanly(tmp_path):
    r = runner.invoke(app, ["verify", str(tmp_path / "nope.spif")])
    _clean_failure(r)

def test_missing_input_trust_fails_closed_cleanly(tmp_path):
    r = runner.invoke(app, ["verify", "--trust", str(tmp_path / "nope.spif")])
    _clean_failure(r)

def test_truncated_input_fails_closed_cleanly(tmp_path):
    f = _setup(tmp_path)
    data = f.read_bytes()
    t = tmp_path / "trunc.spif"; t.write_bytes(data[: len(data)//2])
    r = runner.invoke(app, ["verify", str(t)])
    _clean_failure(r)

def test_empty_input_fails_closed_cleanly(tmp_path):
    e = tmp_path / "empty.spif"; e.write_bytes(b"")
    r = runner.invoke(app, ["verify", str(e)])
    _clean_failure(r)
