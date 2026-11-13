"""Loop probe 2026-11-13-0222 (NEW): sibling CLI commands on a missing input file must fail closed cleanly.
Trigger: operator scripts any spif subcommand in a pipeline; path is typo/unmounted.
Actor: downstream consumer; no key needed.
Preconditions: genuine synthetic signed envelope verifying VALID.
Hostile steps: invoke render, export --lossless-json, validate, inspect, hexdump, sign (missing input, and sign with missing key file) on a missing path.
Invariant: malformed/unreadable inputs fail closed with clean rejection (non-zero, no VALID/OK success, no unhandled exception) -- never a crash.
Evidence: exit code, output, result.exception type.
Cluster: other (malformed-input robustness). Scores: realism 4, impact 3, novelty 3, cost 1.
"""
from typer.testing import CliRunner
from spif import SPIFDocument, Node, Provenance
from spif.cli import app
from spif.crypto import sign_document, generate_key
runner = CliRunner()
TS = 1_700_000_000_000
def _setup(tmp_path):
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="claim")], provenance=Provenance(source_model="m", timestamp_ms=TS))
    f = tmp_path / "good.spif"; f.write_bytes(sign_document(doc, generate_key()))
    # key file for sign control: raw seed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = tmp_path / "key.bin"; k.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw() if hasattr(Ed25519PrivateKey.generate(), 'private_bytes_raw') else b"\x01"*32)
    # Actually generate raw seed deterministically: use os bytes 32
    import os; k.write_bytes(os.urandom(32))
    return f, k
def _out(r): return (r.output or "") + (getattr(r, "stderr", "") or "")
def _clean(r):
    assert r.exit_code != 0, f"accepted exit={r.exit_code} out={_out(r)}"
    assert r.exception is None or isinstance(r.exception, SystemExit), f"unhandled {type(r.exception).__name__}: {r.exception}"
def test_control_validate_ok(tmp_path):
    f,_=_setup(tmp_path); r=runner.invoke(app, ["validate", str(f)]); assert r.exit_code==0, _out(r)
def test_control_inspect_ok(tmp_path):
    f,_=_setup(tmp_path); r=runner.invoke(app, ["inspect", str(f)]); assert r.exit_code==0, _out(r)
def test_control_hexdump_ok(tmp_path):
    f,_=_setup(tmp_path); r=runner.invoke(app, ["hexdump", str(f)]); assert r.exit_code==0, _out(r)
def test_missing_render(tmp_path): _clean(runner.invoke(app, ["render", str(tmp_path/"nope.spif")]))
def test_missing_export(tmp_path): _clean(runner.invoke(app, ["export", "--lossless-json", str(tmp_path/"nope.spif")]))
def test_missing_validate(tmp_path): _clean(runner.invoke(app, ["validate", str(tmp_path/"nope.spif")]))
def test_missing_inspect(tmp_path): _clean(runner.invoke(app, ["inspect", str(tmp_path/"nope.spif")]))
def test_missing_hexdump(tmp_path): _clean(runner.invoke(app, ["hexdump", str(tmp_path/"nope.spif")]))
def test_missing_sign_input(tmp_path):
    _,k=_setup(tmp_path); _clean(runner.invoke(app, ["sign", str(tmp_path/"nope.spif"), "--key", str(k)]))
def test_missing_sign_key(tmp_path):
    f,_=_setup(tmp_path); _clean(runner.invoke(app, ["sign", str(f), "--key", str(tmp_path/"nope.key")]))
def test_empty_hexdump(tmp_path):
    e=tmp_path/"empty.spif"; e.write_bytes(b""); _clean(runner.invoke(app, ["hexdump", str(e)]))
