"""CLI tests for `spif verify` v1.3 trust surfacing.

Contract:
- With NO trust flags, `spif verify` keeps its legacy behavior and
  output exactly (plain signature check, VALID/INVALID/UNSIGNED,
  exit 0/1/2) — plain v1.0 artifacts must not regress.
- With --trust or any trust input (--revocations, --tsa-key, --bundle,
  --known-key) it prints the trust report from spif.trust and exits
  0 (VALID), 1 (INVALID/REVOKED/UNVERIFIABLE/error), 2 (UNSIGNED).
"""

from __future__ import annotations

import base64

from typer.testing import CliRunner
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, NodeRef, Provenance, SPIFWriter
from spif.cli import app
from spif.crypto import sign_document, generate_key
from spif.trust import (
    create_revocation, attach_revocations, create_timestamp_anchor,
    attach_timestamp, save_revocation_list,
)

runner = CliRunner()


def _b64(key) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _doc(text="hello world", refs=None):
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value=text, refs=refs or [])],
        provenance=Provenance(source_model="test-model", timestamp_ms=1_700_000_000_000),
    )


def _write(tmp_path, name, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _signed_file(tmp_path, name="doc.spif", text="hello world"):
    key = generate_key()
    return key, _write(tmp_path, name, sign_document(_doc(text), key))


def _out(result) -> str:
    return (result.output or "") + (getattr(result, "stderr", "") or "")


# ---------------------------------------------------------------------------
# Legacy behavior (no trust flags) — must not regress
# ---------------------------------------------------------------------------

def test_legacy_verify_valid(tmp_path):
    _key, path = _signed_file(tmp_path)
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code == 0
    assert _out(result).startswith("VALID")


def test_legacy_verify_unsigned_exit_2(tmp_path):
    path = _write(tmp_path, "plain.spif", SPIFWriter().encode(_doc()))
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code == 2
    assert "UNSIGNED" in _out(result)


def test_legacy_verify_tampered_exit_1(tmp_path):
    key, path = _signed_file(tmp_path)
    data = bytearray(path.read_bytes())
    idx = bytes(data).find(b"hello world")
    data[idx] = ord("H")  # checksum now fails at decode
    path.write_bytes(bytes(data))
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Trust mode
# ---------------------------------------------------------------------------

def test_trust_flag_valid_report(tmp_path):
    _key, path = _signed_file(tmp_path)
    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 0
    out = _out(result)
    assert "VALID" in out and "trust report" in out
    assert "signature: valid" in out
    assert "timestamp: absent" in out
    assert "forged revocations" not in out  # printed only when nonzero


def test_trust_unsigned_exit_2(tmp_path):
    path = _write(tmp_path, "plain.spif", SPIFWriter().encode(_doc()))
    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 2
    assert "UNSIGNED" in _out(result)


def test_trust_embedded_revocation_reports_revoked(tmp_path):
    key, path = _signed_file(tmp_path)
    data = attach_revocations(
        path.read_bytes(), [create_revocation(path.read_bytes(), key)])
    path.write_bytes(data)
    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 1
    out = _out(result)
    assert "REVOKED" in out
    assert "signature: valid" in out  # cryptography sound, trust retracted
    assert "revocations applied: 1" in out


def test_trust_revocation_file_flag(tmp_path):
    key, path = _signed_file(tmp_path)
    stmt = create_revocation(path.read_bytes(), key)
    list_path = tmp_path / "revocations.json"
    save_revocation_list([stmt], list_path)
    result = runner.invoke(
        app, ["verify", "--revocations", str(list_path), str(path)])
    assert result.exit_code == 1
    assert "REVOKED" in _out(result)


def test_trust_forged_revocation_count_printed(tmp_path):
    _key, path = _signed_file(tmp_path)
    attacker = generate_key()
    forged = create_revocation(path.read_bytes(), attacker, reason="compromised")
    list_path = tmp_path / "forged.json"
    save_revocation_list([forged], list_path)
    result = runner.invoke(
        app, ["verify", "--revocations", str(list_path), str(path)])
    assert result.exit_code == 0  # artifact itself stays VALID
    assert "forged revocations: 1" in _out(result)


def test_trust_timestamp_verified_and_unverified(tmp_path):
    _key, path = _signed_file(tmp_path)
    tsa = generate_key()
    anchor = create_timestamp_anchor(path.read_bytes(), tsa)
    path.write_bytes(attach_timestamp(path.read_bytes(), anchor))

    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 0
    assert "timestamp: unverified" in _out(result)

    result = runner.invoke(app, [
        "verify", "--tsa-key", f"{anchor.authority}={_b64(tsa)}", str(path)])
    assert result.exit_code == 0
    assert "timestamp: verified" in _out(result)


def test_trust_bundle_resolution_reported(tmp_path):
    up = SPIFDocument(
        payload=[Node(id="n7", type="fact", value="upstream evidence")],
        provenance=Provenance(source_model="retriever", timestamp_ms=1_700_000_000_000),
    )
    ref = f"spif:sha256:{up.content_id()}#n7"
    down_key = generate_key()
    down = _write(tmp_path, "down.spif",
                  sign_document(_doc("derived", refs=[NodeRef(ref)]), down_key))

    result = runner.invoke(app, ["verify", "--trust", str(down)])
    assert result.exit_code == 0
    assert "1 cross-document (0 resolved, 1 unresolved)" in _out(result)

    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "up.spif").write_bytes(SPIFWriter().encode(up))
    result = runner.invoke(
        app, ["verify", "--bundle", str(bundle_dir), str(down)])
    assert result.exit_code == 0
    assert "1 cross-document (1 resolved, 0 unresolved)" in _out(result)


def test_trust_garbage_file_is_clean_invalid(tmp_path):
    path = _write(tmp_path, "garbage.spif", b"\xff" * 64)
    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 1
    # Clean exit via typer.Exit (SystemExit), not a traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "INVALID" in _out(result)


def test_trust_bad_tsa_key_shape_is_clean_error(tmp_path):
    _key, path = _signed_file(tmp_path)
    result = runner.invoke(app, ["verify", "--tsa-key", "no-equals-sign", str(path)])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "ERROR" in _out(result)


def test_trust_known_key_for_url_signer(tmp_path):
    key = generate_key()
    data = sign_document(_doc(), key, signer_id="https://keys.example.test/k.pub")
    path = _write(tmp_path, "url-signer.spif", data)

    result = runner.invoke(app, ["verify", "--trust", str(path)])
    assert result.exit_code == 1
    assert "UNVERIFIABLE" in _out(result)  # key cannot be resolved

    result = runner.invoke(app, [
        "verify", "--known-key",
        f"https://keys.example.test/k.pub={_b64(key)}", str(path)])
    assert result.exit_code == 0
    assert "VALID" in _out(result)
