"""
Tests for SPIF sidecar proxy, CRL key revocation, and policy enforcement.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error
import urllib
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFDocument, Node, Distribution, Provenance, SPIFWriter, Signature, SPIFReader
from spif.crypto import derive_key_from_mnemonic
from spif.sidecar import CRLClient, PolicyEvaluator, SidecarHTTPHandler, generate_fpr_document, start_sidecar


# Helper to find a free port
def get_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# Helper to sign a document (two-pass)
def sign_doc(doc: SPIFDocument, private_key, signer_id: str) -> bytes:
    import struct
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    assert sig_offset is not None
    body_to_sign = dummy[:sig_offset]
    real_sig = private_key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=real_sig)
    return writer.encode(doc)


# A mock upstream LLM/Gateway server
class MockUpstreamHandler(BaseHTTPRequestHandler):
    spif_response_bytes = b""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.spif_response_bytes:
            # Send the X-Spif header with base64 encoded document
            b64_spif = base64.b64encode(self.spif_response_bytes).decode("utf-8")
            self.send_header("X-Spif", b64_spif)
        self.end_headers()
        self.wfile.write(b'{"choices": [{"text": "Hello world"}]}')


# A mock CRL server
class MockCRLHandler(BaseHTTPRequestHandler):
    crl_data = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.crl_data.encode("utf-8"))


@pytest.fixture
def keys():
    alice = derive_key_from_mnemonic("alice test mnemonic sidecar")
    bob = derive_key_from_mnemonic("bob test mnemonic sidecar")
    alice_pub = base64.b64encode(alice.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("utf-8")
    bob_pub = base64.b64encode(bob.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("utf-8")
    return {"alice_priv": alice, "bob_priv": bob, "alice_pub": alice_pub, "bob_pub": bob_pub}


@pytest.fixture
def tmp_keystore(tmp_path, keys):
    from spif.keystore import SPIFKeyStore
    ks_path = tmp_path / "keys"
    ks = SPIFKeyStore(ks_path)
    ks.add_key(keys["alice_pub"], keys["alice_priv"].public_key())
    ks.add_key(keys["bob_pub"], keys["bob_priv"].public_key())
    return ks_path


@pytest.fixture
def policy_file(tmp_path, keys):
    p_path = tmp_path / "policy.json"
    p_path.write_text(json.dumps({
        "policy_id": "pol_strict_triage",
        "enforcement": "deny_and_alert",
        "allowed_models": ["gemma-4-e2b-vibrion-sentinel"],
        "trusted_signers": [keys["alice_pub"]],
        "minimum_confidence_mean": 0.85,
        "crl_check": {
            "enabled": True,
            "endpoint": "http://127.0.0.1:0/crl"  # dynamic
        }
    }))
    return p_path


def test_crl_client():
    # Test JSON dict parsing
    client = CRLClient("http://dummy")
    client._parse_crl(json.dumps({"revoked": {"key1": 1234, "key2": 5678}}))
    assert client.get_revoked_keys() == {"key1", "key2"}

    # Test JSON list parsing
    client._parse_crl(json.dumps(["key3", "key4"]))
    assert client.get_revoked_keys() == {"key3", "key4"}

    # Test newline-delimited text parsing
    client._parse_crl("key5\nkey6\n# comment\nkey7")
    assert client.get_revoked_keys() == {"key5", "key6", "key7"}


def test_crl_fetch_failure_fails_open_silently():
    """BUG: _fetch_crl() catches every exception from the CRL HTTP fetch and
    falls back to the cached (here, never-populated) _revoked_keys with no
    signal to the caller. A network partition or DNS failure against the CRL
    endpoint silently disables revocation checking instead of failing closed
    — get_revoked_keys() returns an empty set indistinguishable from "nobody
    is revoked", with no exception and no way to detect the outage."""
    unreachable_port = get_free_port()  # nothing listens here
    client = CRLClient(f"http://127.0.0.1:{unreachable_port}/crl", cache_ttl=0)
    # Should have surfaced a connection error; instead fails open.
    assert client.get_revoked_keys() == set()


def test_policy_evaluator(keys, tmp_keystore, policy_file):
    # Create valid doc signed by Alice
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Haiti SRA data analysis success", confidence=Distribution(mean=0.9))],
        provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
    )
    valid_bytes = sign_doc(doc, keys["alice_priv"], keys["alice_pub"])

    evaluator = PolicyEvaluator(policy_path=policy_file, keystore_dir=tmp_keystore)
    res = evaluator.validate_document(valid_bytes)
    assert res["status"] == "valid"

    # Test violating minimum confidence policy
    low_conf_doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Haiti SRA", confidence=Distribution(mean=0.5))],
        provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
    )
    low_conf_bytes = sign_doc(low_conf_doc, keys["alice_priv"], keys["alice_pub"])
    res = evaluator.validate_document(low_conf_bytes)
    assert res["status"] == "invalid"
    assert res["failure_code"] == "SPIF_ERROR_POLICY_VIOLATION"
    assert "confidence" in res["failure_reason"]

    # Test violating allowed_models policy
    wrong_model_doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Haiti SRA", confidence=Distribution(mean=0.9))],
        provenance=Provenance(source_model="shadow-unapproved-model", timestamp_ms=0)
    )
    wrong_model_bytes = sign_doc(wrong_model_doc, keys["alice_priv"], keys["alice_pub"])
    res = evaluator.validate_document(wrong_model_bytes)
    assert res["status"] == "invalid"
    assert res["failure_code"] == "SPIF_ERROR_POLICY_VIOLATION"
    assert "model" in res["failure_reason"].lower()

    # Test unsigned document (policy enforcement = deny_and_alert)
    doc.signature = None
    unsigned_bytes = SPIFWriter().encode(doc)
    res = evaluator.validate_document(unsigned_bytes)
    assert res["status"] == "invalid"
    assert res["failure_code"] == "SPIF_ERROR_UNSIGNED"


def test_fpr_generation():
    prov = Provenance(source_model="gemma-4", timestamp_ms=1000, task_id="task-123", risk_tier="high")
    fpr_doc = generate_fpr_document(
        failure_code="SPIF_ERROR_KEY_REVOKED",
        failure_reason="Key compromised",
        policy_id="policy_strict",
        original_provenance=prov
    )
    assert fpr_doc.payload[0].type == "verification_failure"
    assert fpr_doc.payload[0].value["failure_code"] == "SPIF_ERROR_KEY_REVOKED"
    assert fpr_doc.payload[0].value["action"] == "BLOCKED"
    assert fpr_doc.provenance.task_id == "task-123"
    assert fpr_doc.provenance.risk_tier == "high"


def test_sidecar_http_server(keys, tmp_keystore, policy_file):
    # Setup mock servers
    upstream_port = get_free_port()
    crl_port = get_free_port()
    sidecar_port = get_free_port()

    # Start mock upstream
    upstream_server = HTTPServer(("127.0.0.1", upstream_port), MockUpstreamHandler)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()

    # Start mock CRL server
    MockCRLHandler.crl_data = json.dumps({"revoked": {keys["bob_pub"]: int(time.time() * 1000)}})
    crl_server = HTTPServer(("127.0.0.1", crl_port), MockCRLHandler)
    crl_thread = threading.Thread(target=crl_server.serve_forever, daemon=True)
    crl_thread.start()

    # Write policy pointing to active CRL endpoint
    p_data = json.loads(policy_file.read_text(encoding="utf-8"))
    p_data["crl_check"]["endpoint"] = f"http://127.0.0.1:{crl_port}/crl"
    policy_file.write_text(json.dumps(p_data))

    # Start sidecar server
    crl_client = CRLClient(f"http://127.0.0.1:{crl_port}/crl")
    evaluator = PolicyEvaluator(policy_path=policy_file, keystore_dir=tmp_keystore, crl_client=crl_client)

    SidecarHTTPHandler.evaluator = evaluator
    SidecarHTTPHandler.upstream_url = f"http://127.0.0.1:{upstream_port}"

    sidecar_server = HTTPServer(("127.0.0.1", sidecar_port), SidecarHTTPHandler)
    sidecar_thread = threading.Thread(target=sidecar_server.serve_forever, daemon=True)
    sidecar_thread.start()

    # Give them a split second to start
    time.sleep(0.1)

    try:
        # Create valid doc signed by Alice
        doc = SPIFDocument(
            payload=[Node(id="n1", type="text", value="Pathogen verification success", confidence=Distribution(mean=0.95))],
            provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
        )
        valid_bytes = sign_doc(doc, keys["alice_priv"], keys["alice_pub"])

        # Create doc signed by Bob (Bob is revoked in CRL)
        doc_bob = SPIFDocument(
            payload=[Node(id="n1", type="text", value="Pathogen triage", confidence=Distribution(mean=0.95))],
            provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
        )
        revoked_bytes = sign_doc(doc_bob, keys["bob_priv"], keys["bob_pub"])

        # Scenario A: standalone upload verification is intentionally disabled.
        for path in ("/validate", "/verify"):
            req = urllib.request.Request(
                f"http://127.0.0.1:{sidecar_port}{path}",
                data=valid_bytes,
                headers={"Content-Type": "application/x-spif"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 410

        # Scenario B: Proxy request with valid response
        MockUpstreamHandler.spif_response_bytes = valid_bytes
        proxy_url = f"http://127.0.0.1:{sidecar_port}/v1/chat/completions"
        req_proxy = urllib.request.Request(
            proxy_url,
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_proxy) as resp:
            assert resp.status == 200
            assert resp.info().get("X-Spif") is not None

        # Scenario C: Proxy request with revoked response -> proxy intercepts, returns 403 & FPR
        MockUpstreamHandler.spif_response_bytes = revoked_bytes
        with pytest.raises(urllib.error.HTTPError) as exc_proxy_err:
            urllib.request.urlopen(req_proxy)
        assert exc_proxy_err.value.code == 403
        assert exc_proxy_err.value.headers.get("X-Spif-FPR") is not None

        # Read the FPR body to verify it
        fpr_bytes = exc_proxy_err.value.read()
        fpr_doc = SPIFReader().decode(fpr_bytes)
        assert fpr_doc.payload[0].type == "verification_failure"
        assert fpr_doc.payload[0].value["failure_code"] == "SPIF_ERROR_KEY_REVOKED"

    finally:
        upstream_server.shutdown()
        upstream_server.server_close()
        crl_server.shutdown()
        crl_server.server_close()
        sidecar_server.shutdown()
        sidecar_server.server_close()
