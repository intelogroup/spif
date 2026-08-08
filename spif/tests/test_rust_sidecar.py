import base64
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest

from spif import SPIFDocument, SPIFReader, SPIFWriter, Node, Provenance, Distribution
from spif.crypto import derive_key_from_mnemonic
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Helper to find a free local port
def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def sign_doc(doc: SPIFDocument, private_key, signer_id: str) -> bytes:
    from spif import Signature
    import struct
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    
    # Locate signature offset
    sig_offset = None
    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07: # SIGNATURE chunk
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
            b64_spif = base64.b64encode(self.spif_response_bytes).decode("utf-8")
            self.send_header("X-Spif", b64_spif)
        self.end_headers()
        self.wfile.write(b'{"choices": [{"text": "Hello from Rust sidecar integration!"}]}')

# A mock CRL server
class MockCRLHandler(BaseHTTPRequestHandler):
    crl_data = "{}"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.crl_data.encode("utf-8"))

@pytest.fixture(scope="module")
def compile_rust_sidecar():
    # Build the binary
    rust_dir = Path(__file__).parent.parent.parent / "spif-rust"
    res = subprocess.run(["cargo", "build", "--bin", "spif-sidecar"], cwd=rust_dir, capture_output=True)
    assert res.returncode == 0, f"Cargo compilation failed:\n{res.stderr.decode()}"
    return rust_dir / "target" / "debug" / "spif-sidecar"

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
    policy_data = {
        "policy_id": "test_crl_policy",
        "enforcement": "deny_and_alert",
        "allowed_models": ["gemma-4-e2b-vibrion-sentinel"],
        "trusted_signers": [keys["alice_pub"], keys["bob_pub"]],
        "crl_check": {
            "enabled": True,
            "endpoint": "http://127.0.0.1:0/crl" # overwritten dynamically
        }
    }
    p_path.write_text(json.dumps(policy_data))
    return p_path

def test_rust_sidecar_http_server(compile_rust_sidecar, keys, tmp_keystore, policy_file):
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

    # Update policy file pointing to active CRL
    p_data = json.loads(policy_file.read_text(encoding="utf-8"))
    p_data["crl_check"]["endpoint"] = f"http://127.0.0.1:{crl_port}/crl"
    policy_file.write_text(json.dumps(p_data))

    # Launch compiled Rust sidecar binary as a subprocess
    sidecar_proc = subprocess.Popen([
        str(compile_rust_sidecar),
        "--port", str(sidecar_port),
        "--upstream", f"http://127.0.0.1:{upstream_port}",
        "--policy", str(policy_file),
        "--keystore", str(tmp_keystore)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Allow startup
    time.sleep(0.5)

    try:
        # Create valid doc signed by Alice
        doc = SPIFDocument(
            payload=[Node(id="n1", type="text", value="Pathogen verification success", confidence=Distribution(mean=0.95))],
            provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
        )
        valid_bytes = sign_doc(doc, keys["alice_priv"], keys["alice_pub"])

        # Create doc signed by Bob (revoked)
        doc_bob = SPIFDocument(
            payload=[Node(id="n1", type="text", value="Pathogen triage", confidence=Distribution(mean=0.95))],
            provenance=Provenance(source_model="gemma-4-e2b-vibrion-sentinel", timestamp_ms=0)
        )
        revoked_bytes = sign_doc(doc_bob, keys["bob_priv"], keys["bob_pub"])

        # Scenario A: Direct validate API with valid doc
        validate_url = f"http://127.0.0.1:{sidecar_port}/validate"
        req = urllib.request.Request(
            validate_url,
            data=valid_bytes,
            headers={"Content-Type": "application/x-spif"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "valid"

        # Scenario B: Direct validate API with revoked Bob key -> should return 403
        req_revoked = urllib.request.Request(
            validate_url,
            data=revoked_bytes,
            headers={"Content-Type": "application/x-spif"},
            method="POST"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_revoked)
        assert exc_info.value.code == 403
        err_res = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_res["status"] == "invalid"
        assert err_res["failure_code"] == "SPIF_ERROR_KEY_REVOKED"

        # Scenario C: Proxy request with valid response
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

        # Scenario D: Proxy request with revoked response -> proxy intercepts, returns 403 & FPR
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
        sidecar_proc.terminate()
        sidecar_proc.wait()
        upstream_server.shutdown()
        upstream_server.server_close()
        crl_server.shutdown()
        crl_server.server_close()
