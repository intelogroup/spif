"""
SPIF Sidecar Proxy & Verification Server.

Provides runtime policy enforcement, Certificate Revocation List (CRL) checks,
and Failing Provenance Record (FPR) generation for enterprise environments.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from .reader import SPIFReader, SPIFError, SPIFSignatureError, _find_first_auth_chunk_offset
from .writer import SPIFWriter
from .types import SPIFDocument, Node, Distribution, Provenance, Signature
from .keystore import SPIFKeyStore

logger = logging.getLogger("spif.sidecar")


class CRLClient:
    """Client for fetching and caching Certificate Revocation Lists (CRL)."""

    def __init__(self, url: str | None, cache_ttl: int = 300) -> None:
        self.url = url
        self.cache_ttl = cache_ttl
        self._revoked_keys: set[str] = set()
        self._last_fetch = 0.0
        self._lock = threading.Lock()

    def get_revoked_keys(self) -> set[str]:
        """Return the set of revoked signer identifiers, updating from URL if TTL expired."""
        if not self.url:
            return set()

        now = time.time()
        with self._lock:
            if now - self._last_fetch > self.cache_ttl:
                self._fetch_crl()
            return set(self._revoked_keys)

    def _fetch_crl(self) -> None:
        if not self.url:
            return
        try:
            logger.info("Fetching CRL from %s", self.url)
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "SPIF-Sidecar/1.1"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode("utf-8")
                self._parse_crl(content)
                self._last_fetch = time.time()
        except Exception as e:
            logger.warning("Failed to fetch CRL from %s: %s. Using cached list.", self.url, e)

    def _parse_crl(self, content: str) -> None:
        try:
            data = json.loads(content)
            # Try matching revoked.json format {"revoked": {"key": timestamp}}
            if isinstance(data, dict):
                if "revoked" in data and isinstance(data["revoked"], dict):
                    self._revoked_keys = set(data["revoked"].keys())
                else:
                    self._revoked_keys = set(data.keys())
            elif isinstance(data, list):
                self._revoked_keys = set(str(k) for k in data)
            else:
                self._revoked_keys = set()
        except json.JSONDecodeError:
            # Fallback to newline-separated list
            self._revoked_keys = {
                line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")
            }
        logger.info("Parsed %d revoked keys from CRL", len(self._revoked_keys))


def _provenance_to_dict(prov: Provenance | None) -> dict | None:
    if not prov:
        return None
    return {
        "source_model": prov.source_model,
        "model_version": prov.model_version,
        "temperature": prov.temperature,
        "input_hash": prov.input_hash,
        "context_ref": prov.context_ref,
        "timestamp_ms": prov.timestamp_ms,
        "attempt": prov.attempt,
        "task_id": prov.task_id,
        "risk_tier": prov.risk_tier,
        "model_card": prov.model_card,
    }


class PolicyEvaluator:
    """Evaluates SPIF documents against a validation policy."""

    def __init__(
        self,
        policy_path: Path | str | None = None,
        keystore_dir: Path | str | None = None,
        crl_client: CRLClient | None = None,
    ) -> None:
        self.policy: dict[str, Any] = {}
        if policy_path:
            p = Path(policy_path)
            if p.exists():
                self.policy = json.loads(p.read_text(encoding="utf-8"))
        self.keystore = SPIFKeyStore(keystore_dir) if keystore_dir else None
        self.crl_client = crl_client

    def validate_document(self, raw_bytes: bytes) -> dict[str, Any]:
        """
        Validate a SPIF payload against the configuration policy and CRL.

        Returns a dictionary indicating verification status and details.
        """
        try:
            reader = SPIFReader()
            doc = reader.decode(raw_bytes)
        except SPIFError as e:
            return {
                "status": "invalid",
                "failure_code": "SPIF_ERROR_TAMPERED" if "Checksum" in str(e) else "SPIF_ERROR_FORMAT",
                "failure_reason": f"SPIF decoding error: {e}",
            }

        # Extract basic info
        sigs = list(doc.signatures)
        if doc.signature:
            sigs.append(doc.signature)

        signer_id = sigs[0].signer if sigs else ""
        model_id = doc.provenance.source_model if doc.provenance else ""
        model_version = doc.provenance.model_version if doc.provenance else ""
        input_hash = doc.provenance.input_hash if doc.provenance else ""
        task_id = doc.provenance.task_id if doc.provenance else ""

        # Enforce signatures if policy requires it or if keystore is enabled
        require_sig = self.policy.get("enforcement") == "deny_and_alert" or self.keystore is not None
        if require_sig and not sigs:
            return {
                "status": "invalid",
                "failure_code": "SPIF_ERROR_UNSIGNED",
                "failure_reason": "Signature required by policy, but none present",
                "provenance": _provenance_to_dict(doc.provenance),
            }

        # Verify cryptographic signatures against keystore
        if sigs and self.keystore:
            try:
                self.keystore.verify(raw_bytes)
            except SPIFSignatureError as e:
                # Determine specific cryptographic failure
                reason = str(e)
                code = "SPIF_ERROR_SIGNATURE_INVALID"
                if "revoked" in reason.lower():
                    code = "SPIF_ERROR_KEY_REVOKED"
                elif "no public key" in reason.lower():
                    code = "SPIF_ERROR_UNTRUSTED"
                return {
                    "status": "invalid",
                    "failure_code": code,
                    "failure_reason": reason,
                    "provenance": _provenance_to_dict(doc.provenance),
                }

        # Enforce CRL checks if enabled in policy
        crl_conf = self.policy.get("crl_check", {})
        if crl_conf.get("enabled", False) and self.crl_client:
            revoked_keys = self.crl_client.get_revoked_keys()
            for sig in sigs:
                if sig.signer in revoked_keys:
                    return {
                        "status": "invalid",
                        "failure_code": "SPIF_ERROR_KEY_REVOKED",
                        "failure_reason": f"Signing key '{sig.signer[:16]}...' is revoked in the active CRL",
                        "provenance": _provenance_to_dict(doc.provenance),
                    }

        # Enforce allowed_models policy
        allowed_models = self.policy.get("allowed_models")
        if allowed_models is not None and model_id not in allowed_models:
            return {
                "status": "invalid",
                "failure_code": "SPIF_ERROR_POLICY_VIOLATION",
                "failure_reason": f"Model '{model_id}' is not authorized in enforcement policy",
                "provenance": _provenance_to_dict(doc.provenance),
            }

        # Enforce trusted_signers policy
        trusted_signers = self.policy.get("trusted_signers")
        if trusted_signers is not None and not any(sig.signer in trusted_signers for sig in sigs):
            return {
                "status": "invalid",
                "failure_code": "SPIF_ERROR_POLICY_VIOLATION",
                "failure_reason": f"Signer '{signer_id[:16]}...' is not in trusted_signers policy",
                "provenance": _provenance_to_dict(doc.provenance),
            }

        # Enforce minimum_confidence_mean policy
        min_conf = self.policy.get("minimum_confidence_mean")
        if min_conf is not None:
            means = [node.confidence.mean for node in doc.payload if node.confidence]
            avg_conf = sum(means) / len(means) if means else 1.0
            if avg_conf < min_conf:
                return {
                    "status": "invalid",
                    "failure_code": "SPIF_ERROR_POLICY_VIOLATION",
                    "failure_reason": f"Average confidence {avg_conf:.2f} is below policy minimum {min_conf:.2f}",
                    "provenance": _provenance_to_dict(doc.provenance),
                }

        return {
            "status": "valid",
            "document_id": doc.content_id(),
            "provenance": _provenance_to_dict(doc.provenance),
        }


def generate_fpr_document(
    failure_code: str,
    failure_reason: str,
    policy_id: str | None = None,
    original_provenance: Provenance | dict | None = None,
) -> SPIFDocument:
    """Generate a standard compliant Failing Provenance Record (FPR) SPIFDocument."""
    # Create the failure status payload node
    payload_node = Node(
        id="fpr_status",
        type="verification_failure",
        value={
            "status": "invalid",
            "failure_code": failure_code,
            "failure_reason": failure_reason,
            "rule_triggered": policy_id or "default_policy",
            "action": "BLOCKED",
        },
        confidence=Distribution.certain(),
    )

    # Reconstruct/clone provenance if possible
    prov = None
    if original_provenance:
        if isinstance(original_provenance, dict):
            prov = Provenance(
                source_model=original_provenance.get("source_model", ""),
                model_version=original_provenance.get("model_version", ""),
                temperature=original_provenance.get("temperature", 0.0),
                input_hash=original_provenance.get("input_hash", ""),
                context_ref=original_provenance.get("context_ref", ""),
                timestamp_ms=int(time.time() * 1000),
                attempt=original_provenance.get("attempt", 0),
                task_id=original_provenance.get("task_id", ""),
                risk_tier=original_provenance.get("risk_tier", ""),
                model_card=original_provenance.get("model_card", ""),
            )
        else:
            prov = Provenance(
                source_model=original_provenance.source_model,
                model_version=original_provenance.model_version,
                temperature=original_provenance.temperature,
                input_hash=original_provenance.input_hash,
                context_ref=original_provenance.context_ref,
                timestamp_ms=int(time.time() * 1000),
                attempt=original_provenance.attempt,
                task_id=original_provenance.task_id,
                risk_tier=original_provenance.risk_tier,
                model_card=original_provenance.model_card,
            )
    else:
        prov = Provenance(
            source_model="spif-sidecar-validator",
            timestamp_ms=int(time.time() * 1000),
        )

    return SPIFDocument(
        payload=[payload_node],
        provenance=prov,
    )


class SidecarHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Handler for verification endpoint and reverse proxy verification."""

    # Set by server initializer
    evaluator: PolicyEvaluator = PolicyEvaluator()
    upstream_url: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(format, *args)

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Handle direct validate/verify endpoint
        if self.path in ("/validate", "/verify"):
            self._handle_direct_validate(body)
            return

        # Forward request to upstream in reverse proxy mode
        if self.upstream_url:
            self._handle_proxy_request("POST", body)
            return

        self.send_error(404, "Not Found")

    def do_GET(self) -> None:
        if self.upstream_url:
            self._handle_proxy_request("GET", b"")
            return
        self.send_error(404, "Not Found")

    def _handle_direct_validate(self, body: bytes) -> None:
        try:
            # Handle JSON body wrapping base64 payload, or raw SPIF bytes
            raw_spif = body
            is_json = "application/json" in self.headers.get("Content-Type", "")
            if is_json:
                data = json.loads(body.decode("utf-8"))
                if "spif" in data:
                    raw_spif = base64.b64decode(data["spif"])
                elif "payload" in data:
                    raw_spif = base64.b64decode(data["payload"])

            res = self.evaluator.validate_document(raw_spif)

            if res["status"] == "valid":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))
            else:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))

        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def _handle_proxy_request(self, method: str, body: bytes) -> None:
        # Build target upstream URL
        url = self.upstream_url.rstrip("/") + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}

        try:
            req = urllib.request.Request(
                url,
                data=body if method == "POST" else None,
                headers=headers,
                method=method,
            )
            with urllib.request.urlopen(req) as response:
                res_body = response.read()
                res_headers = response.info()

                # Inspect for X-Spif header
                x_spif = res_headers.get("X-Spif") or res_headers.get("x-spif")
                if x_spif:
                    try:
                        raw_spif = base64.b64decode(x_spif)
                        val_res = self.evaluator.validate_document(raw_spif)
                        if val_res["status"] != "valid":
                            # Block and return FPR
                            self._return_fpr_block(val_res)
                            return
                    except Exception as e:
                        logger.error("Error verifying X-Spif in proxy response: %s", e)
                        self._return_fpr_block({
                            "status": "invalid",
                            "failure_code": "SPIF_ERROR_INTERNAL",
                            "failure_reason": f"Proxy validation exception: {e}",
                        })
                        return

                # Validation passed or no SPIF header; forward upstream response
                self.send_response(response.status)
                for k, v in res_headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(res_body)

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

    def _return_fpr_block(self, val_res: dict[str, Any]) -> None:
        policy_id = self.evaluator.policy.get("policy_id")
        fpr = generate_fpr_document(
            failure_code=val_res.get("failure_code", "SPIF_ERROR_POLICY_VIOLATION"),
            failure_reason=val_res.get("failure_reason", "Validation failed"),
            policy_id=policy_id,
            original_provenance=val_res.get("provenance"),
        )
        fpr_bytes = SPIFWriter().encode(fpr)
        fpr_b64 = base64.b64encode(fpr_bytes).decode("utf-8")

        self.send_response(403)
        self.send_header("Content-Type", "application/x-spif")
        self.send_header("X-Spif-FPR", fpr_b64)
        self.end_headers()
        self.wfile.write(fpr_bytes)


def start_sidecar(
    port: int,
    upstream_url: str | None = None,
    policy_path: str | Path | None = None,
    keystore_dir: str | Path | None = None,
    crl_url: str | None = None,
) -> None:
    """Start the sidecar HTTP proxy server."""
    # Setup CRL client. cache_ttl is read from policy's crl_check.cache_ttl
    # (default 300s) regardless of whether the endpoint comes from --crl-url
    # or the policy file, so --crl-url can still be tuned via policy.
    crl_client = None
    crl_cache_ttl = 300
    crl_conf: dict[str, Any] = {}
    if policy_path:
        try:
            p = Path(policy_path)
            if p.exists():
                policy_data = json.loads(p.read_text(encoding="utf-8"))
                crl_conf = policy_data.get("crl_check") or {}
                if not isinstance(crl_conf, dict):
                    logger.warning("crl_check policy field must be an object, got %r; ignoring", crl_conf)
                    crl_conf = {}
                ttl = crl_conf.get("cache_ttl", 300)
                if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
                    logger.warning("crl_check.cache_ttl must be a non-negative integer, got %r; using default 300", ttl)
                else:
                    crl_cache_ttl = ttl
        except Exception as e:
            logger.warning("Failed to parse CRL config from policy: %s", e)

    if crl_url:
        crl_client = CRLClient(crl_url, cache_ttl=crl_cache_ttl)
    elif crl_conf.get("enabled", False) and crl_conf.get("endpoint"):
        crl_client = CRLClient(crl_conf["endpoint"], cache_ttl=crl_cache_ttl)

    evaluator = PolicyEvaluator(policy_path, keystore_dir, crl_client)

    # Bind evaluator and upstream to the handler class
    SidecarHTTPHandler.evaluator = evaluator
    SidecarHTTPHandler.upstream_url = upstream_url

    server = HTTPServer(("127.0.0.1", port), SidecarHTTPHandler)
    logger.info("SPIF Sidecar running on http://127.0.0.1:%d", port)
    if upstream_url:
        logger.info("Upstream configured to forward requests to: %s", upstream_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down SPIF Sidecar")
        server.server_close()
