"""
Cross-organization AI output handoff — trust without a shared intermediary.

Scenario: Provider Corp runs inference, signs the SPIF artifact, ships it to
Consumer Corp. Consumer Corp verifies the output was produced by Provider Corp's
model, unmodified in transit, without trusting any middleware or shared DB.

This is the B2B AI supply chain primitive:
  - Contracts cite a public key fingerprint, not a URL
  - No shared secret, no callback endpoint, no API call to verify
  - Works offline, works years later, works across jurisdictions

Patterns demonstrated:
  1. Provider signs → Consumer verifies (happy path)
  2. Transit tampering detected (MITM modifies payload)
  3. Wrong signer rejected (output from unauthorized model)
  4. Replay of old artifact detected via context_ref chain

Run:
    python examples/cross_org_handoff.py
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node, compute_content_id
from spfx.types import Distribution, Provenance, Signature
from spfx.format import MAGIC, CHUNK_SIGNATURE
from spfx.reader import SPIFChecksumError


# ---------------------------------------------------------------------------
# Shared signing utility
# ---------------------------------------------------------------------------

def _sign(doc: SPIFDocument, private_key: Ed25519PrivateKey, signer_id: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_SIGNATURE:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    raw_sig = private_key.sign(dummy[:sig_offset])
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


def _verify_signature(data: bytes, expected_signer: str) -> tuple[bool, str]:
    try:
        doc = SPIFReader().decode(data)
    except SPIFChecksumError:
        return False, "checksum failed — bytes modified in transit"
    except Exception as e:
        return False, f"parse error: {e}"

    if not doc.signature:
        return False, "no signature present"

    if doc.signature.signer != expected_signer:
        return False, (
            f"signer mismatch\n"
            f"  expected: {expected_signer[:40]}...\n"
            f"  got:      {doc.signature.signer[:40]}..."
        )

    # Re-derive body_to_sign
    writer = SPIFWriter()
    doc2 = SPIFReader().decode(data)
    doc2.signature = Signature(algorithm="ed25519", signer=doc.signature.signer, signature=b"\x00" * 64)
    dummy = writer.encode(doc2)
    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_SIGNATURE:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    try:
        pub_bytes = base64.b64decode(expected_signer)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(bytes(doc.signature.signature), dummy[:sig_offset])
        return True, "ok"
    except InvalidSignature:
        return False, "signature invalid — payload modified after signing"


# ---------------------------------------------------------------------------
# Provider Corp: produce and sign AI outputs
# ---------------------------------------------------------------------------

class ProviderCorp:
    def __init__(self, model: str = "provider-llm-v3"):
        self._key = Ed25519PrivateKey.generate()
        pub = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key_b64 = base64.b64encode(pub).decode()
        self.model = model
        self._call_count = 0

    @property
    def public_key_fingerprint(self) -> str:
        digest = hashlib.sha256(base64.b64decode(self.public_key_b64)).hexdigest()
        return digest[:16]

    def run_inference(self, query: str, context_ref: str = "") -> bytes:
        self._call_count += 1
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"response_{self._call_count}",
                    type="text",
                    value=f"Provider inference result for: {query[:60]}",
                    confidence=Distribution(
                        mean=0.88,
                        var=0.03,
                        shape="gaussian",
                        semantics="output_stability",
                    ),
                )
            ],
            provenance=Provenance(
                source_model=self.model,
                model_version="3.0.1",
                temperature=0.7,
                input_hash=hashlib.sha256(query.encode()).hexdigest(),
                context_ref=context_ref,
                timestamp_ms=int(time.time() * 1000) + self._call_count,
            ),
        )
        return _sign(doc, self._key, self.public_key_b64)


# ---------------------------------------------------------------------------
# Consumer Corp: receive and verify AI outputs
# ---------------------------------------------------------------------------

class ConsumerCorp:
    def __init__(self, trusted_signer: str):
        self.trusted_signer = trusted_signer
        self._chain: list[str] = []  # content_ids in received order

    def receive(self, data: bytes, expected_context_ref: str = "") -> dict:
        ok, msg = _verify_signature(data, self.trusted_signer)
        result = {"verified": ok, "reason": msg}

        if ok:
            doc = SPIFReader().decode(data)
            cid = compute_content_id(doc)
            result["content_id"] = cid
            result["model"] = doc.provenance.source_model if doc.provenance else None
            result["value"] = doc.payload[0].value if doc.payload else None
            result["confidence"] = doc.payload[0].confidence.mean if doc.payload and doc.payload[0].confidence else None

            # Context chain validation
            if expected_context_ref:
                actual = doc.provenance.context_ref if doc.provenance else ""
                result["chain_ok"] = (actual == expected_context_ref)
                if not result["chain_ok"]:
                    result["verified"] = False
                    result["reason"] = f"context_ref chain broken (expected {expected_context_ref[:16]}..., got {actual[:16]}...)"

            self._chain.append(cid)

        return result


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def _status(ok: bool) -> str:
    return "ACCEPT" if ok else "REJECT"


def run() -> None:
    print("\n=== Cross-Org AI Output Handoff ===\n")

    provider = ProviderCorp()
    print(f"Provider public key fingerprint: {provider.public_key_fingerprint}")
    print(f"(Consumer would receive this fingerprint via contract/SLA, not a live endpoint)\n")

    consumer = ConsumerCorp(trusted_signer=provider.public_key_b64)

    # --- Scenario 1: Happy path ---
    print("Scenario 1: Clean handoff")
    data = provider.run_inference("Summarize Q3 earnings risk factors.")
    result = consumer.receive(data)
    print(f"  {_status(result['verified'])} | {result['reason']}")
    print(f"  Model: {result['model']} | Confidence: {result['confidence']:.2f}")
    print(f"  content_id: {result['content_id'][:16]}...")

    # --- Scenario 2: Transit tampering ---
    print("\nScenario 2: MITM modifies payload in transit")
    data = provider.run_inference("Classify this contract clause.")
    tampered = bytearray(data)
    tampered[len(data) // 2] ^= 0xFF
    result = consumer.receive(bytes(tampered))
    print(f"  {_status(result['verified'])} | {result['reason']}")

    # --- Scenario 3: Wrong signer (unauthorized model) ---
    print("\nScenario 3: Output from unauthorized model (different key)")
    rogue_provider = ProviderCorp(model="rogue-model-v1")
    data = rogue_provider.run_inference("Recommend this investment.")
    result = consumer.receive(data)
    print(f"  {_status(result['verified'])} | {result['reason']}")

    # --- Scenario 4: Context chain (multi-turn conversation integrity) ---
    print("\nScenario 4: Multi-turn chain — each response links to previous")
    prev_cid = ""
    for i, query in enumerate([
        "What is the counterparty's jurisdiction?",
        "What governing law applies given that jurisdiction?",
        "What dispute resolution mechanism is standard for this law?",
    ]):
        data = provider.run_inference(query, context_ref=prev_cid)
        result = consumer.receive(data, expected_context_ref=prev_cid)
        print(f"  Turn {i+1}: {_status(result['verified'])} | chain_ok={result.get('chain_ok', True)}")
        prev_cid = result.get("content_id", "")

    # --- Scenario 5: Replay attack (old artifact with broken chain) ---
    print("\nScenario 5: Replay of old artifact breaks chain integrity")
    old_data = provider.run_inference("Old query from yesterday.", context_ref="")
    old_result = consumer.receive(old_data)
    old_cid = old_result.get("content_id", "")

    # New query references prev_cid from chain; attacker replays old artifact
    new_data = provider.run_inference("New query.", context_ref=prev_cid)
    # Attacker substitutes old_data instead
    replay_result = consumer.receive(old_data, expected_context_ref=prev_cid)
    print(f"  {_status(replay_result['verified'])} | {replay_result['reason']}")

    print("\nSummary: Consumer verified all 5 scenarios using only the provider's public key.")
    print("No shared secret. No callback URL. No live endpoint. Works offline.")


if __name__ == "__main__":
    run()
