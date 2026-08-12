"""
Advanced C2PA and Watermarking Edge Case Security Tests.

Covers state-of-the-art 2026 security threat models for AI provenance:
1. Provenance Piggybacking: Attacking a document by grafting a valid signature/provenance chunk 
   from a genuine document onto tampered/malicious payload nodes.
2. Metadata Stripping & Watermark Resilience (Defense-in-Depth): Verifying that if 
   the cryptographic signature is stripped (C2PA metadata stripping), soft watermarks 
   embedded directly in the payload remain verifiable.
3. C2PA v2.3 Manifest Alignment: Simulating and verifying C2PA-style structured assertions 
   (e.g., c2pa.actions, c2pa.hash, X.509 bindings) inside the SPIF context.
"""

from __future__ import annotations
import base64
import hashlib
import json
import struct
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    SPIFDocument, Node, Provenance, Distribution, Signature,
    SPIFWriter, SPIFReader, SPIFSignatureError, SPIFChecksumError
)
from spif.format import CHUNK_SIGNATURE, CHUNK_CHECKSUM, MAGIC


def _generate_ed25519_key():
    key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return key, pub_b64


def _sign_document(doc: SPIFDocument, key: ed25519.Ed25519PrivateKey, pub_b64: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_SIGNATURE:
            sig_offset = offset
            break
        if ct == CHUNK_CHECKSUM:
            break
        offset += 5 + ln
    assert sig_offset is not None

    body_to_sign = dummy[:sig_offset]
    real_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=real_sig)
    return writer.encode(doc)


def test_provenance_piggybacking_detection():
    """
    Test that 'Provenance Piggybacking' (where an attacker takes a valid signature block 
    from a real document and grafts it onto a tampered payload) is successfully rejected 
    by SPIF's cryptographic binding and checksum verification.
    """
    key, pub_b64 = _generate_ed25519_key()

    # 1. Create a genuine document and sign it
    genuine_doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Genuine AI statement", 
                      confidence=Distribution(mean=0.98, semantics="factual_accuracy"))],
        provenance=Provenance(source_model="gpt-4o-mini", timestamp_ms=1712000000000)
    )
    genuine_bytes = _sign_document(genuine_doc, key, pub_b64)

    # Verify genuine bytes pass
    assert SPIFReader().verify_signature(genuine_bytes) is True

    # 2. Extract the signature chunk from the genuine document
    offset = len(MAGIC) + 2
    sig_chunk = b""
    while offset < len(genuine_bytes):
        ct, ln = struct.unpack_from(">BI", genuine_bytes, offset)
        if ct == CHUNK_SIGNATURE:
            sig_chunk = genuine_bytes[offset : offset + 5 + ln]
            break
        offset += 5 + ln
    assert len(sig_chunk) > 0

    # 3. Create a malicious/fake document
    fake_doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Maliciously tampered fake statement", 
                      confidence=Distribution(mean=0.01, semantics="factual_accuracy"))],
        provenance=Provenance(source_model="gpt-4o-mini", timestamp_ms=1712000000000)
    )
    
    # Encode fake document without signature
    fake_bytes = SPIFWriter().encode(fake_doc)

    # 4. Graft the genuine signature chunk onto the fake document body (before checksum)
    # Find checksum chunk in fake_bytes to place signature before it
    offset = len(MAGIC) + 2
    checksum_offset = None
    while offset < len(fake_bytes):
        ct, ln = struct.unpack_from(">BI", fake_bytes, offset)
        if ct == CHUNK_CHECKSUM:
            checksum_offset = offset
            break
        offset += 5 + ln
    assert checksum_offset is not None

    piggybacked_bytes = fake_bytes[:checksum_offset] + sig_chunk
    
    # Recompute the checksum over the piggybacked body so it passes basic checksum validation
    checksum_val = hashlib.sha256(piggybacked_bytes).digest()
    checksum_chunk = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum_val)) + checksum_val
    piggybacked_bytes_with_checksum = piggybacked_bytes + checksum_chunk

    # The document must be REJECTED during signature verification because the signature 
    # covers the genuine body's hashes, not the fake body's hashes!
    reader = SPIFReader()
    with pytest.raises(SPIFSignatureError, match="[Ss]ignature verification failed"):
        reader.verify_signature(piggybacked_bytes_with_checksum)


def test_soft_watermark_resilience_after_signature_stripping():
    """
    Verifies the Defense-in-Depth threat model (EU AI Act v2026/C2PA):
    If an intermediary stripped the cryptographic signature (C2PA manifest stripping),
    soft watermarking (e.g. SynthID-style statistical property or embedded watermarking tags)
    embedded in the text value must remain intact and verifiable.
    """
    key, pub_b64 = _generate_ed25519_key()

    # Simulate a soft-watermarked AI text payload (containing imperceptible or statistical markers)
    watermarked_text = "This is a statistically watermarked text output from an AI model. [MARKER-SYNTHID-2026]"
    
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value=watermarked_text, 
                      confidence=Distribution(mean=0.95, semantics="factual_accuracy"))],
        provenance=Provenance(source_model="gpt-4o-mini", timestamp_ms=1712000000000)
    )
    
    # Encode and sign the document
    signed_bytes = _sign_document(doc, key, pub_b64)

    # 1. Verify cryptographic validity
    assert SPIFReader().verify_signature(signed_bytes) is True

    # 2. Simulate Metadata Stripping (an attacker removes the signature chunk)
    # We decode the bytes, strip the signature, and re-serialize
    decoded = SPIFReader().decode(signed_bytes)
    decoded.signature = None
    
    stripped_bytes = SPIFWriter().encode(decoded)
    
    # The cryptographic signature is gone
    restored = SPIFReader().decode(stripped_bytes)
    assert restored.signature is None

    # 3. Soft Watermark verification remains successful
    assert "[MARKER-SYNTHID-2026]" in restored.payload[0].value
    # A watermark verification function can easily detect and approve this
    def verify_soft_watermark(text: str) -> bool:
        return "[MARKER-SYNTHID-2026]" in text

    assert verify_soft_watermark(restored.payload[0].value) is True


def test_c2pa_v23_manifest_alignment():
    """
    Simulates C2PA v2.3 manifest assertions (actions, binding, digital certificate)
    housed within the SPIF format's extensible metadata and verifies their structured integrity.
    """
    # Create structured C2PA metadata alignment
    c2pa_manifest_assertion = {
        "c2pa.manifest": {
            "active_manifest": "self",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "softwareAgent": "gpt-4o-mini-spif-adapter-v1.0"
                            }
                        ]
                    }
                },
                {
                    "label": "c2pa.hash",
                    "data": {
                        "algorithm": "sha256",
                        "hash_value": hashlib.sha256(b"Genuine AI statement").hexdigest()
                    }
                }
            ]
        }
    }

    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="Genuine AI statement", 
                      confidence=Distribution(mean=0.99, semantics="factual_accuracy"))],
        provenance=Provenance(
            source_model="gpt-4o-mini", 
            timestamp_ms=1712000000000,
            # Extensible properties can house the simulated C2PA assertion
            context_ref=json.dumps(c2pa_manifest_assertion)
        )
    )

    # Roundtrip SPIF serialization
    raw = SPIFWriter().encode(doc)
    restored = SPIFReader().decode(raw)

    # Verify the C2PA assertions can be cleanly parsed back and verified
    parsed_c2pa = json.loads(restored.provenance.context_ref)
    assert "c2pa.manifest" in parsed_c2pa
    assertions = parsed_c2pa["c2pa.manifest"]["assertions"]
    
    actions_assertion = next(a for a in assertions if a["label"] == "c2pa.actions")
    assert actions_assertion["data"]["actions"][0]["action"] == "c2pa.created"
    assert "spif-adapter" in actions_assertion["data"]["actions"][0]["softwareAgent"]
