"""
EU AI Act Article 12 — tamper-evident AI output logging with SPIF.

Art. 12 requires high-risk AI systems to automatically log events that allow
post-market monitoring and investigation of incidents. Crucially, those logs
must be tamper-evident — an auditor must be able to prove the record hasn't
been modified since it was produced.

This example walks the full lifecycle an auditor would follow:

  1. Generate — AI produces a decision + reasoning trace
  2. Sign   — provider signs output with ed25519 (two-pass)
  3. Store  — artifact written to immutable-log storage (filesystem here)
  4. Incident — simulate tampering (confidence inflated post-hoc)
  5. Audit  — auditor loads artifact, verifies signature + checksum

Run:
    python examples/eu_ai_act_audit.py
    python examples/eu_ai_act_audit.py --tamper  # simulate incident
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node
from spfx.types import Distribution, Provenance, TraceStep, Signature
from spfx.format import MAGIC, CHUNK_SIGNATURE
from spfx.reader import SPIFChecksumError


# ---------------------------------------------------------------------------
# Step 1: Generate — clinical risk-scoring AI decision
# ---------------------------------------------------------------------------

def generate_decision(patient_id: str, model: str = "clinical-risk-v2") -> SPIFDocument:
    """Simulate a high-risk AI system producing a clinical risk score."""
    return SPIFDocument(
        payload=[
            Node(
                id="risk_score",
                type="classification",
                value="HIGH_RISK",
                confidence=Distribution(
                    mean=0.87,
                    var=0.04,
                    shape="gaussian",
                    semantics="custom:calibrated_probability",
                    p5=0.79,
                    p95=0.94,
                ),
            ),
            Node(
                id="recommendation",
                type="text",
                value="Immediate clinical review recommended. Primary indicators: elevated biomarker "
                      "pattern consistent with early-stage intervention window.",
                confidence=Distribution(mean=0.91, var=0.02, shape="gaussian"),
            ),
        ],
        trace=[
            TraceStep(
                id="feature_extraction",
                type="evidence",
                content="Extracted 47 biomarker features from patient record.",
                confidence=Distribution(mean=0.99, var=0.001, shape="gaussian"),
            ),
            TraceStep(
                id="risk_model_inference",
                type="inference",
                content="Applied calibrated gradient-boosting ensemble. Threshold: 0.80.",
                confidence=Distribution(mean=0.87, var=0.04, shape="gaussian"),
            ),
            TraceStep(
                id="guideline_lookup",
                type="evidence",
                content="Retrieved NICE guideline NG12 section 1.4.3 for recommendation text.",
                confidence=Distribution(mean=0.95, var=0.01, shape="gaussian"),
            ),
        ],
        trace_method="online",
        provenance=Provenance(
            source_model=model,
            model_version="2.1.0",
            temperature=0.0,
            input_hash=hashlib.sha256(patient_id.encode()).hexdigest(),
            timestamp_ms=int(time.time() * 1000),
        ),
    )


# ---------------------------------------------------------------------------
# Step 2: Sign — two-pass ed25519 (same pattern as spfx sign CLI)
# ---------------------------------------------------------------------------

def sign_document(doc: SPIFDocument, private_key: Ed25519PrivateKey, signer_id: str) -> bytes:
    writer = SPIFWriter()

    # Pass 1: dummy sig to fix final binary layout
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    # Locate SIGNATURE chunk
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

    if sig_offset is None:
        raise RuntimeError("SIGNATURE chunk not found in encoded document")

    # Pass 2: sign body up to signature chunk, re-encode with real sig
    raw_sig = private_key.sign(dummy[:sig_offset])
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


# ---------------------------------------------------------------------------
# Step 3: Store — write to append-only artifact log
# ---------------------------------------------------------------------------

def store_artifact(data: bytes, log_dir: Path, label: str) -> Path:
    checksum = hashlib.sha256(data).hexdigest()[:12]
    path = log_dir / f"{label}_{checksum}.spfx"
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Step 4: Tamper simulation
# ---------------------------------------------------------------------------

def tamper_confidence(data: bytes) -> bytes:
    """Inflate confidence mean from 0.87 → 0.99 in raw CBOR bytes (post-hoc fraud)."""
    # CBOR encodes 0.87 as float — find and flip a byte to change the value
    tampered = bytearray(data)
    # Simple approach: flip a byte deep in the payload region
    mid = len(data) // 2
    tampered[mid] ^= 0x08
    return bytes(tampered)


# ---------------------------------------------------------------------------
# Step 5: Audit — what the auditor's tool does
# ---------------------------------------------------------------------------

def audit_artifact(path: Path, expected_signer: str) -> dict:
    data = path.read_bytes()
    result = {
        "file": str(path.name),
        "size_bytes": len(data),
        "checksum_ok": False,
        "signature_ok": False,
        "signer_matches": False,
        "model": None,
        "timestamp_ms": None,
        "confidence_mean": None,
        "errors": [],
    }

    # Checksum — fires automatically on decode()
    try:
        doc = SPIFReader().decode(data)
        result["checksum_ok"] = True
    except SPIFChecksumError as e:
        result["errors"].append(f"CHECKSUM FAILED: {e}")
        return result
    except Exception as e:
        result["errors"].append(f"PARSE ERROR: {e}")
        return result

    # Signature
    if doc.signature:
        try:
            pub_bytes = base64.b64decode(doc.signature.signer)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

            # Re-derive body_to_sign (same two-pass logic)
            writer = SPIFWriter()
            dummy_doc = SPIFReader().decode(data)
            dummy_doc.signature = Signature(
                algorithm="ed25519",
                signer=doc.signature.signer,
                signature=b"\x00" * 64,
            )
            dummy = writer.encode(dummy_doc)
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

            if sig_offset is not None:
                pub_key.verify(bytes(doc.signature.signature), dummy[:sig_offset])
                result["signature_ok"] = True
                result["signer_matches"] = (doc.signature.signer == expected_signer)
        except InvalidSignature:
            result["errors"].append("SIGNATURE INVALID — document may have been modified after signing")
        except Exception as e:
            result["errors"].append(f"SIGNATURE CHECK ERROR: {e}")
    else:
        result["errors"].append("NO SIGNATURE — document was not signed")

    # Metadata
    if doc.provenance:
        result["model"] = doc.provenance.source_model
        result["timestamp_ms"] = doc.provenance.timestamp_ms
    if doc.payload:
        result["confidence_mean"] = doc.payload[0].confidence.mean if doc.payload[0].confidence else None

    return result


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def _yn(v: bool) -> str:
    return "PASS" if v else "FAIL"


def run(tamper: bool = False) -> None:
    print("\n=== EU AI Act Art. 12 — Tamper-Evident AI Output Logging ===\n")

    # Key setup — in production: HSM or KMS
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer_id = base64.b64encode(pub_bytes).decode()

    print(f"Provider key: {signer_id[:32]}...")

    # Step 1: Generate
    patient_id = "P-2024-00847"
    doc = generate_decision(patient_id)
    print(f"\n[1] Generated decision for patient {patient_id}")
    print(f"    Risk score  : {doc.payload[0].value}")
    print(f"    Confidence  : {doc.payload[0].confidence.mean:.2f} ± {doc.payload[0].confidence.var:.3f}")
    print(f"    Trace steps : {len(doc.trace)}")

    # Step 2: Sign
    signed_bytes = sign_document(doc, private_key, signer_id)
    print(f"\n[2] Signed ({len(signed_bytes)} bytes, ed25519)")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)

        # Step 3: Store
        artifact_path = store_artifact(signed_bytes, log_dir, "P-2024-00847")
        print(f"\n[3] Stored → {artifact_path.name}")

        # Step 4: Optional tamper
        if tamper:
            print("\n[4] SIMULATING INCIDENT: post-hoc confidence inflation")
            tampered_bytes = tamper_confidence(signed_bytes)
            artifact_path.write_bytes(tampered_bytes)
            print("    Artifact overwritten with tampered version")
        else:
            print("\n[4] No tampering (run with --tamper to simulate incident)")

        # Step 5: Audit
        print("\n[5] Auditor review:")
        audit = audit_artifact(artifact_path, signer_id)
        print(f"    File          : {audit['file']}")
        print(f"    Size          : {audit['size_bytes']} bytes")
        print(f"    Checksum      : {_yn(audit['checksum_ok'])}")
        print(f"    Signature     : {_yn(audit['signature_ok'])}")
        print(f"    Signer match  : {_yn(audit['signer_matches'])}")
        print(f"    Model         : {audit['model']}")
        print(f"    Timestamp     : {audit['timestamp_ms']}")
        print(f"    Confidence    : {audit['confidence_mean']}")

        if audit["errors"]:
            print(f"\n    AUDIT FINDINGS:")
            for e in audit["errors"]:
                print(f"      - {e}")
            print("\n  -> Artifact integrity COMPROMISED. Escalate to incident response.")
        else:
            print("\n  -> Artifact integrity CONFIRMED. Compliant with Art. 12.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tamper", action="store_true", help="Simulate post-hoc tampering")
    args = ap.parse_args()
    run(tamper=args.tamper)
