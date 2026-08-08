"""
EU AI Act / NIST AI RMF compliance report generator for SIF files.

Takes a .sif file and outputs a machine-readable compliance assessment
showing which regulatory requirements it satisfies.

This is the killer demo: a SIF file can self-report its compliance status.
A JSON file cannot — it requires external schema knowledge.

Usage:
    python experiments/compliance_report.py <file.sif>
    python experiments/compliance_report.py --demo   # create demo file and run
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sif import SIFReader, SIFChecksumError, SIFSignatureError, SIFFormatError


def generate_compliance_report(sif_path: Path) -> dict:
    """
    Read a SIF file and produce a structured compliance report.
    All checks are derived purely from the binary file — no external schema.
    """
    data = sif_path.read_bytes()

    # -----------------------------------------------------------------------
    # Parse the document (checksum validation is automatic)
    # -----------------------------------------------------------------------
    integrity_verified = False
    integrity_error = None
    doc = None

    try:
        doc = SIFReader().decode(data)
        integrity_verified = True
    except SIFChecksumError as e:
        integrity_error = str(e)
    except SIFFormatError as e:
        integrity_error = str(e)

    # -----------------------------------------------------------------------
    # Signature verification
    # -----------------------------------------------------------------------
    signature_present = False
    signature_valid = False
    signature_algorithm = None
    signer_id = None
    signature_error = None

    if doc is not None and doc.signature is not None:
        signature_present = True
        signature_algorithm = doc.signature.algorithm
        signer_id = doc.signature.signer
        try:
            signature_valid = SIFReader().verify_signature(data)
        except SIFSignatureError as e:
            signature_error = str(e)

    # -----------------------------------------------------------------------
    # Provenance completeness
    # -----------------------------------------------------------------------
    provenance_present = doc is not None and doc.provenance is not None
    timestamp_present = (
        provenance_present and
        doc.provenance.timestamp_ms is not None and
        doc.provenance.timestamp_ms > 0
    )
    source_model_present = (
        provenance_present and
        bool(doc.provenance.source_model)
    )
    input_reference_present = (
        provenance_present and
        bool(doc.provenance.input_hash)
    )

    # -----------------------------------------------------------------------
    # Uncertainty quantification
    # -----------------------------------------------------------------------
    n_nodes = len(doc.payload) if doc else 0
    uncertainty_quantified = n_nodes > 0
    semantics_values = []
    if doc:
        for n in doc.payload:
            if n.confidence and n.confidence.semantics:
                semantics_values.append(n.confidence.semantics)

    uncertainty_semantics_defined = len(semantics_values) == n_nodes and n_nodes > 0
    unique_semantics = list(set(semantics_values)) if semantics_values else []

    # -----------------------------------------------------------------------
    # Reasoning trace
    # -----------------------------------------------------------------------
    trace_present = doc is not None and len(doc.trace) > 0
    trace_method = doc.trace_method if doc else "post-hoc"
    n_trace_steps = len(doc.trace) if doc else 0

    # -----------------------------------------------------------------------
    # Assemble report
    # -----------------------------------------------------------------------
    now_ms = int(time.time() * 1000)

    report = {
        "sif_file": str(sif_path),
        "report_generated_ms": now_ms,
        "sif_format_version": f"0x{data[8]:02x}" if len(data) > 8 else "unknown",

        # --- EU AI Act Article 12 (Record-keeping for high-risk AI) ---
        "eu_ai_act_art12": {
            "compliant": (
                integrity_verified and
                timestamp_present and
                source_model_present
            ),
            "requirements": {
                "log_integrity_verified": {
                    "status": integrity_verified,
                    "mechanism": "SHA-256 checksum (SIF CHUNK_CHECKSUM)",
                    "error": integrity_error,
                },
                "timestamp_present": {
                    "status": timestamp_present,
                    "value_ms": doc.provenance.timestamp_ms if timestamp_present else None,
                },
                "source_system_identified": {
                    "status": source_model_present,
                    "value": doc.provenance.source_model if source_model_present else None,
                },
                "input_reference_present": {
                    "status": input_reference_present,
                    "value": doc.provenance.input_hash[:16] + "..." if input_reference_present else None,
                },
                "verifier_identity": {
                    "status": signature_present and signature_valid,
                    "algorithm": signature_algorithm,
                    "signer": signer_id[:32] + "..." if signer_id and len(signer_id) > 32 else signer_id,
                    "verified": signature_valid,
                    "error": signature_error,
                },
            },
        },

        # --- EU AI Act Article 13 (Transparency) ---
        "eu_ai_act_art13": {
            "compliant": trace_present,
            "requirements": {
                "reasoning_method_declared": {
                    "status": True,  # trace_method is always present (defaults to post-hoc)
                    "value": trace_method,
                    "note": (
                        "live = generated simultaneously with output (most honest)" if trace_method == "live"
                        else "post-hoc = model narrated reasoning after output"
                        if trace_method == "post-hoc"
                        else "verified = derived from model internals"
                    ),
                },
                "reasoning_steps_present": {
                    "status": trace_present,
                    "n_steps": n_trace_steps,
                },
            },
        },

        # --- NIST AI RMF MEASURE function ---
        "nist_ai_rmf_measure": {
            "compliant": uncertainty_quantified and uncertainty_semantics_defined,
            "requirements": {
                "uncertainty_quantified": {
                    "status": uncertainty_quantified,
                    "n_values": n_nodes,
                },
                "uncertainty_semantics_defined": {
                    "status": uncertainty_semantics_defined,
                    "semantics_in_use": unique_semantics,
                    "note": (
                        "factual_accuracy = P(claim is factually correct) — most auditable"
                        if "factual_accuracy" in unique_semantics
                        else "epistemic = model's subjective confidence"
                        if "epistemic" in unique_semantics
                        else "custom semantics"
                    ),
                },
            },
        },

        # --- ISO/IEC 42001 (AI Management System) ---
        "iso_42001": {
            "compliant": integrity_verified and provenance_present,
            "requirements": {
                "audit_log_integrity": {
                    "status": integrity_verified,
                    "mechanism": "SHA-256 + optional ed25519 signature",
                },
                "model_provenance_documented": {
                    "status": provenance_present,
                },
            },
        },

        # --- Overall score ---
        "overall": {
            "frameworks_fully_compliant": sum([
                integrity_verified and timestamp_present and source_model_present,
                trace_present,
                uncertainty_quantified and uncertainty_semantics_defined,
                integrity_verified and provenance_present,
            ]),
            "frameworks_checked": 4,
            "gaps": _identify_gaps(
                integrity_verified, timestamp_present, source_model_present,
                input_reference_present, signature_present, signature_valid,
                trace_present, uncertainty_quantified, uncertainty_semantics_defined,
                provenance_present,
            ),
        },
    }

    return report


def _identify_gaps(
    integrity_verified, timestamp_present, source_model_present,
    input_reference_present, signature_present, signature_valid,
    trace_present, uncertainty_quantified, uncertainty_semantics_defined,
    provenance_present,
) -> list[str]:
    gaps = []
    if not integrity_verified:
        gaps.append("CRITICAL: Checksum invalid — log integrity not established")
    if not timestamp_present:
        gaps.append("EU AI Act Art.12: No timestamp (add provenance.timestamp_ms)")
    if not source_model_present:
        gaps.append("EU AI Act Art.12: No source model identified (add provenance.source_model)")
    if not input_reference_present:
        gaps.append("EU AI Act Art.12 (recommended): No input hash (add provenance.input_hash)")
    if not signature_present:
        gaps.append("EU AI Act Art.12 (recommended): No cryptographic signature (run `sif sign`)")
    elif not signature_valid:
        gaps.append("CRITICAL: Signature present but invalid — document may be tampered")
    if not trace_present:
        gaps.append("EU AI Act Art.13: No reasoning trace (add trace steps)")
    if not uncertainty_quantified:
        gaps.append("NIST RMF MEASURE: No uncertainty values (add confidence to nodes)")
    if not uncertainty_semantics_defined:
        gaps.append("NIST RMF MEASURE: Uncertainty semantics undefined (set Distribution.semantics)")
    return gaps


def print_report(report: dict) -> None:
    def status_icon(v):
        return "PASS" if v else "FAIL"

    print(f"\nCompliance Report: {report['sif_file']}")
    print(f"SIF format version: {report['sif_format_version']}")
    print()

    for framework, key in [
        ("EU AI Act Article 12 (Record-keeping)", "eu_ai_act_art12"),
        ("EU AI Act Article 13 (Transparency)",   "eu_ai_act_art13"),
        ("NIST AI RMF MEASURE",                   "nist_ai_rmf_measure"),
        ("ISO/IEC 42001 (AI Management)",          "iso_42001"),
    ]:
        f = report[key]
        icon = "PASS" if f["compliant"] else "FAIL"
        print(f"  [{icon}] {framework}")
        for req, details in f["requirements"].items():
            req_icon = "PASS" if details["status"] else "FAIL"
            extra = ""
            if "value" in details and details["value"]:
                extra = f" = {details['value']}"
            elif "n_steps" in details:
                extra = f" ({details['n_steps']} steps)"
            elif "n_values" in details:
                extra = f" ({details['n_values']} values)"
            elif "semantics_in_use" in details:
                extra = f" {details['semantics_in_use']}"
            elif "signer" in details and details["signer"]:
                extra = f" [{details['algorithm']}:{details['signer']}]"
            print(f"       [{req_icon}] {req}{extra}")
        print()

    score = report["overall"]
    print(f"  Score: {score['frameworks_fully_compliant']}/{score['frameworks_checked']} frameworks fully compliant")

    if score["gaps"]:
        print("\n  Gaps to address:")
        for gap in score["gaps"]:
            print(f"    - {gap}")
    else:
        print("\n  No gaps — all checked requirements satisfied.")


def _make_demo_file() -> Path:
    """Create a demo SIF file with full provenance + signature for compliance testing."""
    import base64
    import struct
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from sif import SIFDocument, Node, TraceStep, SIFWriter
    from sif.types import Distribution, Provenance, Signature
    from sif.format import DIST_SEM_FACTUAL, TRACE_LIVE

    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    doc = SIFDocument(
        payload=[
            Node(id="claim_1", type="factual",
                 value="Water boils at 100°C at sea level.",
                 confidence=Distribution(mean=0.99, var=0.005, shape="gaussian",
                                         semantics=DIST_SEM_FACTUAL)),
            Node(id="claim_2", type="factual",
                 value="The capital of France is Paris.",
                 confidence=Distribution(mean=0.99, var=0.005, shape="gaussian",
                                         semantics=DIST_SEM_FACTUAL)),
        ],
        trace=[
            TraceStep(id="s0", type="evidence", content="Retrieved factual knowledge.",
                      confidence=Distribution(mean=0.98, var=0.01, shape="gaussian",
                                              semantics=DIST_SEM_FACTUAL)),
            TraceStep(id="s1", type="conclusion", content="Facts confirmed.",
                      confidence=Distribution(mean=0.99, var=0.005, shape="gaussian",
                                              semantics=DIST_SEM_FACTUAL),
                      deps=["s0"]),
        ],
        trace_method=TRACE_LIVE,
        provenance=Provenance(
            source_model="claude-haiku-4-5-20251001",
            model_version="claude-haiku-4-5-20251001",
            temperature=0.0,
            input_hash="sha256:" + "b" * 60,
            timestamp_ms=int(time.time() * 1000),
        ),
    )

    writer = SIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = 10
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    body_to_sign = dummy[:sig_offset]
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=raw_sig)

    out = Path("/tmp/compliance_demo.sif")
    writer.write(doc, out)
    return out


def main():
    parser = argparse.ArgumentParser(description="SIF compliance report generator")
    parser.add_argument("file", nargs="?", help="Path to a .sif file")
    parser.add_argument("--demo", action="store_true", help="Create a demo SIF file and run report")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted report")
    args = parser.parse_args()

    if args.demo:
        print("Creating demo SIF file with full provenance + ed25519 signature...")
        sif_path = _make_demo_file()
        print(f"Demo file: {sif_path}  ({sif_path.stat().st_size} bytes)")
    elif args.file:
        sif_path = Path(args.file)
    else:
        parser.print_help()
        sys.exit(1)

    report = generate_compliance_report(sif_path)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
        print()
        print("  (Run with --json for machine-readable output)")


if __name__ == "__main__":
    main()
