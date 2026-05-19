"""
Tamper evidence demo: what SIF detects that JSON cannot.

Three attack scenarios:
  1. Bit flip (storage corruption)          → SIFChecksumError
  2. Confidence inflation (adversarial edit) → SIFChecksumError (if no resign)
  3. Provenance spoofing                     → SIFSignatureError (signature mismatch)

JSON equivalent: all three attacks are silent.

Usage:
    python experiments/tamper_demo.py
"""
from __future__ import annotations
import base64
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sif import SIFDocument, Node, SIFWriter, SIFReader, SIFChecksumError, SIFSignatureError, SIFFormatError
from sif.types import Distribution, Provenance, Signature
from sif.format import DIST_SEM_FACTUAL


# ---------------------------------------------------------------------------
# Build a signed SIF document
# ---------------------------------------------------------------------------

def _make_signed_doc() -> tuple[bytes, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    nodes = [
        Node(
            id=f"claim_{i}",
            type="factual_claim",
            value=f"The capital of country {i} is City_{i}.",
            confidence=Distribution(mean=0.9 - i * 0.05, var=0.02,
                                    shape="gaussian", semantics=DIST_SEM_FACTUAL),
        )
        for i in range(10)
    ]

    doc = SIFDocument(
        payload=nodes,
        provenance=Provenance(
            source_model="claude-haiku-4-5-20251001",
            model_version="claude-haiku-4-5-20251001",
            temperature=0.0,
            input_hash="a" * 64,
            timestamp_ms=1_700_000_000_000,
        ),
    )

    writer = SIFWriter()

    # Two-pass signing
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
    return writer.encode(doc), key


def _to_json(data: bytes) -> dict:
    """Decode SIF and produce a JSON-equivalent dict (lossy)."""
    doc = SIFReader().decode(data)
    return {
        "payload": [
            {
                "id": n.id,
                "type": n.type,
                "value": n.value,
                "confidence_mean": n.confidence.mean,
                "confidence_var": n.confidence.var,
                "confidence_shape": n.confidence.shape,
                # semantics field: convention only, not type-enforced
                "confidence_semantics": n.confidence.semantics,
            }
            for n in doc.payload
        ],
        "provenance": {
            "source_model": doc.provenance.source_model if doc.provenance else "",
            "timestamp_ms": doc.provenance.timestamp_ms if doc.provenance else 0,
        },
    }


# ---------------------------------------------------------------------------
# Attack 1: Bit flip (storage corruption)
# ---------------------------------------------------------------------------

def attack_bit_flip(data: bytes) -> None:
    print("\n" + "=" * 60)
    print("ATTACK 1: Bit flip (storage corruption)")
    print("=" * 60)
    print("Scenario: A file is written to disk, a single bit flips during storage.")
    print("          This is rare but happens with failing HDDs, cosmic rays, etc.")

    corrupted = bytearray(data)
    flip_pos = 50  # somewhere in the payload body
    corrupted[flip_pos] ^= 0x01
    print(f"  Flipped bit at byte offset {flip_pos}: {data[flip_pos]:08b} → {corrupted[flip_pos]:08b}")

    # SIF
    print("\n  SIF response:")
    try:
        SIFReader().decode(bytes(corrupted))
        print("  FAIL — corruption not detected")
    except SIFChecksumError as e:
        print(f"  PASS — SIFChecksumError raised: {e}")

    # JSON
    print("\n  JSON response:")
    j = _to_json(data)
    j_bytes = bytearray(json.dumps(j).encode())
    j_bytes[min(50, len(j_bytes) - 1)] ^= 0x01
    try:
        result = json.loads(bytes(j_bytes))
        # Silently parsed — was corruption detected?
        print(f"  FAIL — corruption silent, parsed {len(result['payload'])} nodes")
        print("         (corrupt byte landed in whitespace/key, not value)")
    except json.JSONDecodeError as e:
        print(f"  NOTE — JSON parse error (corrupt byte hit JSON syntax): {e}")
        print("         (only detected because bit happened to break JSON syntax)")
        print("         JSON detection is accidental, not guaranteed.")


# ---------------------------------------------------------------------------
# Attack 2: Confidence inflation (adversarial manipulation)
# ---------------------------------------------------------------------------

def attack_confidence_inflation(data: bytes) -> None:
    print("\n" + "=" * 60)
    print("ATTACK 2: Confidence inflation (adversarial manipulation)")
    print("=" * 60)
    print("Scenario: An attacker (or buggy system) modifies confidence scores")
    print("          upward before storing the audit log. E.g., inflate 0.45 → 0.99")
    print("          to make a low-confidence claim appear highly confident.")

    # JSON: deserialize, inflate, re-serialize → silent
    j = _to_json(data)
    orig_conf = [n["confidence_mean"] for n in j["payload"]]
    for n in j["payload"]:
        n["confidence_mean"] = 0.99  # inflate all to 0.99
    inflated_json = json.dumps(j)

    print(f"\n  Original confidences: {[f'{c:.2f}' for c in orig_conf]}")
    inflated = [f"{n['confidence_mean']:.2f}" for n in j["payload"]]
    print(f"  Inflated confidences: {inflated}")

    print("\n  JSON response: SILENT — inflation accepted, no error raised")
    parsed = json.loads(inflated_json)
    print(f"  Parsed {len(parsed['payload'])} nodes with all confidence_mean=0.99")
    print("  An auditor reading this JSON cannot tell it was tampered with.")

    # SIF: re-encoding with changed confidence without re-signing → checksum mismatch
    print("\n  SIF response:")
    doc = SIFReader().decode(data)
    for n in doc.payload:
        n.confidence = Distribution(mean=0.99, var=0.01, shape="gaussian",
                                    semantics=DIST_SEM_FACTUAL)
    # Write without re-signing
    writer = SIFWriter()
    doc.signature = None  # strip signature to force re-encode
    tampered = writer.encode(doc)

    # Re-encode without the private key (signature stripped)
    print("  If attacker re-encodes without the private key:")
    result = SIFReader().verify_signature(tampered)
    if result is False:
        print("  PASS — verify_signature=False (no signature → not trusted by audit system)")
    else:
        print("  FAIL — unsigned document accepted as valid")

    # Direct byte manipulation attempt on the signed original
    print("\n  If attacker flips bytes directly in the signed SIF binary:")
    corrupted = bytearray(data)
    flip_pos = len(data) // 3  # guaranteed in body, not header/checksum
    corrupted[flip_pos] ^= 0xFF
    try:
        SIFReader().decode(bytes(corrupted))
        print("  FAIL — not detected")
    except (SIFChecksumError, SIFFormatError) as e:
        print(f"  PASS — {type(e).__name__}: detected immediately")


# ---------------------------------------------------------------------------
# Attack 3: Provenance spoofing
# ---------------------------------------------------------------------------

def attack_provenance_spoof(data: bytes) -> None:
    print("\n" + "=" * 60)
    print("ATTACK 3: Provenance spoofing")
    print("=" * 60)
    print("Scenario: A bad actor claims inference was done by 'gpt-4o' instead")
    print("          of 'claude-haiku'. They modify the source_model field.")

    # JSON: change source_model → silent
    j = _to_json(data)
    original_model = j["provenance"]["source_model"]
    j["provenance"]["source_model"] = "gpt-4o"

    print(f"\n  Original source_model: '{original_model}'")
    print("  Spoofed  source_model: 'gpt-4o'")

    print("\n  JSON response: SILENT — model field changed, no error")
    parsed = json.loads(json.dumps(j))
    print(f"  Parsed source_model = '{parsed['provenance']['source_model']}'")
    print("  An auditor cannot distinguish this from a legitimate gpt-4o response.")

    # SIF: changing provenance bytes invalidates signature
    print("\n  SIF response:")
    doc = SIFReader().decode(data)
    doc.provenance = Provenance(
        source_model="gpt-4o",  # spoofed
        model_version="gpt-4o",
        temperature=0.0,
        input_hash="a" * 64,
        timestamp_ms=1_700_000_000_000,
    )
    # Keep original signature (now invalid for this body)
    doc.signature = SIFReader().decode(data).signature
    tampered = SIFWriter().encode(doc)

    try:
        SIFReader().verify_signature(tampered)
        print("  FAIL — spoofed provenance accepted")
    except SIFSignatureError as e:
        print(f"  PASS — SIFSignatureError: {e}")
    except SIFChecksumError as e:
        print(f"  PASS — SIFChecksumError: {e}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary() -> None:
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    rows = [
        ("Attack",               "JSON",           "SIF"),
        ("-" * 28,               "-" * 16,         "-" * 20),
        ("Bit flip (corruption)", "Silent*",        "SIFChecksumError"),
        ("Confidence inflation",  "Silent",         "Signature invalid"),
        ("Provenance spoof",      "Silent",         "SIFSignatureError"),
    ]
    for r in rows:
        print(f"  {r[0]:<28} {r[1]:<16} {r[2]}")
    print()
    print("  * JSON detects bit-flips only if they happen to break JSON syntax.")
    print("    SIF detects ALL bit-flips in the covered body via SHA-256.")
    print()
    print("  Implication: SIF audit logs are tamper-evident by construction.")
    print("  JSON audit logs require external integrity infrastructure (separate")
    print("  .sig files, database checksums, etc.) — which are rarely implemented.")


def main():
    print("SIF Tamper Evidence Demo")
    print("Building signed SIF document with 10 factual claims...")
    data, key = _make_signed_doc()
    print(f"Document size: {len(data)} bytes")

    # Verify it's valid before tampering
    assert SIFReader().verify_signature(data) is True
    print("Pre-tamper verification: VALID")

    attack_bit_flip(data)
    attack_confidence_inflation(data)
    attack_provenance_spoof(data)
    print_summary()


if __name__ == "__main__":
    main()
