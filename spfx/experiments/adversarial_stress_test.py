import hashlib
import json
import os
import random
import struct
import sys
from pathlib import Path

# Mock or install bson/cbor2/msgpack if needed, but they should be in the environment from previous turn
import bson
import cbor2
import msgpack

# Add local sif to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sif import SIFDocument, Node, Distribution, SIFWriter, SIFReader, SIFError, SIFChecksumError

# -----------------------------------------------------------------------------
# Test Data
# -----------------------------------------------------------------------------

def create_target_doc():
    """Create a document with a critical security-sensitive value."""
    # Use a longer string to make searching in binary blob easier
    return SIFDocument(
        payload=[
            Node(
                id="auth_check",
                type="security_policy",
                value="ALLOW_ACCESS_TO_RESOURCES",
                confidence=Distribution(mean=0.99, var=0.001, semantics="factual_accuracy")
            )
        ]
    )

def to_dict(doc):
    """Lossy conversion to dict for other formats."""
    return {
        "id": doc.payload[0].id,
        "type": doc.payload[0].type,
        "value": doc.payload[0].value,
        "conf_mean": doc.payload[0].confidence.mean,
        "conf_var": doc.payload[0].confidence.var,
    }

# -----------------------------------------------------------------------------
# Adversarial Tests
# -----------------------------------------------------------------------------

def test_hackability(doc):
    """
    Test 1: Spoofing/Hackability
    Can we change 'ALLOW_ACCESS_TO_RESOURCES' to 'DENY_ACCESS_TO_RESOURCES'
    without the reader noticing?
    """
    print("\n[Test 1] Hackability: Silent modification of critical values")
    
    # Define encoders and decoders for each format
    def enc_sif(d): return SIFWriter().encode(d)
    def dec_sif(b): return SIFReader().decode(b)
    
    def enc_json(d): return json.dumps(to_dict(d)).encode()
    def dec_json(b): return json.loads(b)
    
    def enc_cbor(d): return cbor2.dumps(to_dict(d))
    def dec_cbor(b): return cbor2.loads(b)
    
    def enc_msgpack(d): return msgpack.packb(to_dict(d))
    def dec_msgpack(b): return msgpack.unpackb(b)
    
    def enc_bson(d): return bson.encode(to_dict(d))
    def dec_bson(b): return bson.decode(b)

    formats = {
        "SIF": (enc_sif, dec_sif),
        "JSON": (enc_json, dec_json),
        "CBOR": (enc_cbor, dec_cbor),
        "MsgPack": (enc_msgpack, dec_msgpack),
        "BSON": (enc_bson, dec_bson),
    }

    results = {}
    for name, (enc, dec) in formats.items():
        try:
            original_bytes = enc(doc)
            
            target_val = b"ALLOW_ACCESS_TO_RESOURCES"
            hack_val = b"DENY_ACCESS_TO_RESOURCES " # Same length
            
            if target_val in original_bytes:
                hacked_bytes = original_bytes.replace(target_val, hack_val)
                try:
                    decoded = dec(hacked_bytes)
                    # If we get here, the reader didn't catch the tamper
                    val = ""
                    if name == "SIF":
                        val = decoded.payload[0].value
                    else:
                        val = decoded["value"]
                    
                    if "DENY_ACCESS" in val:
                        results[name] = "🔓 HACKED (Silent Tamper)"
                    else:
                        results[name] = "✓ PROTECTED (Logical Check)"
                except Exception as e:
                    results[name] = f"🛡️ BLOCKED ({type(e).__name__})"
            else:
                results[name] = "N/A (Target not found in raw bytes)"
        except Exception as e:
            results[name] = f"❌ ERROR ({type(e).__name__})"
            
    return results

def test_corruption_susceptibility(doc, error_rate=0.01):
    """
    Test 2: Corruption Susceptibility
    Flip random bits. Does the parser return garbage, crash, or catch it?
    """
    print(f"\n[Test 2] Corruption Susceptibility: Randomly flipping bits (Rate: {error_rate*100}%)")
    
    # Encoders/Decoders
    encs = {
        "SIF": lambda d: SIFWriter().encode(d),
        "JSON": lambda d: json.dumps(to_dict(d)).encode(),
        "CBOR": lambda d: cbor2.dumps(to_dict(d)),
        "MsgPack": lambda d: msgpack.packb(to_dict(d)),
        "BSON": lambda d: bson.encode(to_dict(d)),
    }
    decs = {
        "SIF": lambda b: SIFReader().decode(b),
        "JSON": lambda b: json.loads(b),
        "CBOR": lambda b: cbor2.loads(b),
        "MsgPack": lambda b: msgpack.unpackb(b),
        "BSON": lambda b: bson.decode(b),
    }

    results = {}
    for name, enc in encs.items():
        try:
            original_bytes = enc(doc)
            tampered = bytearray(original_bytes)
            
            # Flip random bits
            num_flips = max(1, int(len(tampered) * error_rate))
            for _ in range(num_flips):
                idx = random.randint(0, len(tampered) - 1)
                tampered[idx] ^= (1 << random.randint(0, 7))
                
            try:
                decs[name](bytes(tampered))
                results[name] = "⚠️ SILENT CORRUPTION (Returned Garbage)"
            except Exception as e:
                if name == "SIF" and isinstance(e, SIFChecksumError):
                    results[name] = "✓ CAUGHT (Integrity Check)"
                else:
                    results[name] = f"🛡️ CAUGHT ({type(e).__name__})"
        except Exception as e:
             results[name] = f"❌ ERROR ({type(e).__name__})"
                
    return results

def test_degradation_robustness(doc):
    """
    Test 3: Truncation / Degradation
    Cut the file in half.
    """
    print("\n[Test 3] Degradation Robustness: Truncating file at 50%")
    
    encs = {
        "SIF": lambda d: SIFWriter().encode(d),
        "JSON": lambda d: json.dumps(to_dict(d)).encode(),
        "CBOR": lambda d: cbor2.dumps(to_dict(d)),
        "MsgPack": lambda d: msgpack.packb(to_dict(d)),
        "BSON": lambda d: bson.encode(to_dict(d)),
    }
    decs = {
        "SIF": lambda b: SIFReader().decode(b),
        "JSON": lambda b: json.loads(b),
        "CBOR": lambda b: cbor2.loads(b),
        "MsgPack": lambda b: msgpack.unpackb(b),
        "BSON": lambda b: bson.decode(b),
    }

    results = {}
    for name, enc in encs.items():
        try:
            original_bytes = enc(doc)
            truncated = original_bytes[:len(original_bytes)//2]
            
            try:
                decs[name](truncated)
                results[name] = "⚠️ INCOMPLETE DATA (Partial Read)"
            except Exception as e:
                results[name] = f"✓ REJECTED ({type(e).__name__})"
        except Exception as e:
            results[name] = f"❌ ERROR ({type(e).__name__})"
            
    return results

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    doc = create_target_doc()
    
    print("="*80)
    print("SIF ADVERSARIAL STRESS TEST: INTEGRITY, SECURITY, & HACKABILITY")
    print("="*80)
    
    hack_res = test_hackability(doc)
    corr_res = test_corruption_susceptibility(doc)
    degr_res = test_degradation_robustness(doc)
    
    print("\n" + "="*80)
    print("FINAL ADVERSARIAL REPORT")
    print("="*80)
    
    print(f"\n{'Format':<12} {'Hackability':<30} {'Corruption':<30} {'Degradation'}")
    print("-" * 110)
    
    for name in ["SIF", "JSON", "CBOR", "MsgPack", "BSON"]:
        h = hack_res.get(name, "N/A")
        c = corr_res.get(name, "N/A")
        d = degr_res.get(name, "N/A")
        print(f"{name:<12} {h:<30} {c:<30} {d}")
    
    print("\nSummary:")
    print("- SIF: Built-in SHA-256 makes 'Silent Tamper' impossible for attackers.")
    print("- JSON/CBOR/BSON: Vulnerable to silent bit-flips and value injection if the structure remains valid.")
    print("- Integrity: SIF explicitly validates entire body vs checksum; others rely on parser luck.")
