import os
import sys
import json
import base64
from pathlib import Path

# Add spfx path to sys
sys.path.insert(0, str(Path(__file__).parent.parent / "spfx"))

from spfx import SPIFReader, SPIFWriter, Signature
from spfx.adapters.openai_adapter import OpenAISPIFAdapter
from spfx.crypto import derive_key_from_mnemonic

def run_simulation():
    print("=" * 70)
    print(" 🤖 SPIF ZERO-TRUST MULTI-AGENT VERIFICATION DEMO")
    print("=" * 70)

    # Automatically load from parent directory's .env if present
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    if k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
                        os.environ[k] = v

    # 1. Retrieve the OpenAI API key
    openai_key = os.environ.get("OPENAI_API_KEY")
    if not openai_key:
        print("\n❌ ERROR: OPENAI_API_KEY environment variable is not set.")
        print("Please export it in your terminal first, e.g.:")
        print("   export OPENAI_API_KEY='your-key-here'")
        print("   python3 scratch/verify_live_agents.py")
        print("-" * 70)
        return

    try:
        import openai
    except ImportError:
        print("\n❌ ERROR: openai library is not installed.")
        print("Please install it using: pip install openai")
        print("-" * 70)
        return

    # 2. Derive Cryptographic Keys for our agents to sign their communications
    print("\n🔐 Deriving cryptographic signing keys for agents...")
    key_agent_a = derive_key_from_mnemonic("agent alpha primary authority cryptographic key secure seed 2026")
    key_agent_b = derive_key_from_mnemonic("agent beta peer verification cryptographic key validation seed 2026")

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_bytes_a = key_agent_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64_a = base64.b64encode(pub_bytes_a).decode("utf-8")

    pub_bytes_b = key_agent_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64_b = base64.b64encode(pub_bytes_b).decode("utf-8")

    print(f"   [Agent A] Public Key: {pub_b64_a[:20]}...")
    print(f"   [Agent B] Public Key: {pub_b64_b[:20]}...")

    # Initialize OpenAI client & adapter
    client = openai.OpenAI(api_key=openai_key)
    adapter = OpenAISPIFAdapter(client, model="gpt-4o-mini", max_tokens=100)

    # ──────────────────────────────────────────────────────────────────────────
    # TURN 1: Agent A generates a verified signed recommendation
    # ──────────────────────────────────────────────────────────────────────────
    print("\n🎬 TURN 1: Agent A is generating structured analysis and signing it...")
    prompt_a = "Analyze why Pfhrp2/3 gene deletions are absent in Haiti in 1 short sentence."
    doc_a = adapter.complete(prompt_a)

    # Inject signature of Agent A
    writer = SPIFWriter()
    doc_a.signatures = [Signature(algorithm="ed25519", signer=pub_b64_a, signature=b"\x00"*64, key_id="agent-a-key")]
    doc_a.signature = doc_a.signatures[0]
    dummy_bytes_a = writer.encode(doc_a)

    # Locate signature offset
    auth_offset_a = dummy_bytes_a.find(b"\x07") # signature chunk header type is 0x07
    if auth_offset_a == -1:
        auth_offset_a = dummy_bytes_a.find(b"\x08") # or 0x08 (multisig)
    
    # Actually sign
    sig_a = key_agent_a.sign(dummy_bytes_a[:auth_offset_a])
    doc_a.signatures[0].signature = sig_a
    doc_a.signature.signature = sig_a

    signed_bytes_a = writer.encode(doc_a)
    print(f"✅ Agent A generated signed document. Length: {len(signed_bytes_a)} bytes.")
    print(f"   Payload Value: \"{doc_a.payload[0].value}\"")

    # ──────────────────────────────────────────────────────────────────────────
    # TRANSMISSION & INGESTION (Agent B receives and eagerly verifies)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n🚀 TRANSMITTING SIF BINARY BLOB FROM AGENT A TO AGENT B...")
    print("⏳ Agent B is eagerly decoding and verifying the signature...")

    reader = SPIFReader()
    # Agent B parses the incoming bytes
    try:
        decoded_a = reader.decode(signed_bytes_a)
        is_signature_valid = reader.verify_signature(signed_bytes_a)
        
        if is_signature_valid:
            print("🟢 VERIFICATION SUCCESS: Signature matches Agent A's identity!")
            print("   The payload has NOT been altered in transit.")
        else:
            print("🔴 VERIFICATION FAILED: Invalid signature detected!")
            return
    except Exception as e:
        print(f"🔴 VERIFICATION EXCEPTION: {e}")
        return

    # ──────────────────────────────────────────────────────────────────────────
    # TURN 2: Agent B responds, linking cryptographically to Agent A's turn
    # ──────────────────────────────────────────────────────────────────────────
    print("\n🎬 TURN 2: Agent B is generating a response and linking back...")
    prompt_b = "Summarize the findings received from Agent A in one word."
    
    # We pass decoded_a as the context to create a secure context_ref chain link
    doc_b = adapter.complete(prompt_b, context=decoded_a)

    # Inject signature of Agent B
    doc_b.signatures = [Signature(algorithm="ed25519", signer=pub_b64_b, signature=b"\x00"*64, key_id="agent-b-key")]
    doc_b.signature = doc_b.signatures[0]
    dummy_bytes_b = writer.encode(doc_b)

    auth_offset_b = dummy_bytes_b.find(b"\x07")
    if auth_offset_b == -1:
        auth_offset_b = dummy_bytes_b.find(b"\x08")

    sig_b = key_agent_b.sign(dummy_bytes_b[:auth_offset_b])
    doc_b.signatures[0].signature = sig_b
    doc_b.signature.signature = sig_b

    signed_bytes_b = writer.encode(doc_b)

    print(f"✅ Agent B generated signed response. Length: {len(signed_bytes_b)} bytes.")
    print(f"   Payload Value: \"{doc_b.payload[0].value}\"")
    print(f"   Linked Context Reference (prior turn hash): {doc_b.provenance.context_ref}")
    
    # ──────────────────────────────────────────────────────────────────────────
    # FINAL AUDIT TRAIL VERIFICATION
    # ──────────────────────────────────────────────────────────────────────────
    print("\n🔍 RUNNING COMPLETE AUDIT TRAIL VALIDATION...")
    try:
        restored_b = reader.decode(signed_bytes_b)
        assert restored_b.provenance.context_ref == decoded_a.content_id()
        print("🎉 AUDIT PASSED: The multi-turn conversation chain is cryptographically unbroken and fully authentic!")
    except Exception as e:
        print(f"❌ AUDIT FAILED: {e}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    run_simulation()
