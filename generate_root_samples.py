import sys
import os
import hashlib
import struct
import base64

# Insert spif path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "spif"))

from spif import SPIFDocument, Node, NodeRef, Distribution, TraceStep, TaskInfo, Provenance, Signature, SPIFWriter, SPIFReader
from spif.crypto import derive_key_from_mnemonic
from spif.format import CHUNK_CHECKSUM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def create_samples():
    print("Generating fresh SIF/SPIF sample files...")
    
    # 1. Create a premium SPIF Document with all new fields: task_info, multi-signatures, and provenance
    doc = SPIFDocument(
        payload=[
            Node(
                id="claim_01",
                type="fact",
                value="The Pfhrp2/3 gene deletions are absent in Haitian P. falciparum populations.",
                confidence=Distribution(mean=0.98, var=0.002, shape="gaussian", semantics="custom:clinical_validation"),
                refs=[NodeRef("claim_02")] # References another payload node
            ),
            Node(
                id="claim_02",
                type="fact",
                value="High-sensitivity RDTs (hsRDTs) outperform conventional RDTs for low-density asymptomatic cases in Haiti.",
                confidence=Distribution(mean=0.95, var=0.005, shape="gaussian", semantics="custom:diagnostic_accuracy"),
                refs=[]
            )
        ],
        trace=[
            TraceStep(
                id="trace_step_01",
                type="inference",
                content="Analyze multiplex bead assay and hsRDT field sensitivity data (Herman et al., Rogier et al.).",
                confidence=Distribution(mean=0.97, var=0.003, shape="gaussian", semantics="epistemic"),
                deps=[]
            ),
            TraceStep(
                id="trace_step_02",
                type="inference",
                content="Query local RAG vector database for recent surveillance articles on P. falciparum hrp2 gene status.",
                confidence=Distribution(mean=0.99, var=0.001, shape="gaussian", semantics="epistemic"),
                deps=["trace_step_01"] # References another trace step
            )
        ],
        provenance=Provenance(
            source_model="gemma-4-e2b-vibrion-sentinel",
            model_version="2026.05.21",
            timestamp_ms=1779379200000, # 2026-05-21
            temperature=0.2,
            input_hash="a" * 64,
            attempt=1,
            task_id="task_haiti_malaria_surveillance_2026_05"
        ),
        task_info=TaskInfo(
            task_id="task_haiti_malaria_surveillance_2026_05",
            attempt=1,
            status="ok",
            total_ms=1240,
            tool_count=5,
            error_count=0
        )
    )

    # We will derive two distinct Ed25519 keys for multi-signature verification
    key_primary = derive_key_from_mnemonic(
        "medical expert diagnostic consensus key primary medical team hsdrt 2026",
        passphrase="haiti-consortium"
    )
    key_secondary = derive_key_from_mnemonic(
        "secondary auditor validation signature clinical research partner expert 2026",
        passphrase="haiti-consortium"
    )

    # Get public key base64 encodings
    pub_bytes_primary = key_primary.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64_primary = base64.b64encode(pub_bytes_primary).decode()

    pub_bytes_secondary = key_secondary.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64_secondary = base64.b64encode(pub_bytes_secondary).decode()

    # Encode with placeholder signatures to locate signature chunks
    writer = SPIFWriter()
    doc.signatures = [
        Signature(algorithm="ed25519", signer=pub_b64_primary, signature=b"\x00" * 64, key_id="pubkey-01"),
        Signature(algorithm="ed25519", signer=pub_b64_secondary, signature=b"\x00" * 64, key_id="pubkey-02")
    ]
    doc.signature = doc.signatures[0] # back-compat field

    dummy_encoded = writer.encode(doc)

    # Find offsets for signature chunks
    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    sig_offsets = []
    while offset < len(dummy_encoded):
        ct, ln = struct.unpack_from(">BI", dummy_encoded, offset)
        if ct in (0x07, 0x08): # CHUNK_SIGNATURE or CHUNK_MULTISIG
            sig_offsets.append(offset)
        if ct == 0xFF: # CHUNK_CHECKSUM
            break
        offset += 5 + ln

    # We sign the body up to the first signature chunk
    body_to_sign = dummy_encoded[:sig_offsets[0]]
    sig1 = key_primary.sign(body_to_sign)
    sig2 = key_secondary.sign(body_to_sign)

    doc.signatures = [
        Signature(algorithm="ed25519", signer=pub_b64_primary, signature=sig1, key_id="pubkey-01"),
        Signature(algorithm="ed25519", signer=pub_b64_secondary, signature=sig2, key_id="pubkey-02")
    ]
    doc.signature = doc.signatures[0]

    # Write valid output
    valid_bytes = writer.encode(doc)
    with open("sample_valid.spif", "wb") as f:
        f.write(valid_bytes)
    print("Created sample_valid.spif")

    # 2. Create a programmatically Tampered document
    # Modify the payload content but keep the original signature values (which make them invalid for this text)
    doc.payload[0].value = "The Pfhrp2/3 gene deletions are present in Haitian P. falciparum populations."
    tampered_bytes = writer.encode(doc)

    with open("sample_tampered.spif", "wb") as f:
        f.write(tampered_bytes)
    print("Created sample_tampered.spif")

    # 3. Create a Corrupted document (truncated / bad checksum)
    corrupted_bytes = bytearray(valid_bytes)
    # Corrupt the checksum byte
    corrupted_bytes[-1] ^= 0xFF
    with open("sample_corrupted.spif", "wb") as f:
        f.write(corrupted_bytes)
    print("Created sample_corrupted.spif")

if __name__ == "__main__":
    create_samples()
