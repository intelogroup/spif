"""Provenance-reorder / DAG-order attack (anti-fluff gap #2).

Construct a validly-signed SPIF doc whose trace DAG contains a cycle
(s1 -> deps [s2], s2 -> deps [s1]). Confirm the cycle is rejected even
though the ed25519 signature over the body is cryptographically valid.

Finding: DAG validation (_validate_trace_dag) runs INSIDE decode(), and
verify_signature() calls decode() internally — so there is no window where
"signature verifies" is reported before DAG validation runs. A cyclic trace
is rejected at decode time regardless of signature validity, not merely
flagged by a separate downstream check.
"""
import base64
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spfx import (
    SPIFDocument, Node, TraceStep, Provenance, Signature,
    SPIFWriter, SPIFReader, SPIFFormatError,
)
from spfx.format import MAGIC


def _sign(doc: SPIFDocument, key, signer_id: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    assert sig_offset is not None
    raw_sig = key.sign(dummy[:sig_offset])
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


def test_cyclic_trace_dag_rejected_despite_valid_signature():
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="x")],
        provenance=Provenance(source_model="attacker-model", timestamp_ms=int(time.time() * 1000)),
        trace=[
            TraceStep(id="s1", type="inference", content="a", deps=["s2"]),
            TraceStep(id="s2", type="inference", content="b", deps=["s1"]),
        ],
    )
    data = _sign(doc, key, pub_b64)

    reader = SPIFReader()
    try:
        reader.verify_signature(data)
        assert False, "expected SPIFFormatError (cycle) to be raised, decode succeeded instead"
    except SPIFFormatError as e:
        assert "Cycle detected" in str(e)


if __name__ == "__main__":
    test_cyclic_trace_dag_rejected_despite_valid_signature()
    print("PASS: cyclic trace DAG rejected despite cryptographically valid signature")
