import hashlib
import struct
import sys
import os

from spfx.reader import SPIFReader
from spfx.format import CHUNK_CHECKSUM
from spfx.crypto import derive_key_from_mnemonic
from spfx.writer import SPIFWriter
from spfx.types import SPIFDocument, Node, Signature

def _sign_doc(doc: SPIFDocument, private_key, signer_id: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07: # CHUNK_SIGNATURE
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln

    body_to_sign = dummy[:sig_offset]
    real_sig = private_key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=real_sig)
    return writer.encode(doc)

# 1. Create a signed document
doc = SPIFDocument(payload=[Node(id="1", type="text", value="original")])
key = derive_key_from_mnemonic("test test test test test test test test test test test junk", passphrase="pass")
data = _sign_doc(doc, key, "test_signer")

# 2. Tamper with it
tampered_data = data.replace(b"original", b"tampered")

# 3. Update the checksum chunk
checksum_offset = None
offset = 9 + 2
while offset < len(tampered_data):
    if offset + 5 > len(tampered_data):
        break
    chunk_type, length = struct.unpack_from(">BI", tampered_data, offset)
    if chunk_type == CHUNK_CHECKSUM:
        checksum_offset = offset
        break
    offset += 5 + length

if checksum_offset is None:
    raise RuntimeError("No checksum chunk")

body = tampered_data[:checksum_offset]
new_checksum = hashlib.sha256(body).digest()

# Construct the new final data
final_data = body + struct.pack(">BI", CHUNK_CHECKSUM, len(new_checksum)) + new_checksum

# 4. Try to decode it
reader = SPIFReader()
try:
    decoded = reader.decode(final_data)
    print("VULNERABILITY FOUND: Silently accepted tampered document!")
    print(f"Value: {decoded.payload[0].value}")
    print(f"Signature present: {decoded.signature is not None}")
except Exception as e:
    print(f"Exception raised: {e}")
