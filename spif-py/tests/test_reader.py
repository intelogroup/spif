import pytest
from spif import SPIFWriter, SPIFReader, SPIFDocument, Node, Distribution
from spif import SPIFMagicError, SPIFChecksumError, SPIFFormatError


def _minimal_doc():
    return SPIFDocument(payload=[
        Node(id="n1", type="text", value="test",
             confidence=Distribution(mean=0.9, var=0.01))
    ])


def _encoded():
    return SPIFWriter().encode(_minimal_doc())


def test_reads_valid_file(tmp_path):
    path = tmp_path / "ok.sif"
    SPIFWriter().write(_minimal_doc(), path)
    doc = SPIFReader().read(path)
    assert len(doc.payload) == 1
    assert doc.payload[0].id == "n1"


def test_bad_magic_raises():
    data = b"\x00" * 8 + b"\x01\x00" + b"\x00" * 20
    with pytest.raises(SPIFMagicError):
        SPIFReader().decode(data)


def test_too_short_raises():
    with pytest.raises(SPIFMagicError):
        SPIFReader().decode(b"\x89SIF")


def test_tampered_payload_raises():
    data = bytearray(_encoded())
    # Flip a byte somewhere in the middle (after the 10-byte header)
    data[50] ^= 0xFF
    with pytest.raises(SPIFChecksumError):
        SPIFReader().decode(bytes(data))


def test_no_checksum_raises():
    # Produce data without the checksum chunk
    data = _encoded()
    # Strip last chunk (checksum is 5 + 32 = 37 bytes)
    truncated = data[:-37]
    with pytest.raises(SPIFFormatError, match="CHECKSUM"):
        SPIFReader().decode(truncated)


def test_missing_payload_raises():
    # Build raw bytes that have magic + header chunk + checksum but no payload
    import struct
    import hashlib
    import cbor2
    from spif.format import MAGIC, FORMAT_VERSION, CHUNK_HEADER, CHUNK_CHECKSUM
    parts = [MAGIC, bytes([FORMAT_VERSION, 0x00])]
    header_data = cbor2.dumps({"version": 1, "flags": 0, "created_ms": 0})
    parts.append(struct.pack(">BI", CHUNK_HEADER, len(header_data)) + header_data)
    body = b"".join(parts)
    checksum = hashlib.sha256(body).digest()
    data = body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + checksum
    with pytest.raises(SPIFFormatError, match="PAYLOAD"):
        SPIFReader().decode(data)


def test_empty_payload_raises_format_error():
    import struct
    import hashlib
    import cbor2
    from spif.format import MAGIC, FORMAT_VERSION, CHUNK_HEADER, CHUNK_PAYLOAD, CHUNK_CHECKSUM

    parts = [MAGIC, bytes([FORMAT_VERSION, 0x00])]
    header_data = cbor2.dumps({"version": FORMAT_VERSION, "flags": 0, "created_ms": 0})
    payload_data = cbor2.dumps([])
    parts.append(struct.pack(">BI", CHUNK_HEADER, len(header_data)) + header_data)
    parts.append(struct.pack(">BI", CHUNK_PAYLOAD, len(payload_data)) + payload_data)
    body = b"".join(parts)
    checksum = hashlib.sha256(body).digest()
    data = body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + checksum

    with pytest.raises(SPIFFormatError, match="PAYLOAD must contain at least one node"):
        SPIFReader().decode(data)


def test_payload_non_dict_entry_raises_format_error():
    import struct
    import hashlib
    import cbor2
    from spif.format import MAGIC, FORMAT_VERSION, CHUNK_HEADER, CHUNK_PAYLOAD, CHUNK_CHECKSUM

    parts = [MAGIC, bytes([FORMAT_VERSION, 0x00])]
    header_data = cbor2.dumps({"version": FORMAT_VERSION, "flags": 0, "created_ms": 0})
    payload_data = cbor2.dumps([1])
    parts.append(struct.pack(">BI", CHUNK_HEADER, len(header_data)) + header_data)
    parts.append(struct.pack(">BI", CHUNK_PAYLOAD, len(payload_data)) + payload_data)
    body = b"".join(parts)
    checksum = hashlib.sha256(body).digest()
    data = body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + checksum

    with pytest.raises(SPIFFormatError, match="Node entry must be a dict"):
        SPIFReader().decode(data)


def test_trace_non_container_raises_format_error():
    import struct
    import hashlib
    import cbor2
    from spif.format import (
        MAGIC,
        FORMAT_VERSION,
        CHUNK_HEADER,
        CHUNK_TRACE,
        CHUNK_PAYLOAD,
        CHUNK_CHECKSUM,
    )

    parts = [MAGIC, bytes([FORMAT_VERSION, 0x00])]
    header_data = cbor2.dumps({"version": FORMAT_VERSION, "flags": 0, "created_ms": 0})
    trace_data = cbor2.dumps("bad-trace")
    payload_data = cbor2.dumps([
        {"id": "n1", "type": "text", "value": "ok", "confidence": {"mean": 1.0}}
    ])
    parts.append(struct.pack(">BI", CHUNK_HEADER, len(header_data)) + header_data)
    parts.append(struct.pack(">BI", CHUNK_TRACE, len(trace_data)) + trace_data)
    parts.append(struct.pack(">BI", CHUNK_PAYLOAD, len(payload_data)) + payload_data)
    body = b"".join(parts)
    checksum = hashlib.sha256(body).digest()
    data = body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + checksum

    with pytest.raises(SPIFFormatError, match="TRACE chunk must decode to a list or dict"):
        SPIFReader().decode(data)
