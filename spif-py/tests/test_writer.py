import struct
import pytest
from spif import SPIFWriter, SPIFDocument, Node, Distribution
from spif.format import MAGIC, FORMAT_VERSION, CHUNK_PAYLOAD, CHUNK_CHECKSUM


def _minimal_doc():
    return SPIFDocument(payload=[
        Node(id="n1", type="text", value="Hello, SIF.",
             confidence=Distribution(mean=1.0, var=0.0, shape="point"))
    ])


def test_magic_bytes():
    data = SPIFWriter().encode(_minimal_doc())
    assert data[:len(MAGIC)] == MAGIC


def test_version_byte():
    data = SPIFWriter().encode(_minimal_doc())
    assert data[len(MAGIC)] == FORMAT_VERSION


def test_flags_byte_minimal():
    data = SPIFWriter().encode(_minimal_doc())
    # No optional layers → flags should be 0
    assert data[len(MAGIC) + 1] == 0x00


def test_payload_chunk_present():
    data = SPIFWriter().encode(_minimal_doc())
    offset = len(MAGIC) + 2
    found = False
    while offset < len(data):
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        if chunk_type == CHUNK_PAYLOAD:
            found = True
            break
        if chunk_type == CHUNK_CHECKSUM:
            break
        offset += 5 + length
    assert found, "PAYLOAD chunk not found"


def test_checksum_chunk_last():
    data = SPIFWriter().encode(_minimal_doc())
    offset = len(MAGIC) + 2
    last_type = None
    while offset < len(data):
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        last_type = chunk_type
        offset += 5 + length
    assert last_type == CHUNK_CHECKSUM


def test_checksum_length():
    data = SPIFWriter().encode(_minimal_doc())
    offset = len(MAGIC) + 2
    while offset < len(data):
        chunk_type, length = struct.unpack_from(">BI", data, offset)
        if chunk_type == CHUNK_CHECKSUM:
            assert length == 32
            return
        offset += 5 + length
    pytest.fail("CHECKSUM chunk not found")


def test_write_to_file(tmp_path):
    path = tmp_path / "test.sif"
    SPIFWriter().write(_minimal_doc(), path)
    assert path.exists()
    assert path.stat().st_size > 0
