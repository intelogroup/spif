"""
Live provider acceptance tests for real API keys.

These tests are broader than the provider-specific unit tests but cheaper and
less brittle than deep end-to-end evaluations. They verify that a real model
response can survive the SPIF lifecycle:

1. provider call -> SPIFDocument
2. stream -> partial_text events -> verified SPIFDocument
3. encode/sign/decode -> strict verification
4. export -> OTel / PROV
5. context chaining where the adapter supports it

Run explicitly:

    pytest tests/test_live_provider_acceptance.py -v -m live

Environment variables:
    ANTHROPIC_API_KEY
    OPENAI_API_KEY
    GEMINI_API_KEY or GOOGLE_API_KEY
"""

from __future__ import annotations

import base64
import os
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFReader, SPIFWriter, Signature
from spif.exporters.otel import to_otel_span
from spif.exporters.prov import to_prov
from spif.format import CHUNK_CHECKSUM, MAGIC
from spif.streaming import SPIFStreamReader


pytestmark = [pytest.mark.live]

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
_CHUNK_STRUCT = struct.Struct(">BI")


def _pub_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


def _find_auth_offset(data: bytes) -> int | None:
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            return None
        chunk_type, length = _CHUNK_STRUCT.unpack_from(data, offset)
        if chunk_type in (0x07, 0x08):
            return offset
        if chunk_type == CHUNK_CHECKSUM:
            return None
        offset += 5 + length
    return None


def _sign_bytes(doc) -> bytes:
    key = Ed25519PrivateKey.generate()
    signer = _pub_b64(key)
    writer = SPIFWriter()

    doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    auth_offset = _find_auth_offset(dummy)
    assert auth_offset is not None, "signature chunk not found in dummy encoding"

    doc.signature = Signature(
        algorithm="ed25519",
        signer=signer,
        signature=key.sign(dummy[:auth_offset]),
    )
    return writer.encode(doc)


def _consume_stream(gen):
    stream_reader = SPIFStreamReader()
    chunks: list[bytes] = []
    partial_texts: list[str] = []
    final_doc = None

    try:
        while True:
            chunk = next(gen)
            assert isinstance(chunk, bytes) and chunk
            chunks.append(chunk)
            for event in stream_reader.feed(chunk):
                if event.type == "partial_text":
                    partial_texts.append(event.text)
                elif event.type == "verified":
                    final_doc = event.document
    except StopIteration as exc:
        if final_doc is None:
            final_doc = exc.value

    return b"".join(chunks), partial_texts, final_doc


def _assert_exportable_and_signable(doc) -> None:
    raw = SPIFWriter().encode(doc)
    decoded = SPIFReader().decode(raw)
    assert decoded.payload
    assert decoded.provenance is not None

    signed = _sign_bytes(decoded)
    restored = SPIFReader.strict().decode(signed)
    assert restored.signature is not None
    assert SPIFReader().verify_signature(signed) is True

    span = to_otel_span(restored)
    prov = to_prov(restored)
    assert "attributes" in span
    assert "entity" in prov


@pytest.mark.skipif(not ANTHROPIC_API_KEY, reason="ANTHROPIC_API_KEY not set")
def test_live_anthropic_acceptance():
    anthropic = pytest.importorskip("anthropic")
    from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(
        client,
        model="claude-haiku-4-5-20251001",
        max_tokens=64,
        temperature=0.2,
    )

    doc1 = adapter.complete("Reply with exactly: BLUE")
    assert doc1.payload[0].value.strip()
    assert doc1.provenance is not None
    assert "claude" in doc1.provenance.source_model.lower()
    _assert_exportable_and_signable(doc1)

    stream_bytes, partials, streamed_doc = _consume_stream(
        adapter.stream("Reply with exactly: GREEN")
    )
    assert partials
    assert streamed_doc is not None
    assert streamed_doc.payload[0].value == "".join(partials)
    assert SPIFReader().decode(stream_bytes).payload[0].value == streamed_doc.payload[0].value

    doc2 = adapter.complete("What single color did I tell you first?", context=doc1)
    assert doc2.provenance is not None
    assert doc2.provenance.context_ref == doc1.content_id()


@pytest.mark.skipif(not OPENAI_API_KEY, reason="OPENAI_API_KEY not set")
def test_live_openai_acceptance():
    openai = pytest.importorskip("openai")
    from spif.adapters.openai_adapter import OpenAISPIFAdapter

    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    adapter = OpenAISPIFAdapter(
        client,
        model="gpt-4o-mini",
        max_tokens=64,
        temperature=0.2,
        logprobs=False,
    )

    doc1 = adapter.complete("Reply with exactly: TRIANGLE")
    assert doc1.payload[0].value.strip()
    assert doc1.provenance is not None
    assert "gpt" in doc1.provenance.source_model.lower() or "o" in doc1.provenance.source_model.lower()
    _assert_exportable_and_signable(doc1)

    stream_bytes, partials, streamed_doc = _consume_stream(
        adapter.stream("Reply with exactly: SQUARE")
    )
    assert partials
    assert streamed_doc is not None
    assert streamed_doc.payload[0].value == "".join(partials)
    assert SPIFReader().decode(stream_bytes).payload[0].value == streamed_doc.payload[0].value

    doc2 = adapter.complete("What shape did I ask you to say first?", context=doc1)
    assert doc2.provenance is not None
    assert doc2.provenance.context_ref == doc1.content_id()


@pytest.mark.skipif(not GEMINI_API_KEY, reason="GEMINI_API_KEY / GOOGLE_API_KEY not set")
def test_live_gemini_acceptance():
    genai = pytest.importorskip("google.genai")
    from spif.adapters.gemini_adapter import GeminiSPIFAdapter

    client = genai.Client(api_key=GEMINI_API_KEY)
    adapter = GeminiSPIFAdapter(
        client,
        model="gemini-2.0-flash",
        max_tokens=64,
        temperature=0.2,
        logprobs=False,
        use_genai_sdk=True,
    )

    doc = adapter.complete("Reply with exactly: HEXAGON")
    assert doc.payload[0].value.strip()
    assert doc.provenance is not None
    assert "gemini" in doc.provenance.source_model.lower()
    _assert_exportable_and_signable(doc)

    stream_bytes, partials, streamed_doc = _consume_stream(
        adapter.stream("Reply with exactly: CIRCLE")
    )
    assert partials
    assert streamed_doc is not None
    assert streamed_doc.payload[0].value == "".join(partials)
    assert SPIFReader().decode(stream_bytes).payload[0].value == streamed_doc.payload[0].value
