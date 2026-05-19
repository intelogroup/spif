"""
Live integration tests — require a real ANTHROPIC_API_KEY in the environment.

These tests are marked `live` and skipped automatically when the key is absent.
Run them explicitly:

    pytest tests/test_live_integration.py -v
    pytest tests/test_live_integration.py -v -m live

What is tested
──────────────
1. complete() — blocking call, minimal prompt, verify document structure
2. stream()   — streaming call, verify byte sequence + final document
3. thinking   — extended thinking enabled, trace steps present + DAG valid
4. provenance — source_model, input_hash, timestamp all populated correctly
5. checksum   — SHA-256 in the SPIF bytes is valid (SPIFReader verifies)
6. cross-lang — Python writes SPIF → Rust spfx-viewer reads and exits 0
7. chained    — two calls linked via context_ref (multi-turn provenance chain)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
RUST_VIEWER = Path(__file__).parent.parent.parent / "sif-rust" / "target" / "release" / "spfx-viewer"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not ANTHROPIC_API_KEY, reason="ANTHROPIC_API_KEY not set"),
]

# ---------------------------------------------------------------------------
# Lazy imports — only pulled in when tests actually run
# ---------------------------------------------------------------------------

def _imports():
    import anthropic
    from spfx.adapters.anthropic_adapter import AnthropicSPIFAdapter
    from spfx.reader import SPIFReader
    from spfx.streaming import SPIFStreamReader
    from spfx.writer import SPIFWriter
    return anthropic, AnthropicSPIFAdapter, SPIFReader, SPIFStreamReader, SPIFWriter


# ---------------------------------------------------------------------------
# 1. complete() — blocking, document structure
# ---------------------------------------------------------------------------

def test_complete_returns_valid_document():
    anthropic, AnthropicSPIFAdapter, SPIFReader, _, SPIFWriter = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=64)

    doc = adapter.complete("Reply with the single word: SPIF")

    # Payload
    assert len(doc.payload) >= 1, "document must have at least one payload node"
    response_text = doc.payload[0].value
    assert isinstance(response_text, str) and len(response_text) > 0

    # Provenance
    assert doc.provenance is not None, "provenance must be set"
    assert "haiku" in doc.provenance.source_model.lower() or "claude" in doc.provenance.source_model.lower()
    assert doc.provenance.timestamp_ms > 0
    assert len(doc.provenance.input_hash) == 64, "input_hash must be 64-char hex SHA-256"

    # Confidence on every node
    for node in doc.payload:
        c = node.confidence
        assert 0.0 <= c.mean <= 1.0, f"confidence mean out of range: {c.mean}"
        assert c.var >= 0.0
        assert c.shape in ("gaussian", "beta", "uniform")

    # Round-trip: write → read via SPIFReader (also verifies checksum)
    writer = SPIFWriter()
    raw = writer.encode(doc)
    reader = SPIFReader()
    doc2 = reader.decode(raw)
    assert doc2.payload[0].value == doc.payload[0].value


# ---------------------------------------------------------------------------
# 2. stream() — byte sequence + final document
# ---------------------------------------------------------------------------

def test_stream_yields_bytes_and_final_document():
    anthropic, AnthropicSPIFAdapter, SPIFReader, SPIFStreamReader, _ = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=64)

    all_bytes: list[bytes] = []
    partial_texts: list[str] = []
    stream_reader = SPIFStreamReader()
    final_doc = None

    gen = adapter.stream("Count from 1 to 5, one number per line.")
    try:
        while True:
            chunk = next(gen)
            assert isinstance(chunk, bytes) and len(chunk) > 0, "each chunk must be non-empty bytes"
            all_bytes.append(chunk)
            for event in stream_reader.feed(chunk):
                if event.type == "partial_text":
                    partial_texts.append(event.text)
                elif event.type == "verified":
                    final_doc = event.document
    except StopIteration as exc:
        if final_doc is None:
            final_doc = exc.value

    assert len(all_bytes) > 1, "streaming should yield multiple chunks"
    assert len(partial_texts) > 0, "at least one partial_text event expected"
    assert final_doc is not None, "final document must be produced"

    # Full byte blob must be readable by SPIFReader (checksum verified inside)
    full_bytes = b"".join(all_bytes)
    reader = SPIFReader()
    doc = reader.decode(full_bytes)
    assert doc.payload[0].value == "".join(partial_texts)


# ---------------------------------------------------------------------------
# 3. thinking — extended thinking, trace DAG present and valid
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_thinking_produces_trace_dag():
    anthropic, AnthropicSPIFAdapter, SPIFReader, _, SPIFWriter = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(
        client,
        model="claude-sonnet-4-6",
        max_tokens=5000,
    )

    doc = adapter.complete(
        "What is 17 * 23? Show your reasoning.",
        thinking=True,
        thinking_budget_tokens=2000,
    )

    assert doc.trace_method == "live", "thinking responses must have trace_method='live'"
    assert len(doc.trace) > 0, "extended thinking must produce trace steps"

    # Verify DAG structure: each dep must reference an earlier step
    step_ids = {s.id for s in doc.trace}
    for step in doc.trace:
        for dep in step.deps:
            assert dep in step_ids, f"step '{step.id}' has dangling dep '{dep}'"

    # Confidence on trace steps
    for step in doc.trace:
        assert 0.0 <= step.confidence.mean <= 1.0

    # SPIFReader validates the DAG internally — if it reads, DAG is valid
    writer = SPIFWriter()
    raw = writer.encode(doc)
    reader = SPIFReader()
    doc2 = reader.decode(raw)
    assert len(doc2.trace) == len(doc.trace)


# ---------------------------------------------------------------------------
# 4. provenance — input_hash is deterministic for same prompt
# ---------------------------------------------------------------------------

def test_provenance_input_hash_is_deterministic():
    anthropic, AnthropicSPIFAdapter, _, _, _ = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=32)

    prompt = "Reply with exactly: OK"

    doc1 = adapter.complete(prompt)
    doc2 = adapter.complete(prompt)

    # Same prompt → same input_hash regardless of response content
    assert doc1.provenance.input_hash == doc2.provenance.input_hash, \
        "input_hash must be deterministic for identical prompts"

    # Verify hash matches what we'd compute ourselves
    messages = [{"role": "user", "content": prompt}]
    canonical = json.dumps(messages, sort_keys=True, ensure_ascii=False)
    expected_hash = hashlib.sha256(canonical.encode()).hexdigest()
    assert doc1.provenance.input_hash == expected_hash


# ---------------------------------------------------------------------------
# 5. checksum — tamper detection end-to-end
# ---------------------------------------------------------------------------

def test_tampered_bytes_rejected_by_reader():
    anthropic, AnthropicSPIFAdapter, SPIFReader, _, SPIFWriter = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=32)

    doc = adapter.complete("Say hello.")
    writer = SPIFWriter()
    raw = bytearray(writer.encode(doc))

    # Flip a byte in the middle of the document body
    mid = len(raw) // 2
    raw[mid] ^= 0xFF

    reader = SPIFReader()
    with pytest.raises(Exception, match="[Cc]hecksum|[Cc]orrupt|[Mm]ismatch"):
        reader.decode(bytes(raw))


# ---------------------------------------------------------------------------
# 6. cross-language — Python writes SPIF → Rust spfx-viewer reads it
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not RUST_VIEWER.exists(), reason="Rust spfx-viewer binary not built")
def test_python_spif_readable_by_rust_viewer():
    anthropic, AnthropicSPIFAdapter, _, _, SPIFWriter = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=32)

    doc = adapter.complete("Name one planet in our solar system.")
    writer = SPIFWriter()
    raw = writer.encode(doc)

    with tempfile.NamedTemporaryFile(suffix=".spfx", delete=False) as f:
        f.write(raw)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [str(RUST_VIEWER), tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, \
            f"Rust spfx-viewer failed (exit {result.returncode}):\n{result.stderr}"
        # Viewer output should contain the model name from provenance
        assert "claude" in result.stdout.lower() or "haiku" in result.stdout.lower(), \
            f"Expected model name in viewer output. Got:\n{result.stdout}"
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# 7. chained calls — context_ref links documents in a provenance chain
# ---------------------------------------------------------------------------

def test_chained_calls_link_via_context_ref():
    anthropic, AnthropicSPIFAdapter, SPIFReader, _, SPIFWriter = _imports()

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    adapter = AnthropicSPIFAdapter(client, model="claude-haiku-4-5-20251001", max_tokens=64)

    # First turn
    doc1 = adapter.complete("My favourite colour is blue. Acknowledge this in one word.")

    # Second turn — passes doc1 as context
    doc2 = adapter.complete(
        "What did I just tell you my favourite colour is?",
        context=doc1,
    )

    assert doc2.provenance.context_ref != "", \
        "second document must reference the first via context_ref"
    assert doc2.provenance.context_ref == doc1.content_id(), \
        "context_ref must equal the content_id of the prior document"

    # Both must be independently readable
    reader = SPIFReader()
    writer = SPIFWriter()
    reader.decode(writer.encode(doc1))
    reader.decode(writer.encode(doc2))
