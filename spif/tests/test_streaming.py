"""Tests for SIF streaming (SSIF protocol)."""

from __future__ import annotations

import pytest

from spif import SPIFDocument, Node, Distribution, Provenance, TraceStep
from spif.streaming import SPIFStreamWriter, SPIFStreamReader, iter_events
from spif.reader import SPIFReader, SPIFChecksumError, SPIFFormatError
from spif.format import CHUNK_PARTIAL_TEXT, FLAG_STREAMING, MAGIC, FORMAT_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_node() -> Node:
    return Node(
        id="n1",
        type="fact",
        value="The sky is blue.",
        confidence=Distribution(mean=0.97, var=0.01, shape="point",
                                semantics="factual_accuracy"),
    )


def _minimal_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[_minimal_node()],
        provenance=None,
        semantic=None,
        trace=[],
        trace_method="post-hoc",
        alternatives=[],
        delta=None,
        signature=None,
        signatures=[],
    )


def _prov() -> Provenance:
    return Provenance(
        source_model="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6",
        temperature=0.7,
        input_hash="a" * 64,
        context_ref="",
        timestamp_ms=1712000000000,
    )


def _stream_doc(doc: SPIFDocument, tokens: list[str] | None = None,
                prov: Provenance | None = None) -> bytes:
    """Produce a complete streaming SIF document as bytes."""
    writer = SPIFStreamWriter()
    parts = [writer.open(prov)]
    for tok in (tokens or ["hello", " world"]):
        parts.append(writer.partial_text(tok, node_id="n1"))
    parts.append(writer.commit(doc))
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Wire format basics
# ---------------------------------------------------------------------------

class TestStreamWireFormat:
    def test_open_starts_with_sif_magic(self):
        writer = SPIFStreamWriter()
        header = writer.open()
        assert header[:len(MAGIC)] == MAGIC

    def test_open_sets_streaming_flag(self):
        writer = SPIFStreamWriter()
        header = writer.open()
        flags_byte = header[len(MAGIC) + 1]  # VERSION at +0, FLAGS at +1
        assert flags_byte & FLAG_STREAMING, "FLAG_STREAMING must be set in header"

    def test_partial_text_uses_chunk_type_0x10(self):
        writer = SPIFStreamWriter()
        writer.open()
        chunk = writer.partial_text("hi")
        assert chunk[0] == CHUNK_PARTIAL_TEXT

    def test_complete_stream_is_valid_sif(self):
        """A full stream (open + partials + commit) must be readable by SPIFReader."""
        data = _stream_doc(_minimal_doc(), tokens=["The sky ", "is blue."])
        doc = SPIFReader().decode(data)
        assert doc.payload[0].id == "n1"

    def test_stream_with_provenance(self):
        prov = _prov()
        data = _stream_doc(_minimal_doc(), prov=prov)
        doc = SPIFReader().decode(data)
        assert doc.provenance is not None
        assert doc.provenance.source_model == "claude-sonnet-4-6"
        assert doc.provenance.timestamp_ms == 1712000000000

    def test_zero_partial_chunks_still_valid(self):
        """commit() with no partial_text() calls must produce valid SIF."""
        writer = SPIFStreamWriter()
        parts = [writer.open(), writer.commit(_minimal_doc())]
        data = b"".join(parts)
        doc = SPIFReader().decode(data)
        assert doc.payload

    def test_open_twice_raises(self):
        writer = SPIFStreamWriter()
        writer.open()
        with pytest.raises(RuntimeError, match="open()"):
            writer.open()

    def test_commit_twice_raises(self):
        writer = SPIFStreamWriter()
        writer.open()
        writer.commit(_minimal_doc())
        with pytest.raises(RuntimeError, match="commit()"):
            writer.commit(_minimal_doc())

    def test_partial_after_commit_raises(self):
        writer = SPIFStreamWriter()
        writer.open()
        writer.commit(_minimal_doc())
        with pytest.raises(RuntimeError):
            writer.partial_text("oops")


# ---------------------------------------------------------------------------
# Checksum integrity
# ---------------------------------------------------------------------------

class TestStreamChecksum:
    def test_tampered_byte_detected(self):
        data = bytearray(_stream_doc(_minimal_doc()))
        # Flip a bit inside the stored checksum (last 32 bytes)
        data[-1] ^= 0xFF
        with pytest.raises(Exception):  # SPIFChecksumError or SPIFFormatError
            SPIFReader().decode(bytes(data))

    def test_truncated_stream_rejected(self):
        data = _stream_doc(_minimal_doc())
        # Strip the checksum chunk (last 37 bytes)
        with pytest.raises(SPIFFormatError, match="CHECKSUM"):
            SPIFReader().decode(data[:-37])

    def test_partial_chunks_covered_by_checksum(self):
        """Modifying a PARTIAL_TEXT chunk must invalidate the checksum."""
        data = bytearray(_stream_doc(_minimal_doc(), tokens=["secret"]))
        # Find the PARTIAL_TEXT chunk (type 0x10) and corrupt its payload
        pos = len(MAGIC) + 2
        while pos + 5 < len(data):
            ct = data[pos]
            clen = int.from_bytes(data[pos + 1:pos + 5], "big")
            if ct == CHUNK_PARTIAL_TEXT:
                data[pos + 5] ^= 0x01  # corrupt first byte of CBOR payload
                break
            pos += 5 + clen
        with pytest.raises(Exception):
            SPIFReader().decode(bytes(data))


# ---------------------------------------------------------------------------
# Stream reader events
# ---------------------------------------------------------------------------

class TestSPIFStreamReader:
    def test_opened_event_fired(self):
        data = _stream_doc(_minimal_doc(), tokens=["hi"])
        events = list(iter_events(data))
        types = [e.type for e in events]
        assert "opened" in types

    def test_partial_text_events_emitted(self):
        tokens = ["The sky ", "is ", "blue."]
        data = _stream_doc(_minimal_doc(), tokens=tokens)
        events = list(iter_events(data))
        partial = [e for e in events if e.type == "partial_text"]
        assert len(partial) == len(tokens)
        assert [e.text for e in partial] == tokens

    def test_partial_text_seq_monotonic(self):
        tokens = ["a", "b", "c", "d"]
        data = _stream_doc(_minimal_doc(), tokens=tokens)
        events = [e for e in iter_events(data) if e.type == "partial_text"]
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs)
        assert seqs == list(range(len(tokens)))

    def test_verified_event_fires_at_end(self):
        data = _stream_doc(_minimal_doc(), tokens=["hi"])
        events = list(iter_events(data))
        verified = [e for e in events if e.type == "verified"]
        assert len(verified) == 1

    def test_verified_event_contains_document(self):
        doc = _minimal_doc()
        data = _stream_doc(doc, tokens=["The sky is blue."])
        events = list(iter_events(data))
        verified = next(e for e in events if e.type == "verified")
        assert verified.document is not None
        assert verified.document.payload[0].id == "n1"

    def test_no_events_after_verified(self):
        data = _stream_doc(_minimal_doc(), tokens=["hi"])
        reader = SPIFStreamReader()
        all_events = reader.feed(data)
        # reader is done; further feed calls return nothing
        assert reader.done()
        assert reader.feed(b"garbage") == []

    def test_incremental_feed_same_as_bulk(self):
        """Feeding one byte at a time must produce the same events as one bulk feed."""
        data = _stream_doc(_minimal_doc(), tokens=["tok1", "tok2"])

        bulk_reader = SPIFStreamReader()
        bulk_events = bulk_reader.feed(data)

        byte_reader = SPIFStreamReader()
        byte_events = []
        for byte in data:
            byte_events.extend(byte_reader.feed(bytes([byte])))

        assert [e.type for e in bulk_events] == [e.type for e in byte_events]
        assert [e.text for e in bulk_events if e.type == "partial_text"] == \
               [e.text for e in byte_events if e.type == "partial_text"]

    def test_invalid_magic_emits_error_event(self):
        data = bytearray(_stream_doc(_minimal_doc()))
        data[0] = 0x00  # corrupt magic
        reader = SPIFStreamReader()
        events = reader.feed(bytes(data))
        error_events = [e for e in events if e.type == "error"]
        assert error_events, "expected an error event for bad magic"
        assert reader.done()

    def test_ordinary_sif_file_readable_by_stream_reader(self):
        """A non-streaming SIF file must still fire 'opened' and 'verified'."""
        from spif import SPIFWriter
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        events = list(iter_events(data))
        types = [e.type for e in events]
        assert "opened" in types
        assert "verified" in types
        assert "partial_text" not in types


# ---------------------------------------------------------------------------
# Document fidelity through stream
# ---------------------------------------------------------------------------

class TestStreamDocumentFidelity:
    def test_trace_survives_stream(self):
        doc = SPIFDocument(
            payload=[_minimal_node()],
            trace=[
                TraceStep(id="s0", type="hypothesis", content="initial",
                          confidence=Distribution(mean=0.8, var=0.05,
                                                  shape="gaussian", semantics="epistemic"),
                          deps=[], alternatives=[]),
                TraceStep(id="s1", type="conclusion", content="final",
                          confidence=Distribution(mean=0.95, var=0.01,
                                                  shape="gaussian", semantics="epistemic"),
                          deps=["s0"], alternatives=[]),
            ],
            trace_method="live",
            provenance=None, semantic=None, alternatives=[],
            delta=None, signature=None, signatures=[],
        )
        data = _stream_doc(doc, tokens=["result"])
        restored = SPIFReader().decode(data)
        assert len(restored.trace) == 2
        assert restored.trace[1].deps == ["s0"]
        assert restored.trace_method == "live"

    def test_many_tokens_fidelity(self):
        words = [f"word{i} " for i in range(200)]
        full_text = "".join(words)
        doc = SPIFDocument(
            payload=[Node(id="r", type="text", value=full_text,
                          confidence=Distribution.certain("epistemic"))],
            provenance=_prov(),
            semantic=None, trace=[], trace_method="post-hoc",
            alternatives=[], delta=None, signature=None, signatures=[],
        )
        data = _stream_doc(doc, tokens=words)
        restored = SPIFReader().decode(data)
        assert restored.payload[0].value == full_text

    def test_require_signature_unsigned_emits_error(self):
        """SPIFStreamReader(require_signature=True) must reject unsigned documents."""
        data = _stream_doc(_minimal_doc(), tokens=["hello"])
        reader = SPIFStreamReader(require_signature=True)
        events = reader.feed(data)
        error_events = [e for e in events if e.type == "error"]
        assert error_events, "expected an error event for unsigned document"
        assert "unsigned" in error_events[0].error.lower() or \
               "signature" in error_events[0].error.lower()
        assert reader.done()

    def test_require_signature_false_accepts_unsigned(self):
        """SPIFStreamReader(require_signature=False) (default) must accept unsigned documents."""
        data = _stream_doc(_minimal_doc(), tokens=["hello"])
        reader = SPIFStreamReader(require_signature=False)
        events = reader.feed(data)
        verified = [e for e in events if e.type == "verified"]
        assert verified, "expected a verified event for unsigned document with default reader"

    def test_require_signature_real_fixture(self):
        """resumability_study.sif is unsigned — strict reader must reject it via stream."""
        import pathlib
        sif_path = pathlib.Path(__file__).parent.parent / "experiments" / "resumability_study.spif"
        data = sif_path.read_bytes()
        reader = SPIFStreamReader(require_signature=True)
        events = reader.feed(data)
        error_events = [e for e in events if e.type == "error"]
        assert error_events, "unsigned real fixture must fail strict streaming reader"

    def test_partial_text_reconstruction_matches_payload(self):
        """
        The concatenation of partial_text events must equal the payload
        value (for single-node text documents where the adapter assembles them).
        """
        tokens = ["The ", "sky ", "is ", "blue."]
        full = "".join(tokens)
        doc = SPIFDocument(
            payload=[Node(id="main", type="text", value=full,
                          confidence=Distribution.certain("epistemic"))],
            provenance=None, semantic=None, trace=[], trace_method="post-hoc",
            alternatives=[], delta=None, signature=None, signatures=[],
        )
        data = _stream_doc(doc, tokens=tokens, prov=None)
        events = list(iter_events(data))

        partial_texts = [e.text for e in events if e.type == "partial_text"]
        assert "".join(partial_texts) == full

        verified = next(e for e in events if e.type == "verified")
        assert verified.document.payload[0].value == full


# ---------------------------------------------------------------------------
# Resume protocol
# ---------------------------------------------------------------------------

from spif.streaming import _make_resume_token, _parse_resume_token


class TestResumeToken:
    """Unit tests for resume token encode/decode."""

    def test_roundtrip(self):
        token = _make_resume_token(42, b"\xab" * 32)
        seq, body_hash = _parse_resume_token(token)
        assert seq == 42
        assert body_hash == b"\xab" * 32

    def test_zero_seq(self):
        token = _make_resume_token(0, b"\x00" * 32)
        seq, body_hash = _parse_resume_token(token)
        assert seq == 0
        assert body_hash == b"\x00" * 32

    def test_max_seq(self):
        token = _make_resume_token(0xFFFFFFFF, b"\xff" * 32)
        seq, _ = _parse_resume_token(token)
        assert seq == 0xFFFFFFFF

    def test_malformed_base64_raises(self):
        with pytest.raises(ValueError, match="base64"):
            _parse_resume_token("!!!not-base64!!!")

    def test_wrong_length_raises(self):
        import base64
        short = base64.urlsafe_b64encode(b"\x00" * 10).decode()
        with pytest.raises(ValueError, match="36 bytes"):
            _parse_resume_token(short)

    def test_token_is_urlsafe(self):
        """Token must not contain + or / (urlsafe base64)."""
        token = _make_resume_token(999, b"\xff\xfe\xfd" * 10 + b"\x00\x00")
        assert "+" not in token
        assert "/" not in token


class TestResumeTokenFromWriter:
    """resume_token() on the writer."""

    def test_resume_token_before_commit(self):
        writer = SPIFStreamWriter()
        writer.open()
        writer.partial_text("hello")
        writer.partial_text(" world")
        token = writer.resume_token()
        assert isinstance(token, str)
        seq, body_hash = _parse_resume_token(token)
        assert seq == 2  # two partial_text calls
        assert len(body_hash) == 32

    def test_resume_token_before_open_raises(self):
        writer = SPIFStreamWriter()
        with pytest.raises(RuntimeError):
            writer.resume_token()

    def test_resume_token_reflects_seq(self):
        writer = SPIFStreamWriter()
        writer.open()
        t0 = writer.resume_token()
        seq0, _ = _parse_resume_token(t0)
        writer.partial_text("a")
        t1 = writer.resume_token()
        seq1, _ = _parse_resume_token(t1)
        assert seq1 == seq0 + 1

    def test_resume_token_hash_changes_with_body(self):
        w1 = SPIFStreamWriter()
        w1.open()
        w1.partial_text("aaa")
        t1 = w1.resume_token()
        _, h1 = _parse_resume_token(t1)

        w2 = SPIFStreamWriter()
        w2.open()
        w2.partial_text("bbb")
        t2 = w2.resume_token()
        _, h2 = _parse_resume_token(t2)

        assert h1 != h2


class TestStreamResume:
    """Integration tests for the full resume protocol."""

    def _make_stream_and_resume(self, tokens: list[str], break_after: int):
        """
        Simulate a dropped connection mid-stream.

        Returns:
            resume_token: the token the consumer holds
            original_doc: the SPIFDocument that was being streamed
        """
        doc = _minimal_doc()
        writer = SPIFStreamWriter()
        parts = [writer.open()]
        for i, tok in enumerate(tokens):
            parts.append(writer.partial_text(tok))
            if i + 1 == break_after:
                resume_token = writer.resume_token()
                break
        # Connection dropped — return what the consumer confirmed
        return resume_token, doc, tokens

    def test_resume_emits_stream_resume_chunk(self):
        """Writer created with resume_from must include STREAM_RESUME chunk."""
        from spif.format import CHUNK_STREAM_RESUME, MAGIC
        import struct

        token = _make_resume_token(3, b"\x42" * 32)
        writer = SPIFStreamWriter(resume_from=token)
        header_bytes = writer.open()

        # Scan for CHUNK_STREAM_RESUME in the emitted bytes
        pos = len(MAGIC) + 2
        found = False
        while pos + 5 <= len(header_bytes):
            ct = header_bytes[pos]
            clen = struct.unpack_from(">I", header_bytes, pos + 1)[0]
            if ct == CHUNK_STREAM_RESUME:
                found = True
                break
            pos += 5 + clen
        assert found, "STREAM_RESUME chunk not found in resumed stream header"

    def test_resume_chunk_sets_seq_in_writer(self):
        """Writer initialized with resume_from picks up seq from resume point."""
        token = _make_resume_token(5, b"\x00" * 32)
        writer = SPIFStreamWriter(resume_from=token)
        writer.open()
        # Tokens 0..4 are already confirmed — partial_text calls with lower seqs return empty
        assert writer.partial_text("pre0") == b""
        assert writer.partial_text("pre1") == b""
        assert writer.partial_text("pre2") == b""
        assert writer.partial_text("pre3") == b""
        assert writer.partial_text("pre4") == b""
        # Seq 5 and above are new — must produce non-empty bytes
        chunk = writer.partial_text("new")
        assert len(chunk) > 0

    def test_resumed_stream_is_valid_spif(self):
        """A resumed stream (with all tokens replayed) must produce a valid SPIF doc."""
        tokens = ["The ", "quick ", "brown ", "fox."]
        doc = _minimal_doc()

        # First stream: 2 tokens, then drop
        writer1 = SPIFStreamWriter()
        writer1.open()
        writer1.partial_text(tokens[0])
        writer1.partial_text(tokens[1])
        resume_token = writer1.resume_token()

        # Second stream: resume from seq=2, replay all tokens (writer skips 0,1)
        writer2 = SPIFStreamWriter(resume_from=resume_token)
        parts = [writer2.open()]
        for tok in tokens:
            chunk = writer2.partial_text(tok)
            if chunk:  # may be empty for already-confirmed tokens
                parts.append(chunk)
        parts.append(writer2.commit(doc))
        resumed_bytes = b"".join(parts)

        restored = SPIFReader().decode(resumed_bytes)
        assert restored.payload[0].id == "n1"

    def test_stream_reader_fires_resumed_event(self):
        """SPIFStreamReader must emit 'resumed' event when STREAM_RESUME chunk is seen."""
        token = _make_resume_token(3, b"\x01" * 32)
        writer = SPIFStreamWriter(resume_from=token)
        doc = _minimal_doc()
        parts = [writer.open()]
        parts.append(writer.commit(doc))
        data = b"".join(parts)

        events = list(iter_events(data))
        resumed_events = [e for e in events if e.type == "resumed"]
        assert len(resumed_events) == 1
        assert resumed_events[0].seq == 3

    def test_resumed_event_contains_token(self):
        """The 'resumed' event must carry a valid resume_token string."""
        token = _make_resume_token(7, b"\xde" * 32)
        writer = SPIFStreamWriter(resume_from=token)
        parts = [writer.open(), writer.commit(_minimal_doc())]
        data = b"".join(parts)

        events = list(iter_events(data))
        resumed = next(e for e in events if e.type == "resumed")
        assert resumed.resume_token != ""
        seq, _ = _parse_resume_token(resumed.resume_token)
        assert seq == 7

    def test_no_resume_chunk_in_fresh_stream(self):
        """A fresh (non-resumed) stream must not emit a STREAM_RESUME chunk."""
        from spif.format import CHUNK_STREAM_RESUME, MAGIC
        import struct

        writer = SPIFStreamWriter()
        parts = [writer.open(), writer.commit(_minimal_doc())]
        data = b"".join(parts)

        pos = len(MAGIC) + 2
        found = False
        while pos + 5 <= len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_STREAM_RESUME:
                found = True
                break
            pos += 5 + clen
        assert not found

    def test_invalid_resume_token_raises_on_construction(self):
        with pytest.raises(ValueError):
            SPIFStreamWriter(resume_from="not-a-valid-token!!!")
