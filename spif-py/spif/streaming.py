"""
SPIF Streaming (SSPIF) — incremental delivery protocol.

Wire format (strict superset of the SPIF file format):

    MAGIC + VERSION(0x02) + FLAGS(|FLAG_STREAMING)
    HEADER chunk
    [PROVENANCE chunk]           ← emitted at open() if model info is known
    [STREAM_RESUME(0x12) chunk]  ← present only when resuming a dropped stream
    PARTIAL_TEXT(0x10) chunk...  ← one per token/fragment during generation
    PAYLOAD(0x04) chunk          ← commit point — full assembled content
    [TRACE / ALTS / DELTA chunks]
    CHECKSUM(0xFF) chunk         ← SHA-256 trailer over ALL preceding bytes
    [SIGNATURE(0x07) chunk]      ← optional; covers everything before this chunk

Backward compatibility
──────────────────────
Existing SPIFReader v0.2 skips unknown chunk types (0x10, 0x12) and waits for
PAYLOAD + CHECKSUM.  A streaming document is therefore readable by any v0.2
reader without modification — it just ignores the partial/resume chunks.

Streaming reader usage
──────────────────────
    reader = SPIFStreamReader()
    for chunk_bytes in tcp_socket:          # or aiohttp, websocket, etc.
        for event in reader.feed(chunk_bytes):
            if event.type == "partial_text":
                print(event.text, end="", flush=True)
            elif event.type == "committed":
                doc = event.document        # fully verified SPIFDocument
            elif event.type == "error":
                raise RuntimeError(event.error)

Streaming writer usage
──────────────────────
    writer = SPIFStreamWriter()
    yield writer.open(provenance)           # send header immediately
    for token in llm_token_stream:
        yield writer.partial_text(token)    # send each token
    yield writer.commit(doc)               # send PAYLOAD + CHECKSUM

Resume protocol
───────────────
If a connection drops mid-stream, the consumer holds a *resume token* — a
compact proof of how far it received.  The producer can restart the stream
from the confirmed point instead of the beginning:

    # Consumer stores the token when the connection drops
    token = writer.resume_token()   # call at any time after open()

    # On reconnect, producer resumes:
    writer2 = SPIFStreamWriter(resume_from=token)
    yield writer2.open(provenance)  # emits STREAM_RESUME chunk
    for token_text in llm_tokens[confirmed_seq:]:
        yield writer2.partial_text(token_text)
    yield writer2.commit(doc)

The resume token is a base64url string encoding:
    seq      (4 bytes, big-endian uint32) — last confirmed PARTIAL_TEXT seq
    sha256   (32 bytes) — SHA-256 of all stream bytes confirmed received

The hash is trusted only when a side actually checks it:

  - The reader must be constructed with the consumer's stored token
    (``SPIFStreamReader(resume_token=token)``).  A STREAM_RESUME chunk
    whose (seq, body_hash) does not exactly match that token is an
    error, as is any STREAM_RESUME chunk when the reader holds no
    token — unless the caller explicitly opts into legacy behaviour
    with ``allow_unbound_resume=True``.
  - A producer that still holds the original stream's prefix bytes can
    pass them as ``resume_prefix_bytes`` to ``SPIFStreamWriter``; the
    writer refuses construction unless SHA-256 of the prefix equals
    the token's hash.  ``verify_resume_token(token, prefix_bytes)``
    exposes the same check to any party holding the prefix.

A STREAM_RESUME chunk is honoured at most once per reader, only before
any partial_text has been emitted, and partials with seq below the
resume seq are rejected.  Before the reader emits "verified", the
partial text it emitted live must reconcile with the verified payload:
for each node, the concatenation of its partials must equal the
payload value (or, on a resumed stream, be a suffix of it — the prefix
was delivered by the earlier stream).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from typing import Iterator

import cbor2

from .format import (
    MAGIC, FORMAT_VERSION,
    CHUNK_HEADER, CHUNK_PROVENANCE, CHUNK_PAYLOAD,
    CHUNK_TRACE, CHUNK_ALTS, CHUNK_DELTA, CHUNK_SIGNATURE, CHUNK_MULTISIG, CHUNK_CHECKSUM,
    CHUNK_PARTIAL_TEXT, CHUNK_STREAM_META, CHUNK_STREAM_RESUME,
    FLAG_PROVENANCE, FLAG_TRACE, FLAG_ALTS, FLAG_DELTA,
    FLAG_SIGNATURE, FLAG_MULTISIG, FLAG_STREAMING,
)
from .reader import _cbor_load
from .types import SPIFDocument, Provenance
from .writer import _chunk, _raw_chunk, _encode_node, _encode_step, _encode_distribution

_CHUNK_STRUCT = struct.Struct(">BI")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@dataclass
class StreamEvent:
    """
    An event emitted by SPIFStreamReader as bytes arrive.

    type values:
      "opened"       — magic + header parsed, stream is valid SPIF
      "resumed"      — STREAM_RESUME chunk received; stream continues from event.seq
      "partial_text" — one text fragment (token) received
      "committed"    — PAYLOAD received; full document available if verified
      "verified"     — CHECKSUM matched; event.document is the final SPIFDocument
      "error"        — unrecoverable parse or integrity error
    """
    type: str                        # "opened" | "resumed" | "partial_text" | "committed" | "verified" | "error"
    node_id: str = "main"
    text: str = ""
    seq: int = 0
    resume_token: str = ""
    document: SPIFDocument | None = None
    error: str = ""


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class SPIFStreamWriter:
    """
    Produces a streaming SPIF byte sequence piece by piece.

    All methods return plain bytes — the caller owns transport (TCP, HTTP
    chunked, WebSocket, generator yield, file write, etc.).

    Call order: open() → partial_text()* → commit()

    Parameters
    ----------
    resume_from :
        A resume token produced by a previous writer's ``resume_token()``
        call.  When provided, ``open()`` emits a ``STREAM_RESUME`` chunk
        so the reader knows which tokens have already been delivered.
        Tokens with seq strictly less than the confirmed seq in the token
        are silently dropped by ``partial_text()`` — the caller is
        responsible for only feeding tokens that need to be (re-)sent, or
        can feed all tokens and let the writer skip already-confirmed ones.
    resume_prefix_bytes :
        The original stream's prefix bytes (everything the first writer
        emitted up to the point the resume token was taken), when the
        producer still holds them.  When provided, the constructor
        verifies SHA-256 of the prefix against the token's body hash
        and raises ``ValueError`` on mismatch — a token is never trusted
        past the bytes it claims to continue.
    """

    def __init__(self, *, resume_from: str | None = None,
                 resume_prefix_bytes: bytes | None = None) -> None:
        self._body = bytearray()   # accumulates all emitted bytes for checksum
        self._seq = 0
        self._opened = False
        self._committed = False
        # Resume state
        self._resume_token: str | None = resume_from
        self._resume_seq: int = 0
        self._resume_hash: bytes | None = None
        if resume_from is not None:
            seq, body_hash = _parse_resume_token(resume_from)
            if resume_prefix_bytes is not None and not hmac.compare_digest(
                    hashlib.sha256(resume_prefix_bytes).digest(), body_hash):
                raise ValueError(
                    "resume_prefix_bytes do not hash to the resume token's "
                    "body_hash — refusing to resume from an unverified prefix"
                )
            self._resume_seq = seq
            self._resume_hash = body_hash
        elif resume_prefix_bytes is not None:
            raise ValueError(
                "resume_prefix_bytes requires resume_from (a resume token to "
                "verify the prefix against)"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resume_token(self) -> str:
        """
        Return a resume token encoding the current position in the stream.

        The token is a base64url string containing:
          - 4 bytes: current seq number (big-endian uint32)
          - 32 bytes: SHA-256 of all body bytes emitted so far

        Call this at any point after ``open()`` and before ``commit()``.
        The consumer stores this token; on reconnect it passes it to
        ``SPIFStreamWriter(resume_from=token)`` so the new writer can
        emit a ``STREAM_RESUME`` chunk and skip already-delivered tokens.
        """
        self._require_open()
        seq_bytes = struct.pack(">I", self._seq)
        body_hash = hashlib.sha256(self._body).digest()
        raw = seq_bytes + body_hash
        return base64.urlsafe_b64encode(raw).decode()

    def open(self, provenance: Provenance | None = None) -> bytes:
        """
        Emit the stream header (magic, version, flags, HEADER chunk, optional
        PROVENANCE chunk).  Must be called exactly once before any other method.
        """
        if self._opened:
            raise RuntimeError("SPIFStreamWriter.open() called twice")
        self._opened = True

        flags = FLAG_STREAMING
        if provenance is not None:
            flags |= FLAG_PROVENANCE

        ts = provenance.timestamp_ms if provenance else int(time.time() * 1000)

        parts: list[bytes] = [
            MAGIC,
            bytes([FORMAT_VERSION, flags]),
            _chunk(CHUNK_HEADER, {
                "version":    FORMAT_VERSION,
                "flags":      flags,
                "created_ms": ts,
            }, fast=True),
        ]

        if provenance is not None:
            parts.append(_chunk(CHUNK_PROVENANCE, {
                "source_model":  provenance.source_model,
                "model_version": provenance.model_version,
                "temperature":   provenance.temperature,
                "input_hash":    provenance.input_hash,
                "context_ref":   provenance.context_ref,
                "timestamp_ms":  provenance.timestamp_ms,
            }, fast=True))

        # Emit STREAM_RESUME chunk if this is a resumed stream
        if self._resume_token is not None:
            assert self._resume_hash is not None
            parts.append(_chunk(CHUNK_STREAM_RESUME, {
                "seq":       self._resume_seq,
                "body_hash": self._resume_hash,
            }, fast=True))

        data = b"".join(parts)
        self._body.extend(data)
        return data

    def partial_text(self, text: str, node_id: str = "main") -> bytes:
        """
        Emit a PARTIAL_TEXT chunk for one text fragment (e.g., one LLM token).
        May be called zero or more times between open() and commit().

        When the writer was created with ``resume_from``, tokens whose seq
        is strictly less than the confirmed resume seq are silently dropped
        (returns empty bytes).  This lets callers replay from position 0
        without worrying about deduplication on the receiving end.
        """
        self._require_open()
        current_seq = self._seq
        self._seq += 1
        # Skip tokens already confirmed delivered (resume fast-forward)
        if current_seq < self._resume_seq:
            return b""
        data = _chunk(CHUNK_PARTIAL_TEXT, {
            "node_id": node_id,
            "seq":     current_seq,
            "text":    text,
        }, fast=True)
        self._body.extend(data)
        return data

    def commit(self, doc: SPIFDocument) -> bytes:
        """
        Finalize the stream.  Emits PAYLOAD (and TRACE/ALTS/DELTA/SIG chunks
        if present), then appends the CHECKSUM trailer.

        Returns all bytes from PAYLOAD through the end — append these to
        whatever you've already sent and the complete stream is a valid
        SPIF document that any SPIFReader can verify.
        """
        self._require_open()
        if self._committed:
            raise RuntimeError("SPIFStreamWriter.commit() called twice")
        self._committed = True

        # Determine flags for the tail (some may differ from the open() flags)
        tail_parts: list[bytes] = []

        # PAYLOAD (required)
        tail_parts.append(_chunk(CHUNK_PAYLOAD,
            [_encode_node(n) for n in doc.payload], fast=True))

        # SEMANTIC
        if doc.semantic:
            from .format import CHUNK_SEMANTIC, TAG_EMBEDDING
            s = doc.semantic
            tail_parts.append(_chunk(CHUNK_SEMANTIC, {
                "embedding_model": s.embedding_model,
                "dim":             s.dim,
                "embedding":       cbor2.CBORTag(TAG_EMBEDDING, s.embedding),
                "covariance":      s.covariance,
            }, fast=True))

        # TRACE
        if doc.trace:
            tail_parts.append(_chunk(CHUNK_TRACE, {
                "method": doc.trace_method,
                "steps":  [_encode_step(s) for s in doc.trace],
            }, fast=True))

        # ALTS
        if doc.alternatives:
            tail_parts.append(_chunk(CHUNK_ALTS, {
                "normalized": doc.alternatives[0].normalized,
                "alts": [
                    {"weight": a.weight, "nodes": [_encode_node(n) for n in a.nodes]}
                    for a in doc.alternatives
                ],
            }, fast=True))

        # DELTA
        if doc.delta:
            tail_parts.append(_chunk(CHUNK_DELTA, {
                "base_hash": doc.delta.base_hash,
                "changes":   doc.delta.changes,
            }, fast=True))

        # SIGNATURE (always canonical CBOR when present)
        if doc.signature:
            sig = doc.signature
            tail_parts.append(_chunk(CHUNK_SIGNATURE, {
                "algorithm": sig.algorithm,
                "signer":    sig.signer,
                "signature": sig.signature,
                "key_id":    sig.key_id,
            }))

        # MULTISIG
        if doc.signatures:
            tail_parts.append(_chunk(CHUNK_MULTISIG, [
                {"algorithm": s.algorithm, "signer": s.signer,
                 "signature": s.signature, "key_id": s.key_id}
                for s in doc.signatures
            ]))

        tail = b"".join(tail_parts)
        self._body.extend(tail)

        # CHECKSUM over the complete body
        checksum = hashlib.sha256(self._body).digest()
        checksum_chunk = _raw_chunk(CHUNK_CHECKSUM, checksum)

        return tail + checksum_chunk

    def assembled(self) -> bytes:
        """
        Return all bytes emitted so far (for testing or saving to file).
        Only valid after commit(); does NOT include the checksum chunk.
        """
        if not self._committed:
            raise RuntimeError("Call commit() first")
        return bytes(self._body)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if not self._opened:
            raise RuntimeError("Call open() before writing chunks")
        if self._committed:
            raise RuntimeError("Stream already committed")


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

class SPIFStreamReader:
    """
    Incremental SPIF stream reader.

    Call feed(bytes) with however many bytes have arrived — the reader
    maintains an internal buffer and emits a list of StreamEvent objects
    each time feed() is called.

    The reader is also compatible with ordinary (non-streaming) SPIF files:
    no PARTIAL_TEXT chunks will be emitted, but "verified" is still fired
    when the CHECKSUM is parsed.

    Resume discipline: a STREAM_RESUME chunk is honoured only when this
    reader was constructed with the consumer's stored ``resume_token``
    and the chunk's (seq, body_hash) matches it exactly — or when the
    caller explicitly passes ``allow_unbound_resume=True`` (legacy
    behaviour).  A resume is accepted at most once and only before any
    partial_text; partials below the resume seq are rejected.  Before
    "verified" is emitted, the live-emitted partial text must reconcile
    with the verified payload (equality, or a suffix on resumed streams).

    Typical usage (sync generator):

        reader = SPIFStreamReader()
        with open("response.spif", "rb") as f:
            while chunk := f.read(4096):
                for event in reader.feed(chunk):
                    handle(event)
    """

    def __init__(self, *, require_signature: bool = False,
                 resume_token: str | None = None,
                 allow_unbound_resume: bool = False) -> None:
        self._buf = bytearray()
        self._pos = 0               # parse cursor into self._buf
        self._state = "header"      # "header" | "chunks" | "done"
        self._require_signature = require_signature
        self._last_seq: dict[str, int] = {}  # node_id -> highest seq seen
        # Resume state machine + token binding
        self._expected_resume: tuple[int, bytes] | None = None
        if resume_token is not None:
            # ValueError on a malformed token — fail fast at construction.
            self._expected_resume = _parse_resume_token(resume_token)
        self._allow_unbound_resume = allow_unbound_resume
        self._resumed = False
        self._emitted_partial = False
        self._seq_floor = 0
        # Live-emitted partial text per node, for payload binding at verify
        self._partial_text: dict[str, list[str]] = {}

    def feed(self, data: bytes | bytearray) -> list[StreamEvent]:
        """
        Feed bytes.  Returns any events emitted during this call.
        After an "error" or "verified" event the reader is done.
        """
        if self._state == "done":
            return []
        self._buf.extend(data)
        events: list[StreamEvent] = []
        self._pump(events)
        return events

    def done(self) -> bool:
        """True once a "verified" or "error" event has been emitted."""
        return self._state == "done"

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _pump(self, events: list[StreamEvent]) -> None:
        if self._state == "header":
            if len(self._buf) < len(MAGIC) + 2:
                return
            if bytes(self._buf[:len(MAGIC)]) != MAGIC:
                events.append(StreamEvent(type="error",
                    error=f"Invalid magic bytes: {bytes(self._buf[:len(MAGIC)]).hex()}"))
                self._state = "done"
                return
            # version byte is at MAGIC.len(), flags at MAGIC.len()+1 — we don't
            # need to inspect them here; SPIFReader.decode() will validate on commit.
            self._pos = len(MAGIC) + 2
            self._state = "chunks"
            events.append(StreamEvent(type="opened"))

        while self._state == "chunks":
            # Need at least a 5-byte chunk header
            if self._pos + 5 > len(self._buf):
                return

            chunk_type = self._buf[self._pos]
            chunk_len = struct.unpack_from(">I", self._buf, self._pos + 1)[0]
            payload_start = self._pos + 5
            payload_end = payload_start + chunk_len

            if payload_end > len(self._buf):
                return  # wait for more data

            payload = bytes(self._buf[payload_start:payload_end])
            self._dispatch(chunk_type, payload, payload_end, events)
            self._pos = payload_end

    def _dispatch(
        self,
        chunk_type: int,
        payload: bytes,
        payload_end: int,
        events: list[StreamEvent],
    ) -> None:
        if chunk_type == CHUNK_PARTIAL_TEXT:
            try:
                # Strict decode (same entry point as the document reader):
                # duplicate map keys and trailing bytes are malformed.
                d = _cbor_load(payload, "PARTIAL_TEXT")
                if not isinstance(d, dict):
                    raise ValueError(
                        f"PARTIAL_TEXT payload must be a dict, got {type(d).__name__}")
                node_id = d.get("node_id", "main")
                if not isinstance(node_id, str):
                    events.append(StreamEvent(
                        type="error",
                        error=f"PARTIAL_TEXT node_id must be a str, got {node_id!r}",
                    ))
                    self._state = "done"
                    return
                text = d.get("text", "")
                if not isinstance(text, str):
                    events.append(StreamEvent(
                        type="error",
                        error=f"PARTIAL_TEXT text must be a str, got {type(text).__name__}",
                    ))
                    self._state = "done"
                    return
                seq = d.get("seq", 0)
                if not isinstance(seq, int) or isinstance(seq, bool):
                    events.append(StreamEvent(
                        type="error",
                        error=f"PARTIAL_TEXT seq must be an int, got {seq!r}",
                    ))
                    self._state = "done"
                    return
                if seq < self._seq_floor:
                    events.append(StreamEvent(
                        type="error",
                        error=f"PARTIAL_TEXT seq {seq} for node '{node_id}' is below "
                              f"the resume seq {self._seq_floor} (already delivered "
                              f"before the resume — replay)",
                    ))
                    self._state = "done"
                    return
                last = self._last_seq.get(node_id, -1)
                if seq <= last:
                    events.append(StreamEvent(
                        type="error",
                        error=f"PARTIAL_TEXT seq {seq} for node '{node_id}' is not "
                              f"greater than last seen seq {last} (out-of-order or duplicate)",
                    ))
                    self._state = "done"
                    return
                self._last_seq[node_id] = seq
                self._emitted_partial = True
                self._partial_text.setdefault(node_id, []).append(text)
                events.append(StreamEvent(
                    type="partial_text",
                    node_id=node_id,
                    text=text,
                    seq=seq,
                ))
            except Exception as exc:
                events.append(StreamEvent(type="error",
                    error=f"Malformed PARTIAL_TEXT chunk: {exc}"))
                self._state = "done"

        elif chunk_type == CHUNK_STREAM_RESUME:
            try:
                # Strict decode (same entry point as the document reader):
                # duplicate map keys and trailing bytes are malformed.
                d = _cbor_load(payload, "STREAM_RESUME")
                if not isinstance(d, dict):
                    raise ValueError(
                        f"STREAM_RESUME payload must be a dict, got {type(d).__name__}")
                seq = d.get("seq", 0)
                # Strict field contract (SPIF-RESUME-TYPE-001): seq is
                # an int (never bool), body_hash is exactly 32 bytes.
                # No coercion — bytes(32) would silently turn the int
                # 32 into a valid-looking all-zero hash.
                if not isinstance(seq, int) or isinstance(seq, bool):
                    events.append(StreamEvent(
                        type="error",
                        error=f"STREAM_RESUME seq must be an int, got {seq!r}",
                    ))
                    self._state = "done"
                    return
                raw_hash = d.get("body_hash", b"")
                if not isinstance(raw_hash, (bytes, bytearray, memoryview)):
                    events.append(StreamEvent(
                        type="error",
                        error=f"STREAM_RESUME body_hash must be bytes, "
                              f"got {type(raw_hash).__name__}",
                    ))
                    self._state = "done"
                    return
                body_hash = bytes(raw_hash)
                if len(body_hash) != 32:
                    events.append(StreamEvent(
                        type="error",
                        error=f"STREAM_RESUME body_hash must be 32 bytes, "
                              f"got {len(body_hash)}",
                    ))
                    self._state = "done"
                    return
                # Placement: the writer contract emits STREAM_RESUME only
                # from open(), before any PARTIAL_TEXT, at most once.
                if self._resumed:
                    events.append(StreamEvent(
                        type="error",
                        error="STREAM_RESUME received after this stream "
                              "already resumed",
                    ))
                    self._state = "done"
                    return
                if self._emitted_partial:
                    events.append(StreamEvent(
                        type="error",
                        error="STREAM_RESUME received after partial_text "
                              "was already emitted",
                    ))
                    self._state = "done"
                    return
                # Token binding: the chunk must claim exactly the position
                # the consumer's stored token claims — nothing else is a
                # continuation this reader may trust.
                if self._expected_resume is not None:
                    exp_seq, exp_hash = self._expected_resume
                    if seq != exp_seq or not hmac.compare_digest(body_hash, exp_hash):
                        events.append(StreamEvent(
                            type="error",
                            error="STREAM_RESUME (seq, body_hash) does not "
                                  "match the resume token held by this reader",
                        ))
                        self._state = "done"
                        return
                elif not self._allow_unbound_resume:
                    events.append(StreamEvent(
                        type="error",
                        error="STREAM_RESUME received but this reader holds "
                              "no resume token (construct with "
                              "resume_token=... or allow_unbound_resume=True)",
                    ))
                    self._state = "done"
                    return
                self._resumed = True
                self._seq_floor = seq
                token = _make_resume_token(seq, body_hash)
                events.append(StreamEvent(
                    type="resumed",
                    seq=seq,
                    resume_token=token,
                ))
            except Exception as exc:
                events.append(StreamEvent(type="error",
                    error=f"Malformed STREAM_RESUME chunk: {exc}"))
                self._state = "done"

        elif chunk_type == CHUNK_CHECKSUM:
            # The stream is complete — decode the full accumulated buffer
            # (including the checksum chunk we just finished receiving).
            full_bytes = bytes(self._buf[:payload_end])
            try:
                from .reader import SPIFReader
                doc = SPIFReader(require_signature=self._require_signature).decode(full_bytes)
                binding_error = self._partial_binding_error(doc)
                if binding_error is not None:
                    events.append(StreamEvent(type="error", error=binding_error))
                else:
                    events.append(StreamEvent(type="verified", document=doc))
            except Exception as exc:
                events.append(StreamEvent(type="error", error=str(exc)))
            self._state = "done"

        # All other chunks (HEADER, PROVENANCE, PAYLOAD, TRACE, etc.) are
        # silently buffered so that SPIFReader.decode() can process them in
        # one pass when the CHECKSUM arrives.

    def _partial_binding_error(self, doc: SPIFDocument) -> str | None:
        """
        Reconcile the partial text emitted live with the verified payload.

        Returns an error string when the live layer and the verified
        document diverge, else None.  Streams that emitted no partials
        are unaffected.  On a resumed stream only the post-resume
        partials are visible to this reader, so their concatenation
        must be a suffix of the payload value.
        """
        if not self._partial_text:
            return None
        payload_by_id = {node.id: node for node in doc.payload}
        for node_id, fragments in self._partial_text.items():
            node = payload_by_id.get(node_id)
            if node is None:
                return (
                    f"partial_text was emitted for node '{node_id}', which is "
                    f"absent from the verified payload"
                )
            if not isinstance(node.value, str):
                return (
                    f"partial_text was emitted for node '{node_id}', whose "
                    f"verified payload value is not a string"
                )
            streamed = "".join(fragments)
            if self._resumed:
                if not node.value.endswith(streamed):
                    return (
                        f"resumed partial_text for node '{node_id}' is not a "
                        f"suffix of the verified payload value"
                    )
            elif streamed != node.value:
                return (
                    f"partial_text for node '{node_id}' does not match the "
                    f"verified payload value"
                )
        return None


# ---------------------------------------------------------------------------
# Resume token helpers
# ---------------------------------------------------------------------------

def verify_resume_token(token: str, prefix_bytes: bytes) -> bool:
    """
    Check a resume token against the stream prefix it claims to continue.

    Returns True only when SHA-256 of ``prefix_bytes`` equals the body
    hash carried by ``token`` (constant-time compare).  A malformed
    token returns False — this is a verification predicate, not a parser.
    """
    try:
        _, body_hash = _parse_resume_token(token)
    except ValueError:
        return False
    return hmac.compare_digest(hashlib.sha256(prefix_bytes).digest(), body_hash)


def _make_resume_token(seq: int, body_hash: bytes) -> str:
    """Encode seq + body_hash as a base64url resume token."""
    raw = struct.pack(">I", seq) + body_hash
    return base64.urlsafe_b64encode(raw).decode()


def _parse_resume_token(token: str) -> tuple[int, bytes]:
    """
    Decode a resume token back to (seq, body_hash).

    Raises ValueError if the token is malformed.
    """
    try:
        raw = base64.urlsafe_b64decode(token.encode())
    except Exception as exc:
        raise ValueError(f"Invalid resume token (base64 error): {exc}") from exc
    if len(raw) != 36:
        raise ValueError(
            f"Invalid resume token length: expected 36 bytes (4 seq + 32 hash), got {len(raw)}"
        )
    seq = struct.unpack(">I", raw[:4])[0]
    body_hash = raw[4:]
    return seq, body_hash


# ---------------------------------------------------------------------------
# Convenience: iterate a complete bytes object as events
# ---------------------------------------------------------------------------

def iter_events(data: bytes, chunk_size: int = 4096, *,
                resume_token: str | None = None,
                allow_unbound_resume: bool = False) -> Iterator[StreamEvent]:
    """
    Yield StreamEvents from a complete (possibly streaming) SPIF byte sequence.
    Useful for replaying a stored stream or testing without real I/O.

    ``resume_token`` / ``allow_unbound_resume`` are forwarded to
    ``SPIFStreamReader`` — a resumed stream needs the consumer's stored
    token (or the explicit legacy opt-in) to be honoured.
    """
    reader = SPIFStreamReader(
        resume_token=resume_token,
        allow_unbound_resume=allow_unbound_resume,
    )
    offset = 0
    while offset < len(data):
        piece = data[offset: offset + chunk_size]
        yield from reader.feed(piece)
        offset += chunk_size
        if reader.done():
            break
