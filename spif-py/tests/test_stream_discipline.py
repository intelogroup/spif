"""Permanent regression tests for the stream-discipline pass (2026-11-14).

Converted unweakened from the adversarial loop's preserved probes:

  SPIF-STREAM-RESUME-TOKEN-UNBOUND-001   evidence/2026-11-13-2322/spif/
  SPIF-STREAM-RESUME-SEQ-REPLAY-001      evidence/2026-11-14-0222/spif/
  SPIF-STREAM-RESUME-PLACEMENT-001       evidence/2026-11-14-0522/spif/
  SPIF-STREAM-CBOR-AMBIGUITY-001         evidence/2026-11-14-0822/spif/
  SPIF-STREAM-PARTIAL-PAYLOAD-BINDING-001 evidence/2026-11-14-1122/spif/

Conversion notes (assertions are the probes' own, verbatim): the probes
were written against a reader with no token parameter.  Where a probe's
scenario has a consumer holding a genuine resume token, the converted
test supplies that token to the reader (SPIFStreamReader(resume_token=…)
or iter_events(…, resume_token=…)) — the wiring the D1 contract
requires.  Two probe fixtures were also made honest streams (partials
naming the payload node and reconstructing its value), because the
binding rule now — correctly — refuses the divergent fixtures the
probes happened to use; each such change is noted inline.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from spif import SPIFDocument, Node, Distribution
from spif.format import (
    CHUNK_PARTIAL_TEXT, CHUNK_PAYLOAD, CHUNK_CHECKSUM, CHUNK_STREAM_RESUME,
)
from spif.reader import SPIFReader, _assert_unambiguous_cbor
from spif.streaming import (
    SPIFStreamWriter, SPIFStreamReader, iter_events,
    verify_resume_token, _make_resume_token, _parse_resume_token,
)
from spif.writer import _chunk, _raw_chunk, _encode_node


def _doc(node_id: str = "n1", value: str = "The sky is blue."):
    return SPIFDocument(
        payload=[Node(id=node_id, type="fact", value=value,
                      confidence=Distribution(mean=0.97, var=0.01, shape="point",
                                              semantics="factual_accuracy"))],
        provenance=None, semantic=None, trace=[], trace_method="post-hoc",
        alternatives=[], delta=None, signature=None, signatures=[])


# ---------------------------------------------------------------------------
# SPIF-STREAM-RESUME-TOKEN-UNBOUND-001 (probe 2026-11-13-2322)
#
# Fixture honesty change vs the probe: the doc value is the full token
# text ("The quick brown fox.") and partials name the payload node
# ("main"), so the control stream satisfies the partial/payload binding
# rule as well; only the token can refuse the hostile legs.
# ---------------------------------------------------------------------------

def _token_doc():
    return _doc(node_id="main", value="The quick brown fox.")


def test_control_genuine_resume_verifies():
    w1 = SPIFStreamWriter(); w1.open()
    w1.partial_text("The "); w1.partial_text("quick ")
    token = w1.resume_token()
    w2 = SPIFStreamWriter(resume_from=token)
    parts = [w2.open()]
    for t in ["The ", "quick ", "brown ", "fox."]:
        c = w2.partial_text(t)
        if c: parts.append(c)
    parts.append(w2.commit(_token_doc()))
    data = b"".join(parts)
    # Conversion wiring: the consumer supplies its stored token.
    ev = list(iter_events(data, resume_token=token))
    assert any(e.type == "resumed" for e in ev)
    assert any(e.type == "verified" for e in ev)
    SPIFReader().decode(data)


def test_forged_token_random_hash_rejected():
    forged = _make_resume_token(2, hashlib.sha256(b"never emitted").digest())
    w = SPIFStreamWriter(resume_from=forged)
    parts = [w.open()]
    for t in ["The ", "quick ", "brown ", "fox."]:
        c = w.partial_text(t)
        if c: parts.append(c)
    parts.append(w.commit(_token_doc()))
    data = b"".join(parts)
    ev = list(iter_events(data))
    resumed = [e for e in ev if e.type == "resumed"]
    verified = [e for e in ev if e.type == "verified"]
    # Invariant: forged position must not be asserted AND verified.
    assert not (resumed and verified), (
        f"forged token accepted: resumed seq={resumed[0].seq if resumed else None}, verified={bool(verified)}")


def test_foreign_token_transplant_rejected():
    wa = SPIFStreamWriter(); wa.open()
    wa.partial_text("aaa"); wa.partial_text("aaa")
    foreign = wa.resume_token()
    seq_f, hash_f = _parse_resume_token(foreign)
    wb = SPIFStreamWriter(resume_from=foreign)
    parts = [wb.open()]
    for t in ["ZZZ", "ZZZ", "new ", "content"]:
        c = wb.partial_text(t)
        if c: parts.append(c)
    parts.append(wb.commit(_token_doc()))
    data = b"".join(parts)
    ev = list(iter_events(data))
    resumed = [e for e in ev if e.type == "resumed"]
    verified = [e for e in ev if e.type == "verified"]
    assert not (resumed and verified), (
        f"foreign token (seq={seq_f}) transplanted into a different body and verified")
    if resumed:
        _, h = _parse_resume_token(resumed[0].resume_token)
        assert h != hash_f or not verified


# ---------------------------------------------------------------------------
# Token binding — new controls for the D1 contract
# ---------------------------------------------------------------------------

class TestResumeTokenBinding:
    def _genuine_token(self):
        w1 = SPIFStreamWriter(); w1.open()
        w1.partial_text("The "); w1.partial_text("quick ")
        return w1.resume_token()

    def _stream_with_token(self, token, doc=None):
        w2 = SPIFStreamWriter(resume_from=token)
        parts = [w2.open()]
        for t in ["The ", "quick ", "brown ", "fox."]:
            c = w2.partial_text(t)
            if c: parts.append(c)
        parts.append(w2.commit(doc or _token_doc()))
        return b"".join(parts)

    def test_forged_chunk_against_supplied_genuine_token_errors(self):
        genuine = self._genuine_token()
        forged = _make_resume_token(2, hashlib.sha256(b"never emitted").digest())
        data = self._stream_with_token(forged)
        reader = SPIFStreamReader(resume_token=genuine)
        ev = reader.feed(data)
        assert not any(e.type == "resumed" for e in ev)
        assert not any(e.type == "verified" for e in ev)
        assert any(e.type == "error" for e in ev)

    def test_seq_mismatch_against_supplied_token_errors(self):
        genuine = self._genuine_token()
        seq, body_hash = _parse_resume_token(genuine)
        shifted = _make_resume_token(seq + 5, body_hash)  # same hash, wrong seq
        data = self._stream_with_token(shifted)
        reader = SPIFStreamReader(resume_token=genuine)
        ev = reader.feed(data)
        assert not any(e.type == "resumed" for e in ev)
        assert any(e.type == "error" for e in ev)

    def test_unbound_resume_default_refused(self):
        data = self._stream_with_token(self._genuine_token())
        ev = SPIFStreamReader().feed(data)
        assert not any(e.type == "resumed" for e in ev)
        assert any(e.type == "error" for e in ev)

    def test_unbound_resume_opt_in_is_legacy_behaviour(self):
        """allow_unbound_resume=True is the named, deliberate escape hatch."""
        data = self._stream_with_token(self._genuine_token())
        ev = list(iter_events(data, allow_unbound_resume=True))
        assert any(e.type == "resumed" for e in ev)

    def test_malformed_reader_token_raises_at_construction(self):
        with pytest.raises(ValueError):
            SPIFStreamReader(resume_token="!!!not-a-token!!!")

    def test_verify_resume_token_helper(self):
        w1 = SPIFStreamWriter()
        parts = [w1.open()]
        parts.append(w1.partial_text("The "))
        parts.append(w1.partial_text("quick "))
        prefix = b"".join(parts)
        token = w1.resume_token()
        assert verify_resume_token(token, prefix) is True
        assert verify_resume_token(token, prefix + b"x") is False
        assert verify_resume_token(token, b"completely different") is False
        assert verify_resume_token("!!!not-a-token!!!", prefix) is False

    def test_writer_resume_prefix_bytes_match_constructs(self):
        w1 = SPIFStreamWriter()
        parts = [w1.open()]
        parts.append(w1.partial_text("The "))
        prefix = b"".join(parts)
        token = w1.resume_token()
        w2 = SPIFStreamWriter(resume_from=token, resume_prefix_bytes=prefix)
        assert w2.open()  # constructs and opens without raising

    def test_writer_resume_prefix_bytes_mismatch_refused(self):
        w1 = SPIFStreamWriter(); w1.open(); w1.partial_text("The ")
        token = w1.resume_token()
        with pytest.raises(ValueError):
            SPIFStreamWriter(resume_from=token,
                             resume_prefix_bytes=b"not the real prefix")

    def test_writer_prefix_bytes_without_token_refused(self):
        with pytest.raises(ValueError):
            SPIFStreamWriter(resume_prefix_bytes=b"orphan prefix")


# ---------------------------------------------------------------------------
# SPIF-STREAM-RESUME-SEQ-REPLAY-001 (probe 2026-11-14-0222)
#
# Conversion wiring: readers hold the genuine token (returned by the
# prefix builder).  Fixture honesty change: the composition doc's
# payload node is "main" with the full assembled value, so the replay —
# not a partial/payload divergence — is what refuses the composed stream.
# ---------------------------------------------------------------------------

def _seq_doc():
    return _doc(node_id="main", value="aa bb cc dd ")


def _resumed_stream_prefix():
    """Genuine stream: 3 partials (seq 0,1,2), token, resumed writer open."""
    w1 = SPIFStreamWriter(); w1.open()
    for t in ["aa ", "bb ", "cc "]:
        w1.partial_text(t)
    token = w1.resume_token()  # packs seq == 3
    w2 = SPIFStreamWriter(resume_from=token)
    return w2.open(), token  # MAGIC + HEADER + STREAM_RESUME(seq=3)


def _partial(seq, text):
    return _chunk(CHUNK_PARTIAL_TEXT,
                  {"node_id": "main", "seq": seq, "text": text}, fast=True)


def test_control_post_resume_partial_accepted():
    prefix, token = _resumed_stream_prefix()
    r = SPIFStreamReader(resume_token=token)
    ev = r.feed(prefix)
    assert any(e.type == "resumed" and e.seq == 3 for e in ev), ev
    ev2 = r.feed(_partial(3, "dd "))
    assert any(e.type == "partial_text" and e.seq == 3 for e in ev2), ev2
    assert not any(e.type == "error" for e in ev2), ev2


def test_replayed_pre_resume_partials_not_reemitted():
    prefix, token = _resumed_stream_prefix()
    r = SPIFStreamReader(resume_token=token)
    ev = r.feed(prefix)
    assert any(e.type == "resumed" for e in ev), ev
    replayed = []
    errors = []
    for seq in (0, 1, 2):
        out = r.feed(_partial(seq, "REPLAY "))
        replayed += [e for e in out if e.type == "partial_text"]
        errors += [e for e in out if e.type == "error"]
    # Invariant: no duplicate delivery — replays are dropped or errored,
    # never emitted as fresh partial_text.
    assert not replayed, (
        f"pre-resume partials re-emitted after resumed(seq=3): "
        f"{[(e.seq, e.text) for e in replayed]}")


def test_replay_composition_reaches_verified_with_duplicates():
    prefix, token = _resumed_stream_prefix()
    body = bytearray(prefix)
    body += _partial(0, "REPLAY0 ")
    body += _partial(1, "REPLAY1 ")
    body += _partial(3, "dd ")
    body += _chunk(CHUNK_PAYLOAD, [_encode_node(n) for n in _seq_doc().payload],
                   fast=True)
    checksum = hashlib.sha256(bytes(body)).digest()
    data = bytes(body) + _raw_chunk(CHUNK_CHECKSUM, checksum)
    r = SPIFStreamReader(resume_token=token)
    ev = r.feed(data)
    partials = [e for e in ev if e.type == "partial_text"]
    verified = [e for e in ev if e.type == "verified"]
    dup = [e for e in partials if e.seq < 3]
    assert not (dup and verified), (
        f"stream with replayed pre-resume partials verified; "
        f"duplicate partials emitted: {[(e.seq, e.text) for e in dup]}")


# ---------------------------------------------------------------------------
# SPIF-STREAM-RESUME-PLACEMENT-001 (probe 2026-11-14-0522)
#
# Conversion wiring: the control and second-resume legs hold the genuine
# token.  The mid-stream leg holds exactly the token the injected chunk
# claims, so placement — not token refusal — is the rule that refuses it.
# ---------------------------------------------------------------------------

def _resume_chunk(seq):
    return _chunk(CHUNK_STREAM_RESUME, {"seq": seq, "body_hash": b"\x00" * 32}, fast=True)


def _placement_prefix():
    w1 = SPIFStreamWriter(); w1.open()
    for t in ["aa ", "bb ", "cc "]:
        w1.partial_text(t)
    token = w1.resume_token()
    w2 = SPIFStreamWriter(resume_from=token)
    return w2.open(), token


def test_control_genuine_resume_accepted():
    prefix, token = _placement_prefix()
    r = SPIFStreamReader(resume_token=token)
    ev = r.feed(prefix)
    assert sum(1 for e in ev if e.type == "resumed" and e.seq == 3) == 1, ev
    ev2 = r.feed(_partial(3, "dd "))
    assert any(e.type == "partial_text" and e.seq == 3 for e in ev2), ev2


def test_midstream_resume_injection_not_honored():
    w = SPIFStreamWriter(); prefix = w.open()
    # The reader holds exactly the injected chunk's claimed token, so the
    # token check passes and placement must be what refuses the chunk.
    r = SPIFStreamReader(resume_token=_make_resume_token(0, b"\x00" * 32))
    ev = r.feed(prefix + _partial(0, "aa ") + _partial(1, "bb "))
    assert sum(1 for e in ev if e.type == "partial_text") == 2, ev
    ev2 = r.feed(_resume_chunk(0))
    resumed = [e for e in ev2 if e.type == "resumed"]
    assert not resumed, f"mid-stream STREAM_RESUME honored as resumed: {resumed}"


def test_second_resume_not_honored():
    prefix, token = _placement_prefix()
    r = SPIFStreamReader(resume_token=token)
    ev = r.feed(prefix)
    assert sum(1 for e in ev if e.type == "resumed") == 1, ev
    ev2 = r.feed(_resume_chunk(99))
    resumed = [e for e in ev2 if e.type == "resumed"]
    assert not resumed, f"second STREAM_RESUME honored as resumed: {resumed}"


# ---------------------------------------------------------------------------
# SPIF-STREAM-CBOR-AMBIGUITY-001 (probe 2026-11-14-0822, verbatim)
# plus STREAM_RESUME ambiguity legs (new).
# ---------------------------------------------------------------------------

def _tstr(s):
    b = s.encode(); assert len(b) < 24
    return bytes([0x60 + len(b)]) + b


def _raw(ctype, payload):
    return struct.pack(">BI", ctype, len(payload)) + payload


def _prefix():
    w = SPIFStreamWriter(); return w.open()


def test_control_canonical_partial_accepted():
    r = SPIFStreamReader()
    good = _chunk(CHUNK_PARTIAL_TEXT, {"node_id": "main", "seq": 0, "text": "hi"}, fast=True)
    ev = r.feed(_prefix() + good)
    assert any(e.type == "partial_text" and e.text == "hi" and e.seq == 0 for e in ev), ev


def test_sibling_decoder_rejects_duplicate_keys():
    dup = (b"\xa4" + _tstr("node_id") + _tstr("main") + _tstr("seq") + b"\x00"
           + _tstr("text") + _tstr("first") + _tstr("text") + _tstr("second"))
    try:
        _assert_unambiguous_cbor(dup, "PARTIAL_TEXT")
    except Exception:
        return
    raise AssertionError("document reader unexpectedly accepted duplicate keys")


def test_duplicate_text_key_not_emitted():
    dup = (b"\xa4" + _tstr("node_id") + _tstr("main") + _tstr("seq") + b"\x00"
           + _tstr("text") + _tstr("first") + _tstr("text") + _tstr("second"))
    r = SPIFStreamReader()
    ev = r.feed(_prefix() + _raw(CHUNK_PARTIAL_TEXT, dup))
    assert not any(e.type == "partial_text" for e in ev), ev
    assert any(e.type == "error" for e in ev), ev


def test_duplicate_seq_key_not_emitted():
    dup = (b"\xa4" + _tstr("node_id") + _tstr("main") + _tstr("seq") + b"\x00"
           + _tstr("seq") + b"\x05" + _tstr("text") + _tstr("hi"))
    r = SPIFStreamReader()
    ev = r.feed(_prefix() + _raw(CHUNK_PARTIAL_TEXT, dup))
    assert not any(e.type == "partial_text" for e in ev), ev
    assert any(e.type == "error" for e in ev), ev


def test_trailing_bytes_not_emitted():
    good = _chunk(CHUNK_PARTIAL_TEXT, {"node_id": "main", "seq": 0, "text": "hi"}, fast=True)
    r = SPIFStreamReader()
    ev = r.feed(_prefix() + _raw(CHUNK_PARTIAL_TEXT, good[5:] + b"\xff"))
    assert not any(e.type == "partial_text" for e in ev), ev
    assert any(e.type == "error" for e in ev), ev


class TestStreamResumeCborAmbiguity:
    """The strict decode covers STREAM_RESUME exactly as PARTIAL_TEXT.
    Readers use the legacy opt-in so only the decode can refuse."""

    def test_duplicate_seq_key_in_resume_not_emitted(self):
        dup = (b"\xa3" + _tstr("seq") + b"\x00" + _tstr("seq") + b"\x05"
               + _tstr("body_hash") + b"\x58\x20" + b"\x01" * 32)
        r = SPIFStreamReader(allow_unbound_resume=True)
        ev = r.feed(_prefix() + _raw(CHUNK_STREAM_RESUME, dup))
        assert not any(e.type == "resumed" for e in ev), ev
        assert any(e.type == "error" for e in ev), ev

    def test_trailing_bytes_in_resume_not_emitted(self):
        good = _chunk(CHUNK_STREAM_RESUME,
                      {"seq": 3, "body_hash": b"\x01" * 32}, fast=True)
        r = SPIFStreamReader(allow_unbound_resume=True)
        ev = r.feed(_prefix() + _raw(CHUNK_STREAM_RESUME, good[5:] + b"\xff"))
        assert not any(e.type == "resumed" for e in ev), ev
        assert any(e.type == "error" for e in ev), ev

    def test_canonical_resume_control_accepted(self):
        good = _chunk(CHUNK_STREAM_RESUME,
                      {"seq": 3, "body_hash": b"\x01" * 32}, fast=True)
        r = SPIFStreamReader(allow_unbound_resume=True)
        ev = r.feed(_prefix() + good)
        assert any(e.type == "resumed" and e.seq == 3 for e in ev), ev


# ---------------------------------------------------------------------------
# SPIF-STREAM-PARTIAL-PAYLOAD-BINDING-001 (probe 2026-11-14-1122, verbatim)
# plus binding controls (new).
# ---------------------------------------------------------------------------

def _binding_doc(node_id, value):
    return SPIFDocument(
        payload=[Node(id=node_id, type="text", value=value,
                      confidence=Distribution.certain("epistemic"))],
        provenance=None, semantic=None, trace=[], trace_method="post-hoc",
        alternatives=[], delta=None, signature=None, signatures=[])


def _binding_stream(doc, fragments):
    """fragments: list of (node_id, text). Writer is used honestly as a
    byte producer; nothing in the writer binds fragments to the doc."""
    w = SPIFStreamWriter()
    parts = [w.open()]
    for node_id, text in fragments:
        parts.append(w.partial_text(text, node_id=node_id))
    parts.append(w.commit(doc))
    return b"".join(parts)


def test_control_partials_match_payload_verifies():
    data = _binding_stream(_binding_doc("main", "hello world"),
                           [("main", "hello "), ("main", "world")])
    ev = SPIFStreamReader().feed(data)
    assert [e.text for e in ev if e.type == "partial_text"] == ["hello ", "world"]
    v = [e for e in ev if e.type == "verified"]
    assert v and v[0].document.payload[0].value == "hello world", ev


def test_mismatched_payload_not_silently_verified():
    data = _binding_stream(_binding_doc("main", "TRANSFER DENIED"),
                           [("main", "TRANSFER "), ("main", "APPROVED")])
    ev = SPIFStreamReader().feed(data)
    partials = "".join(e.text for e in ev if e.type == "partial_text")
    assert partials == "TRANSFER APPROVED"  # live layer really emitted it
    v = [e for e in ev if e.type == "verified"]
    assert not v, ev  # must error instead of verifying divergent content
    assert any(e.type == "error" for e in ev), ev


def test_ghost_node_partial_not_silently_verified():
    data = _binding_stream(_binding_doc("main", "hello"),
                           [("main", "hello"), ("ghost", "boo")])
    ev = SPIFStreamReader().feed(data)
    assert any(e.type == "partial_text" and e.node_id == "ghost" for e in ev), ev
    v = [e for e in ev if e.type == "verified"]
    assert not v, ev
    assert any(e.type == "error" for e in ev), ev


class TestPartialPayloadBindingControls:
    def test_zero_partial_stream_verifies_as_before(self):
        w = SPIFStreamWriter()
        data = b"".join([w.open(), w.commit(_binding_doc("main", "static"))])
        ev = SPIFStreamReader().feed(data)
        assert any(e.type == "verified" for e in ev), ev

    def test_partial_prefix_without_resume_errors(self):
        """Non-resumed streams require equality, not a suffix: a partial
        that is merely a prefix of the payload value must not verify."""
        data = _binding_stream(_binding_doc("main", "hello world"),
                               [("main", "hello ")])
        ev = SPIFStreamReader().feed(data)
        assert not any(e.type == "verified" for e in ev), ev
        assert any(e.type == "error" for e in ev), ev

    def test_non_string_payload_value_errors(self):
        doc = SPIFDocument(
            payload=[Node(id="main", type="tool_call",
                          value={"name": "search"},
                          confidence=Distribution.certain("epistemic"))],
            provenance=None, semantic=None, trace=[], trace_method="post-hoc",
            alternatives=[], delta=None, signature=None, signatures=[])
        data = _binding_stream(doc, [("main", "hi")])
        ev = SPIFStreamReader().feed(data)
        assert not any(e.type == "verified" for e in ev), ev
        assert any(e.type == "error" for e in ev), ev


class TestResumedPartialBinding:
    """On a resumed stream the reader sees only post-resume partials:
    their concatenation must be a suffix of the payload value."""

    def _resumed_stream(self, tail_fragments):
        doc = _binding_doc("main", "hello streaming world")
        w1 = SPIFStreamWriter()
        w1.open()
        w1.partial_text("hello ", node_id="main")
        token = w1.resume_token()  # seq == 1
        w2 = SPIFStreamWriter(resume_from=token)
        parts = [w2.open()]
        # Replay from the start; the writer drops the confirmed prefix.
        for text in ["hello "] + tail_fragments:
            c = w2.partial_text(text, node_id="main")
            if c: parts.append(c)
        parts.append(w2.commit(doc))
        return b"".join(parts), token

    def test_proper_suffix_verifies(self):
        data, token = self._resumed_stream(["streaming ", "world"])
        ev = list(iter_events(data, resume_token=token))
        assert any(e.type == "resumed" for e in ev), ev
        assert any(e.type == "verified" for e in ev), ev

    def test_suffix_divergence_errors(self):
        data, token = self._resumed_stream(["forged ", "tail"])
        ev = list(iter_events(data, resume_token=token))
        assert any(e.type == "resumed" for e in ev), ev
        assert not any(e.type == "verified" for e in ev), ev
        assert any(e.type == "error" for e in ev), ev
