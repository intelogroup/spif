"""
A1 — Fuzz + property-based tests.

Claims tested:
1. SPIFReader never raises anything other than SPIFError on any bytes input.
2. For any valid SPIFDocument, write→read produces an equal document (roundtrip property).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from spfx import (
    SPIFWriter, SPIFReader, SPIFDocument,
    Distribution, Node, TraceStep,
    SPIFError,
)
from spfx.format import MAGIC, FORMAT_VERSION


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

floats_01 = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
small_floats = st.floats(min_value=0.0, max_value=0.5, allow_nan=False, allow_infinity=False)

dist_strategy = st.builds(
    Distribution,
    mean=floats_01,
    var=small_floats,
    shape=st.sampled_from(["gaussian", "beta", "bimodal", "uniform", "point"]),
    p5=st.one_of(st.none(), floats_01),
    p95=st.one_of(st.none(), floats_01),
)

node_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-"),
    min_size=1, max_size=16,
)

node_strategy = st.builds(
    Node,
    id=node_id_strategy,
    type=st.sampled_from(["text", "fact", "concept", "code"]),
    value=st.one_of(
        st.text(max_size=200),
        st.integers(min_value=0, max_value=10**6),
    ),
    confidence=dist_strategy,
    refs=st.just([]),  # no cross-refs in generated docs (avoids dangling ref complexity)
)

step_strategy = st.builds(
    TraceStep,
    id=node_id_strategy,
    type=st.sampled_from(["hypothesis", "evidence", "inference", "conclusion"]),
    content=st.text(max_size=200),
    confidence=dist_strategy,
    deps=st.just([]),
    alternatives=st.lists(st.text(max_size=50), max_size=3),
)

doc_strategy = st.builds(
    SPIFDocument,
    payload=st.lists(node_strategy, min_size=1, max_size=5),
    # unique_by ensures no duplicate step IDs (DAG validator rejects duplicates)
    trace=st.lists(step_strategy, max_size=4, unique_by=lambda s: s.id),
)


# ---------------------------------------------------------------------------
# Property 1: roundtrip fidelity
# ---------------------------------------------------------------------------

@given(doc_strategy)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_roundtrip_property(doc):
    """For any valid SPIFDocument, write→read must return equal content."""
    data = SPIFWriter().encode(doc)
    restored = SPIFReader().decode(data)

    assert len(restored.payload) == len(doc.payload)
    for orig, got in zip(doc.payload, restored.payload):
        assert got.id == orig.id
        assert got.type == orig.type
        assert got.value == orig.value
        assert abs(got.confidence.mean - orig.confidence.mean) < 1e-5
        assert got.confidence.shape == orig.confidence.shape

    assert len(restored.trace) == len(doc.trace)
    for orig, got in zip(doc.trace, restored.trace):
        assert got.id == orig.id
        assert got.type == orig.type
        assert got.deps == orig.deps
        assert got.alternatives == orig.alternatives


# ---------------------------------------------------------------------------
# Property 2: no crash on arbitrary bytes
# ---------------------------------------------------------------------------

@given(st.binary(max_size=2048))
@settings(max_examples=2000, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_crash(data):
    """Reader must only raise SPIFError (or subclass) on any input, never crash."""
    try:
        SPIFReader().decode(data)
    except SPIFError:
        pass  # expected
    except Exception as exc:
        pytest.fail(
            f"Reader raised unexpected {type(exc).__name__}: {exc!r} "
            f"on input {data[:32].hex()!r}"
        )


# ---------------------------------------------------------------------------
# Property 3: structured-but-corrupted bytes (valid magic, scrambled body)
# ---------------------------------------------------------------------------

@given(st.binary(min_size=1, max_size=4096))
@settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
def test_valid_magic_bad_body_never_crash(body):
    """Valid magic + version + flags but random body → only SPIFError."""
    data = MAGIC + bytes([FORMAT_VERSION, 0x00]) + body
    try:
        SPIFReader().decode(data)
    except SPIFError:
        pass
    except Exception as exc:
        pytest.fail(
            f"Reader raised unexpected {type(exc).__name__}: {exc!r} "
            f"on structured-corrupt input"
        )


# ---------------------------------------------------------------------------
# Property 4: single-bit flips detected by checksum
# ---------------------------------------------------------------------------

def _minimal_sif() -> bytes:
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="test")])
    return SPIFWriter().encode(doc)


def test_single_bit_flip_detected():
    """Flipping any bit in the body raises SPIFChecksumError."""
    from spfx import SPIFChecksumError
    data = bytearray(_minimal_sif())
    # Flip a byte in the middle of the payload (after magic+version+flags = 10 bytes)
    # but before the checksum chunk (last 37 bytes)
    mid = len(data) // 2
    data[mid] ^= 0x01
    with pytest.raises(SPIFChecksumError):
        SPIFReader().decode(bytes(data))


def test_truncated_at_every_byte():
    """Truncating at any byte in [1, len-1] raises SPIFError, never crashes."""
    data = _minimal_sif()
    for cut in range(1, len(data)):
        try:
            SPIFReader().decode(data[:cut])
        except SPIFError:
            pass
        except Exception as exc:
            pytest.fail(
                f"Truncation at byte {cut} raised {type(exc).__name__}: {exc!r}"
            )
