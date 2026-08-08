"""Distribution.semantics field: validation, roundtrip, v0.1 compatibility."""

import warnings
import pytest
from spif import Distribution, Node, SPIFDocument, SPIFWriter, SPIFReader
from spif.format import (
    DIST_SEM_EPISTEMIC, DIST_SEM_FACTUAL, DIST_SEM_STABILITY, DIST_SEM_TOKEN_PROB,
    KNOWN_DIST_SEMANTICS,
)


def _roundtrip(doc):
    return SPIFReader().decode(SPIFWriter().encode(doc))


def test_default_semantics_is_epistemic():
    d = Distribution(mean=0.8)
    assert d.semantics == DIST_SEM_EPISTEMIC


def test_custom_semantics_roundtrip():
    for sem in [DIST_SEM_FACTUAL, DIST_SEM_STABILITY, DIST_SEM_EPISTEMIC, "custom:domain_relevance"]:
        d = Distribution(mean=0.75, semantics=sem)
        doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="x", confidence=d)])
        restored = _roundtrip(doc)
        assert restored.payload[0].confidence.semantics == sem


def test_empty_semantics_rejected():
    with pytest.raises(ValueError, match="semantics"):
        Distribution(mean=0.5, semantics="")


def test_semantics_in_dict_roundtrip():
    d = Distribution(mean=0.9, semantics=DIST_SEM_FACTUAL)
    d2 = Distribution.from_dict(d.to_dict())
    assert d2.semantics == DIST_SEM_FACTUAL


def test_v1_compat_missing_semantics_defaults():
    """from_dict with no 'semantics' key → defaults to epistemic (v0.1 compat)."""
    d = Distribution.from_dict({"mean": 0.7, "var": 0.02, "shape": "gaussian"})
    assert d.semantics == DIST_SEM_EPISTEMIC


def test_certain_factory_accepts_semantics():
    d = Distribution.certain(semantics=DIST_SEM_FACTUAL)
    assert d.mean == 1.0
    assert d.semantics == DIST_SEM_FACTUAL


def test_trace_step_confidence_semantics_roundtrip():
    from spif import TraceStep
    from spif.format import TRACE_LIVE
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="x")],
        trace=[
            TraceStep(
                id="s1", type="evidence", content="y",
                confidence=Distribution(mean=0.95, semantics=DIST_SEM_STABILITY),
            )
        ],
        trace_method=TRACE_LIVE,
    )
    restored = _roundtrip(doc)
    assert restored.trace[0].confidence.semantics == DIST_SEM_STABILITY
    assert restored.trace_method == TRACE_LIVE


def test_token_probability_semantics_known():
    assert DIST_SEM_TOKEN_PROB in KNOWN_DIST_SEMANTICS


def test_unknown_semantics_emits_user_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        Distribution(mean=0.8, var=0.05, shape="gaussian", semantics="my_custom_thing")
    assert len(w) == 1
    assert issubclass(w[0].category, UserWarning)
    assert "my_custom_thing" in str(w[0].message)


def test_custom_prefix_no_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        Distribution(mean=0.8, var=0.05, shape="gaussian", semantics="custom:my_thing")
    assert len(w) == 0


def test_all_known_semantics_no_warning():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        for sem in KNOWN_DIST_SEMANTICS:
            Distribution(mean=0.5, semantics=sem)
    assert len(w) == 0
