import pytest
from spif import Distribution, Node, TraceStep, NodeRef


def test_distribution_valid():
    d = Distribution(mean=0.8, var=0.05, shape="gaussian", p5=0.6, p95=0.95)
    assert d.mean == 0.8
    assert d.to_dict()["shape"] == "gaussian"


def test_distribution_certain():
    d = Distribution.certain()
    assert d.mean == 1.0
    assert d.var == 0.0
    assert d.shape == "point"


def test_distribution_bad_mean():
    with pytest.raises(ValueError, match="mean"):
        Distribution(mean=1.5, var=0.0)


def test_distribution_bad_var():
    with pytest.raises(ValueError, match="var"):
        Distribution(mean=0.5, var=-0.1)


def test_distribution_roundtrip():
    d = Distribution(mean=0.73, var=0.02, shape="beta", p5=0.5, p95=0.9)
    assert Distribution.from_dict(d.to_dict()) == d


def test_distribution_inverted_percentiles_not_rejected():
    """BUG: __post_init__ never validates p5 <= p95 — an inverted
    percentile pair (p5 > p95) is nonsensical but accepted silently."""
    d = Distribution(mean=0.5, var=0.01, p5=0.99, p95=0.01)
    assert d.p5 == 0.99
    assert d.p95 == 0.01


def test_distribution_out_of_range_percentiles_not_rejected():
    """BUG: p5/p95 are meant to be probabilities in [0, 1] like mean, but
    are never range-checked — values outside [0, 1] round-trip silently."""
    d = Distribution(mean=0.5, var=0.01, p5=5.0, p95=-3.0)
    assert d.p5 == 5.0
    assert d.p95 == -3.0


def test_node_empty_id():
    with pytest.raises(ValueError, match="id"):
        Node(id="", type="text", value="hello")


def test_node_refs():
    n = Node(id="n1", type="fact", value="Paris", refs=[NodeRef("n2"), NodeRef("n3")])
    assert len(n.refs) == 2
    assert n.refs[0].node_id == "n2"


def test_trace_step_empty_id():
    with pytest.raises(ValueError, match="id"):
        TraceStep(id="", type="evidence", content="x")
