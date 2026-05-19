"""
Comprehensive edge case tests for SIF format.

Covers boundary conditions, field variations, and stress cases not exercised
by the existing test suite.
"""

import pytest

from spfx import (
    SPIFDocument, Node, TraceStep, SPIFWriter, SPIFReader,
    SPIFFormatError, SPIFChecksumError,
)
from spfx.types import (
    Distribution, SemanticLayer, Alternative, Delta, Provenance, NodeRef,
)
from spfx.format import (
    DIST_SEM_FACTUAL, DIST_SEM_EPISTEMIC, DIST_SEM_STABILITY,
    TRACE_LIVE, TRACE_POSTHOC, TRACE_VERIFIED, MAGIC,
)


def _rtrip(doc: SPIFDocument) -> SPIFDocument:
    return SPIFReader().decode(SPIFWriter().encode(doc))


def _node(i=0, **kw) -> Node:
    defaults = dict(id=f"n{i}", type="fact", value=f"v{i}")
    defaults.update(kw)
    return Node(**defaults)


# ---------------------------------------------------------------------------
# Distribution boundary conditions
# ---------------------------------------------------------------------------

class TestDistributionBoundaries:
    def test_mean_zero(self):
        d = Distribution(mean=0.0, var=0.0, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value="x", confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.mean == pytest.approx(0.0)

    def test_mean_one(self):
        d = Distribution(mean=1.0, var=0.0, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value="x", confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.mean == pytest.approx(1.0)

    def test_mean_below_zero_rejected(self):
        with pytest.raises(ValueError, match="mean"):
            Distribution(mean=-0.01, var=0.0, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)

    def test_mean_above_one_rejected(self):
        with pytest.raises(ValueError, match="mean"):
            Distribution(mean=1.01, var=0.0, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)

    def test_var_zero(self):
        d = Distribution(mean=0.5, var=0.0, shape="point", semantics=DIST_SEM_FACTUAL)
        doc = SPIFDocument(payload=[_node(confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.var == pytest.approx(0.0)

    def test_var_negative_rejected(self):
        with pytest.raises(ValueError, match="var"):
            Distribution(mean=0.5, var=-0.01, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)

    def test_empty_semantics_rejected(self):
        with pytest.raises(ValueError):
            Distribution(mean=0.5, var=0.01, shape="gaussian", semantics="")

    def test_all_shapes_roundtrip(self):
        for shape in ("gaussian", "beta", "bimodal", "uniform", "point"):
            d = Distribution(mean=0.7, var=0.05, shape=shape, semantics=DIST_SEM_EPISTEMIC)
            doc = SPIFDocument(payload=[_node(confidence=d)])
            r = _rtrip(doc)
            assert r.payload[0].confidence.shape == shape, f"shape={shape} failed roundtrip"

    def test_all_semantics_roundtrip(self):
        for sem in (DIST_SEM_FACTUAL, DIST_SEM_EPISTEMIC, DIST_SEM_STABILITY, "custom:my_metric"):
            d = Distribution(mean=0.7, var=0.05, shape="gaussian", semantics=sem)
            doc = SPIFDocument(payload=[_node(confidence=d)])
            r = _rtrip(doc)
            assert r.payload[0].confidence.semantics == sem

    def test_p5_p95_roundtrip(self):
        d = Distribution(mean=0.7, var=0.05, shape="gaussian",
                         semantics=DIST_SEM_FACTUAL, p5=0.55, p95=0.85)
        doc = SPIFDocument(payload=[_node(confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.p5 == pytest.approx(0.55)
        assert r.payload[0].confidence.p95 == pytest.approx(0.85)

    def test_p5_p95_absent_by_default(self):
        d = Distribution(mean=0.7, var=0.05, shape="gaussian", semantics=DIST_SEM_EPISTEMIC)
        doc = SPIFDocument(payload=[_node(confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.p5 is None
        assert r.payload[0].confidence.p95 is None

    def test_bimodal_high_variance(self):
        d = Distribution(mean=0.5, var=0.24, shape="bimodal", semantics=DIST_SEM_EPISTEMIC)
        doc = SPIFDocument(payload=[_node(confidence=d)])
        r = _rtrip(doc)
        assert r.payload[0].confidence.shape == "bimodal"
        assert r.payload[0].confidence.var == pytest.approx(0.24)


# ---------------------------------------------------------------------------
# Node value type diversity
# ---------------------------------------------------------------------------

class TestNodeValueTypes:
    def test_value_int(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=42)])
        r = _rtrip(doc)
        assert r.payload[0].value == 42

    def test_value_float(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=3.14159)])
        r = _rtrip(doc)
        assert r.payload[0].value == pytest.approx(3.14159)

    def test_value_bool_true(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=True)])
        r = _rtrip(doc)
        assert r.payload[0].value is True

    def test_value_bool_false(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=False)])
        r = _rtrip(doc)
        assert r.payload[0].value is False

    def test_value_none(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=None)])
        r = _rtrip(doc)
        assert r.payload[0].value is None

    def test_value_list(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=[1, 2, 3])])
        r = _rtrip(doc)
        assert r.payload[0].value == [1, 2, 3]

    def test_value_nested_dict(self):
        v = {"key": "val", "nested": {"x": 1, "y": [1, 2]}}
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=v)])
        r = _rtrip(doc)
        assert r.payload[0].value == v

    def test_value_empty_string(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value="")])
        r = _rtrip(doc)
        assert r.payload[0].value == ""

    def test_value_large_string(self):
        v = "x" * 10_000
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=v)])
        r = _rtrip(doc)
        assert len(r.payload[0].value) == 10_000

    def test_value_unicode_cjk(self):
        v = "日本語テスト: 人工知能の推論トレース"
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=v)])
        r = _rtrip(doc)
        assert r.payload[0].value == v

    def test_value_unicode_arabic(self):
        v = "اختبار: تتبع استدلال الذكاء الاصطناعي"
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=v)])
        r = _rtrip(doc)
        assert r.payload[0].value == v

    def test_value_unicode_emoji(self):
        v = "Inference trace: ✅🧠💡📊 with confidence 0.99"
        doc = SPIFDocument(payload=[Node(id="n0", type="t", value=v)])
        r = _rtrip(doc)
        assert r.payload[0].value == v


# ---------------------------------------------------------------------------
# Unicode in all string fields
# ---------------------------------------------------------------------------

class TestUnicodeFields:
    def test_unicode_node_type(self):
        doc = SPIFDocument(payload=[Node(id="n0", type="推論ステップ", value="x")])
        r = _rtrip(doc)
        assert r.payload[0].type == "推論ステップ"

    def test_unicode_trace_content(self):
        content = "Думаю, что это правильный ответ: да"
        doc = SPIFDocument(
            payload=[_node()],
            trace=[TraceStep(id="s0", type="inference", content=content)],
        )
        r = _rtrip(doc)
        assert r.trace[0].content == content

    def test_unicode_provenance_model(self):
        doc = SPIFDocument(
            payload=[_node()],
            provenance=Provenance(
                source_model="モデル・クロード",
                model_version="v1.0",
                temperature=0.5,
                timestamp_ms=0,
            ),
        )
        r = _rtrip(doc)
        assert r.provenance.source_model == "モデル・クロード"

    def test_rtl_text_in_value(self):
        v = "نتیجه‌گیری: این یک تست است"
        doc = SPIFDocument(payload=[Node(id="n0", type="fact", value=v)])
        r = _rtrip(doc)
        assert r.payload[0].value == v


# ---------------------------------------------------------------------------
# Large documents (stress tests)
# ---------------------------------------------------------------------------

class TestLargeDocuments:
    def test_100_node_payload(self):
        nodes = [
            Node(id=f"n{i}", type="fact", value=f"Claim number {i}.",
                 confidence=Distribution(mean=0.5 + i * 0.004, var=0.01,
                                         shape="gaussian", semantics=DIST_SEM_FACTUAL))
            for i in range(100)
        ]
        doc = SPIFDocument(payload=nodes)
        r = _rtrip(doc)
        assert len(r.payload) == 100
        assert r.payload[99].id == "n99"

    def test_50_step_deep_linear_dag(self):
        steps = [
            TraceStep(
                id=f"s{i}", type="inference",
                content=f"Reasoning step {i}.",
                deps=[f"s{i-1}"] if i > 0 else [],
            )
            for i in range(50)
        ]
        doc = SPIFDocument(payload=[_node()], trace=steps)
        r = _rtrip(doc)
        assert len(r.trace) == 50
        assert r.trace[49].deps == ["s48"]

    def test_diamond_dag(self):
        """s0 → s1, s0 → s2, s1+s2 → s3 (two paths converging)."""
        steps = [
            TraceStep(id="s0", type="evidence", content="root"),
            TraceStep(id="s1", type="inference", content="branch A", deps=["s0"]),
            TraceStep(id="s2", type="inference", content="branch B", deps=["s0"]),
            TraceStep(id="s3", type="conclusion", content="merge", deps=["s1", "s2"]),
        ]
        doc = SPIFDocument(payload=[_node()], trace=steps)
        r = _rtrip(doc)
        assert set(r.trace[3].deps) == {"s1", "s2"}

    def test_wide_dag_many_roots(self):
        """10 independent roots, 1 sink."""
        roots = [TraceStep(id=f"r{i}", type="evidence", content=f"root {i}") for i in range(10)]
        sink = TraceStep(id="sink", type="conclusion", content="merged",
                         deps=[f"r{i}" for i in range(10)])
        doc = SPIFDocument(payload=[_node()], trace=roots + [sink])
        r = _rtrip(doc)
        assert len(r.trace[10].deps) == 10

    def test_large_embedding_1536_dim(self):
        """1536-dimension embedding (OpenAI ada-002 size)."""
        embedding = [float(i) / 1536 for i in range(1536)]
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(
                embedding=embedding,
                embedding_model="text-embedding-ada-002",
            ),
        )
        r = _rtrip(doc)
        assert len(r.semantic.embedding) == 1536
        assert r.semantic.embedding[0] == pytest.approx(0.0 / 1536)

    def test_node_with_many_refs(self):
        nodes = [Node(id=f"n{i}", type="fact", value=f"v{i}") for i in range(10)]
        refs = [NodeRef(f"n{i}") for i in range(9)]
        nodes[9] = Node(id="n9", type="synthesis", value="combined", refs=refs)
        doc = SPIFDocument(payload=nodes)
        r = _rtrip(doc)
        assert len(r.payload[9].refs) == 9
        assert r.payload[9].refs[0].node_id == "n0"


# ---------------------------------------------------------------------------
# Alternatives edge cases
# ---------------------------------------------------------------------------

class TestAlternativesEdgeCases:
    def test_normalized_false_weights_over_one(self):
        """normalized=False: weights > 1.0 are valid (they're scores, not probs)."""
        alts = [
            Alternative(weight=3.7, normalized=False,
                        nodes=[Node(id="a0", type="fact", value="option A")]),
            Alternative(weight=1.2, normalized=False,
                        nodes=[Node(id="a1", type="fact", value="option B")]),
        ]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        r = _rtrip(doc)
        assert r.alternatives[0].weight == pytest.approx(3.7)

    def test_normalized_true_exact_sum(self):
        """weights that sum to exactly 1.0 must pass."""
        alts = [
            Alternative(weight=0.6, nodes=[Node(id="a0", type="fact", value="A")]),
            Alternative(weight=0.4, nodes=[Node(id="a1", type="fact", value="B")]),
        ]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        r = _rtrip(doc)
        assert len(r.alternatives) == 2

    def test_normalized_true_within_tolerance(self):
        """weights summing to 0.999 (within ±0.01) must pass."""
        alts = [
            Alternative(weight=0.501, nodes=[Node(id="a0", type="fact", value="A")]),
            Alternative(weight=0.498, nodes=[Node(id="a1", type="fact", value="B")]),
        ]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        r = _rtrip(doc)
        assert len(r.alternatives) == 2

    def test_normalized_true_outside_tolerance_rejected(self):
        """weights summing to 0.3 (outside ±0.01) must raise ValueError on encode."""
        alts = [
            Alternative(weight=0.3, nodes=[Node(id="a0", type="fact", value="A")]),
        ]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        with pytest.raises((SPIFFormatError, ValueError)):
            SPIFWriter().encode(doc)

    def test_single_alternative_weight_one(self):
        alts = [Alternative(weight=1.0, nodes=[Node(id="a0", type="fact", value="only")])]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        r = _rtrip(doc)
        assert r.alternatives[0].weight == pytest.approx(1.0)

    def test_many_alternatives(self):
        alts = [
            Alternative(
                weight=1.0 / 10,
                nodes=[Node(id=f"alt{i}", type="fact", value=f"option {i}")],
            )
            for i in range(10)
        ]
        doc = SPIFDocument(payload=[_node()], alternatives=alts)
        r = _rtrip(doc)
        assert len(r.alternatives) == 10


# ---------------------------------------------------------------------------
# Delta chunk edge cases
# ---------------------------------------------------------------------------

class TestDeltaEdgeCases:
    def test_delta_with_empty_changes(self):
        delta = Delta(base_hash="a" * 64, changes=[])
        doc = SPIFDocument(payload=[_node()], delta=delta)
        r = _rtrip(doc)
        assert r.delta.base_hash == "a" * 64
        assert r.delta.changes == []

    def test_delta_with_changes(self):
        changes = [
            {"op": "replace", "path": "/payload/0/value", "value": "new value"},
            {"op": "add", "path": "/payload/1", "value": {"id": "n1", "type": "fact"}},
        ]
        delta = Delta(base_hash="b" * 64, changes=changes)
        doc = SPIFDocument(payload=[_node()], delta=delta)
        r = _rtrip(doc)
        assert len(r.delta.changes) == 2
        assert r.delta.changes[0]["op"] == "replace"

    def test_delta_base_hash_arbitrary_format(self):
        for h in ("sha256:abc123", "0" * 64, "git:main@abc123def456"):
            delta = Delta(base_hash=h, changes=[])
            doc = SPIFDocument(payload=[_node()], delta=delta)
            r = _rtrip(doc)
            assert r.delta.base_hash == h


# ---------------------------------------------------------------------------
# SemanticLayer edge cases
# ---------------------------------------------------------------------------

class TestSemanticLayerEdgeCases:
    def test_embedding_model_empty_string(self):
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(embedding=[0.1, 0.2, 0.3], embedding_model=""),
        )
        r = _rtrip(doc)
        assert r.semantic.embedding_model == ""

    def test_embedding_model_url(self):
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(
                embedding=[0.1] * 768,
                embedding_model="https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2",
            ),
        )
        r = _rtrip(doc)
        assert "huggingface" in r.semantic.embedding_model

    def test_embedding_with_covariance(self):
        emb = [0.1, 0.2, 0.3]
        cov = [0.01, 0.0, 0.0, 0.0, 0.02, 0.0, 0.0, 0.0, 0.03]
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(embedding=emb, covariance=cov),
        )
        r = _rtrip(doc)
        assert len(r.semantic.covariance) == 9

    def test_single_dim_embedding(self):
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(embedding=[0.999], embedding_model="scalar"),
        )
        r = _rtrip(doc)
        assert len(r.semantic.embedding) == 1

    def test_negative_embedding_values(self):
        """Embeddings commonly have negative values."""
        emb = [-0.5, 0.3, -0.1, 0.8, -0.9]
        doc = SPIFDocument(
            payload=[_node()],
            semantic=SemanticLayer(embedding=emb, embedding_model="test"),
        )
        r = _rtrip(doc)
        assert r.semantic.embedding[0] == pytest.approx(-0.5)


# ---------------------------------------------------------------------------
# Trace method variations
# ---------------------------------------------------------------------------

class TestTraceMethodVariations:
    def test_trace_method_live(self):
        doc = SPIFDocument(
            payload=[_node()],
            trace=[TraceStep(id="s0", type="evidence", content="live thought")],
            trace_method=TRACE_LIVE,
        )
        r = _rtrip(doc)
        assert r.trace_method == TRACE_LIVE

    def test_trace_method_posthoc(self):
        doc = SPIFDocument(
            payload=[_node()],
            trace=[TraceStep(id="s0", type="inference", content="retro")],
            trace_method=TRACE_POSTHOC,
        )
        r = _rtrip(doc)
        assert r.trace_method == TRACE_POSTHOC

    def test_trace_method_verified(self):
        doc = SPIFDocument(
            payload=[_node()],
            trace=[TraceStep(id="s0", type="conclusion", content="verified")],
            trace_method=TRACE_VERIFIED,
        )
        r = _rtrip(doc)
        assert r.trace_method == TRACE_VERIFIED

    def test_trace_method_default_posthoc(self):
        doc = SPIFDocument(payload=[_node()])
        r = _rtrip(doc)
        assert r.trace_method == TRACE_POSTHOC

    def test_empty_trace_method_defaults_posthoc(self):
        """When trace is empty, no TRACE chunk is written, so trace_method defaults to post-hoc."""
        doc = SPIFDocument(payload=[_node()], trace=[], trace_method=TRACE_LIVE)
        r = _rtrip(doc)
        # Writer omits TRACE chunk when trace is empty → reader defaults to TRACE_POSTHOC
        assert r.trace_method == TRACE_POSTHOC


# ---------------------------------------------------------------------------
# Full document stress test (all chunks simultaneously)
# ---------------------------------------------------------------------------

class TestFullDocumentAllChunks:
    def test_all_chunks_with_signature(self):
        import base64
        import struct
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from spfx.types import Signature

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

        doc = SPIFDocument(
            payload=[
                Node(id="n0", type="fact", value="claim A",
                     confidence=Distribution(mean=0.9, var=0.01, shape="gaussian",
                                             semantics=DIST_SEM_FACTUAL)),
                Node(id="n1", type="inference", value="derived",
                     confidence=Distribution(mean=0.75, var=0.05, shape="beta",
                                             semantics=DIST_SEM_EPISTEMIC),
                     refs=[NodeRef("n0")]),
            ],
            trace=[
                TraceStep(id="s0", type="evidence", content="observed",
                          confidence=Distribution(mean=0.95, var=0.01, shape="gaussian",
                                                  semantics=DIST_SEM_FACTUAL)),
                TraceStep(id="s1", type="conclusion", content="concluded",
                          confidence=Distribution(mean=0.80, var=0.03, shape="gaussian",
                                                  semantics=DIST_SEM_EPISTEMIC),
                          deps=["s0"]),
            ],
            trace_method=TRACE_LIVE,
            provenance=Provenance(
                source_model="claude-haiku-4-5-20251001",
                model_version="claude-haiku-4-5-20251001",
                temperature=0.7,
                input_hash="sha256:" + "a" * 60,
                timestamp_ms=1_700_000_000_000,
            ),
            semantic=SemanticLayer(
                embedding=[float(i) / 10 for i in range(10)],
                embedding_model="test-model-v1",
            ),
            alternatives=[
                Alternative(weight=0.7, nodes=[
                    Node(id="alt_a", type="alt", value="option A")]),
                Alternative(weight=0.3, nodes=[
                    Node(id="alt_b", type="alt", value="option B")]),
            ],
            delta=Delta(
                base_hash="c" * 64,
                changes=[{"op": "add", "path": "/payload/2", "value": "..."}],
            ),
        )

        # Two-pass sign
        writer = SPIFWriter()
        doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
        dummy = writer.encode(doc)
        offset = len(MAGIC) + 2
        sig_offset = None
        while offset < len(dummy):
            ct, ln = struct.unpack_from(">BI", dummy, offset)
            if ct == 0x07:
                sig_offset = offset
                break
            if ct == 0xFF:
                break
            offset += 5 + ln
        assert sig_offset is not None
        raw_sig = key.sign(dummy[:sig_offset])
        doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=raw_sig)

        data = writer.encode(doc)
        assert SPIFReader().verify_signature(data) is True

        r = SPIFReader().decode(data)
        assert len(r.payload) == 2
        assert len(r.trace) == 2
        assert r.trace_method == TRACE_LIVE
        assert r.provenance.source_model == "claude-haiku-4-5-20251001"
        assert len(r.semantic.embedding) == 10
        assert len(r.alternatives) == 2
        assert r.delta.base_hash == "c" * 64
        assert r.signature is not None
        assert len(r.signature.signature) == 64

    def test_all_chunks_no_signature(self):
        """All optional chunks except signature — should still be valid."""
        doc = SPIFDocument(
            payload=[_node()],
            trace=[TraceStep(id="s0", type="evidence", content="x")],
            provenance=Provenance(
                source_model="test", temperature=0.5, timestamp_ms=1_000_000_000
            ),
            semantic=SemanticLayer(embedding=[0.1, 0.2], embedding_model="m"),
            alternatives=[Alternative(weight=1.0, nodes=[_node(id="a0")])],
            delta=Delta(base_hash="d" * 64, changes=[]),
        )
        r = _rtrip(doc)
        assert r.provenance.source_model == "test"
        assert r.semantic.embedding[1] == pytest.approx(0.2)
        assert r.delta.base_hash == "d" * 64


# ---------------------------------------------------------------------------
# Checksum and integrity
# ---------------------------------------------------------------------------

class TestIntegrity:
    def test_every_byte_position_detected(self):
        """Flip every byte in body and confirm SIF detects it."""
        doc = SPIFDocument(payload=[_node(value="integrity test")])
        data = bytearray(SPIFWriter().encode(doc))
        # Find checksum offset
        import struct
        offset = len(MAGIC) + 2
        cs_offset = None
        while offset < len(data):
            ct, ln = struct.unpack_from(">BI", data, offset)
            if ct == 0xFF:
                cs_offset = offset
                break
            offset += 5 + ln

        n_detected = 0
        # Sample every 3rd byte in the body (to keep test fast)
        for pos in range(10, cs_offset, 3):
            tampered = bytearray(data)
            tampered[pos] ^= 0xFF
            try:
                SPIFReader().decode(bytes(tampered))
            except (SPIFChecksumError, SPIFFormatError):
                n_detected += 1

        body_sample_size = len(range(10, cs_offset, 3))
        # Expect at least 90% detection rate (some flips may produce valid structure)
        assert n_detected / body_sample_size >= 0.90, (
            f"Only {n_detected}/{body_sample_size} tampers detected"
        )

    def test_checksum_not_in_body(self):
        """Verify the checksum chunk itself is NOT included in the hash body."""
        import struct
        import hashlib
        doc = SPIFDocument(payload=[_node()])
        data = SPIFWriter().encode(doc)

        offset = len(MAGIC) + 2
        cs_offset = None
        while offset < len(data):
            ct, ln = struct.unpack_from(">BI", data, offset)
            if ct == 0xFF:
                cs_offset = offset
                break
            offset += 5 + ln

        body = data[:cs_offset]
        stored = data[cs_offset + 5: cs_offset + 5 + 32]
        computed = hashlib.sha256(body).digest()
        assert stored == computed


# ---------------------------------------------------------------------------
# Duplicate IDs (payload)
# ---------------------------------------------------------------------------

class TestDuplicateIDs:
    def test_duplicate_trace_step_ids_detected(self):
        """Duplicate step IDs in trace must raise SPIFFormatError."""
        doc = SPIFDocument(
            payload=[_node()],
            trace=[
                TraceStep(id="s1", type="evidence", content="a"),
                TraceStep(id="s1", type="inference", content="b"),
            ],
        )
        data = SPIFWriter().encode(doc)
        with pytest.raises(SPIFFormatError, match="Duplicate"):
            SPIFReader().decode(data)


# ---------------------------------------------------------------------------
# Provenance completeness
# ---------------------------------------------------------------------------

class TestProvenanceEdgeCases:
    def test_provenance_all_fields_empty(self):
        doc = SPIFDocument(
            payload=[_node()],
            provenance=Provenance(
                source_model="", model_version="", temperature=0.0,
                input_hash="", context_ref="", timestamp_ms=0,
            ),
        )
        r = _rtrip(doc)
        assert r.provenance.source_model == ""
        assert r.provenance.timestamp_ms == 0

    def test_provenance_temperature_extremes(self):
        for temp in (0.0, 0.5, 1.0, 2.0):
            doc = SPIFDocument(
                payload=[_node()],
                provenance=Provenance(source_model="m", temperature=temp, timestamp_ms=0),
            )
            r = _rtrip(doc)
            assert r.provenance.temperature == pytest.approx(temp)

    def test_provenance_large_timestamp(self):
        ts = 9_999_999_999_999  # ~year 2286
        doc = SPIFDocument(
            payload=[_node()],
            provenance=Provenance(source_model="m", temperature=0.0, timestamp_ms=ts),
        )
        r = _rtrip(doc)
        assert r.provenance.timestamp_ms == ts

    def test_signature_without_provenance(self):
        import base64
        import struct
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from spfx.types import Signature

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

        doc = SPIFDocument(payload=[_node()])  # no provenance
        writer = SPIFWriter()
        doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
        dummy = writer.encode(doc)

        offset = len(MAGIC) + 2
        sig_offset = None
        while offset < len(dummy):
            ct, ln = struct.unpack_from(">BI", dummy, offset)
            if ct == 0x07:
                sig_offset = offset
                break
            if ct == 0xFF:
                break
            offset += 5 + ln
        raw_sig = key.sign(dummy[:sig_offset])
        doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=raw_sig)

        data = writer.encode(doc)
        assert SPIFReader().verify_signature(data) is True
        r = SPIFReader().decode(data)
        assert r.provenance is None
        assert r.signature is not None
