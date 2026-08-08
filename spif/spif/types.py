"""Core dataclasses for SPIF — Semantic Provenance Inference Format."""

from __future__ import annotations
import warnings
from dataclasses import dataclass, field
from typing import Any

from .format import DIST_SEM_EPISTEMIC, TRACE_POSTHOC, KNOWN_DIST_SEMANTICS, NODE_TOOL_RESULT


@dataclass
class Distribution:
    """A probability distribution — first-class uncertain value."""
    mean: float
    var: float = 0.0
    shape: str = "gaussian"        # gaussian | beta | bimodal | uniform | point
    semantics: str = DIST_SEM_EPISTEMIC  # factual_accuracy | output_stability | epistemic | custom:*
    p5: float | None = None        # 5th percentile
    p95: float | None = None       # 95th percentile

    def __post_init__(self):
        if not 0.0 <= self.mean <= 1.0:
            raise ValueError(f"Distribution.mean must be in [0, 1], got {self.mean}")
        if self.var < 0:
            raise ValueError(f"Distribution.var must be >= 0, got {self.var}")
        if not self.semantics:
            raise ValueError("Distribution.semantics must not be empty")
        if self.semantics not in KNOWN_DIST_SEMANTICS and not self.semantics.startswith("custom:"):
            warnings.warn(
                f"Unknown Distribution.semantics: {self.semantics!r}. "
                f"Known values: {sorted(KNOWN_DIST_SEMANTICS)}. "
                "Use 'custom:<name>' to suppress this warning for application-specific semantics.",
                UserWarning,
                stacklevel=2,
            )

    def to_dict(self) -> dict:
        d = {
            "mean":      self.mean,
            "var":       self.var,
            "shape":     self.shape,
            "semantics": self.semantics,
        }
        if self.p5 is not None:
            d["p5"] = self.p5
        if self.p95 is not None:
            d["p95"] = self.p95
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Distribution":
        return cls(
            mean=d["mean"],
            var=d.get("var", 0.0),
            shape=d.get("shape", "gaussian"),
            semantics=d.get("semantics", DIST_SEM_EPISTEMIC),  # v0.1 compat: default
            p5=d.get("p5"),
            p95=d.get("p95"),
        )

    @classmethod
    def certain(cls, semantics: str = DIST_SEM_EPISTEMIC) -> "Distribution":
        return cls(mean=1.0, var=0.0, shape="point", semantics=semantics)


@dataclass
class NodeRef:
    """A typed reference to another node by ID."""
    node_id: str


@dataclass
class Node:
    """A content node in the payload graph."""
    id: str
    type: str                              # NODE_* constant
    value: Any                             # str | bytes | Distribution | list | dict
    confidence: Distribution = field(default_factory=Distribution.certain)
    refs: list[NodeRef] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            raise ValueError("Node.id must not be empty")


@dataclass
class TraceStep:
    """A single step in the reasoning trace DAG."""
    id: str
    type: str                               # STEP_* constant
    content: Any                            # str | dict
    confidence: Distribution = field(default_factory=Distribution.certain)
    deps: list[str] = field(default_factory=list)        # step IDs this depends on
    alternatives: list[Any] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            raise ValueError("TraceStep.id must not be empty")


@dataclass
class Provenance:
    """Origin metadata for a SPIF document."""
    source_model: str
    timestamp_ms: int
    temperature: float = 0.0
    input_hash: str = ""      # sha256 hex of the generating input
    context_ref: str = ""     # hash of prior SIF state, if any
    model_version: str = ""
    attempt: int = 0          # v1.1+: which retry attempt this is (0 = first)
    task_id: str = ""         # v1.1+: stable ID for the parent task/run
    risk_tier: str = ""       # v1.1+: EU AI Act risk tier (minimal/limited/high/unacceptable)
    model_card: str = ""      # v1.1+: URI to model card / training data registry
    training_data_hash: str = ""  # v1.1+: stable hash of the dataset training manifest or weights base
    energy_wh: float = 0.0        # v1.1+: total energy consumed during generation in Watt-hours
    human_oversight: str = ""     # v1.1+: EU AI Act Art. 14 — "none"/"human-in-loop"/"human-on-loop"
    nonce: str = ""                # v1.1+: unique per-signing value; verifiers use this for replay rejection



@dataclass
class TaskInfo:
    """Task/run envelope — summary metadata for a multi-step agent run (v1.1+)."""
    task_id: str
    attempt: int = 0
    status: str = "ok"        # "ok" | "failed" | "aborted"
    total_ms: int = 0
    tool_count: int = 0
    error_count: int = 0


@dataclass
class SemanticLayer:
    """Dense vector representation of the document's meaning."""
    embedding: list[float]
    embedding_model: str = ""              # v0.2: coordinate system ID (e.g. "text-embedding-3-small")
    covariance: list[list[float]] = field(default_factory=list)

    @property
    def dim(self) -> int:
        return len(self.embedding)


@dataclass
class Alternative:
    """An alternative payload with an associated weight."""
    weight: float
    nodes: list[Node]
    normalized: bool = True   # True = weights sum to 1.0 (probability); False = unnormalized scores


@dataclass
class Delta:
    """Express this document as a diff from a base state."""
    base_hash: str
    changes: list[dict]


@dataclass
class Signature:
    """ed25519 signature over the document body (v0.2+)."""
    algorithm: str       # "ed25519"
    signer: str          # URL or key identifier (e.g. "https://keys.anthropic.com/claude-sonnet-4-6.pub")
    signature: bytes     # raw 64-byte ed25519 signature
    key_id: str = ""     # optional: rotation hint / key identifier for multi-sig


@dataclass
class SPIFDocument:
    """A complete SPIF document."""
    payload: list[Node]
    provenance: Provenance | None = None
    semantic: SemanticLayer | None = None
    trace: list[TraceStep] = field(default_factory=list)
    trace_method: str = TRACE_POSTHOC      # v0.2: how the trace was produced
    alternatives: list[Alternative] = field(default_factory=list)
    delta: Delta | None = None
    signature: Signature | None = None     # v0.2: optional single ed25519 signature
    signatures: list[Signature] = field(default_factory=list)  # v0.2: multi-signature list
    task_info: "TaskInfo | None" = field(default=None)          # v1.1+: task/run envelope
    pending_tool_results: bool = field(                          # runtime only — not serialized
        default=False, compare=False, repr=False
    )

    def __post_init__(self):
        if not self.payload:
            raise ValueError("SPIFDocument.payload must contain at least one node")

    @property
    def document_status(self) -> str:
        """Derived status: 'failed' if any tool_result node has is_error=True, else 'ok'."""
        for node in self.payload:
            if (node.type == NODE_TOOL_RESULT
                    and isinstance(node.value, dict)
                    and node.value.get("is_error")):
                return "failed"
        return "ok"

    def content_id(self) -> str:
        """SHA-256 of the canonical CBOR encoding of {payload, trace, provenance}.

        Use as ``context_ref`` to chain multi-turn conversations::

            doc2 = adapter.complete("follow-up", context=doc1)
            # doc2.provenance.context_ref == doc1.content_id()

        Ignores signatures, embeddings, and alternatives — two documents with
        identical semantic content but different signatures produce the same ID.
        Delegates to ``SPIFWriter.compute_content_id()`` to avoid a circular import.
        """
        from .writer import compute_content_id as _cid  # noqa: PLC0415
        return _cid(self)
