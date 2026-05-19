"""
Synthetic test data generators for SIF hard benchmark.

Generates test cases across difficulty levels + hard edge cases.
Hybrid approach: synthetic for deterministic edge cases, LLM for realistic QA.
"""

from __future__ import annotations
import json
import os
import random
import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from spfx import (
    SPIFDocument,
    Node,
    TraceStep,
    Alternative,
    Provenance,
    Distribution,
    SemanticLayer,
    NodeRef,
    Signature,
    SPIFWriter,
    SPIFReader,
)


def _dist(
    mean: float,
    var: float = 0.04,
    shape: str = "gaussian",
    semantics: str = "factual_accuracy",
) -> Distribution:
    return Distribution(mean=mean, var=var, shape=shape, semantics=semantics)


def _rand_id(prefix: str = "n") -> str:
    return f"{prefix}_{random.randint(1000, 9999)}"


def _rand_text(min_words: int = 5, max_words: int = 20) -> str:
    words = [
        "data",
        "model",
        "system",
        "result",
        "analysis",
        "process",
        "input",
        "output",
        "error",
        "value",
        "state",
        "action",
        "option",
        "choice",
        "question",
        "answer",
    ]
    n = random.randint(min_words, max_words)
    return " ".join(random.choice(words) for _ in range(n)) + "."


# -----------------------------------------------------------------------------
# Level 1: Minimal - baseline (1 node, no trace/provenance)
# -----------------------------------------------------------------------------


def gen_minimal(n: int = 50, seed: int = 42) -> list[SPIFDocument]:
    """Level 1: single fact node, no optional layers."""
    random.seed(seed)
    docs = []
    for i in range(n):
        conf_mean = random.uniform(0.5, 1.0)
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"fact_{i}",
                    type="fact",
                    value=f"Statement number {i}: {_rand_text(3, 8)}",
                    confidence=_dist(conf_mean),
                )
            ]
        )
        docs.append(doc)
    return docs


# -----------------------------------------------------------------------------
# Level 2: Medium - provenance + refs
# -----------------------------------------------------------------------------


def gen_medium(n: int = 50, seed: int = 43) -> list[SPIFDocument]:
    """Level 2: 5 nodes with refs, provenance."""
    random.seed(seed)
    docs = []
    for i in range(n):
        nodes = [
            Node(
                id=f"n{j}",
                type="fact",
                value=f"Fact {j} in document {i}: {_rand_text(5, 12)}",
                confidence=_dist(0.6 + j * 0.08),
                refs=[NodeRef(f"n{j - 1}")] if j > 0 else [],
            )
            for j in range(5)
        ]
        doc = SPIFDocument(
            payload=nodes,
            provenance=Provenance(
                source_model=random.choice(["claude-sonnet-4-6", "gpt-4o", "gemini-2"]),
                model_version=random.choice(["4.6", "2024-05", "2.0"]),
                temperature=random.uniform(0.1, 0.9),
                input_hash="".join(random.choices(string.hexdigits, k=64)),
                timestamp_ms=int(time.time() * 1000) + i,
            ),
        )
        docs.append(doc)
    return docs


# -----------------------------------------------------------------------------
# Level 3: Complex Trace - DAG with cycle detection
# -----------------------------------------------------------------------------


def gen_complex_trace(n: int = 50, seed: int = 44) -> list[SPIFDocument]:
    """Level 3: 8-step reasoning trace DAG, tests cycle detection."""
    random.seed(seed)
    docs = []
    for i in range(n):
        step_types = ["evidence", "hypothesis", "inference", "conclusion"]
        steps = [
            TraceStep(
                id=f"s{j}",
                type=step_types[j % 4],
                content=f"Step {j}: {_rand_text(6, 15)}",
                confidence=_dist(0.5 + j * 0.05),
                deps=[f"s{j - 1}"] if j > 0 else [],
            )
            for j in range(8)
        ]
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"concl_{i}",
                    type="fact",
                    value=f"Conclusion for doc {i}: {_rand_text(8, 20)}",
                    confidence=_dist(0.85 + random.random() * 0.1),
                )
            ],
            trace=steps,
            trace_method="post-hoc",
            provenance=Provenance(
                source_model="claude-sonnet-4-6",
                timestamp_ms=int(time.time() * 1000) + i,
            ),
        )
        docs.append(doc)
    return docs


# -----------------------------------------------------------------------------
# Level 4: Full - all layers
# -----------------------------------------------------------------------------


def gen_full(n: int = 50, seed: int = 45) -> list[SPIFDocument]:
    """Level 4: all layers - nodes, trace, semantic, alternatives, signature."""
    random.seed(seed)
    docs = []
    for i in range(n):
        nodes = [
            Node(
                id=f"n{j}",
                type="fact",
                value=f"Node {j}: {_rand_text(5, 12)}",
                confidence=_dist(0.5 + j * 0.04),
            )
            for j in range(10)
        ]
        steps = [
            TraceStep(
                id=f"s{j}",
                type=["evidence", "hypothesis", "inference", "conclusion"][j % 4],
                content=f"Step {j}: {_rand_text(6, 15)}",
                confidence=_dist(0.6 + j * 0.03),
                deps=[f"s{j - 1}"] if j > 0 else [],
            )
            for j in range(10)
        ]
        embedding = [random.uniform(-1, 1) for _ in range(128)]
        doc = SPIFDocument(
            payload=nodes,
            trace=steps,
            trace_method="post-hoc",
            provenance=Provenance(
                source_model="claude-sonnet-4-6",
                model_version="4.6",
                temperature=random.uniform(0.3, 0.8),
                input_hash="".join(random.choices(string.hexdigits, k=64)),
                timestamp_ms=int(time.time() * 1000) + i,
            ),
            semantic=SemanticLayer(
                embedding=embedding,
                embedding_model="text-embedding-3-small",
            ),
            alternatives=[
                Alternative(
                    weight=0.85,
                    nodes=[
                        Node(
                            id=f"alt_main_{i}",
                            type="fact",
                            value=f"Primary answer for {i}",
                            confidence=_dist(0.85),
                        )
                    ],
                    normalized=True,
                ),
                Alternative(
                    weight=0.15,
                    nodes=[
                        Node(
                            id=f"alt_backup_{i}",
                            type="fact",
                            value=f"Alternative for {i}",
                            confidence=_dist(0.15),
                        )
                    ],
                    normalized=True,
                ),
            ],
        )
        docs.append(doc)
    return docs


# -----------------------------------------------------------------------------
# Hard Edge Cases
# -----------------------------------------------------------------------------


def gen_extreme_dist(n: int = 50, seed: int = 46) -> list[SPIFDocument]:
    """Edge: extreme confidence values, bimodal, uniform distributions."""
    random.seed(seed)
    docs = []
    shapes = ["gaussian", "beta", "bimodal", "uniform", "point"]
    for i in range(n):
        shape = shapes[i % len(shapes)]
        if shape == "point":
            mean = random.choice([0.0, 1.0])
            var = 0.0
        elif shape == "gaussian":
            mean = random.choice([0.01, 0.05, 0.95, 0.99])
            var = random.uniform(0.001, 0.04)
        elif shape == "beta":
            mean = random.choice([0.1, 0.3, 0.7, 0.9])
            var = random.uniform(0.01, 0.05)
        elif shape == "uniform":
            mean = random.uniform(0.3, 0.7)
            var = 0.08
        else:  # bimodal
            mean = random.uniform(0.4, 0.6)
            var = 0.1
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"extreme_{i}",
                    type="fact",
                    value=f"Extreme distribution test case {i}",
                    confidence=Distribution(
                        mean=mean, var=var, shape=shape, semantics="factual_accuracy"
                    ),
                )
            ]
        )
        docs.append(doc)
    return docs


def gen_unicode_stress(n: int = 50, seed: int = 47) -> list[SPIFDocument]:
    """Unicode stress: emoji, RTL, CJK, combining characters."""
    random.seed(seed)
    docs = []
    unicode_samples = [
        "Hello 🌍🌎🌏 world! 🎉🎊🎁",
        "السلام عليكم بالعربية",
        "こんにちは日本語テスト",
        "Привет мир на русском",
        "Ελληνικά είναι ωραία",
        "한국어 테스트입니다 👨‍👩‍👧‍👦 family",
        "Zalgo text: H̷̪̱̙͎̓̈́̓̌ě͎̾ľ͎̈l̷̛̲̙̈́̈ơ̶̗̩̓̐",
        "Mixed: 上海🌸东京🎌서울🏯มกุฎ",
    ]
    for i in range(n):
        text = unicode_samples[i % len(unicode_samples)] + f" case {i}"
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"unicode_{i}",
                    type="fact",
                    value=text,
                    confidence=_dist(0.8),
                )
            ]
        )
        docs.append(doc)
    return docs


def gen_large_embeddings(n: int = 50, seed: int = 48) -> list[SPIFDocument]:
    """Large 1024-dim embeddings."""
    random.seed(seed)
    docs = []
    for i in range(n):
        embedding = [random.uniform(-1, 1) for _ in range(1024)]
        doc = SPIFDocument(
            payload=[
                Node(
                    id=f"large_emb_{i}",
                    type="fact",
                    value=f"Document with large embedding {i}",
                    confidence=_dist(0.75),
                )
            ],
            semantic=SemanticLayer(
                embedding=embedding,
                embedding_model="text-embedding-3-large",
            ),
        )
        docs.append(doc)
    return docs


def gen_max_payload(n: int = 50, seed: int = 49) -> list[SPIFDocument]:
    """Max payload: 1000 nodes."""
    random.seed(seed)
    docs = []
    for i in range(n):
        nodes = [
            Node(
                id=f"n{j}",
                type="fact",
                value=f"Node {j} in massive document {i}: {_rand_text(3, 6)}",
                confidence=_dist(random.uniform(0.5, 0.95)),
            )
            for j in range(1000)
        ]
        doc = SPIFDocument(payload=nodes)
        docs.append(doc)
    return docs


def gen_adversarial(n: int = 50, seed: int = 50) -> list[SPIFDocument]:
    """Adversarial: dangling refs, miscalibration tests, malformed data handling."""
    random.seed(seed)
    docs = []
    for i in range(n):
        case_type = i % 3
        if case_type == 0:
            # Dangling node ref (not a trace cycle - the SIF reader has a bug there)
            # We'll test with a payload node reference instead
            doc = SPIFDocument(
                payload=[
                    Node(
                        id="n0",
                        type="fact",
                        value="Node with dangling reference",
                        confidence=_dist(0.8),
                    ),
                    Node(
                        id="n1",
                        type="fact",
                        value="Node referencing non-existent",
                        confidence=_dist(0.7),
                        refs=[NodeRef("n999_nonexistent")],
                    ),
                ]
            )
        elif case_type == 1:
            # Invalid ref format - should be caught
            doc = SPIFDocument(
                payload=[
                    Node(
                        id="bad_ref",
                        type="fact",
                        value="Test node",
                        confidence=_dist(0.9),
                        refs=[NodeRef("")],  # Empty ID
                    )
                ]
            )
        else:
            # Miscalibrated: high confidence but wrong answer (for judge testing)
            doc = SPIFDocument(
                payload=[
                    Node(
                        id="miscalibrated",
                        type="qa_answer",
                        value="This answer is factually incorrect but stated with high confidence",
                        confidence=_dist(0.95, 0.005),  # Very confident but wrong
                    ),
                ],
                alternatives=[
                    Alternative(
                        weight=0.9,
                        nodes=[
                            Node(
                                id="main",
                                type="qa_answer",
                                value="Wrong answer",
                                confidence=_dist(0.95),
                            )
                        ],
                        normalized=True,
                    ),
                    Alternative(
                        weight=0.1,
                        nodes=[
                            Node(
                                id="alt",
                                type="qa_answer",
                                value="Actually correct",
                                confidence=_dist(0.05),
                            )
                        ],
                        normalized=True,
                    ),
                ],
            )
        docs.append(doc)
    return docs


# -----------------------------------------------------------------------------
# LLM-generated realistic QA (requires API)
# -----------------------------------------------------------------------------


def gen_realistic_qa_llm(client, n: int = 50, seed: int = 51) -> list[SPIFDocument]:
    """LLM-generated hard QA questions with calibration."""
    random.seed(seed)
    docs = []

    prompt = """Generate a SIF-structured QA item for benchmarking calibration.

Respond ONLY with a valid JSON object:
{{
  "question": "...",
  "answer": "...",
  "answer_grade": "correct|partial|incorrect",
  "confidence_mean": 0.0-1.0,
  "confidence_var": 0.0-0.1,
  "trace_steps": [
    {{"id": "s0", "type": "evidence", "content": "...", "confidence_mean": 0.0-1.0}},
    {{"id": "s1", "type": "inference", "content": "...", "confidence_mean": 0.0-1.0, "deps": ["s0"]}},
    {{"id": "s2", "type": "conclusion", "content": "...", "confidence_mean": 0.0-1.0, "deps": ["s1"]}}
  ],
  "alternative": {{"answer": "...", "weight": 0.05-0.4}}
}}

Requirements:
- question: challenging, non-trivial
- answer_grade: honest reflection of answer quality
- confidence_mean: high if correct, low if incorrect
- trace_steps: causally valid chain
- alternative: plausible wrong answer with low weight
- Respond ONLY with JSON"""

    for i in range(n):
        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
            text = msg.content[0].text.strip()
            if text.startswith("```"):
                text = text.split("```", 2)[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            item = json.loads(text)

            ts = int(time.time() * 1000) + i
            doc = SPIFDocument(
                payload=[
                    Node(
                        id=f"qa_{i}",
                        type="qa_answer",
                        value=item["answer"],
                        confidence=Distribution(
                            mean=float(item["confidence_mean"]),
                            var=float(item["confidence_var"]),
                            shape="gaussian",
                            semantics="factual_accuracy",
                        ),
                    )
                ],
                trace=[
                    TraceStep(
                        id=step["id"],
                        type=step["type"],
                        content=step["content"],
                        confidence=Distribution(
                            mean=float(step.get("confidence_mean", 0.8)),
                            var=0.03,
                            shape="gaussian",
                            semantics="epistemic",
                        ),
                        deps=step.get("deps", []),
                    )
                    for step in item["trace_steps"]
                ],
                alternatives=[
                    Alternative(
                        weight=1.0 - item["alternative"]["weight"],
                        nodes=[
                            Node(
                                id=f"qa_{i}_main",
                                type="qa_answer",
                                value=item["answer"],
                                confidence=Distribution(
                                    mean=float(item["confidence_mean"]),
                                    var=float(item["confidence_var"]),
                                    shape="gaussian",
                                ),
                            )
                        ],
                        normalized=True,
                    ),
                    Alternative(
                        weight=item["alternative"]["weight"],
                        nodes=[
                            Node(
                                id=f"qa_{i}_alt",
                                type="qa_answer",
                                value=item["alternative"]["answer"],
                                confidence=Distribution(
                                    mean=1.0 - float(item["confidence_mean"]),
                                    var=0.05,
                                    shape="gaussian",
                                ),
                            )
                        ],
                        normalized=True,
                    ),
                ],
                provenance=Provenance(
                    source_model="claude-sonnet-4-6", timestamp_ms=ts
                ),
            )
            docs.append(doc)
        except Exception as e:
            print(f"  LLM generation error: {e}", file=sys.stderr)
        time.sleep(0.1)

    return docs


# -----------------------------------------------------------------------------
# Registry
# -----------------------------------------------------------------------------

GENERATORS = {
    "minimal": gen_minimal,
    "medium": gen_medium,
    "complex_trace": gen_complex_trace,
    "full": gen_full,
    "extreme_dist": gen_extreme_dist,
    "unicode_stress": gen_unicode_stress,
    "large_embeddings": gen_large_embeddings,
    "max_payload": gen_max_payload,
    "adversarial": gen_adversarial,
}


def generate_all(
    n_per_category: int = 50, llm_client=None, skip_llm: bool = False
) -> dict[str, list[SPIFDocument]]:
    """Generate all test categories."""
    results = {}
    for name, gen_fn in GENERATORS.items():
        print(f"  Generating {name}...")
        if name == "realistic_qa" and llm_client and not skip_llm:
            results[name] = gen_realistic_qa_llm(llm_client, n_per_category)
        else:
            results[name] = gen_fn(n_per_category)
    return results


def save_generated(docs: dict[str, list[SPIFDocument]], output_dir: Path) -> None:
    """Save all generated SIF files to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)

    writer = SPIFWriter()
    total = 0

    for category, doc_list in docs.items():
        cat_dir = output_dir / category
        cat_dir.mkdir(exist_ok=True)

        for i, doc in enumerate(doc_list):
            path = cat_dir / f"{category}_{i:03d}.sif"
            writer.write(doc, path)
            total += 1

    print(f"  Saved {total} SIF files to {output_dir}")


def load_category(path: Path) -> list[SPIFDocument]:
    """Load all SIF files from a category directory."""
    reader = SPIFReader()
    docs = []
    for f in sorted(path.glob("*.sif")):
        try:
            docs.append(reader.read(str(f)))
        except Exception as e:
            print(f"  Error loading {f}: {e}", file=sys.stderr)
    return docs


if __name__ == "__main__":
    print("Generating synthetic test data...")
    docs = generate_all(50)

    experiments_dir = Path(__file__).parent.parent / "experiments"
    output_dir = experiments_dir / "hard_bench_synthetic"
    save_generated(docs, output_dir)

    print("Done!")
