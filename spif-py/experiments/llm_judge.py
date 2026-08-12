"""
LLM-as-Judge: evaluate a SIF document for calibration quality using Claude.

The judge is meta-recursive: it consumes a SIF document and produces a SIF document.
The output judgment SIF has one Node per rubric criterion, a reasoning trace, and
alternatives that encode the judge's uncertainty about its own scores.

Rubric criteria (1–5 scale):
  - factual_accuracy_calibration: does Distribution.mean reflect claim correctness?
  - trace_coherence:              is the reasoning DAG internally consistent?
  - alternative_coverage:         do alternatives adequately cover the hypothesis space?

Usage:
    python experiments/llm_judge.py --input experiments/calibration_truthfulqa.sif
    python experiments/llm_judge.py --input foo.sif --ground-truth "Paris is the capital of France."
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic

from sif import (
    SIFDocument, Node, TraceStep, Alternative, Provenance, Distribution,
    SIFWriter, SIFReader, SIFRenderer,
)

MODEL = "claude-sonnet-4-6"

RUBRIC = {
    "factual_accuracy_calibration": (
        "On a 1–5 scale, how well does the document's factual_accuracy distribution "
        "(mean, var, shape) reflect the actual correctness of the payload claims? "
        "1=severely miscalibrated (high confidence on wrong claims or vice versa), "
        "5=well-calibrated (confidence tracks actual correctness)."
    ),
    "trace_coherence": (
        "On a 1–5 scale, is the reasoning trace internally consistent and non-circular? "
        "Do step dependencies form a valid causal chain toward the payload conclusions? "
        "1=incoherent or missing, 5=clear, non-circular causal chain."
    ),
    "alternative_coverage": (
        "On a 1–5 scale, do the alternatives adequately cover the plausible hypothesis space? "
        "1=no alternatives or implausible ones, 5=thorough alternatives with calibrated weights."
    ),
}


def render_doc_for_judge(doc: SIFDocument) -> str:
    """Produce a text summary of the SIF document suitable for the judge prompt."""
    visual = SIFRenderer().render(doc)
    # Append machine-readable distribution summary for precise scoring
    dist_summary = []
    for n in doc.payload:
        c = n.confidence
        dist_summary.append({
            "node_id": n.id,
            "type": n.type,
            "value_preview": str(n.value)[:120],
            "confidence": {"mean": c.mean, "var": c.var, "shape": c.shape, "semantics": c.semantics},
        })
    trace_summary = []
    for s in doc.trace:
        c = s.confidence
        trace_summary.append({
            "step_id": s.id,
            "type": s.type,
            "deps": s.deps,
            "confidence_mean": c.mean,
        })
    machine_part = json.dumps({
        "payload_distributions": dist_summary,
        "trace_summary": trace_summary,
        "n_alternatives": len(doc.alternatives),
        "alt_weights": [a.weight for a in doc.alternatives],
    }, indent=2)
    return f"{visual}\n\n--- Machine-readable summary ---\n{machine_part}"


def build_judge_prompt(doc_text: str, ground_truth: str | None) -> str:
    gt_section = ""
    if ground_truth:
        gt_section = f"\nGROUND TRUTH PROVIDED:\n{ground_truth}\n"

    criteria_text = "\n".join(
        f"  {name}:\n    {desc}" for name, desc in RUBRIC.items()
    )

    return f"""You are evaluating a SIF (Semantic Inference Format) document for quality.
{gt_section}
SIF DOCUMENT TO EVALUATE:
{doc_text}

Evaluate the document on these criteria:
{criteria_text}

For each criterion, respond in EXACTLY this format (repeat for each):

CRITERION: <criterion_name>
SCORE: <integer 1-5>
JUSTIFICATION: <one to two sentences>

After all criteria, add:

SUMMARY: <one sentence overall assessment>

Respond ONLY with the structured evaluation above — no preamble."""


def parse_judge_response(text: str) -> dict[str, dict]:
    """Parse Claude's structured response into per-criterion dicts."""
    result: dict[str, dict] = {}
    # Extract each CRITERION block
    blocks = re.split(r"\nCRITERION:", text)
    for block in blocks:
        if not block.strip():
            continue
        lines = block.strip().splitlines()
        criterion_name = lines[0].strip()
        if criterion_name not in RUBRIC:
            continue
        score = None
        justification = ""
        for line in lines[1:]:
            if line.startswith("SCORE:"):
                try:
                    score = int(line.split(":", 1)[1].strip())
                except ValueError:
                    score = 3
            elif line.startswith("JUSTIFICATION:"):
                justification = line.split(":", 1)[1].strip()
        if score is None:
            score = 3
        result[criterion_name] = {"score": score, "justification": justification}

    # Fill missing criteria with defaults
    for name in RUBRIC:
        if name not in result:
            result[name] = {"score": 3, "justification": "Could not parse judgment for this criterion."}
    return result


def build_judge_sif_document(
    judgment: dict[str, dict],
    subject_doc: SIFDocument,
    model: str,
) -> SIFDocument:
    """Construct the output SIF judgment document."""
    ts = int(time.time() * 1000)

    # One node per criterion
    nodes = []
    for criterion, data in judgment.items():
        score = data["score"]
        confidence_mean = round(score / 5.0, 3)
        nodes.append(Node(
            id=criterion,
            type="judgment",
            value=data["justification"],
            confidence=Distribution(
                mean=confidence_mean,
                var=0.04,
                shape="gaussian",
                semantics="factual_accuracy",
            ),
        ))

    # 3-step reasoning trace
    trace = [
        TraceStep(
            id="evidence",
            type="evidence",
            content=f"Evaluated SIF document with {len(subject_doc.payload)} payload node(s) "
                    f"and {len(subject_doc.trace)} trace step(s).",
            confidence=Distribution(mean=0.95, var=0.01, shape="point", semantics="epistemic"),
            deps=[],
        ),
        TraceStep(
            id="inference",
            type="inference",
            content="Applied rubric: factual calibration, trace coherence, alternative coverage.",
            confidence=Distribution(mean=0.85, var=0.04, shape="gaussian", semantics="epistemic"),
            deps=["evidence"],
        ),
        TraceStep(
            id="conclusion",
            type="conclusion",
            content=(
                "Scores: "
                + ", ".join(f"{k}={v['score']}/5" for k, v in judgment.items())
            ),
            confidence=Distribution(mean=0.80, var=0.06, shape="gaussian", semantics="epistemic"),
            deps=["inference"],
        ),
    ]

    # Alternatives encode the judge's uncertainty about its own scores
    # (counter-argument nodes weighted by 1 - score/5)
    alt_nodes = []
    for criterion, data in judgment.items():
        counter_weight = round(1.0 - data["score"] / 5.0, 3)
        alt_nodes.append(Node(
            id=f"{criterion}_counter",
            type="judgment",
            value=f"Counter-argument: the {criterion} score could be lower due to judge uncertainty.",
            confidence=Distribution(
                mean=max(0.05, counter_weight),
                var=0.05,
                shape="gaussian",
                semantics="epistemic",
            ),
        ))

    alternatives = [
        Alternative(weight=0.8, nodes=nodes, normalized=False),
        Alternative(weight=0.2, nodes=alt_nodes, normalized=False),
    ]

    return SIFDocument(
        payload=nodes,
        trace=trace,
        trace_method="post-hoc",
        alternatives=alternatives,
        provenance=Provenance(
            source_model=model,
            timestamp_ms=ts,
            temperature=0.0,
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM-as-judge for SIF documents")
    parser.add_argument("--input", required=True, help="Path to SIF document to evaluate")
    parser.add_argument("--ground-truth", default=None, help="Optional ground truth text")
    parser.add_argument("--output-sif", default=None, help="Output judge SIF path")
    parser.add_argument("--output-json", default=None, help="Output summary JSON path")
    parser.add_argument("--model", default=MODEL)
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    # Resolve output paths
    experiments_dir = Path(__file__).parent
    out_sif = Path(args.output_sif) if args.output_sif else experiments_dir / "judge_output.sif"
    out_json = Path(args.output_json) if args.output_json else experiments_dir / "judge_summary.json"
    out_sif.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # Load subject document
    print(f"Loading: {args.input}")
    subject_doc = SIFReader().read(args.input)
    print(f"  {len(subject_doc.payload)} node(s), {len(subject_doc.trace)} trace step(s)")

    # Build prompt and call Claude
    doc_text = render_doc_for_judge(subject_doc)
    prompt = build_judge_prompt(doc_text, args.ground_truth)

    print(f"Calling {args.model}...")
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=args.model,
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    response_text = message.content[0].text

    # Parse judgment
    judgment = parse_judge_response(response_text)

    # Build and save judge SIF
    judge_doc = build_judge_sif_document(judgment, subject_doc, args.model)
    SIFWriter().write(judge_doc, out_sif)
    print(f"Judge SIF saved: {out_sif}")

    # Save summary JSON
    summary = {
        "model": args.model,
        "input": str(args.input),
        "judgment": judgment,
        "raw_response": response_text,
    }
    out_json.write_text(json.dumps(summary, indent=2))
    print(f"Summary JSON saved: {out_json}")

    # Print table
    print("\n--- Judgment ---")
    for criterion, data in judgment.items():
        bar = "█" * data["score"] + "░" * (5 - data["score"])
        print(f"  {criterion:<35} [{bar}] {data['score']}/5")
        print(f"    {data['justification']}")


if __name__ == "__main__":
    main()
