"""
LLM Judge Runner: Run existing llm_judge.py on generated SIF files and aggregate results.

Uses Claude as judge to evaluate SIF documents on:
  - factual_accuracy_calibration (1-5)
  - trace_coherence (1-5)
  - alternative_coverage (1-5)
"""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic

from spif import SPIFReader
from spif.renderer import SPIFRenderer


MODEL = "claude-sonnet-4-6"

RUBRIC = {
    "factual_accuracy_calibration": (
        "On a 1–5 scale, how well does the document's factual_accuracy distribution "
        "(mean, var, shape) reflect the actual correctness of the payload claims? "
        "1=severely miscalibrated, 5=well-calibrated."
    ),
    "trace_coherence": (
        "On a 1–5 scale, is the reasoning trace internally consistent and non-circular? "
        "1=incoherent or missing, 5=clear, non-circular causal chain."
    ),
    "alternative_coverage": (
        "On a 1–5 scale, do the alternatives adequately cover the plausible hypothesis space? "
        "1=no alternatives or implausible, 5=thorough alternatives with calibrated weights."
    ),
}


def render_doc_for_judge(doc) -> str:
    """Produce a text summary of the SIF document suitable for the judge."""
    visual = SPIFRenderer().render(doc)

    dist_summary = []
    for n in doc.payload:
        c = n.confidence
        dist_summary.append(
            {
                "node_id": n.id,
                "type": n.type,
                "value_preview": str(n.value)[:120],
                "confidence": {
                    "mean": c.mean,
                    "var": c.var,
                    "shape": c.shape,
                    "semantics": c.semantics,
                },
            }
        )

    trace_summary = []
    for s in doc.trace:
        c = s.confidence
        trace_summary.append(
            {
                "step_id": s.id,
                "type": s.type,
                "deps": s.deps,
                "confidence_mean": c.mean,
            }
        )

    machine_part = json.dumps(
        {
            "payload_distributions": dist_summary,
            "trace_summary": trace_summary,
            "n_alternatives": len(doc.alternatives),
            "alt_weights": [a.weight for a in doc.alternatives],
        },
        indent=2,
    )

    return f"{visual}\n\n--- Machine-readable summary ---\n{machine_part}"


def build_judge_prompt(doc_text: str, ground_truth: str | None = None) -> str:
    gt_section = f"\nGROUND TRUTH PROVIDED:\n{ground_truth}\n" if ground_truth else ""

    criteria_text = "\n".join(f"  {name}:\n    {desc}" for name, desc in RUBRIC.items())

    return f"""You are evaluating a SIF (Semantic Inference Format) document for quality.
{gt_section}
SIF DOCUMENT TO EVALUATE:
{doc_text}

Evaluate the document on these criteria:
{criteria_text}

For each criterion, respond in EXACTLY this format:

CRITERION: <criterion_name>
SCORE: <integer 1-5>
JUSTIFICATION: <one to two sentences>

After all criteria, add:

SUMMARY: <one sentence overall assessment>

Respond ONLY with the structured evaluation above — no preamble."""


def parse_judge_response(text: str) -> dict:
    """Parse Claude's structured response into per-criterion dicts."""
    result = {}

    blocks = text.split("\nCRITERION:")
    for block in blocks:
        if not block.strip():
            continue

        lines = block.strip().splitlines()
        if not lines:
            continue

        # First line is the criterion name (might have leading content)
        first_line = lines[0].strip()
        # Extract just the criterion name after "CRITERION:"
        criterion_name = first_line.replace("CRITERION:", "").strip()

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

    # Fill missing with defaults
    for name in RUBRIC:
        if name not in result:
            result[name] = {"score": 3, "justification": "Could not parse judgment."}

    return result


def judge_single_document(doc, client, ground_truth: str | None = None) -> dict:
    """Judge a single SIF document."""
    doc_text = render_doc_for_judge(doc)
    prompt = build_judge_prompt(doc_text, ground_truth)

    message = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    response_text = message.content[0].text

    return parse_judge_response(response_text)


def run_judge_on_directory(
    dir_path: Path,
    client,
    sample_size: int | None = None,
    ground_truths: dict | None = None,
) -> dict:
    """
    Run LLM judge on all SIF files in a directory.

    Args:
        dir_path: Directory containing .sif files
        client: Anthropic client
        sample_size: If set, only judge this many files (for speed)
        ground_truths: Dict mapping file_id -> ground truth string

    Returns:
        Dict with per-file judgments and aggregate statistics
    """
    reader = SPIFReader()

    sif_files = sorted(dir_path.glob("*.sif"))
    if sample_size:
        sif_files = sif_files[:sample_size]

    results = {
        "n_total": len(sif_files),
        "judgments": {},
        "aggregate": {},
    }

    scores_by_criterion = {name: [] for name in RUBRIC}

    print(f"  Judging {len(sif_files)} files in {dir_path.name}...")

    for i, sif_file in enumerate(sif_files):
        try:
            doc = reader.read(str(sif_file))
            file_id = sif_file.stem

            gt = ground_truths.get(file_id) if ground_truths else None
            judgment = judge_single_document(doc, client, gt)

            results["judgments"][file_id] = judgment

            for criterion, data in judgment.items():
                scores_by_criterion[criterion].append(data["score"])

            if (i + 1) % 10 == 0:
                print(f"    {i + 1}/{len(sif_files)}...")

        except Exception as e:
            print(f"    Error on {sif_file.name}: {e}", file=sys.stderr)
            results["judgments"][sif_file.stem] = {"error": str(e)}

        time.sleep(0.1)  # Rate limit

    # Compute aggregates
    for criterion, scores in scores_by_criterion.items():
        if scores:
            results["aggregate"][criterion] = {
                "mean": round(sum(scores) / len(scores), 2),
                "min": min(scores),
                "max": max(scores),
                "std": round(
                    (
                        sum((s - sum(scores) / len(scores)) ** 2 for s in scores)
                        / len(scores)
                    )
                    ** 0.5,
                    2,
                ),
                "n": len(scores),
            }

    return results


def run_judge_on_all_categories(
    base_dir: Path,
    client,
    categories: list[str] | None = None,
    sample_size: int | None = 10,
) -> dict:
    """Run judge on all categories in hard_bench_synthetic."""

    if categories is None:
        categories = [d.name for d in base_dir.iterdir() if d.is_dir()]

    all_results = {
        "timestamp_ms": int(time.time() * 1000),
        "model": MODEL,
        "categories": {},
    }

    for cat in categories:
        cat_dir = base_dir / cat
        if not cat_dir.exists():
            print(f"  Skipping {cat} (not found)")
            continue

        results = run_judge_on_directory(cat_dir, client, sample_size)
        all_results["categories"][cat] = results

    # Overall aggregate
    all_scores = {name: [] for name in RUBRIC}
    for cat_result in all_results["categories"].values():
        for criterion, agg in cat_result.get("aggregate", {}).items():
            if "mean" in agg:
                all_scores[criterion].append(agg["mean"])

    for criterion, means in all_scores.items():
        if means:
            all_results[f"overall_{criterion}"] = round(sum(means) / len(means), 2)

    return all_results


def print_judge_report(results: dict) -> None:
    """Print formatted judge report."""
    print("\n" + "=" * 80)
    print("LLM JUDGE REPORT")
    print("=" * 80)

    print(f"\nModel: {results.get('model', 'unknown')}")

    print("\n## Per-Category Averages")
    print(
        f"{'Category':<25} {'Factual Acc':>12} {'Trace Coherence':>15} {'Alt Coverage':>14}"
    )
    print("-" * 70)

    for cat, data in results.get("categories", {}).items():
        agg = data.get("aggregate", {})
        fa = agg.get("factual_accuracy_calibration", {}).get("mean", "-")
        tc = agg.get("trace_coherence", {}).get("mean", "-")
        ac = agg.get("alternative_coverage", {}).get("mean", "-")

        def fmt(v):
            return f"{v:.2f}" if isinstance(v, (int, float)) else str(v)

        print(f"{cat:<25} {fmt(fa):>12} {fmt(tc):>15} {fmt(ac):>14}")

    # Overall scores
    print("\n## Overall Scores")
    for key in [
        "overall_factual_accuracy_calibration",
        "overall_trace_coherence",
        "overall_alternative_coverage",
    ]:
        if key in results:
            criterion = key.replace("overall_", "").replace("_", " ").title()
            print(f"  {criterion}: {results[key]:.2f}/5")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run LLM judge on SIF benchmark files")
    parser.add_argument(
        "--input-dir", type=str, default=None, help="Directory with SIF files to judge"
    )
    parser.add_argument(
        "--categories", type=str, default=None, help="Comma-separated category names"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=10,
        help="Sample size per category (for quick testing)",
    )
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    # Determine input directory
    if args.input_dir:
        input_dir = Path(args.input_dir)
    else:
        input_dir = (
            Path(__file__).parent.parent / "experiments" / "hard_bench_synthetic"
        )

    categories = args.categories.split(",") if args.categories else None

    print(f"Running LLM judge on {input_dir}")
    print(f"Sample size: {args.sample} per category")

    results = run_judge_on_all_categories(input_dir, client, categories, args.sample)

    print_judge_report(results)

    # Save results
    output_path = (
        Path(args.output)
        if args.output
        else input_dir.parent / "llm_judge_results.json"
    )
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nResults saved to {output_path}")
