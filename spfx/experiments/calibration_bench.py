"""
Calibration benchmark: ECE (Expected Calibration Error) on real benchmarks.

Tests SIF's core claim: Distribution(semantics="factual_accuracy") captures
per-claim confidence in a typed, auditable way that enables calibration analysis.

Benchmarks:
  - TruthfulQA: 817 adversarial questions (Apache 2.0, HuggingFace)
  - SimpleQA: 4,326 factual questions (OpenAI 2024, HuggingFace)

ECE = sum_b (|B_b| / n) * |accuracy(B_b) - confidence(B_b)|
  where B_b = all predictions with confidence in bucket b

A well-calibrated model: ECE ≈ 0.0
Typical LLM overconfidence: ECE ≈ 0.10–0.20

Usage:
    python experiments/calibration_bench.py --benchmark truthfulqa --n 50
    python experiments/calibration_bench.py --benchmark simpleqa --n 50
    python experiments/calibration_bench.py --both --n 30
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic

MODEL = "claude-haiku-4-5-20251001"

# ---------------------------------------------------------------------------
# ECE computation
# ---------------------------------------------------------------------------

def compute_ece(confidences: list[float], corrects: list[bool], n_bins: int = 10) -> float:
    """
    Expected Calibration Error (ECE) with equal-width bins.
    Lower is better. 0.0 = perfect calibration.
    """
    bins = [[] for _ in range(n_bins)]
    for conf, correct in zip(confidences, corrects):
        b = min(int(conf * n_bins), n_bins - 1)
        bins[b].append((conf, correct))

    ece = 0.0
    n = len(confidences)
    bucket_data = []

    for b_idx, b in enumerate(bins):
        if not b:
            bucket_data.append(None)
            continue
        avg_conf = sum(c for c, _ in b) / len(b)
        accuracy = sum(1 for _, ok in b if ok) / len(b)
        ece += (len(b) / n) * abs(avg_conf - accuracy)
        bucket_data.append({
            "bin": b_idx / n_bins,
            "count": len(b),
            "avg_confidence": avg_conf,
            "accuracy": accuracy,
            "calibration_error": abs(avg_conf - accuracy),
        })

    return ece, bucket_data


# ---------------------------------------------------------------------------
# Benchmark loaders
# ---------------------------------------------------------------------------

def load_truthfulqa(n: int) -> list[dict]:
    """Load TruthfulQA multiple-choice questions."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("ERROR: pip install datasets", file=sys.stderr)
        sys.exit(1)

    ds = load_dataset("truthfulqa/truthful_qa", "multiple_choice", split="validation")
    questions = []
    for row in ds:
        if len(questions) >= n:
            break
        choices = row["mc1_targets"]["choices"]
        labels = row["mc1_targets"]["labels"]
        if not choices:
            continue
        correct_idx = labels.index(1) if 1 in labels else 0
        questions.append({
            "id": f"tqa_{len(questions)}",
            "question": row["question"],
            "choices": choices,
            "correct_idx": correct_idx,
            "correct_answer": choices[correct_idx],
            "benchmark": "truthfulqa",
        })
    return questions


def load_simpleqa(n: int) -> list[dict]:
    """Load SimpleQA questions."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("ERROR: pip install datasets", file=sys.stderr)
        sys.exit(1)

    dataset_ids = [
        "openai/simple-evals",
        "basicrag/simpleQA",
        "simpleqa/simpleqa",
    ]
    ds = None
    for did in dataset_ids:
        try:
            ds = load_dataset(did, split="test")
            break
        except Exception:
            continue
    if ds is None:
        # Final fallback: download directly from GitHub
        try:
            import urllib.request
            import csv
            import io
            url = "https://openaipublic.blob.core.windows.net/simple-evals/simple_qa_test_set.csv"
            with urllib.request.urlopen(url, timeout=30) as r:
                content = r.read().decode()
            reader = csv.DictReader(io.StringIO(content))
            rows = list(reader)
            questions = []
            for row in rows:
                if len(questions) >= n:
                    break
                q = row.get("problem") or row.get("question") or ""
                a = row.get("answer") or row.get("correct_answer") or ""
                if q and a:
                    questions.append({
                        "id": f"sqa_{len(questions)}",
                        "question": q,
                        "correct_answer": a,
                        "benchmark": "simpleqa",
                    })
            return questions
        except Exception as e:
            print(f"ERROR loading SimpleQA from all sources: {e}", file=sys.stderr)
            print("Falling back to TruthfulQA only", file=sys.stderr)
            return []

    questions = []
    for row in ds:
        if len(questions) >= n:
            break
        q = row.get("problem") or row.get("question") or ""
        a = row.get("answer") or row.get("correct_answer") or ""
        if not q or not a:
            continue
        questions.append({
            "id": f"sqa_{len(questions)}",
            "question": q,
            "correct_answer": a,
            "benchmark": "simpleqa",
        })
    return questions


# ---------------------------------------------------------------------------
# Model querying
# ---------------------------------------------------------------------------

def ask_with_confidence(client: anthropic.Anthropic, question: dict) -> tuple[str, float]:
    """
    Ask the model a question and get answer + confidence.
    For MC questions, ask to choose and state confidence.
    For open questions, ask for short answer + confidence.
    """
    if "choices" in question:
        choices_text = "\n".join(f"  {chr(65+i)}) {c}" for i, c in enumerate(question["choices"]))
        prompt = f"""Answer this multiple-choice question. Choose the single best answer.
Then state your confidence as a decimal 0.0–1.0.

Question: {question['question']}

Choices:
{choices_text}

Respond EXACTLY as:
ANSWER: <letter A/B/C/D>
CONFIDENCE: <0.0-1.0>"""
    else:
        prompt = f"""Answer this factual question with a short, direct answer (1-10 words max).
Then state your confidence as a decimal 0.0–1.0.

Question: {question['question']}

Respond EXACTLY as:
ANSWER: <your answer>
CONFIDENCE: <0.0-1.0>"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=80,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    answer = ""
    confidence = 0.5

    for line in text.splitlines():
        if line.startswith("ANSWER:"):
            answer = line[7:].strip()
        elif line.startswith("CONFIDENCE:"):
            try:
                confidence = max(0.0, min(1.0, float(line[11:].strip())))
            except ValueError:
                confidence = 0.5

    return answer, confidence


def check_correct(question: dict, answer: str) -> bool:
    """Check if the answer is correct."""
    ans = answer.lower().strip()

    if "choices" in question:
        # MC: check if chosen letter maps to correct index
        correct_idx = question["correct_idx"]
        # Model may say "A", "A)", "A. choice text", etc.
        for i, choice in enumerate(question["choices"]):
            letter = chr(65 + i)
            if ans.startswith(letter.lower()):
                return i == correct_idx
        # Fallback: substring match on correct answer text
        correct = question["correct_answer"].lower()
        return correct in ans or ans in correct
    else:
        correct = question["correct_answer"].lower().strip()
        return correct in ans or ans in correct or _fuzzy_match(ans, correct)


def _fuzzy_match(a: str, b: str) -> bool:
    """Very basic fuzzy match for short answers."""
    a_words = set(a.split())
    b_words = set(b.split())
    overlap = a_words & b_words
    if not b_words:
        return False
    return len(overlap) / len(b_words) >= 0.5


# ---------------------------------------------------------------------------
# SIF storage
# ---------------------------------------------------------------------------

def save_as_sif(questions: list[dict], answers: list[str], confidences: list[float],
                corrects: list[bool], benchmark: str, model: str) -> Path:
    from sif import SIFDocument, Node, SIFWriter
    from sif.types import Distribution, Provenance
    from sif.format import DIST_SEM_FACTUAL

    nodes = []
    for i, (q, ans, conf, ok) in enumerate(zip(questions, answers, confidences, corrects)):
        nodes.append(Node(
            id=f"{benchmark}_{i}",
            type="factual_claim",
            value=json.dumps({"question": q["question"][:100], "answer": ans, "correct": ok}),
            confidence=Distribution(
                mean=conf, var=0.02, shape="gaussian",
                semantics=DIST_SEM_FACTUAL,
            ),
        ))

    doc = SIFDocument(
        payload=nodes,
        provenance=Provenance(
            source_model=model,
            model_version=model,
            temperature=0.0,
            timestamp_ms=int(time.time() * 1000),
        ),
    )
    out = Path(f"experiments/calibration_{benchmark}.sif")
    SIFWriter().write(doc, out)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_benchmark(client: anthropic.Anthropic, questions: list[dict], benchmark: str) -> dict:
    print(f"\n  Running {benchmark} ({len(questions)} questions, model={MODEL})")
    print("  " + "-" * 56)

    answers, confidences, corrects = [], [], []

    for i, q in enumerate(questions):
        answer, confidence = ask_with_confidence(client, q)
        correct = check_correct(q, answer)
        answers.append(answer)
        confidences.append(confidence)
        corrects.append(correct)

        status = "OK" if correct else "XX"
        print(f"  [{i+1:2d}/{len(questions)}] [{status}] conf={confidence:.2f}  "
              f"ans='{answer[:25]}'")
        time.sleep(0.05)

    n_correct = sum(corrects)
    accuracy = n_correct / len(questions)
    avg_conf = sum(confidences) / len(questions)
    ece, bucket_data = compute_ece(confidences, corrects)

    print(f"\n  {benchmark.upper()} RESULTS:")
    print(f"    Accuracy:          {accuracy:.1%}  ({n_correct}/{len(questions)})")
    print(f"    Avg confidence:    {avg_conf:.3f}")
    print(f"    ECE:               {ece:.4f}  (lower = better calibrated)")
    print(f"    Overconfidence:    {avg_conf - accuracy:+.3f}  (positive = overconfident)")

    print("\n    Bucket calibration:")
    print(f"    {'Bucket':>8}  {'Count':>5}  {'Conf':>6}  {'Acc':>6}  {'Error':>7}")
    for b in bucket_data:
        if b is None:
            continue
        print(f"    {b['bin']:>8.1f}  {b['count']:>5}  "
              f"{b['avg_confidence']:>6.3f}  {b['accuracy']:>6.1%}  "
              f"{b['calibration_error']:>7.4f}")

    sif_path = save_as_sif(questions, answers, confidences, corrects, benchmark, MODEL)
    print(f"\n  SIF saved: {sif_path}  ({sif_path.stat().st_size} bytes)")

    return {
        "benchmark": benchmark,
        "model": MODEL,
        "n_questions": len(questions),
        "n_correct": n_correct,
        "accuracy": accuracy,
        "avg_confidence": avg_conf,
        "ece": ece,
        "overconfidence": avg_conf - accuracy,
        "bucket_data": [b for b in bucket_data if b is not None],
    }


def main():
    parser = argparse.ArgumentParser(description="SIF calibration benchmark")
    parser.add_argument("--benchmark", choices=["truthfulqa", "simpleqa"], default="truthfulqa")
    parser.add_argument("--both", action="store_true", help="Run both benchmarks")
    parser.add_argument("--n", type=int, default=50, help="Questions per benchmark")
    parser.add_argument("--output", default="experiments/calibration_bench_results.json")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    results = []

    benchmarks_to_run = (["truthfulqa", "simpleqa"] if args.both
                         else [args.benchmark])

    print("SIF Calibration Benchmark")
    print(f"Model: {MODEL}  |  Questions per benchmark: {args.n}")

    for bm in benchmarks_to_run:
        print(f"\nLoading {bm}...")
        if bm == "truthfulqa":
            questions = load_truthfulqa(args.n)
        else:
            questions = load_simpleqa(args.n)

        if not questions:
            print(f"  Skipping {bm} — no questions loaded")
            continue

        print(f"Loaded {len(questions)} questions.")
        result = run_benchmark(client, questions, bm)
        results.append(result)

    if not results:
        print("No benchmarks ran.")
        sys.exit(1)

    # Cross-benchmark summary
    if len(results) > 1:
        print("\n" + "=" * 60)
        print("CROSS-BENCHMARK SUMMARY")
        print(f"{'Benchmark':>12}  {'Accuracy':>8}  {'Avg Conf':>9}  {'ECE':>6}  {'Overconf':>9}")
        print("-" * 60)
        for r in results:
            print(f"  {r['benchmark']:>12}  {r['accuracy']:>8.1%}  "
                  f"{r['avg_confidence']:>9.3f}  {r['ece']:>6.4f}  "
                  f"{r['overconfidence']:>+9.3f}")

    # Save results
    out = Path(args.output)
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved: {out}")


if __name__ == "__main__":
    main()
