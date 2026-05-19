"""
Hard dataset calibration benchmark: ARC-Challenge, HellaSwag, WinoGrande, BIG-Bench Hard.

Tests model calibration on tasks where LLMs commonly fail — measures whether
the SIF confidence distribution (factual_accuracy) reflects actual uncertainty.

Key metric: ECE (Expected Calibration Error) per dataset.

Usage:
    python experiments/hard_bench.py --n 50
    python experiments/hard_bench.py --n 20 --datasets arc_challenge,hellaswag
    python experiments/hard_bench.py --n 10 --datasets bbh_causal_judgment --output results.json
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

from sif import (
    SIFDocument, Node, Provenance, Distribution,
    SIFWriter,
)

MODEL = "claude-sonnet-4-6"

DATASETS = {
    "arc_challenge": {
        "hf_id":    "allenai/ai2_arc",
        "hf_name":  "ARC-Challenge",
        "split":    "test",
        "format":   "arc",
    },
    "hellaswag": {
        "hf_id":    "Rowan/hellaswag",
        "hf_name":  None,
        "split":    "validation",
        "format":   "hellaswag",
    },
    "winogrande": {
        "hf_id":    "winogrande",
        "hf_name":  "winogrande_xl",
        "split":    "validation",
        "format":   "winogrande",
    },
    "bbh_causal_judgment": {
        "hf_id":    "lukaemon/bbh",
        "hf_name":  "causal_judgement",
        "split":    "test",
        "format":   "bbh_mc",
    },
    "bbh_logical_deduction_3objs": {
        "hf_id":    "lukaemon/bbh",
        "hf_name":  "logical_deduction_three_objects",
        "split":    "test",
        "format":   "bbh_mc",
    },
    "bbh_date_understanding": {
        "hf_id":    "lukaemon/bbh",
        "hf_name":  "date_understanding",
        "split":    "test",
        "format":   "bbh_mc",
    },
}

LETTER_TO_IDX = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}


# ---------------------------------------------------------------------------
# Dataset loading + normalization
# ---------------------------------------------------------------------------

def load_dataset_questions(dataset_key: str, n: int) -> list[dict]:
    """
    Load questions from HuggingFace, normalizing each format to:
      {id, question, choices: list[str], correct_idx: int, dataset: str}
    """
    try:
        from datasets import load_dataset as hf_load
    except ImportError:
        print("ERROR: pip install datasets", file=sys.stderr)
        sys.exit(1)

    cfg = DATASETS[dataset_key]
    try:
        if cfg["hf_name"]:
            ds = hf_load(cfg["hf_id"], cfg["hf_name"], split=cfg["split"])
        else:
            ds = hf_load(cfg["hf_id"], split=cfg["split"])
    except Exception as e:
        print(f"  WARNING: could not load {dataset_key}: {e}", file=sys.stderr)
        return []

    fmt = cfg["format"]
    questions = []
    for i, row in enumerate(ds):
        if len(questions) >= n:
            break
        try:
            q = _normalize_row(row, fmt, dataset_key, i)
            if q:
                questions.append(q)
        except Exception as e:
            print(f"  WARNING: skipping row {i} in {dataset_key}: {e}", file=sys.stderr)
    return questions


def _normalize_row(row: dict, fmt: str, dataset_key: str, idx: int) -> dict | None:
    if fmt == "arc":
        # ARC: choices = {"text": [...], "label": ["A","B","C","D"]}
        # answerKey = "A" | "B" | "C" | "D"
        choices_text = row["choices"]["text"]
        choices_labels = row["choices"]["label"]
        answer_key = row["answerKey"].strip()
        if answer_key not in choices_labels:
            return None
        correct_idx = choices_labels.index(answer_key)
        return {
            "id": f"{dataset_key}_{idx}",
            "question": row["question"],
            "choices": choices_text,
            "correct_idx": correct_idx,
            "dataset": dataset_key,
        }

    if fmt == "hellaswag":
        # HellaSwag: endings = list[str], label = str digit or int
        choices = row["endings"]
        label = row["label"]
        if label == "" or label is None:
            return None  # unanswered rows exist in the validation split
        correct_idx = int(label)
        ctx = row.get("ctx", row.get("activity_label", ""))
        return {
            "id": f"{dataset_key}_{idx}",
            "question": f"Complete the sentence: {ctx}",
            "choices": choices,
            "correct_idx": correct_idx,
            "dataset": dataset_key,
        }

    if fmt == "winogrande":
        # WinoGrande: option1, option2, answer = "1" or "2"
        choices = [row["option1"], row["option2"]]
        answer = row["answer"]
        correct_idx = int(answer) - 1  # "1" -> 0, "2" -> 1
        return {
            "id": f"{dataset_key}_{idx}",
            "question": row["sentence"],
            "choices": choices,
            "correct_idx": correct_idx,
            "dataset": dataset_key,
        }

    if fmt == "bbh_mc":
        # BIG-Bench Hard: input = question text, target = "(A)" or "Yes"/"No" etc.
        input_text = row.get("input", "")
        raw_target = row.get("target", "A").strip()
        target = raw_target.strip("()")

        # Try "(A) ..." style choices first
        choice_lines = [
            ln.strip() for ln in input_text.splitlines()
            if ln.strip().startswith("(") and ")" in ln
        ]
        if choice_lines:
            choices = [ln.split(")", 1)[1].strip() for ln in choice_lines]
            correct_idx = LETTER_TO_IDX.get(target, 0)
        else:
            # Fallback: "- Option" bullet style (e.g. causal_judgement: "- Yes\n- No")
            bullet_lines = [
                ln.strip().lstrip("- ").strip()
                for ln in input_text.splitlines()
                if ln.strip().startswith("- ")
            ]
            if bullet_lines:
                choices = bullet_lines
            else:
                choices = ["Yes", "No"]
            # target is the literal answer text in this format
            target_lower = raw_target.lower()
            correct_idx = next(
                (i for i, c in enumerate(choices) if c.lower() == target_lower), 0
            )

        if correct_idx >= len(choices):
            correct_idx = 0
        return {
            "id": f"{dataset_key}_{idx}",
            "question": input_text,
            "choices": choices,
            "correct_idx": correct_idx,
            "dataset": dataset_key,
        }

    return None


# ---------------------------------------------------------------------------
# Model querying
# ---------------------------------------------------------------------------

def ask_hard_question(client: anthropic.Anthropic, q: dict) -> tuple[str, float]:
    """
    Ask a multiple-choice question. Returns (answer_letter, confidence_float).
    """
    letters = "ABCDEFGH"
    choices_str = "\n".join(
        f"({letters[i]}) {c}" for i, c in enumerate(q["choices"])
    )
    prompt = (
        f"Answer this multiple-choice question. Choose the single best answer.\n\n"
        f"Question: {q['question']}\n\n"
        f"{choices_str}\n\n"
        f"Respond in EXACTLY this format (no other text):\n"
        f"ANSWER: <letter>\n"
        f"CONFIDENCE: <0.0-1.0>"
    )

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=64,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
    except Exception as e:
        print(f"    API error: {e}", file=sys.stderr)
        return "A", 0.5

    answer = "A"
    confidence = 0.5
    for line in text.splitlines():
        if line.startswith("ANSWER:"):
            answer = line.split(":", 1)[1].strip().upper()[:1]
        elif line.startswith("CONFIDENCE:"):
            try:
                confidence = float(line.split(":", 1)[1].strip())
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                confidence = 0.5
    return answer, confidence


# ---------------------------------------------------------------------------
# ECE (Expected Calibration Error)
# ---------------------------------------------------------------------------

def compute_ece(confidences: list[float], corrects: list[bool], n_bins: int = 10) -> float:
    """Expected Calibration Error — identical to mmlu_bench.py implementation."""
    if not confidences:
        return float("nan")
    bin_size = 1.0 / n_bins
    ece = 0.0
    n = len(confidences)
    for b in range(n_bins):
        lo = b * bin_size
        hi = lo + bin_size
        idxs = [i for i, c in enumerate(confidences) if lo <= c < hi]
        if not idxs:
            continue
        avg_conf = sum(confidences[i] for i in idxs) / len(idxs)
        avg_acc  = sum(1 for i in idxs if corrects[i]) / len(idxs)
        ece += len(idxs) / n * abs(avg_conf - avg_acc)
    return round(ece, 4)


# ---------------------------------------------------------------------------
# SIF output
# ---------------------------------------------------------------------------

def save_question_sif(result: dict, model: str, out_root: Path) -> None:
    """Save one SIF file per question result."""
    dataset = result["dataset"]
    qid = result["id"]
    out_dir = out_root / dataset
    out_dir.mkdir(parents=True, exist_ok=True)

    doc = SIFDocument(
        payload=[Node(
            id=qid,
            type="hard_bench_answer",
            value=json.dumps({
                "question": result["question"][:200],
                "answer": result["answer"],
                "correct": result["correct"],
                "correct_answer": result["correct_answer"],
            }),
            confidence=Distribution(
                mean=result["confidence"],
                var=0.04,
                shape="gaussian",
                semantics="factual_accuracy",
            ),
        )],
        provenance=Provenance(
            source_model=model,
            timestamp_ms=int(time.time() * 1000),
        ),
    )
    SIFWriter().write(doc, out_dir / f"{qid}.sif")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Hard dataset calibration benchmark")
    parser.add_argument("--n", type=int, default=50, help="Questions per dataset")
    parser.add_argument(
        "--datasets",
        default=",".join(DATASETS.keys()),
        help="Comma-separated dataset keys",
    )
    parser.add_argument("--output", default=None, help="Aggregate results JSON path")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    experiments_dir = Path(__file__).parent
    out_root = experiments_dir / "hard_bench"
    out_json = Path(args.output) if args.output else experiments_dir / "hard_bench_results.json"
    out_root.mkdir(exist_ok=True)

    selected = [d.strip() for d in args.datasets.split(",") if d.strip() in DATASETS]
    if not selected:
        print(f"ERROR: no valid datasets in '{args.datasets}'", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    letters = "ABCDEFGH"

    aggregate: dict[str, dict] = {}

    for dataset_key in selected:
        print(f"\n=== {dataset_key} ===")
        questions = load_dataset_questions(dataset_key, args.n)
        if not questions:
            print("  No questions loaded — skipping")
            continue

        confidences: list[float] = []
        corrects: list[bool] = []
        results: list[dict] = []

        for q in questions:
            answer_letter, confidence = ask_hard_question(client, q)
            correct_letter = letters[q["correct_idx"]] if q["correct_idx"] < len(letters) else "A"
            is_correct = (answer_letter == correct_letter)
            correct_answer = q["choices"][q["correct_idx"]] if q["choices"] else ""

            result = {
                "id": q["id"],
                "dataset": dataset_key,
                "question": q["question"],
                "answer": answer_letter,
                "correct_answer": correct_letter,
                "correct": is_correct,
                "confidence": confidence,
            }
            results.append(result)
            confidences.append(confidence)
            corrects.append(is_correct)

            mark = "+" if is_correct else " "
            print(f"  [{mark}] {q['id']}: {answer_letter} (conf={confidence:.2f})")

            save_question_sif({**result, "correct_answer": correct_answer}, MODEL, out_root)
            time.sleep(0.05)

        n = len(results)
        accuracy = sum(r["correct"] for r in results) / n if n else 0.0
        ece = compute_ece(confidences, corrects)

        aggregate[dataset_key] = {
            "n":        n,
            "accuracy": round(accuracy, 4),
            "ece":      ece,
            "avg_conf": round(sum(confidences) / n, 4) if n else 0.0,
        }

        print(f"  n={n}  accuracy={accuracy:.1%}  ECE={ece:.4f}")

    # Print summary table
    print("\n" + "=" * 60)
    print(f"{'Dataset':<35} {'n':>5} {'Acc':>7} {'ECE':>8} {'AvgConf':>9}")
    print("-" * 60)
    for dk, stats in aggregate.items():
        print(
            f"{dk:<35} {stats['n']:>5} {stats['accuracy']:>6.1%} "
            f"{stats['ece']:>8.4f} {stats['avg_conf']:>9.3f}"
        )

    overall_ece = (
        sum(s["ece"] for s in aggregate.values()) / len(aggregate)
        if aggregate else float("nan")
    )
    print(f"\nOverall ECE: {overall_ece:.4f}")

    out = {
        "model": MODEL,
        "timestamp_ms": int(time.time() * 1000),
        "datasets": aggregate,
        "overall_ece": round(overall_ece, 4) if aggregate else None,
    }
    out_json.write_text(json.dumps(out, indent=2))
    print(f"Results saved: {out_json}")


if __name__ == "__main__":
    main()
