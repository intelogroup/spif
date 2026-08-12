"""
MMLU calibration benchmark: 57-subject multiple-choice, stored as SIF.

MMLU (Massive Multitask Language Understanding) is the standard benchmark
for measuring knowledge across subjects. Combined with stated confidence,
it gives a rich calibration dataset: do models know when they don't know?

Key metric: ECE per subject category — does calibration vary by domain?

Usage:
    python experiments/mmlu_bench.py --n 5     # 5 questions per subject (~285 total)
    python experiments/mmlu_bench.py --n 10    # 10 per subject (~570 total)
    python experiments/mmlu_bench.py --subjects "high_school_mathematics,philosophy" --n 20
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

SUBJECT_GROUPS = {
    "STEM": [
        "high_school_mathematics", "high_school_physics", "high_school_chemistry",
        "high_school_biology", "college_mathematics", "college_physics",
        "college_chemistry", "college_biology", "electrical_engineering",
        "computer_security", "machine_learning",
    ],
    "Humanities": [
        "philosophy", "world_religions", "prehistory", "world_history",
        "high_school_world_history", "high_school_us_history",
        "us_foreign_policy", "international_law",
    ],
    "Social Sciences": [
        "sociology", "psychology", "high_school_psychology", "econometrics",
        "high_school_microeconomics", "high_school_macroeconomics",
        "public_relations", "political_science",
    ],
    "Professional": [
        "medical_genetics", "clinical_knowledge", "anatomy", "nutrition",
        "virology", "professional_medicine", "professional_psychology",
        "professional_law", "business_ethics",
    ],
    "Other": [
        "logical_fallacies", "formal_logic", "moral_scenarios",
        "miscellaneous", "global_facts",
    ],
}

ALL_SUBJECTS = [s for subjects in SUBJECT_GROUPS.values() for s in subjects]


def load_mmlu(subject: str, n: int) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError:
        print("ERROR: pip install datasets", file=sys.stderr)
        sys.exit(1)

    try:
        ds = load_dataset("cais/mmlu", subject, split="test")
    except Exception as e:
        print(f"  WARNING: could not load mmlu/{subject}: {e}", file=sys.stderr)
        return []

    questions = []
    for row in ds:
        if len(questions) >= n:
            break
        choices = row["choices"]
        correct_idx = row["answer"]
        questions.append({
            "id": f"{subject}_{len(questions)}",
            "subject": subject,
            "question": row["question"],
            "choices": choices,
            "correct_idx": correct_idx,
            "correct_answer": choices[correct_idx],
        })
    return questions


def ask_mmlu(client: anthropic.Anthropic, q: dict) -> tuple[str, float]:
    choices_text = "\n".join(f"  {chr(65+i)}) {c}" for i, c in enumerate(q["choices"]))
    prompt = f"""Answer this multiple-choice question. Pick the single best answer.

Question: {q['question']}

Choices:
{choices_text}

Respond EXACTLY as:
ANSWER: <letter A/B/C/D>
CONFIDENCE: <0.0-1.0>"""

    response = client.messages.create(
        model=MODEL, max_tokens=60,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    answer, confidence = "", 0.5
    for line in text.splitlines():
        if line.startswith("ANSWER:"):
            answer = line[7:].strip()
        elif line.startswith("CONFIDENCE:"):
            try:
                confidence = max(0.0, min(1.0, float(line[11:].strip())))
            except ValueError:
                pass
    return answer, confidence


def check_correct(q: dict, answer: str) -> bool:
    ans = answer.strip().upper()
    correct_letter = chr(65 + q["correct_idx"])
    if ans.startswith(correct_letter):
        return True
    # Fallback: text match
    return q["correct_answer"].lower() in answer.lower()


def compute_ece(confidences: list[float], corrects: list[bool], n_bins: int = 10) -> float:
    bins: list[list] = [[] for _ in range(n_bins)]
    for conf, ok in zip(confidences, corrects):
        b = min(int(conf * n_bins), n_bins - 1)
        bins[b].append((conf, ok))
    ece = 0.0
    n = len(confidences)
    for b in bins:
        if not b:
            continue
        avg_conf = sum(c for c, _ in b) / len(b)
        acc = sum(1 for _, ok in b if ok) / len(b)
        ece += (len(b) / n) * abs(avg_conf - acc)
    return ece


def save_sif(results: list[dict], model: str) -> Path:
    from sif import SIFDocument, Node, SIFWriter
    from sif.types import Distribution, Provenance
    from sif.format import DIST_SEM_FACTUAL

    nodes = [
        Node(
            id=r["id"],
            type=f"mmlu_{r['subject']}",
            value=json.dumps({"q": r["question"][:80], "ans": r["answer"], "ok": r["correct"]}),
            confidence=Distribution(
                mean=r["confidence"], var=0.02, shape="gaussian",
                semantics=DIST_SEM_FACTUAL,
            ),
        )
        for r in results
    ]
    doc = SIFDocument(
        payload=nodes,
        provenance=Provenance(
            source_model=model, model_version=model, temperature=0.0,
            timestamp_ms=int(time.time() * 1000),
        ),
    )
    out = Path("experiments/mmlu_bench.sif")
    SIFWriter().write(doc, out)
    return out


def main():
    parser = argparse.ArgumentParser(description="MMLU calibration benchmark via SIF")
    parser.add_argument("--n", type=int, default=5, help="Questions per subject")
    parser.add_argument("--subjects", default="",
                        help="Comma-separated subject list (default: all)")
    parser.add_argument("--group", default="",
                        help="Subject group: STEM | Humanities | Social Sciences | Professional | Other")
    parser.add_argument("--output", default="experiments/mmlu_results.json")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    if args.subjects:
        subjects = [s.strip() for s in args.subjects.split(",")]
    elif args.group:
        subjects = SUBJECT_GROUPS.get(args.group, ALL_SUBJECTS)
    else:
        subjects = ALL_SUBJECTS

    print("MMLU Calibration Benchmark")
    print(f"Model: {MODEL}  |  Subjects: {len(subjects)}  |  N per subject: {args.n}")
    print(f"Estimated questions: {len(subjects) * args.n}")
    print("=" * 70)

    all_results = []
    subject_stats = {}

    for subj in subjects:
        questions = load_mmlu(subj, args.n)
        if not questions:
            continue

        confs, corrects = [], []
        for q in questions:
            answer, confidence = ask_mmlu(client, q)
            correct = check_correct(q, answer)
            confs.append(confidence)
            corrects.append(correct)
            all_results.append({
                "id": q["id"],
                "subject": subj,
                "question": q["question"][:80],
                "answer": answer,
                "correct": correct,
                "confidence": confidence,
            })
            time.sleep(0.05)

        acc = sum(corrects) / len(corrects)
        avg_conf = sum(confs) / len(confs)
        ece = compute_ece(confs, corrects)
        subject_stats[subj] = {
            "n": len(questions),
            "accuracy": acc,
            "avg_confidence": avg_conf,
            "ece": ece,
            "overconfidence": avg_conf - acc,
        }
        status = "OK" if ece < 0.15 else "MISCALIBRATED"
        print(f"  [{status}] {subj:<45} acc={acc:.0%}  conf={avg_conf:.2f}  ECE={ece:.3f}")

    if not all_results:
        print("No results.")
        sys.exit(1)

    # Global stats
    all_confs = [r["confidence"] for r in all_results]
    all_corrects = [r["correct"] for r in all_results]
    total_acc = sum(all_corrects) / len(all_corrects)
    total_conf = sum(all_confs) / len(all_confs)
    total_ece = compute_ece(all_confs, all_corrects)

    # Group stats
    group_stats = {}
    for group, group_subjects in SUBJECT_GROUPS.items():
        group_results = [r for r in all_results if r["subject"] in group_subjects]
        if not group_results:
            continue
        g_confs = [r["confidence"] for r in group_results]
        g_corrects = [r["correct"] for r in group_results]
        group_stats[group] = {
            "n": len(group_results),
            "accuracy": sum(g_corrects) / len(g_corrects),
            "avg_confidence": sum(g_confs) / len(g_confs),
            "ece": compute_ece(g_confs, g_corrects),
        }

    print("\n" + "=" * 70)
    print("SUMMARY BY SUBJECT GROUP")
    print(f"  {'Group':<22} {'N':>5}  {'Acc':>6}  {'Conf':>6}  {'ECE':>6}  {'Bias':>7}")
    print("-" * 70)
    for g, s in sorted(group_stats.items()):
        print(f"  {g:<22} {s['n']:>5}  {s['accuracy']:>6.1%}  "
              f"{s['avg_confidence']:>6.3f}  {s['ece']:>6.3f}  "
              f"{s['avg_confidence'] - s['accuracy']:>+7.3f}")

    print()
    print(f"  TOTAL  n={len(all_results)}  accuracy={total_acc:.1%}  "
          f"avg_conf={total_conf:.3f}  ECE={total_ece:.4f}  "
          f"bias={total_conf - total_acc:+.3f}")

    # Save
    output = {
        "model": MODEL,
        "timestamp_ms": int(time.time() * 1000),
        "n_total": len(all_results),
        "accuracy": total_acc,
        "avg_confidence": total_conf,
        "ece": total_ece,
        "overconfidence": total_conf - total_acc,
        "group_stats": group_stats,
        "subject_stats": subject_stats,
        "results": all_results,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))

    sif_path = save_sif(all_results, MODEL)
    print(f"\nJSON saved: {out_path}")
    print(f"SIF saved:  {sif_path}  ({sif_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
