"""
Calibration study: do SIF Distribution confidence values track actual accuracy?

For N factual claims, ask Claude:
1. To state the claim with a confidence estimate
2. Whether the claim is correct (ground-truth check via a separate verification call)

Then check: does stated mean ≈ fraction of correct answers in that confidence bucket?
A well-calibrated model produces accuracy ≈ mean for claims where it states mean=X.

Usage:
    python experiments/calibration_study.py --n 40 --output experiments/calibration_results.json
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

MODEL = "claude-haiku-4-5-20251001"  # cheaper for calibration
THINKING_BUDGET = 3000

FACTUAL_QUESTIONS = [
    "What is the boiling point of water at sea level in Celsius?",
    "Who wrote 'Pride and Prejudice'?",
    "What is the chemical symbol for gold?",
    "In what year did World War II end?",
    "What is the capital of Australia?",
    "How many bones are in the adult human body?",
    "What is the square root of 144?",
    "Who painted the Mona Lisa?",
    "What is the speed of light in a vacuum (approximate m/s)?",
    "What planet is known as the Red Planet?",
    "What is the largest ocean on Earth?",
    "Who was the first person to walk on the Moon?",
    "What is the chemical formula for table salt?",
    "In what year was the Eiffel Tower completed?",
    "What is the smallest prime number?",
    "Who invented the telephone?",
    "What is the longest river in the world?",
    "What is the atomic number of carbon?",
    "Who wrote '1984'?",
    "What is the currency of Japan?",
    "What is the freezing point of water in Fahrenheit?",
    "How many continents are there on Earth?",
    "What is the powerhouse of the cell?",
    "Who developed the theory of general relativity?",
    "What is the capital of Canada?",
    "What is the most abundant gas in Earth's atmosphere?",
    "How many sides does a hexagon have?",
    "What year did the Berlin Wall fall?",
    "What is the chemical symbol for iron?",
    "Who wrote 'The Great Gatsby'?",
    "What is the largest planet in our solar system?",
    "What is the value of pi to 4 decimal places?",
    "Who was the first President of the United States?",
    "What is the hardest natural substance on Earth?",
    "What is the capital of Brazil?",
    "How many chambers does the human heart have?",
    "What is the nearest star to Earth (excluding the Sun)?",
    "What is the chemical formula for water?",
    "In what year did humans first land on the Moon?",
    "What is the largest continent by area?",
]

GROUND_TRUTH = {
    "What is the boiling point of water at sea level in Celsius?": "100",
    "Who wrote 'Pride and Prejudice'?": "Jane Austen",
    "What is the chemical symbol for gold?": "Au",
    "In what year did World War II end?": "1945",
    "What is the capital of Australia?": "Canberra",
    "How many bones are in the adult human body?": "206",
    "What is the square root of 144?": "12",
    "Who painted the Mona Lisa?": "Leonardo da Vinci",
    "What is the speed of light in a vacuum (approximate m/s)?": "299792458",
    "What planet is known as the Red Planet?": "Mars",
    "What is the largest ocean on Earth?": "Pacific",
    "Who was the first person to walk on the Moon?": "Neil Armstrong",
    "What is the chemical formula for table salt?": "NaCl",
    "In what year was the Eiffel Tower completed?": "1889",
    "What is the smallest prime number?": "2",
    "Who invented the telephone?": "Alexander Graham Bell",
    "What is the longest river in the world?": "Nile",
    "What is the atomic number of carbon?": "6",
    "Who wrote '1984'?": "George Orwell",
    "What is the currency of Japan?": "Yen",
    "What is the freezing point of water in Fahrenheit?": "32",
    "How many continents are there on Earth?": "7",
    "What is the powerhouse of the cell?": "mitochondria",
    "Who developed the theory of general relativity?": "Albert Einstein",
    "What is the capital of Canada?": "Ottawa",
    "What is the most abundant gas in Earth's atmosphere?": "nitrogen",
    "How many sides does a hexagon have?": "6",
    "What year did the Berlin Wall fall?": "1989",
    "What is the chemical symbol for iron?": "Fe",
    "Who wrote 'The Great Gatsby'?": "F. Scott Fitzgerald",
    "What is the largest planet in our solar system?": "Jupiter",
    "What is the value of pi to 4 decimal places?": "3.1416",
    "Who was the first President of the United States?": "George Washington",
    "What is the hardest natural substance on Earth?": "diamond",
    "What is the capital of Brazil?": "Brasilia",
    "How many chambers does the human heart have?": "4",
    "What is the nearest star to Earth (excluding the Sun)?": "Proxima Centauri",
    "What is the chemical formula for water?": "H2O",
    "In what year did humans first land on the Moon?": "1969",
    "What is the largest continent by area?": "Asia",
}


def ask_with_confidence(client: anthropic.Anthropic, question: str) -> tuple[str, float]:
    """
    Ask Claude a factual question and ask it to report its confidence.
    Returns (answer, confidence_0_to_1).
    """
    prompt = f"""Answer this factual question with a short, direct answer (1-10 words max).
Then on a new line, write your confidence as a decimal between 0.0 and 1.0.

Format your response EXACTLY as:
ANSWER: <your answer>
CONFIDENCE: <0.0-1.0>

Question: {question}"""

    response = client.messages.create(
        model=MODEL,
        max_tokens=100,
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
                confidence = float(line[11:].strip())
                confidence = max(0.0, min(1.0, confidence))
            except ValueError:
                confidence = 0.5

    return answer, confidence


def check_correctness(answer: str, ground_truth: str) -> bool:
    """Simple substring check (case-insensitive)."""
    ans = answer.lower().strip()
    gt = ground_truth.lower().strip()
    return gt in ans or ans in gt


def bucket_calibration(results: list[dict]) -> dict:
    """
    Group results into confidence buckets and compute accuracy per bucket.
    Returns calibration data: {bucket_center: {count, accuracy, mean_confidence}}.
    """
    buckets: dict[float, list[bool]] = {}
    for r in results:
        c = r["confidence"]
        # 10 buckets: 0.05, 0.15, ..., 0.95
        b = round(min(0.9, max(0.0, c - (c % 0.1))) + 0.05, 2)
        buckets.setdefault(b, []).append(r["correct"])

    calibration = {}
    for b, corrects in sorted(buckets.items()):
        calibration[b] = {
            "count": len(corrects),
            "accuracy": sum(corrects) / len(corrects),
        }
    return calibration


def main():
    parser = argparse.ArgumentParser(description="SIF confidence calibration study")
    parser.add_argument("--n", type=int, default=40, help="Number of questions to ask")
    parser.add_argument("--output", default="experiments/calibration_results.json")
    parser.add_argument("--no-sif", action="store_true", help="Skip SIF document creation")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    questions = FACTUAL_QUESTIONS[: args.n]

    print(f"Running calibration study: {len(questions)} questions using {MODEL}")
    print("-" * 60)

    results = []
    for i, q in enumerate(questions):
        answer, confidence = ask_with_confidence(client, q)
        gt = GROUND_TRUTH.get(q, "")
        correct = check_correctness(answer, gt)

        results.append({
            "question": q,
            "answer": answer,
            "ground_truth": gt,
            "confidence": confidence,
            "correct": correct,
        })

        status = "CORRECT" if correct else "WRONG "
        print(f"[{i+1:2d}/{len(questions)}] {status}  conf={confidence:.2f}  "
              f"answer='{answer[:30]}'  expected='{gt}'")
        time.sleep(0.1)  # rate limiting

    # Calibration analysis
    calibration = bucket_calibration(results)
    total = len(results)
    n_correct = sum(1 for r in results if r["correct"])
    overall_accuracy = n_correct / total
    avg_confidence = sum(r["confidence"] for r in results) / total

    print("\n" + "=" * 60)
    print(f"RESULTS: {n_correct}/{total} correct ({overall_accuracy:.1%})")
    print(f"Average stated confidence: {avg_confidence:.2f}")
    print(f"Calibration error (|confidence - accuracy|): "
          f"{abs(avg_confidence - overall_accuracy):.3f}")
    print("\nBucket calibration:")
    print(f"  {'Bucket':>8}  {'Count':>5}  {'Accuracy':>8}  {'Calibration Error':>17}")
    for b, d in sorted(calibration.items()):
        err = abs(b - d["accuracy"])
        print(f"  {b:>8.2f}  {d['count']:>5}  {d['accuracy']:>8.1%}  {err:>17.3f}")

    # Save results
    output = {
        "model": MODEL,
        "timestamp_ms": int(time.time() * 1000),
        "n_questions": total,
        "n_correct": n_correct,
        "overall_accuracy": overall_accuracy,
        "avg_confidence": avg_confidence,
        "calibration_error": abs(avg_confidence - overall_accuracy),
        "calibration": calibration,
        "results": results,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to: {out_path}")

    # Create SIF document if requested
    if not args.no_sif:
        _save_as_sif(results, overall_accuracy, avg_confidence, MODEL)


def _save_as_sif(results, overall_accuracy, avg_confidence, model):
    from sif import SIFDocument, Node, SIFWriter
    from sif.types import Distribution, Provenance
    from sif.format import DIST_SEM_FACTUAL

    nodes = []
    for r in results:
        conf = Distribution(
            mean=r["confidence"],
            var=0.02,
            shape="gaussian",
            semantics=DIST_SEM_FACTUAL,
        )
        nodes.append(Node(
            id=r["question"][:20].replace(" ", "_").lower(),
            type="factual_claim",
            value=r["answer"],
            confidence=conf,
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
    out = Path("experiments/calibration_study.sif")
    SIFWriter().write(doc, out)
    print(f"SIF document saved: {out}  ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
