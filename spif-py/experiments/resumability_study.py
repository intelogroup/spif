"""
Resumability study: can a SIF trace enable a second model to continue reasoning
where a first left off — without seeing the original conversation?

Protocol:
1. Ask Claude Haiku to reason through a multi-step problem with extended thinking.
   Save the reasoning trace as SIF (trace_method="live").
2. Serialize the trace steps into a prompt for a second call.
3. Ask the second call to "continue" from where the trace ended.
4. Measure: does the continuation answer match a direct answer?

This tests SIF's core claim that traces are machine-readable handoff artifacts,
not just human-readable logs.

Usage:
    python experiments/resumability_study.py --output experiments/resumability_results.json
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
THINKING_BUDGET = 5000

PROBLEMS = [
    {
        "id": "logic_1",
        "question": "Alice, Bob, and Carol each have a different pet: a cat, a dog, and a fish. "
                    "Alice does not have the cat. Bob does not have the fish. "
                    "Carol does not have the dog. Who has which pet?",
        "direct_answer_keywords": ["alice", "dog", "bob", "cat", "carol", "fish"],
    },
    {
        "id": "math_1",
        "question": "A train leaves station A at 9:00 AM traveling at 60 mph. "
                    "Another train leaves station B (120 miles away) at 10:00 AM traveling at 80 mph toward station A. "
                    "At what time do they meet?",
        "direct_answer_keywords": ["11", "am", "hour"],
    },
    {
        "id": "reasoning_1",
        "question": "If all Glorps are Flurbs, and some Flurbs are Zints, and no Zints are Wumps, "
                    "which of the following must be true: "
                    "(A) All Glorps are Zints, "
                    "(B) Some Glorps might be Zints, "
                    "(C) No Glorps are Wumps, "
                    "(D) All Flurbs are Glorps?",
        "direct_answer_keywords": ["b", "some glorps"],
    },
]


def get_trace_and_answer(client: anthropic.Anthropic, problem: dict) -> tuple[list, str]:
    """
    Ask Claude with extended thinking. Returns (thinking_blocks, final_answer).
    """
    response = client.messages.create(
        model=MODEL,
        max_tokens=THINKING_BUDGET + 1000,
        thinking={"type": "enabled", "budget_tokens": THINKING_BUDGET},
        temperature=1,
        messages=[{"role": "user", "content": problem["question"]}],
    )

    thinking_blocks = [b.thinking for b in response.content if b.type == "thinking"]
    text_blocks = [b.text for b in response.content if b.type == "text"]
    answer = text_blocks[0] if text_blocks else ""
    return thinking_blocks, answer


def resume_from_trace(client: anthropic.Anthropic, problem: dict, trace_steps: list[str]) -> str:
    """
    Give the second model a truncated trace and ask it to continue.
    Uses only the first N-1 steps (not the conclusion).
    """
    if len(trace_steps) <= 1:
        # Not enough steps to truncate
        trace_text = "\n\n---\n".join(f"Step {i+1}:\n{s}" for i, s in enumerate(trace_steps))
    else:
        # Drop the last step (the conclusion)
        partial_steps = trace_steps[:-1]
        trace_text = "\n\n---\n".join(f"Step {i+1}:\n{s}" for i, s in enumerate(partial_steps))

    prompt = f"""You are continuing a reasoning process that was interrupted mid-way.
Below is the partial reasoning trace from a previous session.

ORIGINAL QUESTION:
{problem["question"]}

PARTIAL REASONING TRACE (the previous session was interrupted before reaching a conclusion):
{trace_text}

Continue from where this trace left off and provide the final answer.
Be concise — just complete the reasoning and state the answer."""

    response = client.messages.create(
        model=MODEL,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )

    return response.content[0].text if response.content else ""


def answers_match(answer1: str, answer2: str, keywords: list[str]) -> tuple[bool, float]:
    """
    Check if two answers agree by counting keyword overlap.
    Returns (match, similarity_score).
    """
    a1 = answer1.lower()
    a2 = answer2.lower()

    matches_in_1 = sum(1 for k in keywords if k in a1)
    matches_in_2 = sum(1 for k in keywords if k in a2)

    if not keywords:
        return False, 0.0

    # Both answers must contain similar keywords
    overlap = sum(1 for k in keywords if k in a1 and k in a2)
    score = overlap / len(keywords)
    match = score >= 0.5 and matches_in_1 >= len(keywords) // 2 and matches_in_2 >= len(keywords) // 2
    return match, score


def main():
    parser = argparse.ArgumentParser(description="SIF trace resumability study")
    parser.add_argument("--output", default="experiments/resumability_results.json")
    parser.add_argument("--no-sif", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    print(f"Running resumability study: {len(PROBLEMS)} problems using {MODEL}")
    print("=" * 60)

    results = []
    for problem in PROBLEMS:
        print(f"\nProblem: {problem['id']}")
        print(f"Q: {problem['question'][:80]}...")

        # Pass 1: get trace + answer
        print("  [Pass 1] Getting trace + direct answer...")
        trace_steps, direct_answer = get_trace_and_answer(client, problem)
        print(f"  Direct answer ({len(trace_steps)} thinking blocks): {direct_answer[:80]}")

        # Pass 2: resume from partial trace
        print("  [Pass 2] Resuming from partial trace...")
        resumed_answer = resume_from_trace(client, problem, trace_steps)
        print(f"  Resumed answer: {resumed_answer[:80]}")

        # Compare
        match, score = answers_match(direct_answer, resumed_answer, problem["direct_answer_keywords"])
        print(f"  Match: {'YES' if match else 'NO'}  (keyword overlap: {score:.0%})")

        results.append({
            "problem_id": problem["id"],
            "n_trace_steps": len(trace_steps),
            "direct_answer": direct_answer,
            "resumed_answer": resumed_answer,
            "keyword_overlap": score,
            "match": match,
        })

        time.sleep(0.5)

    # Summary
    n_match = sum(1 for r in results if r["match"])
    print("\n" + "=" * 60)
    print(f"RESUMABILITY: {n_match}/{len(results)} problems successfully continued from trace")
    print(f"Avg keyword overlap: {sum(r['keyword_overlap'] for r in results)/len(results):.1%}")

    output = {
        "model": MODEL,
        "timestamp_ms": int(time.time() * 1000),
        "n_problems": len(results),
        "n_resumed_correctly": n_match,
        "resumability_rate": n_match / len(results),
        "results": results,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Results saved to: {out_path}")

    if not args.no_sif:
        _save_as_sif(results, MODEL)


def _save_as_sif(results: list[dict], model: str):
    from sif import SIFDocument, Node, TraceStep, SIFWriter
    from sif.types import Distribution, Provenance
    from sif.format import DIST_SEM_EPISTEMIC, TRACE_LIVE

    nodes = []
    trace_steps = []

    for i, r in enumerate(results):
        conf = Distribution(
            mean=r["keyword_overlap"],
            var=0.05,
            shape="gaussian",
            semantics=DIST_SEM_EPISTEMIC,
        )
        nodes.append(Node(
            id=f"problem_{i}",
            type="resumability_result",
            value=json.dumps({
                "problem_id": r["problem_id"],
                "match": r["match"],
                "overlap": r["keyword_overlap"],
            }),
            confidence=conf,
        ))

        trace_steps.append(TraceStep(
            id=f"s{i}",
            type="inference",
            content=f"Problem {r['problem_id']}: resumed={'yes' if r['match'] else 'no'}, "
                    f"overlap={r['keyword_overlap']:.0%}",
            confidence=conf,
            deps=[f"s{i-1}"] if i > 0 else [],
        ))

    doc = SIFDocument(
        payload=nodes,
        trace=trace_steps,
        trace_method=TRACE_LIVE,
        provenance=Provenance(
            source_model=model,
            model_version=model,
            temperature=1.0,
            timestamp_ms=int(time.time() * 1000),
        ),
    )
    out = Path("experiments/resumability_study.sif")
    SIFWriter().write(doc, out)
    print(f"SIF document saved: {out}  ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
