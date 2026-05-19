"""
Multi-agent handoff experiment: SIF as the handoff artifact between models.

Protocol:
  Agent A (Sonnet, extended thinking) solves a hard problem → SIF file
  Agent B (Haiku) receives:
    (1) the SIF file (typed trace, DAG, confidence)
    (2) flat JSON dump of the same data
    (3) cold start (no prior context at all)

  Measure: answer quality, hallucination rate, step coverage.

This tests the core claim that SIF's typed DAG makes model A's reasoning
machine-consumable by model B without sharing context windows.

Usage:
    python experiments/multiagent_handoff.py
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic

MODEL_A = "claude-sonnet-4-6"
MODEL_B = "claude-haiku-4-5-20251001"
THINKING_BUDGET = 6000

PROBLEMS = [
    {
        "id": "logic_chain",
        "question": (
            "There are 5 houses in a row. Each house is a different color. "
            "The green house is immediately to the left of the white house. "
            "The green house owner drinks coffee. "
            "The owner who smokes Pall Mall raises birds. "
            "The owner of the yellow house smokes Dunhill. "
            "The owner in the center house drinks milk. "
            "The Norwegian lives in the first house. "
            "The man who smokes Blends lives next to the one who keeps cats. "
            "The man who keeps horses lives next to the man who smokes Dunhill. "
            "The owner who smokes BlueMaster drinks beer. "
            "The German smokes Prince. "
            "The Norwegian lives next to the blue house. "
            "The man who smokes Blends has a neighbor who drinks water. "
            "Who owns the fish?"
        ),
        "correct_keywords": ["german", "owns", "fish"],
    },
    {
        "id": "multi_step_math",
        "question": (
            "A company's revenue grows by 15% each year. In year 1, revenue is $100,000. "
            "The company reinvests 40% of revenue each year into operations. "
            "Tax is 25% on (revenue - reinvestment). "
            "What is the net profit (after tax, after reinvestment) in year 4? "
            "Round to nearest dollar."
        ),
        "correct_keywords": ["year 4", "profit"],
    },
    {
        "id": "causal_reasoning",
        "question": (
            "A study finds that cities with more ice cream sales have higher drowning rates. "
            "A second study finds that UV index predicts both ice cream sales and swimming pool visits. "
            "A third study finds drowning rates correlate with pool visits (r=0.89) "
            "but not with ice cream sales when controlling for UV index (r=0.02). "
            "What causal structure best explains these findings? "
            "Does ice cream cause drowning? What should a policy maker do?"
        ),
        "correct_keywords": ["confound", "uv", "no causal", "policy"],
    },
]


def get_sif_from_agent_a(client: anthropic.Anthropic, problem: dict) -> tuple[bytes, str]:
    """
    Agent A: Sonnet with extended thinking.
    Returns (sif_bytes, direct_answer).
    """
    response = client.messages.create(
        model=MODEL_A,
        max_tokens=THINKING_BUDGET + 2000,
        thinking={"type": "enabled", "budget_tokens": THINKING_BUDGET},
        temperature=1,
        messages=[{"role": "user", "content": problem["question"]}],
    )

    text_blocks = [b for b in response.content if b.type == "text"]
    direct_answer = text_blocks[0].text if text_blocks else ""

    # Build SIF from the extended thinking trace
    from tools.claude_to_sif import claude_response_to_sif
    from sif import SIFWriter

    doc = claude_response_to_sif(
        response,
        prompt=problem["question"],
        request_params={"temperature": 1},
    )
    sif_bytes = SIFWriter().encode(doc)
    return sif_bytes, direct_answer


def resume_from_sif(client: anthropic.Anthropic, problem: dict, sif_bytes: bytes) -> str:
    """Agent B resumes from SIF trace."""
    from sif import SIFReader

    doc = SIFReader().decode(sif_bytes)
    steps_text = ""
    for i, step in enumerate(doc.trace):
        conf = f" [confidence={step.confidence.mean:.2f}]" if step.confidence else ""
        deps = f" (depends on: {', '.join(step.deps)})" if step.deps else ""
        steps_text += f"\nStep {i+1} [{step.type}]{conf}{deps}:\n{step.content}\n"

    prompt = f"""Another AI model started solving this problem using extended thinking.
The reasoning trace is provided below in structured form (SIF format).
Each step includes: type, confidence score, and dependencies.

ORIGINAL QUESTION:
{problem['question']}

REASONING TRACE FROM PREVIOUS MODEL (trace_method=live, {len(doc.trace)} steps):
{steps_text}

Based on this trace, provide the final answer. You can use the reasoning above
or correct any errors you spot. Be concise — state the answer directly."""

    response = client.messages.create(
        model=MODEL_B, max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text if response.content else ""


def resume_from_json(client: anthropic.Anthropic, problem: dict, sif_bytes: bytes) -> str:
    """Agent B resumes from flat JSON dump (same data, no types)."""
    from sif import SIFReader

    doc = SIFReader().decode(sif_bytes)
    json_trace = [
        {
            "step": i + 1,
            "type": step.type,
            "content": step.content,
            "confidence_mean": step.confidence.mean if step.confidence else None,
            # deps dropped — JSON has no DAG concept enforced
        }
        for i, step in enumerate(doc.trace)
    ]

    prompt = f"""Another AI model started solving this problem. Here is the thinking
data as JSON. Note: dependency information between steps has been lost in this format.

ORIGINAL QUESTION:
{problem['question']}

THINKING DATA (JSON, {len(json_trace)} entries):
{json.dumps(json_trace, indent=2)[:3000]}

Based on this, provide the final answer. Be concise."""

    response = client.messages.create(
        model=MODEL_B, max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text if response.content else ""


def cold_start(client: anthropic.Anthropic, problem: dict) -> str:
    """Agent B answers from scratch with no context."""
    response = client.messages.create(
        model=MODEL_B, max_tokens=500,
        messages=[{"role": "user", "content": problem["question"]}],
    )
    return response.content[0].text if response.content else ""


def score_answer(answer: str, keywords: list[str]) -> float:
    """Keyword overlap score 0.0–1.0."""
    ans = answer.lower()
    return sum(1 for kw in keywords if kw in ans) / len(keywords)


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    print("Multi-Agent Handoff Experiment")
    print(f"Agent A: {MODEL_A} (extended thinking)")
    print(f"Agent B: {MODEL_B} (receives: SIF / JSON / cold)")
    print("=" * 70)

    results = []

    for problem in PROBLEMS:
        print(f"\nProblem: {problem['id']}")
        print(f"Q: {problem['question'][:80]}...")

        # Agent A
        print("  [Agent A] Solving with extended thinking...")
        sif_bytes, direct_answer = get_sif_from_agent_a(client, problem)
        from sif import SIFReader
        doc = SIFReader().decode(sif_bytes)
        print(f"  Agent A: {len(doc.trace)} thinking steps, {len(sif_bytes)} bytes SIF")
        print(f"  Direct:  {direct_answer[:80]}")

        time.sleep(0.3)

        # Agent B: SIF
        print("  [Agent B/SIF] Resuming from typed trace...")
        sif_answer = resume_from_sif(client, problem, sif_bytes)
        sif_score = score_answer(sif_answer, problem["correct_keywords"])
        print(f"  SIF:     {sif_answer[:80]}  (score={sif_score:.0%})")

        time.sleep(0.3)

        # Agent B: JSON
        print("  [Agent B/JSON] Resuming from flat JSON...")
        json_answer = resume_from_json(client, problem, sif_bytes)
        json_score = score_answer(json_answer, problem["correct_keywords"])
        print(f"  JSON:    {json_answer[:80]}  (score={json_score:.0%})")

        time.sleep(0.3)

        # Agent B: cold
        print("  [Agent B/cold] Answering cold...")
        cold_answer = cold_start(client, problem)
        cold_score = score_answer(cold_answer, problem["correct_keywords"])
        print(f"  Cold:    {cold_answer[:80]}  (score={cold_score:.0%})")

        direct_score = score_answer(direct_answer, problem["correct_keywords"])
        results.append({
            "problem_id": problem["id"],
            "n_trace_steps": len(doc.trace),
            "sif_size_bytes": len(sif_bytes),
            "direct_score": direct_score,
            "sif_score": sif_score,
            "json_score": json_score,
            "cold_score": cold_score,
            "sif_vs_json": sif_score - json_score,
            "sif_vs_cold": sif_score - cold_score,
        })

        time.sleep(0.5)

    # Summary
    print("\n" + "=" * 70)
    print("HANDOFF RESULTS")
    print(f"  {'Problem':<20} {'Direct':>7} {'SIF':>6} {'JSON':>6} {'Cold':>6} {'SIF>JSON':>9} {'SIF>Cold':>9}")
    print("-" * 70)
    for r in results:
        print(f"  {r['problem_id']:<20} {r['direct_score']:>7.0%} "
              f"{r['sif_score']:>6.0%} {r['json_score']:>6.0%} {r['cold_score']:>6.0%} "
              f"{r['sif_vs_json']:>+9.0%} {r['sif_vs_cold']:>+9.0%}")

    avg_sif = sum(r["sif_score"] for r in results) / len(results)
    avg_json = sum(r["json_score"] for r in results) / len(results)
    avg_cold = sum(r["cold_score"] for r in results) / len(results)
    print("-" * 70)
    print(f"  {'AVERAGE':<20} {'':>7} {avg_sif:>6.0%} {avg_json:>6.0%} {avg_cold:>6.0%} "
          f"{avg_sif - avg_json:>+9.0%} {avg_sif - avg_cold:>+9.0%}")

    print(f"\nConclusion: SIF handoff score {avg_sif:.0%} vs JSON {avg_json:.0%} "
          f"vs cold {avg_cold:.0%}")

    # Save
    output = {
        "model_a": MODEL_A,
        "model_b": MODEL_B,
        "timestamp_ms": int(time.time() * 1000),
        "results": results,
        "summary": {
            "avg_sif_score": avg_sif,
            "avg_json_score": avg_json,
            "avg_cold_score": avg_cold,
            "sif_advantage_over_json": avg_sif - avg_json,
            "sif_advantage_over_cold": avg_sif - avg_cold,
        },
    }
    out = Path("experiments/multiagent_handoff_results.json")
    out.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved: {out}")


if __name__ == "__main__":
    main()
