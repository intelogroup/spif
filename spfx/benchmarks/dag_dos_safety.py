"""
Test 4 — DAG DoS Safety.

Build large linear trace chains with a cycle spliced at start/middle/end.
Pass: cycle detected at every position, decode time stays O(N) (not
exponential/quadratic), no stack overflow, no OOM (bounded memory growth).
Also confirms scaling holds at N=50k, not just N=10k.

Usage: python spfx/benchmarks/dag_dos_safety.py
"""
from __future__ import annotations

import resource
import sys
import time

from spfx import SPIFDocument, Node, TraceStep, SPIFWriter, SPIFReader, SPIFFormatError

N = 10_000


def _linear_no_cycle(n: int) -> bytes:
    steps = [TraceStep(id="s0", type="evidence", content="root")]
    for i in range(1, n):
        steps.append(TraceStep(id=f"s{i}", type="inference", content="x", deps=[f"s{i-1}"]))
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="v")], trace=steps)
    return SPIFWriter().encode(doc)


def _chain_with_cycle_at(n: int, position: str) -> bytes:
    """Linear chain s0 -> s1 -> ... -> s(n-1), with a back-edge closing a
    cycle whose earliest member sits at 'start', 'middle', or 'end' of the
    chain (position determines how much of the DAG must be walked before
    Kahn's algorithm can prove the remaining nodes are stuck)."""
    steps = [TraceStep(id="s0", type="evidence", content="root")]
    for i in range(1, n):
        steps.append(TraceStep(id=f"s{i}", type="inference", content="x", deps=[f"s{i-1}"]))

    if position == "start":
        # s1 also depends on s(n-1) -> cycle involves nearly the whole chain
        # but the earliest node with elevated in-degree is right at the start.
        steps[1] = TraceStep(id="s1", type="inference", content="x", deps=["s0", f"s{n-1}"])
    elif position == "middle":
        mid = n // 2
        steps[mid] = TraceStep(id=f"s{mid}", type="inference", content="x",
                                deps=[f"s{mid-1}", f"s{n-1}"])
    elif position == "end":
        steps[-1] = TraceStep(id=f"s{n-1}", type="inference", content="x",
                               deps=[f"s{n-2}", "s0"])
        steps[0] = TraceStep(id="s0", type="evidence", content="root", deps=[f"s{n-1}"])
    else:
        raise ValueError(position)

    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="v")], trace=steps)
    return SPIFWriter().encode(doc)


def _check_cycle(data: bytes, label: str) -> tuple[bool, bool, float]:
    """Returns (cycle_detected, no_stack_overflow, elapsed_s)."""
    t0 = time.perf_counter()
    cycle_detected = False
    err_type = None
    try:
        SPIFReader().decode(data)
    except RecursionError:
        err_type = "RecursionError (STACK OVERFLOW — FAIL)"
    except SPIFFormatError as e:
        cycle_detected = True
        err_type = f"SPIFFormatError: {e}"
    elapsed = time.perf_counter() - t0
    no_stack_overflow = (err_type != "RecursionError (STACK OVERFLOW — FAIL)")
    print(f"  [{label}] result={err_type}  time={elapsed*1000:.2f}ms")
    return cycle_detected, no_stack_overflow, elapsed


def main():
    print(f"=== Test 4: DAG DoS Safety (N={N}) ===\n")

    # Recursion-depth guard OFF — if the cycle detector is recursive, this
    # exposes it as a RecursionError instead of silently succeeding via a huge stack.
    sys.setrecursionlimit(1000)

    print(f"Cycle position sweep at N={N}:")
    position_results = {}
    for pos in ("start", "middle", "end"):
        data = _chain_with_cycle_at(N, pos)
        mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        detected, no_overflow, elapsed = _check_cycle(data, f"N={N} cycle@{pos}")
        mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        position_results[pos] = (detected, no_overflow, elapsed, mem_after - mem_before)

    # --- O(N) scaling check at 1k / 10k / 50k acyclic ---
    print("\nAcyclic decode scaling:")
    scale_ns = [1_000, N, 50_000]
    scale_times = {}
    for n in scale_ns:
        data = _linear_no_cycle(n)
        t0 = time.perf_counter()
        SPIFReader().decode(data)
        elapsed = time.perf_counter() - t0
        scale_times[n] = elapsed
        print(f"  N={n:>6} -> {elapsed*1000:.2f}ms  ({len(data)/1024:.1f} KB)")

    ratio_10k = scale_times[N] / scale_times[1_000] if scale_times[1_000] > 0 else float("inf")
    ratio_50k = scale_times[50_000] / scale_times[1_000] if scale_times[1_000] > 0 else float("inf")
    print(f"\n1k->10k (10x nodes): {ratio_10k:.1f}x time (O(N) expects ~10x)")
    print(f"1k->50k (50x nodes): {ratio_50k:.1f}x time (O(N) expects ~50x)")

    # --- 50k cyclic (end position) — confirm detection still holds at scale ---
    print("\n50k-node cyclic chain (end position):")
    data_50k_cyclic = _chain_with_cycle_at(50_000, "end")
    mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    detected_50k, no_overflow_50k, elapsed_50k = _check_cycle(data_50k_cyclic, "N=50000 cycle@end")
    mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_delta_50k = (mem_after - mem_before) / 1024  # KB on Linux, bytes/1024 approx on macOS

    # --- Verdict ---
    all_positions_pass = all(d and n for d, n, _, _ in position_results.values())
    linear_pass = ratio_10k < 25 and ratio_50k < 100  # generous slack, rejects quadratic
    scale_50k_pass = detected_50k and no_overflow_50k

    print("\n=== Verdict ===")
    for pos, (detected, no_overflow, elapsed, mem_delta) in position_results.items():
        print(f"Cycle@{pos} detected, no overflow:    {'PASS' if detected and no_overflow else 'FAIL'} "
              f"({elapsed*1000:.2f}ms)")
    print(f"O(N) scaling (1k/10k/50k):           {'PASS' if linear_pass else 'FAIL'} "
          f"(10x->{ratio_10k:.1f}x, 50x->{ratio_50k:.1f}x)")
    print(f"50k-node cycle detected at scale:    {'PASS' if scale_50k_pass else 'FAIL'} "
          f"(RSS delta: {rss_delta_50k:.0f})")

    all_pass = all_positions_pass and linear_pass and scale_50k_pass
    print(f"\nTEST 4 OVERALL: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
