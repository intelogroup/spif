#!/usr/bin/env python3
"""
SPIF v1.3 conformance runner.

Executes every case in manifest.json against an implementation and prints
per-case PASS / FAIL / BLOCKED against the expected verification outcome.

The default (and currently only) implementation adapter is spif-py
(`spif.trust.verify_artifact`). To run another implementation, replace
`verify_with_spif_py` with an equivalent adapter that maps a case's
artifact + inputs to the same report fields — the manifest is
implementation-agnostic.

Usage:  python run_conformance.py [--verbose]
Exit:   0 when no case FAILs (BLOCKED cases do not fail the run), else 1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "spif-py"))

from spif.trust import verify_artifact  # noqa: E402


def verify_with_spif_py(case: dict) -> dict:
    """Adapter: run one manifest case through spif-py and return the
    report fields the manifest asserts on."""
    data = (HERE / case["artifact"]).read_bytes()
    inputs = case.get("inputs", {})
    kwargs = {}
    if "revocation_file" in inputs:
        kwargs["revocation_file"] = HERE / inputs["revocation_file"]
    if "tsa_keys" in inputs:
        kwargs["tsa_keys"] = json.loads((HERE / inputs["tsa_keys"]).read_text())
    if "bundle" in inputs:
        kwargs["bundle"] = [(HERE / p).read_bytes() for p in inputs["bundle"]]
    report = verify_artifact(data, **kwargs)
    return {
        "trust_status": report.trust_status,
        "signature_status": report.signature_status,
        "timestamp_status": report.timestamp_status,
        "forged_revocations": report.forged_revocations,
        "references": [
            {"kind": r.kind, "status": r.status} for r in report.references
        ],
    }


def evaluate_cases() -> list[dict]:
    manifest = json.loads((HERE / "manifest.json").read_text())
    results = []
    for case in manifest["cases"]:
        entry = {"id": case["id"], "name": case["name"]}
        if not case.get("executable", True):
            entry["result"] = "BLOCKED"
            entry["reason"] = case.get("blocked_reason", "not executable here")
            results.append(entry)
            continue
        try:
            got = verify_with_spif_py(case)
        except Exception as e:  # a crash is a FAIL, not a runner abort
            entry["result"] = "FAIL"
            entry["reason"] = f"verifier raised: {e!r}"
            results.append(entry)
            continue
        expected = case["expected"]
        mismatches = [
            f"{k}: expected {expected[k]!r}, got {got.get(k)!r}"
            for k in expected
            if got.get(k) != expected[k]
        ]
        entry["result"] = "PASS" if not mismatches else "FAIL"
        if mismatches:
            entry["reason"] = "; ".join(mismatches)
        results.append(entry)
    return results


def main() -> int:
    verbose = "--verbose" in sys.argv
    results = evaluate_cases()
    for r in results:
        line = f"CASE {r['id']} {r['name']:<32} {r['result']}"
        if r["result"] != "PASS" and "reason" in r:
            line += f"  ({r['reason']})"
        print(line)
    passed = sum(1 for r in results if r["result"] == "PASS")
    failed = sum(1 for r in results if r["result"] == "FAIL")
    blocked = sum(1 for r in results if r["result"] == "BLOCKED")
    print(f"\n{passed} passed, {failed} failed, {blocked} blocked "
          f"of {len(results)} cases")
    if verbose:
        print(json.dumps(results, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
