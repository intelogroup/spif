#!/usr/bin/env python3
"""
SPIF conformance runner (v1.3 kit, extended by v1.4).

Executes every case in manifest.json against an implementation and prints
per-case PASS / FAIL / BLOCKED against the expected verification outcome.

The default implementation adapter is spif-py
(`spif.trust.verify_artifact`). Case 02 (cross_implementation_rust) is
special: it runs the Rust implementation's `trust_conformance` binary
(spif-rust) in both directions — Rust verifying the Python-produced
artifact, and spif-py verifying a Rust-produced signed artifact. It is
BLOCKED only when no Rust toolchain/binary is available. Cases 12-15
(hybrid PQ, v1.4) carry ``adapter: pq_hybrid`` and run through
`verify_artifact` in the require_pq gate mode (SPEC §7.9.2); they are
BLOCKED when the ML-DSA backend (pqcrypto) is unavailable. To run
another implementation for the remaining cases, replace
`verify_with_spif_py` with an equivalent adapter that maps a case's
artifact + inputs to the same report fields — the manifest is
implementation-agnostic.

Usage:  python run_conformance.py [--verbose]
Exit:   0 when no case FAILs (BLOCKED cases do not fail the run), else 1.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "spif-py"))

from spif.trust import verify_artifact  # noqa: E402


def report_fields(report) -> dict:
    """The report fields the manifest asserts on, from a spif-py report."""
    return {
        "trust_status": report.trust_status,
        "signature_status": report.signature_status,
        "timestamp_status": report.timestamp_status,
        "forged_revocations": report.forged_revocations,
        "references": [
            {"kind": r.kind, "status": r.status} for r in report.references
        ],
    }


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
    return report_fields(verify_artifact(data, **kwargs))


class CaseBlocked(Exception):
    """Raised by an adapter when a case cannot execute in this
    environment (reported BLOCKED, never FAIL — same contract as the
    manifest's non-executable cases)."""


def verify_with_pq_hybrid(case: dict) -> dict:
    """Adapter for the hybrid PQ cases (12-15, v1.4): run the case
    through spif-py's trust layer in the require_pq gate mode (SPEC
    §7.9.2), which is the strict hybrid assessment the cases pin."""
    from spif.pq_hybrid import pq_available

    if not pq_available():
        raise CaseBlocked(
            "requires the ML-DSA-65 backend (pqcrypto; pip install "
            "'spif[pq]'); not available in this environment"
        )
    data = (HERE / case["artifact"]).read_bytes()
    return report_fields(verify_artifact(data, require_pq=True))


def verify_case(case: dict) -> dict:
    """Dispatch on the case's adapter (default: the trust layer)."""
    if case.get("adapter") == "pq_hybrid":
        return verify_with_pq_hybrid(case)
    return verify_with_spif_py(case)


RUST_BIN = HERE.parent / "spif-rust" / "target" / "release" / "trust_conformance"


def rust_conformance_binary() -> Path | None:
    """Locate the Rust trust_conformance binary, building it with cargo
    when needed. None when Rust is unavailable in this environment."""
    if RUST_BIN.exists():
        return RUST_BIN
    cargo = shutil.which("cargo")
    if cargo is None:
        return None
    env = dict(os.environ, CARGO_HTTP_MULTIPLEXING="false")
    build = subprocess.run(
        [cargo, "build", "--release", "--bin", "trust_conformance"],
        cwd=HERE.parent / "spif-rust",
        capture_output=True, text=True, env=env, timeout=1200,
    )
    if build.returncode != 0 or not RUST_BIN.exists():
        return None
    return RUST_BIN


def run_cross_implementation_case(case: dict) -> tuple[str, str | None]:
    """Case 02: cross-implementation parity, in both directions.

    Part A: the Rust binary verifies case 01's Python-produced artifact.
    Part B: the Rust binary signs an artifact; spif-py verifies it.
    Both must produce exactly the case's expected report fields.
    """
    binary = rust_conformance_binary()
    if binary is None:
        return "BLOCKED", (
            "requires the Rust toolchain (cargo/rustc) to build the "
            "spif-rust trust_conformance binary; Rust is not available "
            "in this environment"
        )
    expected = case["expected"]
    mismatches: list[str] = []

    def compare(tag: str, got: dict) -> None:
        mismatches.extend(
            f"{tag} {k}: expected {expected[k]!r}, got {got.get(k)!r}"
            for k in expected
            if got.get(k) != expected[k]
        )

    # Part A — Rust verifies the Python-produced artifact.
    try:
        proc = subprocess.run(
            [str(binary), "verify", str(HERE / case["artifact"])],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            mismatches.append(
                f"rust verify exited {proc.returncode}: {proc.stderr.strip()}"
            )
        else:
            compare("rust-verify", json.loads(proc.stdout))
    except Exception as e:
        mismatches.append(f"rust verify raised: {e!r}")

    # Part B — Python verifies the Rust-produced artifact.
    try:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "rust_signed.spif"
            proc = subprocess.run(
                [str(binary), "sign", str(out)],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                mismatches.append(
                    f"rust sign exited {proc.returncode}: {proc.stderr.strip()}"
                )
            else:
                compare("py-verify", report_fields(verify_artifact(out.read_bytes())))
    except Exception as e:
        mismatches.append(f"py verify of rust artifact raised: {e!r}")

    if mismatches:
        return "FAIL", "; ".join(mismatches)
    return "PASS", None


def evaluate_cases() -> list[dict]:
    manifest = json.loads((HERE / "manifest.json").read_text())
    results = []
    for case in manifest["cases"]:
        entry = {"id": case["id"], "name": case["name"]}
        if case["name"] == "cross_implementation_rust":
            result, reason = run_cross_implementation_case(case)
            entry["result"] = result
            if reason:
                entry["reason"] = reason
            results.append(entry)
            continue
        if not case.get("executable", True):
            entry["result"] = "BLOCKED"
            entry["reason"] = case.get("blocked_reason", "not executable here")
            results.append(entry)
            continue
        try:
            got = verify_case(case)
        except CaseBlocked as e:
            entry["result"] = "BLOCKED"
            entry["reason"] = str(e)
            results.append(entry)
            continue
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
