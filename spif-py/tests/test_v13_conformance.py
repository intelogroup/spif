"""Pytest wrapper for the repo-root conformance kit (vectors/).

Executes the same manifest the standalone runner uses, so CI sees the
kit: every executable case must PASS, and the cross-implementation case
must either PASS against the real Rust binary or be reported BLOCKED
(it needs a Rust toolchain), never silently skipped or faked.
"""

import importlib.util
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parents[2] / "vectors"


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "spif_conformance_runner", VECTORS_DIR / "run_conformance.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_conformance_kit_all_executable_cases_pass():
    results = _load_runner().evaluate_cases()
    assert results, "conformance manifest produced no cases"
    failures = [r for r in results if r["result"] == "FAIL"]
    assert failures == [], f"conformance failures: {failures}"


def test_conformance_kit_rust_case_is_blocked_not_faked():
    results = _load_runner().evaluate_cases()
    rust = [r for r in results if r["name"] == "cross_implementation_rust"]
    assert len(rust) == 1
    # With a Rust toolchain/binary available the case must genuinely PASS;
    # without one it must be reported BLOCKED with the reason — never
    # silently skipped, and never a fake PASS.
    assert rust[0]["result"] in ("PASS", "BLOCKED")
    if rust[0]["result"] == "BLOCKED":
        assert "Rust" in rust[0]["reason"]
