"""
Test 7 — Replay protection + EU AI Act compliance fields.

Pass: (a) re-verifying a doc with a previously-seen (signer, nonce) via
ReplayGuard is rejected, (b) `spif inspect --json` emits producer/model
version/timestamp/human-oversight fields.

Usage: PYTHONPATH=spif python benchmarks/replay_and_compliance.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from spif import SPIFDocument, Node, Provenance, SPIFWriter, ReplayGuard, SPIFReplayError


def main():
    print("=== Test 7: Replay protection + EU AI Act compliance ===\n")

    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="v")],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            timestamp_ms=1700000000000,
            risk_tier="limited",
            human_oversight="human-in-loop",
            nonce="replay-test-nonce-001",
        ),
    )

    guard = ReplayGuard()
    guard.check(doc)  # first use — must pass
    replay_rejected = False
    try:
        guard.check(doc)  # same signer+nonce again — must fail
    except SPIFReplayError:
        replay_rejected = True
    print(f"Replay of same (signer, nonce) rejected: {'PASS' if replay_rejected else 'FAIL'}")

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "doc.spif"
        path.write_bytes(SPIFWriter().encode(doc))
        result = subprocess.run(
            [sys.executable, "-m", "spif.cli", "inspect", str(path), "--json"],
            capture_output=True, text=True,
            cwd=Path(__file__).resolve().parents[1] / "spif",
        )
        try:
            out = json.loads(result.stdout)
        except json.JSONDecodeError:
            out = {}

    required = ["producer", "model_version", "timestamp_ms", "human_oversight"]
    missing = [k for k in required if k not in out]
    json_pass = not missing and out.get("producer") == "claude-sonnet-4-6" and out.get("human_oversight") == "human-in-loop"
    print(f"spif inspect --json has compliance fields: {'PASS' if json_pass else 'FAIL'} "
          f"(missing={missing}, got={out})")

    all_pass = replay_rejected and json_pass
    print(f"\nTEST 7 OVERALL: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
