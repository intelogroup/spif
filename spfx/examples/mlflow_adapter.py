"""
MLflow + SPIF — tamper-evident AI output logging for model deployment platforms.

Shows two patterns:

1. **Callback wrapper**: pass any callable LLM function through SPIFMLflowLogger
   and every call is automatically logged to the active MLflow run as a SPIF artifact.

2. **Manual**: call your model normally, wrap the result in SPIF, then log manually.

Run:
    pip install spfx mlflow
    python examples/mlflow_adapter.py

Or dry-run (no MLflow required):
    python examples/mlflow_adapter.py --dry-run

EU AI Act note: SPIF artifacts logged here cover Art. 12 tamper-evident output logging.
Pair with an audit dashboard for full compliance coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

try:
    import mlflow
    HAVE_MLFLOW = True
except ImportError:
    HAVE_MLFLOW = False

from spfx import SPIFDocument, SPIFWriter, SPIFReader
from spfx.types import Node, Distribution, Provenance


# ---------------------------------------------------------------------------
# Core: convert an LLM response dict to SPIFDocument
# ---------------------------------------------------------------------------

def _response_to_spif(
    content: str,
    model: str,
    temperature: float = 0.0,
    prompt: str = "",
    confidence_mean: float = 0.85,
) -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id="response",
                type="text",
                value=content,
                confidence=Distribution(
                    mean=confidence_mean,
                    var=0.04,
                    shape="gaussian",
                    semantics="output_stability",
                ),
            )
        ],
        provenance=Provenance(
            source_model=model,
            model_version=model,
            temperature=temperature,
            input_hash=hashlib.sha256(prompt.encode()).hexdigest(),
            timestamp_ms=int(time.time() * 1000),
        ),
    )


# ---------------------------------------------------------------------------
# SPIFMLflowLogger — wraps any LLM callable
# ---------------------------------------------------------------------------

class SPIFMLflowLogger:
    """
    Wraps any LLM callable. On each call:
      1. Calls the underlying model.
      2. Wraps the response in a SPIFDocument.
      3. Logs the SPIF bytes as an MLflow artifact.
      4. Logs the checksum and model name as MLflow tags.

    Usage:
        from mlflow_adapter import SPIFMLflowLogger

        def my_model(prompt: str) -> str:
            return openai_client.chat.completions.create(...).choices[0].message.content

        logged_model = SPIFMLflowLogger(my_model, model_name="gpt-4o")
        response = logged_model("Summarize the EU AI Act.")
    """

    def __init__(
        self,
        fn: Callable[[str], str],
        model_name: str = "unknown",
        temperature: float = 0.0,
        artifact_prefix: str = "spfx",
    ) -> None:
        self._fn = fn
        self._model = model_name
        self._temperature = temperature
        self._prefix = artifact_prefix
        self._call_idx = 0

    def __call__(self, prompt: str) -> str:
        content = self._fn(prompt)
        doc = _response_to_spif(content, self._model, self._temperature, prompt)
        self._log(doc, prompt, self._call_idx)
        self._call_idx += 1
        return content

    def _log(self, doc: SPIFDocument, prompt: str, idx: int) -> None:
        encoded = SPIFWriter().encode(doc)
        checksum = hashlib.sha256(encoded).hexdigest()[:16]
        artifact_name = f"{self._prefix}_{idx:04d}_{checksum}.spfx"

        if HAVE_MLFLOW and mlflow.active_run():
            with tempfile.NamedTemporaryFile(suffix=".spfx", delete=False) as f:
                f.write(encoded)
                tmp_path = f.name
            try:
                mlflow.log_artifact(tmp_path, artifact_path="spif_outputs")
                mlflow.set_tag(f"spif_{idx:04d}_model", self._model)
                mlflow.set_tag(f"spif_{idx:04d}_checksum", checksum)
                mlflow.log_param(f"spif_{idx:04d}_prompt_len", len(prompt))
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        else:
            # Dry-run: just print what would be logged
            print(f"  [MLflow] Would log artifact: {artifact_name} ({len(encoded)} bytes)")
            print(f"  [MLflow] Would set tag: spif_{idx:04d}_model = {self._model}")
            print(f"  [MLflow] Would set tag: spif_{idx:04d}_checksum = {checksum}")


# ---------------------------------------------------------------------------
# Demo: manual pattern
# ---------------------------------------------------------------------------

def demo_manual(dry_run: bool = False) -> None:
    print("\n=== Pattern 2: Manual logging ===")

    # Simulate an LLM response
    prompt = "What is the EU AI Act?"
    content = "The EU AI Act is a regulation that establishes rules for AI systems in the EU."
    model = "claude-sonnet-4-6"

    doc = _response_to_spif(content, model, temperature=0.7, prompt=prompt)
    encoded = SPIFWriter().encode(doc)
    checksum = hashlib.sha256(encoded).hexdigest()

    print(f"  Encoded SPIF: {len(encoded)} bytes")
    print(f"  Checksum    : {checksum[:32]}...")

    # Verify roundtrip
    decoded = SPIFReader().decode(encoded)
    assert decoded.payload[0].value == content
    print("  Roundtrip   : OK")

    if HAVE_MLFLOW and not dry_run:
        with mlflow.start_run(run_name="manual_spif_demo"):
            with tempfile.NamedTemporaryFile(suffix=".spfx", delete=False) as f:
                f.write(encoded)
                tmp = f.name
            try:
                mlflow.log_artifact(tmp, artifact_path="spif_outputs")
                mlflow.log_param("model", model)
                mlflow.log_param("prompt_sha256", hashlib.sha256(prompt.encode()).hexdigest()[:16])
                mlflow.set_tag("spif_checksum", checksum[:16])
                print(f"  MLflow run  : {mlflow.active_run().info.run_id}")
            finally:
                Path(tmp).unlink(missing_ok=True)
    else:
        print("  [dry-run] MLflow logging skipped")


# ---------------------------------------------------------------------------
# Demo: wrapper pattern
# ---------------------------------------------------------------------------

def demo_wrapper(dry_run: bool = False) -> None:
    print("\n=== Pattern 1: SPIFMLflowLogger wrapper ===")

    # Fake LLM callable (no API key needed)
    call_count = [0]
    def mock_llm(prompt: str) -> str:
        call_count[0] += 1
        return f"Mock answer {call_count[0]} for: {prompt[:40]}"

    logged_llm = SPIFMLflowLogger(mock_llm, model_name="mock-model", temperature=0.5)

    prompts = [
        "Explain transformer attention.",
        "What is backpropagation?",
        "Describe a convolutional neural network.",
    ]

    if HAVE_MLFLOW and not dry_run:
        with mlflow.start_run(run_name="spif_wrapper_demo"):
            for p in prompts:
                response = logged_llm(p)
                print(f"  Response: {response[:60]}")
            print(f"  MLflow run: {mlflow.active_run().info.run_id}")
    else:
        for p in prompts:
            response = logged_llm(p)
            print(f"  Response: {response[:60]}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="Skip actual MLflow calls (works without mlflow installed)")
    args = ap.parse_args()

    if not HAVE_MLFLOW and not args.dry_run:
        print("mlflow not installed — running in dry-run mode. pip install mlflow to log for real.")
        args.dry_run = True

    demo_wrapper(dry_run=args.dry_run)
    demo_manual(dry_run=args.dry_run)
    print("\nDone.")
