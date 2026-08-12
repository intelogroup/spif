import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks"))

from provenance_comparison_bench import _is_expected_c2pa_cert_rejection


c2pa = pytest.importorskip("c2pa")


def test_c2pa_certificate_rejection_is_classified() -> None:
    error = c2pa.C2paError("Signature: the certificate was self-signed")

    assert _is_expected_c2pa_cert_rejection(error)


def test_unexpected_c2pa_failure_is_not_classified_as_certificate_rejection() -> None:
    error = c2pa.C2paError("manifest setup failed")

    assert not _is_expected_c2pa_cert_rejection(error)


def test_non_c2pa_failure_is_not_classified_as_certificate_rejection() -> None:
    assert not _is_expected_c2pa_cert_rejection(RuntimeError("setup failed"))
