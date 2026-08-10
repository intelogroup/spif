"""
Tests for spif.adapters._common — shared helpers used by every vendor adapter.
"""

from __future__ import annotations

import pytest

from spif.adapters._common import input_hash


class TestInputHashSerializationAssumptions:
    def test_plain_string_content_hashes(self):
        h = input_hash([{"role": "user", "content": "hello"}])
        assert isinstance(h, str) and len(h) == 64

    def test_non_json_serializable_content_raises_typeerror(self):
        """BUG: input_hash() has no default=/error handling, so any adapter
        caller passing non-JSON-serializable message content (raw bytes,
        a PIL Image, a numpy array — all plausible multimodal inputs)
        raises an unhandled TypeError deep inside provenance construction
        instead of a clear SPIF-level error."""
        with pytest.raises(TypeError, match="not JSON serializable"):
            input_hash([{"role": "user", "content": b"raw image bytes"}])

    def test_mixed_key_types_raise_typeerror_under_sort_keys(self):
        """BUG: json.dumps(..., sort_keys=True) requires keys to be
        comparable; a dict with both int and str keys (plausible for
        loosely-typed message metadata) raises TypeError during
        canonicalization instead of being hashed or rejected clearly."""
        with pytest.raises(TypeError):
            input_hash([{"role": "user", 1: "numeric key"}])
