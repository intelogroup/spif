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

    def test_non_json_serializable_content_raises_clear_error(self):
        """Non-JSON-serializable message content (raw bytes, a PIL Image, a
        numpy array — all plausible multimodal inputs) now raises a clear
        ValueError instead of an unhandled TypeError deep inside provenance
        construction."""
        with pytest.raises(ValueError, match="JSON-serializable"):
            input_hash([{"role": "user", "content": b"raw image bytes"}])

    def test_mixed_key_types_raise_clear_error(self):
        """A dict with both int and str keys (plausible for loosely-typed
        message metadata) is rejected with a clear error during
        canonicalization instead of leaking a raw sort_keys TypeError."""
        with pytest.raises(ValueError, match="JSON-serializable"):
            input_hash([{"role": "user", 1: "numeric key"}])
