"""
Dedicated unit tests for SPIF security hardening and production gotchas.
"""

import base64
import time
import warnings
from unittest.mock import MagicMock, patch
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    SPIFDocument, Node, SPIFWriter, SPIFReader,
    Signature, Provenance, SPIFSignatureError,
)
from spif.crypto import derive_key_from_mnemonic
from spif.adapters.openai_adapter import OpenAISPIFAdapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key():
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, pub_b64


def _sign_doc(doc: SPIFDocument, key, signer_id: str) -> bytes:
    import struct
    from spif.format import MAGIC
    writer = SPIFWriter()

    # Pass 1: dummy sig to lock structural layout
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    # Locate signature chunk
    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:  # CHUNK_SIGNATURE
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    assert sig_offset is not None

    body_to_sign = dummy[:sig_offset]

    # Pass 2: real signature
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


# ---------------------------------------------------------------------------
# 1. Empty Passphrase Warning Tests
# ---------------------------------------------------------------------------

def test_empty_passphrase_warns():
    """Verify that derive_key_from_mnemonic warns when passphrase is empty or None."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        derive_key_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", passphrase="")
        assert len(w) >= 1
        assert any("empty passphrase" in str(warn.message) for warn in w)


def test_non_empty_passphrase_does_not_warn():
    """Verify that derive_key_from_mnemonic does NOT warn with a valid passphrase."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        derive_key_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", passphrase="secure_salt")
        # Ensure no warnings from our crypto module are emitted
        crypto_warns = [warn for warn in w if "empty passphrase" in str(warn.message)]
        assert len(crypto_warns) == 0


# ---------------------------------------------------------------------------
# 2. Time-Bounded Signatures Tests
# ---------------------------------------------------------------------------

def test_signature_age_limits():
    """Test that SPIFReader strictly enforces max_signature_age_seconds limits."""
    key, pub_b64 = _make_key()
    current_time_ms = int(time.time() * 1000)

    # Create a fresh doc
    doc_fresh = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Fresh claim.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=current_time_ms)
    )
    data_fresh = _sign_doc(doc_fresh, key, pub_b64)

    # Create an expired doc (e.g., timestamp 15 seconds ago)
    doc_old = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Old claim.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=current_time_ms - 15000)
    )
    data_old = _sign_doc(doc_old, key, pub_b64)

    # 1. Reader with age limit should accept fresh document
    reader_limit = SPIFReader(require_signature=True, max_signature_age_seconds=10)
    decoded_fresh = reader_limit.decode(data_fresh)
    assert decoded_fresh.payload[0].value == "Fresh claim."

    # 2. Reader with age limit should reject expired document
    with pytest.raises(SPIFSignatureError, match="Signature expired"):
        reader_limit.decode(data_old)

    # 3. Permissive reader (no limit, or max_signature_age_seconds is None) should accept both
    reader_permissive = SPIFReader(require_signature=True)
    assert reader_permissive.decode(data_fresh).payload[0].value == "Fresh claim."
    assert reader_permissive.decode(data_old).payload[0].value == "Old claim."


def test_signature_age_limit_in_verify_signature():
    """Test that verify_signature method respects max_signature_age_seconds parameter."""
    key, pub_b64 = _make_key()
    current_time_ms = int(time.time() * 1000)

    # Create expired doc (timestamp 15 seconds ago)
    doc_old = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Expired claim.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=current_time_ms - 15000)
    )
    data_old = _sign_doc(doc_old, key, pub_b64)

    # Instance-level limit
    reader_limit = SPIFReader(max_signature_age_seconds=10)
    with pytest.raises(SPIFSignatureError, match="Signature expired"):
        reader_limit.verify_signature(data_old)

    # Param-level limit override (should reject expired even if reader itself has no limit)
    reader_permissive = SPIFReader()
    with pytest.raises(SPIFSignatureError, match="Signature expired"):
        reader_permissive.verify_signature(data_old, max_signature_age_seconds=10)

    # Reader with limit, but caller passes large override limit that permits it
    assert reader_limit.verify_signature(data_old, max_signature_age_seconds=30) is True


def test_signature_age_limit_missing_provenance():
    """Rejects signature age check if provenance is missing but age limit is active."""
    key, pub_b64 = _make_key()
    doc_no_prov = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="No provenance.")],
        provenance=None
    )
    data = _sign_doc(doc_no_prov, key, pub_b64)

    reader_limit = SPIFReader(max_signature_age_seconds=10)
    with pytest.raises(SPIFSignatureError, match="Provenance chunk is missing"):
        reader_limit.decode(data)

    with pytest.raises(SPIFSignatureError, match="Provenance chunk is missing"):
        reader_limit.verify_signature(data)


# ---------------------------------------------------------------------------
# 3. Dynamic Model Resolution Tests
# ---------------------------------------------------------------------------

def test_openai_adapter_resolves_model_snapshot():
    """Verify that OpenAISPIFAdapter captures response.model snapshot inside .complete()."""
    # Create fake response representing dynamic snapshot returned by OpenAI (e.g. gpt-4o-2024-05-13)
    from types import SimpleNamespace
    mock_response = SimpleNamespace(
        model="gpt-4o-2024-05-13",
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content="Resolved snapshot response"),
                logprobs=None,
            )
        ],
        usage=SimpleNamespace(
            completion_tokens=10,
            completion_tokens_details=SimpleNamespace(reasoning_tokens=0),
        ),
    )

    # Initialize adapter with mock client and set create() return value
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    adapter = OpenAISPIFAdapter(mock_client, model="gpt-4o")
    doc = adapter.complete("Say hello")

    # Document provenance should record the ACTUAL server-resolved model
    assert doc.provenance is not None
    assert doc.provenance.source_model == "gpt-4o-2024-05-13"
    assert doc.provenance.model_version == "gpt-4o-2024-05-13"


def test_openai_adapter_fallback_on_missing_model_response():
    """Verify fallback to requested model if response.model is empty or None."""
    from types import SimpleNamespace
    mock_response = SimpleNamespace(
        model="",  # empty/missing
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content="Fallback response"),
                logprobs=None,
            )
        ],
        usage=None,
    )

    # Initialize adapter with mock client and set create() return value
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    adapter = OpenAISPIFAdapter(mock_client, model="gpt-4o")
    doc = adapter.complete("Say hello")

    # Should gracefully fall back to the requested model name 'gpt-4o'
    assert doc.provenance is not None
    assert doc.provenance.source_model == "gpt-4o"
    assert doc.provenance.model_version == "gpt-4o"
