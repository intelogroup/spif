import base64
import asyncio
import hashlib
import json

import pytest

from spif import Node, Provenance, SPIFDocument
from spif.crypto import generate_key, sign_document
from spif.nostr import (
    EMBEDDED_MODE,
    NOSTR_SPIF_KIND,
    NostrEvent,
    NostrKeyPair,
    NostrRelay,
    SPIFNostrTrustPolicy,
    verify_nostr_signature,
    build_spif_event,
    verify_spif_event,
)


def _signed_spif() -> bytes:
    doc = SPIFDocument(
        payload=[Node(id="answer", type="text", value="hello")],
        provenance=Provenance(
            source_model="test-model",
            timestamp_ms=1_700_000_000_000,
            task_id="task-1",
            nonce="nonce-1",
        ),
    )
    return sign_document(doc, generate_key())


def _signed_event(raw: bytes, *, artifact_url: str | None = None):
    key = NostrKeyPair.generate()
    event = build_spif_event(
        raw, pubkey=key.pubkey, created_at=1_700_000_000,
        artifact_url=artifact_url,
    )
    return key.sign(event)


def test_nip01_event_serialization_and_id_are_bound_to_event_fields():
    event = NostrEvent.unsigned(
        pubkey="ab" * 32,
        created_at=1_700_000_000,
        kind=1,
        tags=[["p", "cd" * 32]],
        content="hello",
    )

    expected_serialized = json.dumps(
        [0, "ab" * 32, 1_700_000_000, 1, [["p", "cd" * 32]], "hello"],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert event.serialized_data == expected_serialized
    assert event.id == hashlib.sha256(expected_serialized).hexdigest()
    assert event.verify_id()

    changed = event.with_signature(sig="11" * 64)
    assert changed.verify_id()
    assert changed.to_dict()["sig"] == "11" * 64


def test_build_embedded_spif_event_roundtrips_and_verifies_both_layers():
    raw = _signed_spif()
    event = _signed_event(raw)

    assert event.kind == NOSTR_SPIF_KIND
    assert event.kind == 78
    assert event.tag_value("d") == event.tag_value("spif_content_id")
    assert event.tag_value("spif_mode") == EMBEDDED_MODE
    result = verify_spif_event(event)

    assert result.valid
    assert result.nostr_id_valid
    assert result.spif_signature_valid
    assert result.spif_sha256 == hashlib.sha256(raw).hexdigest()


def test_embedded_event_binds_exact_signed_bytes_not_only_semantic_content():
    raw = _signed_spif()
    event = _signed_event(raw)
    payload = base64.b64decode(event.content)

    assert payload == raw
    assert event.tag_value("spif_content_id")
    assert event.tag_value("spif_sha256") == hashlib.sha256(raw).hexdigest()


def test_tampered_event_content_fails_before_spif_verification():
    raw = _signed_spif()
    event = _signed_event(raw)
    tampered = event.__class__(
        id=event.id,
        pubkey=event.pubkey,
        created_at=event.created_at,
        kind=event.kind,
        tags=event.tags,
        content=base64.b64encode(raw + b"tampered").decode("ascii"),
        sig=event.sig,
    )

    result = verify_spif_event(tampered)
    assert not result.valid
    assert not result.nostr_id_valid
    assert result.failure_code == "NOSTR_ID_MISMATCH"


def test_pointer_event_requires_supplied_artifact():
    raw = _signed_spif()
    event = _signed_event(raw, artifact_url="https://example.test/artifacts/a.spif")

    with pytest.raises(ValueError, match="artifact bytes"):
        verify_spif_event(event)

    result = verify_spif_event(event, artifact_bytes=raw)
    assert result.valid
    assert result.artifact_url == "https://example.test/artifacts/a.spif"


def test_pointer_event_rejects_url_tag_content_mismatch():
    raw = _signed_spif()
    key = NostrKeyPair.generate()
    source = build_spif_event(raw, pubkey=key.pubkey, created_at=1_700_000_000,
                              artifact_url="https://example.test/a.spif")
    tags = [list(tag) for tag in source.tags]
    next(tag for tag in tags if tag[0] == "url")[1] = "https://example.test/other.spif"
    event = key.sign(NostrEvent.unsigned(
        pubkey=source.pubkey, created_at=source.created_at, kind=source.kind,
        tags=tags, content=source.content,
    ))

    result = verify_spif_event(event, artifact_bytes=raw)
    assert result.failure_code == "SPIF_URL_MISMATCH"


def test_trust_policy_keeps_nostr_and_spif_identity_separate():
    raw = _signed_spif()
    event = _signed_event(raw)

    allowed = SPIFNostrTrustPolicy(allowed_nostr_pubkeys=frozenset({event.pubkey}))
    result = verify_spif_event(event, policy=allowed)
    assert result.valid
    assert result.policy_valid
    assert result.nostr_pubkey == event.pubkey
    assert len(result.spif_signers) == 1

    denied = verify_spif_event(
        event,
        policy=SPIFNostrTrustPolicy(allowed_nostr_pubkeys=frozenset({"00" * 32})),
    )
    assert not denied.valid
    assert denied.failure_code == "NOSTR_PUBLISHER_UNTRUSTED"
    assert not denied.policy_valid

    missing_signer = verify_spif_event(
        event,
        policy=SPIFNostrTrustPolicy(required_spif_signers=frozenset({"human-reviewer"})),
    )
    assert not missing_signer.valid
    assert missing_signer.failure_code == "SPIF_SIGNER_POLICY"


def test_nip01_serialization_uses_required_escaping_and_utf8():
    event = NostrEvent.unsigned(
        pubkey="ab" * 32,
        created_at=0,
        kind=78,
        tags=[],
        content='line\nquote"slash\\cr\rtab\tback\bform\f café',
    )

    assert event.serialized_data == (
        b'[0,"' + b"ab" * 32 +
        b'",0,78,[],"line\\nquote\\"slash\\\\cr\\rtab\\tback\\bform\\f caf\xc3\xa9"]'
    )
    assert event.verify_id()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"pubkey": "AB" * 32}, "pubkey"),
        ({"pubkey": "aa" * 31}, "pubkey"),
        ({"created_at": -1}, "created_at"),
        ({"kind": -1}, "kind"),
        ({"kind": 65536}, "kind"),
    ],
)
def test_nip01_rejects_invalid_event_metadata(kwargs, message):
    params = {
        "pubkey": "aa" * 32,
        "created_at": 1,
        "kind": 78,
        "tags": [],
        "content": "",
    }
    params.update(kwargs)
    with pytest.raises(ValueError, match=message):
        NostrEvent.unsigned(**params)


def test_nip01_rejects_empty_or_non_string_tags_and_malformed_sig():
    with pytest.raises(ValueError, match="tags"):
        NostrEvent.unsigned(pubkey="aa" * 32, created_at=1, kind=78,
                            tags=[[]], content="")
    with pytest.raises(ValueError, match="tags"):
        NostrEvent.unsigned(pubkey="aa" * 32, created_at=1, kind=78,
                            tags=[["d", 42]], content="")
    event = NostrEvent.unsigned(pubkey="aa" * 32, created_at=1, kind=78,
                                tags=[], content="")
    with pytest.raises(ValueError, match="sig"):
        event.with_signature(sig="not-a-schnorr-signature")


def test_nip01_wire_event_requires_signature_field_when_decoding_dict():
    event = NostrEvent.unsigned(pubkey="aa" * 32, created_at=1, kind=78,
                                tags=[], content="")
    wire = event.to_dict()
    del wire["sig"]
    with pytest.raises(ValueError, match="sig"):
        NostrEvent.from_dict(wire)


def test_embedded_invalid_base64_is_rejected():
    raw = _signed_spif()
    key = NostrKeyPair.generate()
    source = build_spif_event(raw, pubkey=key.pubkey, created_at=1_700_000_000)
    unsigned = NostrEvent.unsigned(
        pubkey=source.pubkey, created_at=source.created_at, kind=source.kind,
        tags=source.tags, content="%%%not-base64%%",
    )
    event = key.sign(unsigned)

    result = verify_spif_event(event)
    assert result.failure_code == "SPIF_CONTENT_INVALID"


def test_supplied_artifact_hash_mismatch_is_rejected():
    raw = _signed_spif()
    event = _signed_event(raw)

    result = verify_spif_event(event, artifact_bytes=raw + b"tampered")
    assert not result.valid
    assert result.failure_code == "SPIF_SHA256_MISMATCH"


def test_content_id_mismatch_is_rejected_even_when_raw_hash_matches():
    raw = _signed_spif()
    key = NostrKeyPair.generate()
    source = build_spif_event(raw, pubkey=key.pubkey, created_at=1_700_000_000)
    tags = [list(tag) for tag in source.tags]
    tags[2][1] = "0" * 64  # d tag remains the real content ID; content tag is forged.
    tags[3][1] = "0" * 64
    unsigned = NostrEvent.unsigned(
        pubkey=source.pubkey, created_at=source.created_at, kind=source.kind,
        tags=tags, content=source.content,
    )
    event = key.sign(unsigned)

    result = verify_spif_event(event)
    assert result.failure_code == "SPIF_CONTENT_ID_MISMATCH"


def test_unsigned_spif_is_not_accepted_by_default():
    doc = SPIFDocument(payload=[Node(id="n", type="text", value="unsigned")])
    from spif import SPIFWriter

    raw = SPIFWriter().encode(doc)
    event = _signed_event(raw)

    result = verify_spif_event(event)
    assert not result.valid
    assert result.failure_code == "SPIF_SIGNATURE_INVALID"


def test_kind78_uses_single_letter_grouping_tags_for_relay_filters():
    event = _signed_event(_signed_spif())
    tag_names = {tag[0] for tag in event.tags}

    assert {"t", "d"}.issubset(tag_names)
    assert event.tag_value("d") == event.tag_value("spif_content_id")


def test_bip340_signature_verification_rejects_wrong_event_and_signature():
    key = NostrKeyPair.generate()
    event = NostrEvent.unsigned(
        pubkey=key.pubkey, created_at=1, kind=78, tags=[], content="hello"
    )
    signed = key.sign(event)
    assert signed.sig
    assert verify_nostr_signature(signed)

    changed = NostrEvent.unsigned(
        pubkey=signed.pubkey, created_at=signed.created_at, kind=signed.kind,
        tags=signed.tags, content="changed",
    ).with_signature(sig=signed.sig)
    assert not verify_nostr_signature(changed)

    wrong_key = NostrKeyPair.generate()
    wrong_signature = wrong_key.sign(
        NostrEvent.unsigned(pubkey=wrong_key.pubkey, created_at=1, kind=78,
                            tags=[], content="hello")
    )
    forged = NostrEvent(
        id=signed.id, pubkey=signed.pubkey, created_at=signed.created_at,
        kind=signed.kind, tags=signed.tags, content=signed.content,
        sig=wrong_signature.sig,
    )
    assert not verify_nostr_signature(forged)


@pytest.mark.local_sockets
def test_local_nip01_relay_publish_and_query_roundtrip():
    websockets = pytest.importorskip("websockets")
    stored = []

    async def handler(websocket):
        message = json.loads(await websocket.recv())
        if message[0] == "EVENT":
            stored.append(message[1])
            await websocket.send(json.dumps(["OK", message[1]["id"], True, ""]))
        elif message[0] == "REQ":
            for event in stored:
                await websocket.send(json.dumps(["EVENT", message[1], event]))
            await websocket.send(json.dumps(["EOSE", message[1]]))

    async def scenario():
        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            relay = NostrRelay(f"ws://127.0.0.1:{port}")
            signed = _signed_event(_signed_spif())
            published = await relay.publish(signed)
            received = await relay.query([{"kinds": [78], "#t": ["spif"]}])
            return published, received

    published, received = asyncio.run(scenario())
    assert published.accepted
    assert len(received) == 1
    assert received[0].id == published.event_id


@pytest.mark.local_sockets
def test_relay_query_rejects_invalid_signed_event():
    websockets = pytest.importorskip("websockets")

    async def handler(websocket):
        message = json.loads(await websocket.recv())
        event = NostrEvent.unsigned(
            pubkey="aa" * 32, created_at=1, kind=78, tags=[], content="bad"
        ).with_signature(sig="11" * 64)
        await websocket.send(json.dumps(["EVENT", message[1], event.to_dict()]))

    async def scenario():
        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            with pytest.raises(RuntimeError, match="invalid NIP-01 signature"):
                await NostrRelay(f"ws://127.0.0.1:{port}").query([{"kinds": [78]}])

    asyncio.run(scenario())
