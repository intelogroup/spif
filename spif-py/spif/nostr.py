"""NIP-01 event and SPIF artifact integration.

This module deliberately does not depend on a Nostr client or relay library.
It owns the protocol boundary: NIP-01 event serialization plus binding an
exact SPIF artifact to an event. Applications can pass the resulting event to
any Nostr signer/client implementation.

Nostr signatures and SPIF signatures are separate trust domains. Nostr uses a
secp256k1 Schnorr signature; SPIF uses Ed25519. This adapter therefore never
reuses keys or treats a valid Nostr event as a valid SPIF signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
import asyncio
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

from .reader import SPIFError, SPIFReader

# NIP-78 kind 78 is the regular-event variant intended for multiple app-data
# records. Kind 30078 is addressable/replaceable and requires a d tag; using
# it for an audit stream would allow later events to replace earlier ones.
NOSTR_SPIF_KIND = 78
EMBEDDED_MODE = "embedded"
POINTER_MODE = "pointer"
SPIF_MIME_TYPE = "application/vnd.spif"


def _coincurve():
    try:
        from coincurve import PrivateKey, PublicKeyXOnly
    except ImportError as exc:  # pragma: no cover - exercised without optional extra
        raise ImportError(
            "Nostr Schnorr support requires the optional dependency: "
            "pip install spif[nostr]"
        ) from exc
    return PrivateKey, PublicKeyXOnly


def _validate_hex(value: str, *, name: str, length: int) -> None:
    if len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name} must be {length} lowercase hexadecimal characters")


def _normalise_tags(tags: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
    normalised: list[tuple[str, ...]] = []
    for tag in tags:
        values = tuple(tag)
        if not values or any(not isinstance(value, str) for value in values):
            raise ValueError("Nostr tags must be non-empty arrays of strings")
        normalised.append(values)
    return tuple(normalised)


@dataclass(frozen=True)
class NostrEvent:
    """A NIP-01 event with deterministic ID serialization."""

    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: tuple[tuple[str, ...], ...]
    content: str
    sig: str = ""

    def __post_init__(self) -> None:
        _validate_hex(self.id, name="id", length=64)
        _validate_hex(self.pubkey, name="pubkey", length=64)
        if self.created_at < 0:
            raise ValueError("created_at must be non-negative")
        if not 0 <= self.kind <= 65535:
            raise ValueError("kind must be between 0 and 65535")
        if not isinstance(self.content, str):
            raise ValueError("content must be a string")
        if self.sig and (len(self.sig) != 128 or any(c not in "0123456789abcdef" for c in self.sig)):
            raise ValueError("sig must be 128 lowercase hexadecimal characters")

    @classmethod
    def unsigned(cls, *, pubkey: str, created_at: int, kind: int,
                 tags: Iterable[Iterable[str]], content: str) -> "NostrEvent":
        event = cls(
            id="0" * 64, pubkey=pubkey, created_at=created_at, kind=kind,
            tags=_normalise_tags(tags), content=content,
        )
        return event._with_id(event.compute_id())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "NostrEvent":
        if "sig" not in value:
            raise ValueError("sig is required for a NIP-01 wire event")
        return cls(
            id=value["id"], pubkey=value["pubkey"],
            created_at=value["created_at"], kind=value["kind"],
            tags=_normalise_tags(value["tags"]), content=value["content"],
            sig=value["sig"],
        )

    @property
    def serialized_data(self) -> bytes:
        """The exact NIP-01 serialization used to calculate ``id``."""
        return json.dumps(
            [0, self.pubkey, self.created_at, self.kind,
             [list(t) for t in self.tags], self.content],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")

    def compute_id(self) -> str:
        return hashlib.sha256(self.serialized_data).hexdigest()

    def verify_id(self) -> bool:
        return self.id == self.compute_id()

    def with_signature(self, *, sig: str) -> "NostrEvent":
        return NostrEvent(self.id, self.pubkey, self.created_at, self.kind,
                          self.tags, self.content, sig)

    def _with_id(self, event_id: str) -> "NostrEvent":
        return NostrEvent(event_id, self.pubkey, self.created_at, self.kind,
                          self.tags, self.content, self.sig)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "pubkey": self.pubkey,
                "created_at": self.created_at, "kind": self.kind,
                "tags": [list(tag) for tag in self.tags],
                "content": self.content, "sig": self.sig}

    def tag_value(self, name: str) -> str | None:
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None


@dataclass(frozen=True)
class NostrKeyPair:
    """BIP-340/secp256k1 key pair used by Nostr events."""

    private_key: bytes

    def __post_init__(self) -> None:
        if len(self.private_key) != 32:
            raise ValueError("Nostr private key must be exactly 32 bytes")
        PrivateKey, _ = _coincurve()
        try:
            PrivateKey(self.private_key)
        except ValueError as exc:
            raise ValueError("Nostr private key is not a valid secp256k1 scalar") from exc

    @classmethod
    def generate(cls) -> "NostrKeyPair":
        PrivateKey, _ = _coincurve()
        return cls(PrivateKey().secret)

    @property
    def pubkey(self) -> str:
        PrivateKey, _ = _coincurve()
        return PrivateKey(self.private_key).public_key_xonly.format().hex()

    def sign(self, event: NostrEvent) -> NostrEvent:
        if event.pubkey != self.pubkey:
            raise ValueError("event.pubkey does not match this Nostr private key")
        PrivateKey, _ = _coincurve()
        signature = PrivateKey(self.private_key).sign_schnorr(bytes.fromhex(event.id))
        return event.with_signature(sig=signature.hex())


def verify_nostr_signature(event: NostrEvent) -> bool:
    """Verify the NIP-01 Schnorr signature and event ID."""
    if not event.verify_id() or not event.sig:
        return False
    try:
        _, PublicKeyXOnly = _coincurve()
        return PublicKeyXOnly(bytes.fromhex(event.pubkey)).verify(
            bytes.fromhex(event.sig), bytes.fromhex(event.id)
        )
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class SPIFEventVerification:
    """Result of verifying the Nostr binding and referenced SPIF bytes."""

    valid: bool
    nostr_id_valid: bool
    nostr_signature_valid: bool
    spif_checksum_valid: bool
    spif_signature_valid: bool
    spif_content_id: str
    spif_sha256: str
    artifact_url: str | None = None
    failure_code: str | None = None
    nostr_pubkey: str = ""
    spif_signers: tuple[str, ...] = ()
    policy_valid: bool = True


@dataclass(frozen=True)
class SPIFNostrTrustPolicy:
    """Optional allow-list policy for the two independent trust domains."""

    allowed_nostr_pubkeys: frozenset[str] = frozenset()
    required_spif_signers: frozenset[str] = frozenset()
    require_nostr_signature: bool = True
    require_spif_signature: bool = True


class NostrRelayError(RuntimeError):
    """A relay rejected a publish or closed a subscription."""


def _websocket_connect():
    try:
        from websockets.asyncio.client import connect
    except ImportError:  # websockets < 14 compatibility
        try:
            from websockets import connect
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "Nostr relay support requires the optional dependency: "
                "pip install spif[nostr]"
            ) from exc
    return connect


@dataclass(frozen=True)
class RelayPublishResult:
    event_id: str
    accepted: bool
    message: str


class NostrRelay:
    """Minimal NIP-01 WebSocket client for publishing and querying events."""

    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        if not url.startswith(("ws://", "wss://")):
            raise ValueError("Nostr relay URL must use ws:// or wss://")
        self.url = url
        self.timeout = timeout

    async def publish(self, event: NostrEvent) -> RelayPublishResult:
        if not event.sig or not verify_nostr_signature(event):
            raise ValueError("publish requires a valid NIP-01 Schnorr-signed event")
        connect = _websocket_connect()
        async with connect(self.url, open_timeout=self.timeout) as websocket:
            await websocket.send(json.dumps(["EVENT", event.to_dict()], separators=(",", ":")))
            raw = await asyncio.wait_for(websocket.recv(), timeout=self.timeout)
        message = json.loads(raw)
        if not isinstance(message, list) or len(message) < 4 or message[0] != "OK":
            raise NostrRelayError(f"unexpected relay publish response: {message!r}")
        if message[1] != event.id:
            raise NostrRelayError("relay response event ID does not match published event")
        return RelayPublishResult(event.id, bool(message[2]), str(message[3]))

    async def query(self, filters: Iterable[dict[str, Any]]) -> list[NostrEvent]:
        subscription_id = secrets.token_hex(8)
        request = ["REQ", subscription_id, *list(filters)]
        connect = _websocket_connect()
        events: list[NostrEvent] = []
        async with connect(self.url, open_timeout=self.timeout) as websocket:
            await websocket.send(json.dumps(request, separators=(",", ":")))
            while True:
                raw = await asyncio.wait_for(websocket.recv(), timeout=self.timeout)
                message = json.loads(raw)
                if not isinstance(message, list) or not message:
                    raise NostrRelayError(f"invalid relay message: {message!r}")
                if message[0] == "EOSE" and len(message) >= 2 and message[1] == subscription_id:
                    return events
                if message[0] == "EVENT" and len(message) >= 3 and message[1] == subscription_id:
                    event = NostrEvent.from_dict(message[2])
                    if not verify_nostr_signature(event):
                        raise NostrRelayError("relay returned an event with an invalid NIP-01 signature")
                    events.append(event)
                elif message[0] == "CLOSED":
                    raise NostrRelayError(f"relay closed subscription: {message!r}")
                elif message[0] == "NOTICE":
                    raise NostrRelayError(f"relay notice: {message!r}")


def build_spif_event(artifact_bytes: bytes, *, pubkey: str, created_at: int,
                     kind: int = NOSTR_SPIF_KIND,
                     artifact_url: str | None = None,
                     extra_tags: Iterable[Iterable[str]] = ()) -> NostrEvent:
    """Create an unsigned NIP-01 event binding an exact SPIF artifact."""
    if not artifact_bytes:
        raise ValueError("artifact_bytes must not be empty")
    try:
        doc = SPIFReader().decode(artifact_bytes)
    except SPIFError as exc:
        raise ValueError(f"artifact_bytes is not a valid SPIF document: {exc}") from exc

    mode = POINTER_MODE if artifact_url else EMBEDDED_MODE
    content = artifact_url or base64.b64encode(artifact_bytes).decode("ascii")
    tags: list[tuple[str, ...]] = [
        ("t", "spif"), ("spif_mode", mode),
        ("d", doc.content_id()),
        ("spif_content_id", doc.content_id()),
        ("spif_sha256", hashlib.sha256(artifact_bytes).hexdigest()),
        ("mime", SPIF_MIME_TYPE),
    ]
    if artifact_url:
        tags.append(("url", artifact_url))
    if doc.provenance and doc.provenance.task_id:
        tags.append(("task_id", doc.provenance.task_id))
    tags.extend(tuple(tag) for tag in extra_tags)
    return NostrEvent.unsigned(pubkey=pubkey, created_at=created_at,
                               kind=kind, tags=tags, content=content)


def verify_spif_event(event: NostrEvent, *, artifact_bytes: bytes | None = None,
                      require_spif_signature: bool = True,
                      require_nostr_signature: bool = True,
                      policy: SPIFNostrTrustPolicy | None = None) -> SPIFEventVerification:
    """Verify event identity, exact artifact binding, and SPIF integrity.

    Both the NIP-01 Schnorr signature and SPIF signature are required by
    default. Set either requirement to False only for explicitly unsigned
    ingestion workflows.
    """
    if policy is not None:
        require_nostr_signature = policy.require_nostr_signature
        require_spif_signature = policy.require_spif_signature

    nostr_id_valid = event.verify_id()
    nostr_signature_valid = verify_nostr_signature(event) if nostr_id_valid else False
    if not nostr_id_valid:
        return SPIFEventVerification(False, False, nostr_signature_valid, False, False, "", "",
                                     failure_code="NOSTR_ID_MISMATCH")
    if require_nostr_signature and not nostr_signature_valid:
        return SPIFEventVerification(False, True, False, False, False, "", "",
                                     failure_code="NOSTR_SIGNATURE_INVALID")
    if policy and policy.allowed_nostr_pubkeys and event.pubkey not in policy.allowed_nostr_pubkeys:
        return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", "",
                                     failure_code="NOSTR_PUBLISHER_UNTRUSTED",
                                     nostr_pubkey=event.pubkey, policy_valid=False)

    mode = event.tag_value("spif_mode")
    if mode not in (EMBEDDED_MODE, POINTER_MODE):
        return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", "",
                                     failure_code="SPIF_MODE_INVALID")

    if mode == EMBEDDED_MODE:
        try:
            candidate = (artifact_bytes if artifact_bytes is not None else
                         base64.b64decode(event.content, validate=True))
        except (ValueError, base64.binascii.Error):
            return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", "",
                                         failure_code="SPIF_CONTENT_INVALID")
    else:
        if artifact_bytes is None:
            raise ValueError("pointer events require artifact bytes from the URL")
        if event.tag_value("url") != event.content:
            return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", "",
                                         failure_code="SPIF_URL_MISMATCH",
                                         nostr_pubkey=event.pubkey)
        candidate = artifact_bytes

    expected_sha = event.tag_value("spif_sha256") or ""
    actual_sha = hashlib.sha256(candidate).hexdigest()
    if actual_sha != expected_sha:
        return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", actual_sha,
                                     event.tag_value("url"), "SPIF_SHA256_MISMATCH")

    try:
        doc = SPIFReader().decode(candidate)
    except SPIFError:
        return SPIFEventVerification(False, True, nostr_signature_valid, False, False, "", actual_sha,
                                     event.tag_value("url"), "SPIF_CHECKSUM_INVALID")

    expected_content_id = event.tag_value("spif_content_id") or ""
    actual_content_id = doc.content_id()
    if actual_content_id != expected_content_id:
        return SPIFEventVerification(False, True, nostr_signature_valid, True, False, actual_content_id,
                                     actual_sha, event.tag_value("url"),
                                     "SPIF_CONTENT_ID_MISMATCH")

    signatures = [doc.signature] if doc.signature else []
    signatures.extend(doc.signatures)
    spif_signers = tuple(sig.signer for sig in signatures)
    if policy and policy.required_spif_signers - set(spif_signers):
        return SPIFEventVerification(False, True, nostr_signature_valid, True, False,
                                     actual_content_id, actual_sha, event.tag_value("url"),
                                     "SPIF_SIGNER_POLICY",
                                     event.pubkey, spif_signers, False)

    signature_valid = SPIFReader().verify_signature(candidate) if require_spif_signature else False
    if require_spif_signature and not signature_valid:
        return SPIFEventVerification(False, True, nostr_signature_valid, True, False, actual_content_id,
                                     actual_sha, event.tag_value("url"),
                                     "SPIF_SIGNATURE_INVALID", event.pubkey, spif_signers)
    return SPIFEventVerification(True, True, nostr_signature_valid, True, signature_valid,
                                 actual_content_id, actual_sha, event.tag_value("url"),
                                 nostr_pubkey=event.pubkey, spif_signers=spif_signers)
