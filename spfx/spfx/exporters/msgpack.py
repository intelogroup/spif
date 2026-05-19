"""
SPIF -> lossless MsgPack exporter.

Unlike lossless JSON, this representation preserves binary fields such as
multimodal node values and ed25519 signatures without base64 expansion.

Use this when:
  - You need a compact binary export outside the `.spfx` container
  - Full-fidelity round-trip matters, including raw bytes
  - You want a lightweight integrity check over the exported payload

Do NOT use this when:
  - You need the native SPIF framing, chunking, and CHECKSUM/SIGNATURE chain
  - The consumer only accepts text (use lossless JSON instead)
"""
from __future__ import annotations

import hashlib
from typing import Any

import msgpack

from ..types import (
    Alternative,
    Delta,
    Distribution,
    Node,
    NodeRef,
    Provenance,
    SPIFDocument,
    SemanticLayer,
    Signature,
    TraceStep,
)


def _encode_value(value: Any) -> Any:
    if isinstance(value, Distribution):
        return {"__spif_type__": "Distribution", **value.to_dict()}
    if isinstance(value, NodeRef):
        return {"__spif_type__": "NodeRef", "node_id": value.node_id}
    if isinstance(value, dict):
        return {k: _encode_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_value(v) for v in value]
    return value


def _decode_value(value: Any) -> Any:
    if isinstance(value, dict):
        type_name = value.get("__spif_type__")
        if type_name == "Distribution":
            return Distribution.from_dict({
                "mean": value["mean"],
                "var": value.get("var", 0.0),
                "shape": value.get("shape", "gaussian"),
                "semantics": value.get("semantics", "epistemic"),
                "p5": value.get("p5"),
                "p95": value.get("p95"),
            })
        if type_name == "NodeRef":
            return NodeRef(value["node_id"])
        return {k: _decode_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_value(v) for v in value]
    return value


def _dist(d: Distribution) -> dict[str, Any]:
    out: dict[str, Any] = {
        "mean": d.mean,
        "var": d.var,
        "shape": d.shape,
        "semantics": d.semantics,
    }
    if d.p5 is not None:
        out["p5"] = d.p5
    if d.p95 is not None:
        out["p95"] = d.p95
    return out


def _body(doc: SPIFDocument) -> dict[str, Any]:
    body: dict[str, Any] = {"fmt": "spif", "enc": "msgpack", "v": "0.2"}

    if doc.provenance:
        p = doc.provenance
        body["prov"] = {
            "source_model": p.source_model,
            "model_version": p.model_version,
            "temperature": p.temperature,
            "timestamp_ms": p.timestamp_ms,
            "input_hash": p.input_hash,
            "context_ref": p.context_ref,
        }

    body["payload"] = [
        {
            "id": n.id,
            "type": n.type,
            "value": _encode_value(n.value),
            "confidence": _dist(n.confidence),
            "refs": [r.node_id for r in n.refs],
        }
        for n in doc.payload
    ]

    body["trace"] = [
        {
            "id": s.id,
            "type": s.type,
            "content": _encode_value(s.content),
            "confidence": _dist(s.confidence),
            "deps": s.deps,
            "alternatives": [_encode_value(a) for a in s.alternatives],
        }
        for s in doc.trace
    ]
    body["trace_method"] = doc.trace_method

    if doc.alternatives:
        body["alts"] = [
            {
                "weight": a.weight,
                "normalized": a.normalized,
                "nodes": [
                    {
                        "id": n.id,
                        "type": n.type,
                        "value": _encode_value(n.value),
                        "confidence": _dist(n.confidence),
                        "refs": [r.node_id for r in n.refs],
                    }
                    for n in a.nodes
                ],
            }
            for a in doc.alternatives
        ]

    if doc.semantic:
        body["semantic"] = {
            "embedding": doc.semantic.embedding,
            "embedding_model": doc.semantic.embedding_model,
            "covariance": doc.semantic.covariance,
        }

    if doc.delta:
        body["delta"] = {
            "base_hash": doc.delta.base_hash,
            "changes": _encode_value(doc.delta.changes),
        }

    if doc.signature:
        body["signature"] = {
            "algorithm": doc.signature.algorithm,
            "signer": doc.signature.signer,
            "signature": doc.signature.signature,
            "key_id": doc.signature.key_id,
        }

    if doc.signatures:
        body["signatures"] = [
            {
                "algorithm": s.algorithm,
                "signer": s.signer,
                "signature": s.signature,
                "key_id": s.key_id,
            }
            for s in doc.signatures
        ]

    return body


def to_msgpack(doc: SPIFDocument) -> bytes:
    """
    Serialize a SPIFDocument to a lossless MsgPack envelope.

    The envelope format is:

        {
          "body": <document map>,
          "cksum": <32 raw SHA-256 bytes of the packed body>
        }
    """
    body = _body(doc)
    packed_body = msgpack.packb(body, use_bin_type=True, strict_types=True)
    envelope = {
        "body": body,
        "cksum": hashlib.sha256(packed_body).digest(),
    }
    return msgpack.packb(envelope, use_bin_type=True, strict_types=True)


def from_msgpack(data: bytes | bytearray) -> SPIFDocument:
    """
    Reconstruct a SPIFDocument from bytes produced by ``to_msgpack``.

    Raises
    ------
    ValueError
        If the MsgPack envelope is malformed or the checksum does not match.
    """
    try:
        envelope = msgpack.unpackb(bytes(data), raw=False, strict_map_key=False)
    except Exception as e:
        raise ValueError(f"invalid MsgPack payload: {e}") from e

    if not isinstance(envelope, dict):
        raise ValueError("MsgPack envelope must decode to a dict")

    body = envelope.get("body")
    stored_cksum = envelope.get("cksum")
    if body is None or stored_cksum is None:
        raise ValueError("MsgPack envelope must contain 'body' and 'cksum'")

    packed_body = msgpack.packb(body, use_bin_type=True, strict_types=True)
    expected = hashlib.sha256(packed_body).digest()
    if stored_cksum != expected:
        raise ValueError(
            f"MsgPack checksum mismatch: stored={stored_cksum.hex()}, computed={expected.hex()}"
        )

    if not isinstance(body, dict):
        raise ValueError("MsgPack body must decode to a dict")

    provenance = None
    if "prov" in body:
        p = body["prov"]
        provenance = Provenance(
            source_model=p["source_model"],
            model_version=p.get("model_version", p["source_model"]),
            temperature=p.get("temperature", 1.0),
            timestamp_ms=p.get("timestamp_ms", 0),
            input_hash=p.get("input_hash", ""),
            context_ref=p.get("context_ref", ""),
        )

    payload = [
        Node(
            id=n["id"],
            type=n["type"],
            value=_decode_value(n["value"]),
            confidence=Distribution.from_dict(n["confidence"]),
            refs=[NodeRef(r) for r in n.get("refs", [])],
        )
        for n in body.get("payload", [])
    ]

    trace = [
        TraceStep(
            id=s["id"],
            type=s["type"],
            content=_decode_value(s["content"]),
            confidence=Distribution.from_dict(s["confidence"]),
            deps=s.get("deps", []),
            alternatives=[_decode_value(a) for a in s.get("alternatives", [])],
        )
        for s in body.get("trace", [])
    ]

    alternatives = [
        Alternative(
            weight=a["weight"],
            normalized=a.get("normalized", True),
            nodes=[
                Node(
                    id=n["id"],
                    type=n["type"],
                    value=_decode_value(n["value"]),
                    confidence=Distribution.from_dict(n["confidence"]),
                    refs=[NodeRef(r) for r in n.get("refs", [])],
                )
                for n in a.get("nodes", [])
            ],
        )
        for a in body.get("alts", [])
    ]

    semantic = None
    if "semantic" in body:
        s = body["semantic"]
        semantic = SemanticLayer(
            embedding=s.get("embedding", []),
            embedding_model=s.get("embedding_model", ""),
            covariance=s.get("covariance", []),
        )

    delta = None
    if "delta" in body:
        d = body["delta"]
        delta = Delta(
            base_hash=d["base_hash"],
            changes=_decode_value(d.get("changes", [])),
        )

    signature = None
    if "signature" in body:
        s = body["signature"]
        signature = Signature(
            algorithm=s.get("algorithm", "ed25519"),
            signer=s.get("signer", ""),
            signature=s.get("signature", b""),
            key_id=s.get("key_id", ""),
        )

    signatures = [
        Signature(
            algorithm=s.get("algorithm", "ed25519"),
            signer=s.get("signer", ""),
            signature=s.get("signature", b""),
            key_id=s.get("key_id", ""),
        )
        for s in body.get("signatures", [])
    ]

    return SPIFDocument(
        payload=payload,
        provenance=provenance,
        semantic=semantic,
        trace=trace,
        trace_method=body.get("trace_method", "post-hoc"),
        alternatives=alternatives,
        delta=delta,
        signature=signature,
        signatures=signatures,
    )
