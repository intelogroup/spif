"""
SIF → W3C PROV-JSON exporter.

Maps a SPIFDocument to a PROV-JSON dict per:
https://www.w3.org/Submission/2013/SUBM-prov-json-20130424/

Core PROV model:
  Entity    → a thing (SIF Node, SIF document itself)
  Activity  → an action (inference run, trace step)
  Agent     → responsible party (model, signer)
  Relations → wasGeneratedBy, wasAttributedTo, used, wasAssociatedWith

This is a LOSSY export. The following SIF features have no PROV-JSON equivalent:
  - Distribution.shape → stored as prov:attribute (plain value, no type)
  - Distribution.semantics → stored as prov:attribute (no semantic typing)
  - TraceStep.deps DAG → converted to prov:wasDerivedFrom relations (loses weights/types)
  - CHUNK_SIGNATURE (ed25519) → signer becomes prov:Agent, but crypto bytes dropped
  - CHUNK_CHECKSUM → dropped (PROV has no integrity primitive)
  - CHUNK_ALTS (alternatives) → dropped (PROV has no alternative hypothesis primitive)
  - CHUNK_SEMANTIC (embeddings) → dropped (no vector primitive in PROV)
  - CHUNK_DELTA → partial (base_hash stored as prov:attribute)

What is preserved with full fidelity:
  - Provenance chain (who, what, when)
  - Trace step ordering (as wasDerivedFrom)
  - Node values and confidence means
  - Signer identity (as prov:Agent)
"""
from __future__ import annotations
import time as _time

from ..types import SPIFDocument


def to_prov(doc: SPIFDocument, doc_id: str = "sif:document") -> dict:
    """
    Convert a SPIFDocument to a W3C PROV-JSON dict.

    Returns a dict suitable for json.dumps() as PROV-JSON.
    Lossy: see module docstring.
    """
    prov: dict[str, dict] = {
        "prefix": {
            "sif": "https://github.com/brainex/sif#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "prov": "http://www.w3.org/ns/prov#",
        },
        "entity": {},
        "activity": {},
        "agent": {},
        "wasGeneratedBy": {},
        "wasAttributedTo": {},
        "used": {},
        "wasDerivedFrom": {},
        "wasAssociatedWith": {},
    }

    source_model = doc.provenance.source_model if doc.provenance else "unknown"
    timestamp_ms = doc.provenance.timestamp_ms if doc.provenance else int(_time.time() * 1000)
    timestamp_iso = _ms_to_iso(timestamp_ms)

    # -----------------------------------------------------------------------
    # Agent: the model that produced the document
    # -----------------------------------------------------------------------
    agent_id = f"sif:agent/{source_model}"
    prov["agent"][agent_id] = {
        "prov:type": {"$": "prov:SoftwareAgent", "type": "xsd:QName"},
        "sif:model": source_model,
    }

    # Agent: the signer (if present)
    signer_agent_id = None
    if doc.signature:
        signer_agent_id = f"sif:signer/{doc.signature.signer[:16]}"
        prov["agent"][signer_agent_id] = {
            "prov:type": {"$": "prov:Person", "type": "xsd:QName"},
            "sif:signer_id": doc.signature.signer,
            "sif:algorithm": doc.signature.algorithm,
            # Crypto bytes dropped — PROV has no binary integrity primitive
            "_sif_loss": "ed25519 signature bytes dropped (no PROV binary primitive)",
        }

    # -----------------------------------------------------------------------
    # Activity: the inference run
    # -----------------------------------------------------------------------
    activity_id = f"sif:inference/{source_model}/{timestamp_ms}"
    activity: dict = {
        "prov:startTime": timestamp_iso,
        "prov:endTime": timestamp_iso,
        "sif:trace_method": doc.trace_method,
    }
    if doc.provenance:
        if doc.provenance.input_hash:
            activity["sif:input_hash"] = doc.provenance.input_hash
        if doc.provenance.temperature is not None:
            activity["sif:temperature"] = doc.provenance.temperature
        if doc.provenance.model_version:
            activity["sif:model_version"] = doc.provenance.model_version
    prov["activity"][activity_id] = activity

    prov["wasAssociatedWith"]["sif:assoc/inference/model"] = {
        "prov:activity": activity_id,
        "prov:agent": agent_id,
    }

    # -----------------------------------------------------------------------
    # Entity: each payload node
    # -----------------------------------------------------------------------
    for node in doc.payload:
        entity_id = f"sif:node/{node.id}"
        entity: dict = {
            "prov:type": {"$": f"sif:{node.type}", "type": "xsd:QName"},
            "sif:value": str(node.value),
        }
        if node.confidence:
            # Confidence mean preserved; shape/semantics as plain attributes (type lost)
            entity["sif:confidence_mean"] = node.confidence.mean
            entity["sif:confidence_var"] = node.confidence.var
            entity["sif:confidence_shape"] = node.confidence.shape
            # semantics as plain string — no type enforcement in PROV
            entity["sif:confidence_semantics"] = node.confidence.semantics
            entity["_sif_loss_confidence"] = (
                "Distribution is a typed SIF value; PROV stores as plain attributes. "
                "A generic PROV parser cannot distinguish this from any other attribute dict."
            )
        for ref in node.refs:
            entity.setdefault("sif:refs", []).append(ref.node_id)

        prov["entity"][entity_id] = entity
        prov["wasGeneratedBy"][f"sif:gen/{node.id}"] = {
            "prov:entity": entity_id,
            "prov:activity": activity_id,
        }
        prov["wasAttributedTo"][f"sif:attr/{node.id}"] = {
            "prov:entity": entity_id,
            "prov:agent": agent_id,
        }

    # -----------------------------------------------------------------------
    # Entity: each trace step (as Activity + Entity pair)
    # -----------------------------------------------------------------------
    for step in doc.trace:
        step_entity_id = f"sif:step/{step.id}"
        step_activity_id = f"sif:step_activity/{step.id}"

        prov["entity"][step_entity_id] = {
            "prov:type": {"$": f"sif:{step.type}", "type": "xsd:QName"},
            "sif:content": str(step.content)[:512],
            "sif:confidence_mean": step.confidence.mean if step.confidence else None,
            "sif:confidence_semantics": step.confidence.semantics if step.confidence else None,
        }
        prov["activity"][step_activity_id] = {
            "prov:startTime": timestamp_iso,
            "sif:step_type": step.type,
        }
        prov["wasGeneratedBy"][f"sif:gen/step/{step.id}"] = {
            "prov:entity": step_entity_id,
            "prov:activity": step_activity_id,
        }

        # DAG edges: wasDerivedFrom (partial — loses edge type/weight)
        for dep in step.deps:
            prov["wasDerivedFrom"][f"sif:dep/{step.id}/{dep}"] = {
                "prov:generatedEntity": step_entity_id,
                "prov:usedEntity": f"sif:step/{dep}",
                # Edge type and weight dropped — PROV has no weighted edge primitive
            }

    # -----------------------------------------------------------------------
    # Signature: signer agent wasAssociatedWith inference activity
    # -----------------------------------------------------------------------
    if signer_agent_id:
        prov["wasAssociatedWith"]["sif:assoc/inference/signer"] = {
            "prov:activity": activity_id,
            "prov:agent": signer_agent_id,
        }

    # -----------------------------------------------------------------------
    # Delta: base document reference (partial)
    # -----------------------------------------------------------------------
    if doc.delta:
        prov["entity"]["sif:base_document"] = {
            "sif:base_hash": doc.delta.base_hash,
        }
        prov["wasDerivedFrom"]["sif:delta_derivation"] = {
            "prov:generatedEntity": doc_id,
            "prov:usedEntity": "sif:base_document",
        }

    # -----------------------------------------------------------------------
    # Export loss manifest
    # -----------------------------------------------------------------------
    prov["_sif_export_losses"] = [
        "Distribution type → plain prov:attributes (no type enforcement)",
        "Distribution.semantics → plain string attribute",
        "CHUNK_CHECKSUM (SHA-256) → dropped (PROV has no integrity primitive)",
        "ed25519 signature bytes → dropped (signer identity preserved as Agent)",
        "TraceStep.deps weights/types → wasDerivedFrom (structure preserved, semantics lost)",
        "CHUNK_ALTS (alternatives) → dropped (no PROV alternative-hypothesis primitive)",
        "CHUNK_SEMANTIC (embeddings) → dropped (no vector primitive in PROV)",
    ]

    # Remove empty sections
    return {k: v for k, v in prov.items() if v}


def _ms_to_iso(ms: int) -> str:
    """Convert millisecond timestamp to ISO 8601 string."""
    import datetime
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
