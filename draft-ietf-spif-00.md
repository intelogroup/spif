---
title: Semantic Provenance Inference Format (SPIF)
abbrev: SPIF
docname: draft-ietf-spif-00
category: std
submissiontype: IETF
number: 
date: 2026-07-15
author:
  - name: SPIF Working Group
    org: Intelogroup
    email: hello@brainex.ai
---

# Abstract

This document defines the Semantic Provenance Inference Format (SPIF) version 1.1, a binary container format designed for structured, cryptographically signed, and tamper-evident AI model outputs. SPIF aggregates model outputs (payload nodes) with their generation provenance, reasoning traces, alternative hypotheses, semantic embeddings, and multiple cryptographic signatures in a single binary stream.

# 1. Introduction

Autonomous AI agents and large language models (LLMs) are increasingly integrated into critical enterprise data pipelines. The lack of standard mechanisms to verify the origin, execution constraints, and integrity of these model outputs introduces serious security risks, including model-in-the-middle tampering, rogue unapproved model usage, and prompt injection exploits.

SPIF addresses this gap by defining a compact, streaming-capable binary container based on Concise Binary Object Representation (CBOR) [RFC8949]. Every SPIF document co-locates the model's assertions with detailed provenance, reasoning steps, and cryptographic signatures.

# 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

*   **FPR**: Failing Provenance Record. A standard SPIF document indicating a signature or policy validation block.
*   **CRL**: Certificate Revocation List. A list of revoked public keys / signer IDs.
*   **DAG**: Directed Acyclic Graph.

# 3. File Layout

A SPIF document is a byte stream structured as follows:

```
+-------------------+-------------+------------+-------------+
| MAGIC BYTES (9B)  | VERSION(1B) | FLAGS (1B) | CHUNKS...   |
+-------------------+-------------+------------+-------------+
```

## 3.1 Magic Bytes
The document MUST begin with the following 9 magic bytes:
`\x89 S P I F \r \n \x1a \n` (hex: `89 53 50 49 46 0D 0A 1A 0A`).

## 3.2 Version Byte
Indicates the wire format version. For SPIF v1.1, this byte MUST be `0x02`.

## 3.3 Flags Byte
A bitmask representing the optional chunk types present in the document:

*   Bit 0 (`0x01`): PROVENANCE chunk present
*   Bit 1 (`0x02`): SEMANTIC chunk present
*   Bit 2 (`0x04`): TRACE chunk present
*   Bit 3 (`0x08`): ALTS chunk present
*   Bit 4 (`0x10`): DELTA chunk present
*   Bit 5 (`0x20`): SIGNATURE chunk present
*   Bit 6 (`0x40`): MULTISIG chunk present
*   Bit 7 (`0x80`): Streaming document (SSPIF)

# 4. Chunk Framing

All SPIF chunks share a 5-byte header:

```
+--------------------+-----------------------------+
| chunk_type (1 byte)| payload_length (4 bytes, BE)|
+--------------------+-----------------------------+
| payload (payload_length bytes)                   |
+--------------------------------------------------+
```

## 4.1 Chunk Type Registry

| Chunk Type | Name | Required | Compressible | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | HEADER | Yes | No | Format version, creation timestamp |
| `0x01` | PROVENANCE | No | No | Model ID, version, timestamp, attempt, task_id, risk_tier, model_card |
| `0x02` | SEMANTIC | No | Yes | Dense embedding vector + covariance |
| `0x03` | TRACE | No | Yes | Reasoning trace DAG |
| `0x04` | PAYLOAD | Yes | Yes | Main model output nodes |
| `0x05` | ALTS | No | Yes | Alternative payload hypotheses with weights |
| `0x06` | DELTA | No | Yes | Diff from a base document |
| `0x07` | SIGNATURE | No | No | Single ed25519 signature |
| `0x08` | MULTISIG | No | No | Multiple ed25519 signatures |
| `0x09` | TASK | No | No | Task envelope metadata (attempt, counts, status) |
| `0xFF` | CHECKSUM | Yes | No | SHA-256 over all preceding bytes |

# 5. CBOR Custom Tags

SPIF reserves tag numbers 1000–1099 for its semantic data types:

## 5.1 Tag 1000: Distribution
Represents a probability distribution mapping uncertainty. 
Schema: `{ mean: float64, var: float64, shape: text, semantics: text }`

Semantics vocabulary:
*   `"epistemic"`: Subjective confidence.
*   `"factual_accuracy"`: P(claim is factually correct).
*   `"output_stability"`: P(model produces equivalent output on retry).
*   `"token_probability"`: Mean token softmax probability.

## 5.2 Tag 1001: NodeRef
A typed text string referencing another payload Node ID.

## 5.3 Tag 1002: Embedding
An array of float32 values representing a dense vector.

# 6. Key Revocation and Policy Enforcement Protocol

Enterprise boundaries enforce validation using a sidecar proxy.

## 6.1 Policy Schema
A policy JSON contains:
*   `enforcement`: `"deny_and_alert" | "allow_and_log"`
*   `allowed_models`: List of authorized model identifier strings.
*   `trusted_signers`: List of public keys allowed to sign.
*   `minimum_confidence_mean`: Minimum average confidence allowed.
*   `crl_check`: Configuration for CRL URL endpoints.

## 6.2 Key Revocation Checking
The sidecar checks the signer key of incoming `X-Spif` headers against a Certificate Revocation List (CRL) fetched from `crl_check.endpoint`. If the signer is revoked, it MUST block the response.

## 6.3 Failing Provenance Record (FPR)
Upon blocking, the sidecar generates and returns an FPR SPIF document with a payload node of type `verification_failure` documenting the failure code:
*   `SPIF_ERROR_KEY_REVOKED`
*   `SPIF_ERROR_SIGNATURE_INVALID`
*   `SPIF_ERROR_UNSIGNED`
*   `SPIF_ERROR_POLICY_VIOLATION`

# 7. Security Considerations

## 7.1 Cycle Detection in DAGs
SPIF payload and trace components form a Directed Acyclic Graph (DAG). Conformant decoders MUST run cycle detection ($O(N)$ depth-first search or topological sort) to prevent infinite loops and stack exhaustion exploits from malicious recursive nodes.

## 7.2 Memory Exhaustion Mitigation
To defend against buffer pre-allocation memory exploits (e.g., CVE-2026-34665 style), decoders MUST check payload lengths against stream offsets before allocating buffers.

# 8. IANA Considerations

## 8.1 MIME Type Registration
This document registers the MIME type `application/x-spif` and file extension `.spfx` for SPIF payloads.
