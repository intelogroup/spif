//! Senior audit integration tests for sif-rust.
//!
//! Each test is labelled with the finding number from the audit plan.
//! Tests marked `#[should_panic]` document panic-paths that were present
//! before the fix; after the fix those paths should no longer panic.

use sha2::{Digest, Sha256};
use spif_rust::{types::*, SPIFReader, SPIFRenderer, SPIFWriter};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn minimal_node() -> Node {
    Node {
        id: "n1".to_string(),
        node_type: "fact".to_string(),
        value: Value::Text("Paris is the capital of France.".to_string()),
        confidence: Distribution::certain("epistemic"),
        refs: vec![],
    }
}

fn minimal_doc() -> SPIFDocument {
    SPIFDocument {
        payload: vec![minimal_node()],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    }
}

/// Builds raw SIF bytes from explicit chunks, computing a correct checksum.
/// Useful for crafting targeted malformed inputs.
fn build_raw_sif(chunks: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(MAGIC);
    body.push(FORMAT_VERSION);
    body.push(0x00); // flags

    for (chunk_type, data) in chunks {
        body.push(*chunk_type);
        let len = data.len() as u32;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(data);
    }

    let checksum = Sha256::digest(&body);
    body.push(CHUNK_CHECKSUM);
    body.extend_from_slice(&(32u32).to_be_bytes());
    body.extend_from_slice(&checksum);
    body
}

// ---------------------------------------------------------------------------
// Finding 1 — Checksum NOT required
// ---------------------------------------------------------------------------

/// Stripping the CHECKSUM chunk must be rejected.
#[test]
fn test_no_checksum_chunk_rejected() {
    let data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    // CHECKSUM chunk: 1 byte type + 4 byte len + 32 byte SHA-256 = 37 bytes at the end.
    let stripped = &data[..data.len() - 37];
    let err = SPIFReader::new().read(stripped).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("checksum"),
        "expected checksum error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Finding 2 — Empty PAYLOAD silently accepted
// ---------------------------------------------------------------------------

/// A document with no PAYLOAD chunk must be rejected.
#[test]
fn test_missing_payload_chunk_rejected() {
    // Build a SIF that has a HEADER chunk but no PAYLOAD chunk.
    let header_cbor = {
        let mut h = std::collections::BTreeMap::new();
        h.insert("version", ciborium::value::Value::Integer(2u8.into()));
        h.insert("flags", ciborium::value::Value::Integer(0u8.into()));
        h.insert("created_ms", ciborium::value::Value::Integer(0u64.into()));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&h, &mut buf).unwrap();
        buf
    };
    let data = build_raw_sif(&[(CHUNK_HEADER, header_cbor)]);
    let err = SPIFReader::new().read(&data).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("payload"),
        "expected payload error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Finding 3 — No trace DAG cycle detection
// ---------------------------------------------------------------------------

/// A document with a cyclic trace (s1 → s2 → s1) must be rejected.
#[test]
fn test_cyclic_trace_rejected() {
    let doc = SPIFDocument {
        payload: vec![minimal_node()],
        trace: vec![
            TraceStep {
                id: "s1".into(),
                step_type: "inference".into(),
                content: Value::Text("step a".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec!["s2".into()], // depends on s2
                alternatives: vec![],
            },
            TraceStep {
                id: "s2".into(),
                step_type: "inference".into(),
                content: Value::Text("step b".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec!["s1".into()], // depends on s1 → cycle
                alternatives: vec![],
            },
        ],
        trace_method: "post-hoc".into(),
        provenance: None,
        semantic: None,
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    // Writer has no validation; encoding a cyclic doc succeeds.
    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    // Reader must reject it.
    let err = SPIFReader::new().read(&bytes).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("cycle"),
        "expected cycle error, got: {err}"
    );
}

/// A trace step with a dep that references a non-existent step is rejected.
#[test]
fn test_dangling_dep_rejected() {
    let doc = SPIFDocument {
        payload: vec![minimal_node()],
        trace: vec![TraceStep {
            id: "s1".into(),
            step_type: "inference".into(),
            content: Value::Text("orphan".into()),
            confidence: Distribution::certain("epistemic"),
            deps: vec!["ghost".into()], // "ghost" does not exist
            alternatives: vec![],
        }],
        trace_method: "post-hoc".into(),
        provenance: None,
        semantic: None,
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let err = SPIFReader::new().read(&bytes).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("unknown dep")
            || err.to_string().to_lowercase().contains("ghost"),
        "expected dangling dep error, got: {err}"
    );
}

/// Duplicate step IDs are rejected.
#[test]
fn test_duplicate_trace_step_id_rejected() {
    let doc = SPIFDocument {
        payload: vec![minimal_node()],
        trace: vec![
            TraceStep {
                id: "s1".into(),
                step_type: "inference".into(),
                content: Value::Text("a".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec![],
                alternatives: vec![],
            },
            TraceStep {
                id: "s1".into(), // duplicate
                step_type: "inference".into(),
                content: Value::Text("b".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec![],
                alternatives: vec![],
            },
        ],
        trace_method: "post-hoc".into(),
        provenance: None,
        semantic: None,
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let err = SPIFReader::new().read(&bytes).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("duplicate"),
        "expected duplicate id error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Finding 4 — Version number never validated
// ---------------------------------------------------------------------------

/// A document declaring version 0x99 must be rejected.
#[test]
fn test_unsupported_version_rejected() {
    let mut data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    // Byte index 9 is the version field (after 9-byte magic).
    data[MAGIC.len()] = 0x99;
    // Recompute checksum so the rejection is version-based, not checksum-based.
    let checksum_start = data.len() - 37;
    let new_checksum = Sha256::digest(&data[..checksum_start]);
    data[checksum_start + 5..].copy_from_slice(&new_checksum);

    let err = SPIFReader::new().read(&data).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("version"),
        "expected version error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Finding 5 — Cross-impl Node.refs CBOR tag(1001) compatibility
// ---------------------------------------------------------------------------

/// Plain-string refs must survive a Rust encode→decode roundtrip.
#[test]
fn test_refs_plain_string_roundtrip() {
    let doc = SPIFDocument {
        payload: vec![
            Node {
                id: "a".to_string(),
                node_type: "fact".to_string(),
                value: Value::Text("root".to_string()),
                confidence: Distribution::certain("epistemic"),
                refs: vec![],
            },
            Node {
                id: "b".to_string(),
                node_type: "fact".to_string(),
                value: Value::Text("child".to_string()),
                confidence: Distribution::certain("epistemic"),
                refs: vec!["a".to_string()],
            },
        ],
        ..minimal_doc()
    };

    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let restored = SPIFReader::new().read(&bytes).unwrap();
    assert_eq!(restored.payload[1].refs, vec!["a"]);
}

/// CBOR Tag(1001, "node_id") refs — as written by the Python encoder — must
/// be accepted by the Rust reader and decoded to the plain string "node_id".
#[test]
fn test_refs_cbor_noderef_tag_accepted() {
    // Build a PAYLOAD chunk by hand where refs contains Tag(1001, "a").
    // CBOR encoding of [{"id": "b", "type": "fact", "value": "child",
    //   "confidence": {...}, "refs": [Tag(1001, "a")]}]
    // We leverage ciborium::value::Value::Tag directly.
    let node_with_tagged_ref = Node {
        id: "b".to_string(),
        node_type: "fact".to_string(),
        value: Value::Text("child".to_string()),
        confidence: Distribution::certain("epistemic"),
        refs: vec![], // will be overridden with raw CBOR below
    };

    // Encode to CBOR Value, then patch the refs field.
    let mut node_val: ciborium::value::Value =
        ciborium::value::Value::serialized(&node_with_tagged_ref).unwrap();
    if let ciborium::value::Value::Map(ref mut fields) = node_val {
        // Replace the "refs" field with an array containing Tag(1001, "a")
        for (k, v) in fields.iter_mut() {
            if let ciborium::value::Value::Text(key) = k {
                if key == "refs" {
                    *v = ciborium::value::Value::Array(vec![ciborium::value::Value::Tag(
                        TAG_NODEREF,
                        Box::new(ciborium::value::Value::Text("a".to_string())),
                    )]);
                    break;
                }
            }
        }
    }

    // Wrap in the root node from minimal doc (id="a") + the patched "b" node.
    let mut root_node = minimal_node();
    root_node.id = "a".to_string();
    let root_node_val: ciborium::value::Value =
        ciborium::value::Value::serialized(&root_node).unwrap();
    let payload_val = ciborium::value::Value::Array(vec![root_node_val, node_val]);

    let mut payload_cbor = Vec::new();
    ciborium::ser::into_writer(&payload_val, &mut payload_cbor).unwrap();

    let data = build_raw_sif(&[(CHUNK_PAYLOAD, payload_cbor)]);
    let doc = SPIFReader::new()
        .read(&data)
        .expect("Tag(1001) refs must be accepted");
    assert_eq!(
        doc.payload[1].refs,
        vec!["a"],
        "Tag(1001, 'a') should decode to plain string 'a'"
    );
}

// ---------------------------------------------------------------------------
// Finding 6 — normalized flag lost in ALTS
// ---------------------------------------------------------------------------

/// The outer `normalized=false` from an ALTS chunk must be preserved on
/// every Alternative after roundtrip.
#[test]
fn test_alts_normalized_false_preserved() {
    let doc = SPIFDocument {
        payload: vec![minimal_node()],
        alternatives: vec![
            Alternative {
                weight: 3.0,
                nodes: vec![Node {
                    id: "alt1".to_string(),
                    node_type: "fact".to_string(),
                    value: Value::Text("option A".to_string()),
                    confidence: Distribution::certain("epistemic"),
                    refs: vec![],
                }],
                normalized: false, // unnormalized scores, not probabilities
            },
            Alternative {
                weight: 7.0,
                nodes: vec![Node {
                    id: "alt2".to_string(),
                    node_type: "fact".to_string(),
                    value: Value::Text("option B".to_string()),
                    confidence: Distribution::certain("epistemic"),
                    refs: vec![],
                }],
                normalized: false,
            },
        ],
        ..minimal_doc()
    };

    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let restored = SPIFReader::new().read(&bytes).unwrap();

    for alt in &restored.alternatives {
        assert!(
            !alt.normalized,
            "normalized=false must survive roundtrip, got normalized={}",
            alt.normalized
        );
    }
}

// ---------------------------------------------------------------------------
// Finding 7+8 — conf_bar panic + Distribution validation
// ---------------------------------------------------------------------------

/// The renderer must NOT panic when mean == 1.0 (edge case: filled == width).
#[test]
fn test_conf_bar_mean_one_no_panic() {
    let doc = SPIFDocument {
        payload: vec![Node {
            id: "n1".to_string(),
            node_type: "fact".to_string(),
            value: Value::Text("certain".to_string()),
            confidence: Distribution {
                mean: 1.0,
                var: 0.0,
                shape: "point".to_string(),
                semantics: "epistemic".to_string(),
                p5: None,
                p95: None,
            },
            refs: vec![],
        }],
        ..minimal_doc()
    };
    // Should not panic — if it does, the test framework will mark it failed.
    let _ = SPIFRenderer::new().render(&doc);
}

/// Distribution::validate() rejects mean outside [0, 1] and negative variance.
#[test]
fn test_distribution_validation_rejects_invalid() {
    let bad_mean = Distribution {
        mean: 1.5,
        var: 0.0,
        shape: "gaussian".to_string(),
        semantics: "epistemic".to_string(),
        p5: None,
        p95: None,
    };
    assert!(
        bad_mean.validate().is_err(),
        "mean=1.5 should fail validation"
    );

    let negative_mean = Distribution {
        mean: -0.1,
        var: 0.0,
        shape: "gaussian".to_string(),
        semantics: "epistemic".to_string(),
        p5: None,
        p95: None,
    };
    assert!(
        negative_mean.validate().is_err(),
        "mean=-0.1 should fail validation"
    );

    let negative_var = Distribution {
        mean: 0.5,
        var: -1.0,
        shape: "gaussian".to_string(),
        semantics: "epistemic".to_string(),
        p5: None,
        p95: None,
    };
    assert!(
        negative_var.validate().is_err(),
        "var=-1.0 should fail validation"
    );
}

/// Reader must reject a document that contains a node with mean > 1.0.
#[test]
fn test_reader_rejects_invalid_distribution() {
    // Build raw PAYLOAD CBOR with a node whose confidence.mean = 2.0.
    let bad_node_val: ciborium::value::Value = ciborium::value::Value::Map(vec![
        (Value::Text("id".into()), Value::Text("n1".into())),
        (Value::Text("type".into()), Value::Text("fact".into())),
        (Value::Text("value".into()), Value::Text("bad".into())),
        (
            Value::Text("confidence".into()),
            Value::Map(vec![
                (Value::Text("mean".into()), Value::Float(2.0)),
                (Value::Text("var".into()), Value::Float(0.0)),
            ]),
        ),
        (Value::Text("refs".into()), Value::Array(vec![])),
    ]);
    let payload_val = Value::Array(vec![bad_node_val]);

    let mut payload_cbor = Vec::new();
    ciborium::ser::into_writer(&payload_val, &mut payload_cbor).unwrap();

    let data = build_raw_sif(&[(CHUNK_PAYLOAD, payload_cbor)]);
    let err = SPIFReader::new().read(&data).unwrap_err();
    assert!(
        err.to_string().contains("mean") || err.to_string().contains("Distribution"),
        "expected distribution validation error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Finding 9 — Renderer panic on extreme timestamp
// ---------------------------------------------------------------------------

/// Renderer must NOT panic when timestamp_ms is u64::MAX.
#[test]
fn test_renderer_extreme_timestamp_no_panic() {
    let doc = SPIFDocument {
        payload: vec![minimal_node()],
        provenance: Some(Provenance {
            source_model: "test".to_string(),
            timestamp_ms: u64::MAX,
            temperature: 0.0,
            input_hash: String::new(),
            context_ref: String::new(),
            model_version: String::new(),
            attempt: 0,
            task_id: String::new(),
        }),
        ..minimal_doc()
    };
    let _ = SPIFRenderer::new().render(&doc);
}

// ---------------------------------------------------------------------------
// General — Correctness
// ---------------------------------------------------------------------------

/// Full document with all optional fields must survive a roundtrip.
#[test]
fn test_full_roundtrip_all_fields() {
    let doc = SPIFDocument {
        payload: vec![Node {
            id: "root".into(),
            node_type: "fact".into(),
            value: Value::Text("The sky is blue.".into()),
            confidence: Distribution {
                mean: 0.95,
                var: 0.01,
                shape: "gaussian".into(),
                semantics: "factual_accuracy".into(),
                p5: Some(0.85),
                p95: Some(0.99),
            },
            refs: vec![],
        }],
        provenance: Some(Provenance {
            source_model: "claude-sonnet-4-6".into(),
            timestamp_ms: 1712000000000,
            temperature: 0.7,
            input_hash: "a".repeat(64),
            context_ref: "b".repeat(64),
            model_version: "20241022".into(),
            attempt: 0,
            task_id: String::new(),
        }),
        semantic: Some(SemanticLayer {
            embedding: vec![0.1, 0.2, 0.3],
            embedding_model: "text-embedding-3-small".into(),
            covariance: vec![],
        }),
        trace: vec![
            TraceStep {
                id: "s0".into(),
                step_type: "hypothesis".into(),
                content: Value::Text("initial thought".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec![],
                alternatives: vec![],
            },
            TraceStep {
                id: "s1".into(),
                step_type: "conclusion".into(),
                content: Value::Text("final answer".into()),
                confidence: Distribution::certain("epistemic"),
                deps: vec!["s0".into()],
                alternatives: vec![],
            },
        ],
        trace_method: "live".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let restored = SPIFReader::new().read(&bytes).unwrap();

    assert_eq!(restored.payload[0].id, "root");
    assert_eq!(restored.payload[0].confidence.mean, 0.95);
    assert_eq!(restored.payload[0].confidence.p5, Some(0.85));
    assert_eq!(
        restored.provenance.as_ref().unwrap().source_model,
        "claude-sonnet-4-6"
    );
    assert_eq!(
        restored.provenance.as_ref().unwrap().timestamp_ms,
        1712000000000
    );
    assert_eq!(
        restored.semantic.as_ref().unwrap().embedding,
        vec![0.1f32, 0.2, 0.3]
    );
    assert_eq!(restored.trace.len(), 2);
    assert_eq!(restored.trace[1].deps, vec!["s0"]);
    assert_eq!(restored.trace_method, "live");
}

/// Truncated data (mid-chunk) must be rejected, not silently accepted.
#[test]
fn test_truncated_data_rejected() {
    let data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    // Truncate to just magic + version + flags (no chunks at all)
    let truncated = &data[..MAGIC.len() + 2];
    let err = SPIFReader::new().read(truncated).unwrap_err();
    // Should fail with checksum-not-found or too-short error
    assert!(
        err.to_string().to_lowercase().contains("checksum")
            || err.to_string().to_lowercase().contains("short")
            || err.to_string().to_lowercase().contains("payload"),
        "expected rejection of truncated data, got: {err}"
    );
}

/// Corrupting the stored checksum bytes must be detected as a mismatch.
#[test]
fn test_tampered_checksum_rejected() {
    let mut data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    // The stored checksum occupies the final 32 bytes (SHA-256).
    // The chunk trailer is: type(1) + len(4) + hash(32) = 37 bytes at end.
    // Flip one byte in the stored hash so the computed hash won't match.
    let hash_start = data.len() - 32;
    data[hash_start] ^= 0xFF;
    let err = SPIFReader::new().read(&data).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("checksum")
            || err.to_string().to_lowercase().contains("mismatch"),
        "expected checksum mismatch error, got: {err}"
    );
}

/// Invalid magic bytes must be rejected immediately.
#[test]
fn test_invalid_magic_rejected() {
    let mut data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    data[0] = 0x00; // corrupt the magic
    let err = SPIFReader::new().read(&data).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("magic"),
        "expected magic error, got: {err}"
    );
}

/// Data shorter than magic + 2 bytes must be rejected.
#[test]
fn test_too_short_data_rejected() {
    let err = SPIFReader::new().read(b"hi").unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("short"),
        "expected too-short error, got: {err}"
    );
}

/// Vulnerability: Strict reader accepts structurally signed documents with completely invalid cryptographic signatures.
#[test]
fn test_vulnerability_strict_reader_accepts_invalid_signature() {
    let mut doc = minimal_doc();
    doc.signature = Some(Signature {
        algorithm: "ed25519".to_string(),
        signer: "c2lnbmVyYmFzZTY0ZGF0YWFhYWFhYWFhYWFhYWFhYWFhYQ==".to_string(), // valid base64 but dummy signer
        signature: serde_bytes::ByteBuf::from(vec![0u8; 64]), // completely invalid signature
        key_id: "".to_string(),
    });

    let bytes = SPIFWriter::new().encode(&doc).unwrap();

    // A strict reader with require_signature=true should reject this document because the signature is cryptographically invalid.
    let reader = SPIFReader::strict();
    let decoded = reader.read(&bytes);
    assert!(
        decoded.is_err(),
        "Strict reader must reject a document with an invalid cryptographic signature"
    );
    let err = decoded.unwrap_err();
    assert!(
        err.to_string().contains("Signature verification failed"),
        "Expected signature verification failure error, got: {err}"
    );
}

/// A document with duplicate Node IDs must be rejected.
#[test]
fn test_duplicate_node_id_rejected() {
    let doc = SPIFDocument {
        payload: vec![
            Node {
                id: "n1".into(),
                node_type: "fact".into(),
                value: Value::Text("node 1".into()),
                confidence: Distribution::certain("epistemic"),
                refs: vec![],
            },
            Node {
                id: "n1".into(), // Duplicate ID
                node_type: "fact".into(),
                value: Value::Text("node 2".into()),
                confidence: Distribution::certain("epistemic"),
                refs: vec![],
            },
        ],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };
    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let err = SPIFReader::new().read(&bytes).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("duplicate node id"),
        "expected duplicate Node ID error, got: {err}"
    );
}

/// A document with a cyclic payload reference (n1 → n2 → n1) must be rejected.
#[test]
fn test_cyclic_payload_rejected() {
    let doc = SPIFDocument {
        payload: vec![
            Node {
                id: "n1".into(),
                node_type: "fact".into(),
                value: Value::Text("node 1".into()),
                confidence: Distribution::certain("epistemic"),
                refs: vec!["n2".into()], // Cyclic reference to n2
            },
            Node {
                id: "n2".into(),
                node_type: "fact".into(),
                value: Value::Text("node 2".into()),
                confidence: Distribution::certain("epistemic"),
                refs: vec!["n1".into()], // Cyclic reference to n1
            },
        ],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };
    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let err = SPIFReader::new().read(&bytes).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("cycle detected"),
        "expected cycle detected error, got: {err}"
    );
}

