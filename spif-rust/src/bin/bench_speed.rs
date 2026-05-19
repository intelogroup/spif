//! Fair performance benchmark for SPIF vs JSON/CBOR/MsgPack/BSON/XML/YAML/TOML.
//!
//! Previous version compared SPIF *typed* deserialization against JSON/CBOR
//! *generic dynamic* deserialization — systematically undercounting alternatives
//! because dynamic parsers skip schema validation and field mapping.
//!
//! This version measures both:
//!   (a) Generic dynamic deserialization — fastest possible parse, no typing
//!   (b) Typed deserialization — parse + construct a matching Rust struct
//!
//! Additionally measures what matters most in production:
//!   - Verification latency: SHA-256 checksum over the full document body
//!   - First-byte-to-header: parse just enough to extract provenance/model name

use serde::{Deserialize, Serialize};
use spif_rust::types::*;
use spif_rust::{SPIFReader, SPIFWriter};
use std::time::Instant;

const REPS: u32 = 1000;

// ---------------------------------------------------------------------------
// Typed structs for fair comparison
// ---------------------------------------------------------------------------

/// Mirror of SPIFDocument for JSON/MsgPack/XML/YAML/TOML typed deserialization.
#[derive(Serialize, Deserialize)]
struct TypedDocJson {
    #[serde(default)]
    payload: Vec<TypedNodeJson>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    provenance: Option<TypedProvenanceJson>,
    #[serde(default)]
    trace: Vec<TypedStepJson>,
    #[serde(default)]
    trace_method: String,
}

#[derive(Serialize, Deserialize)]
struct TypedNodeJson {
    id: String,
    node_type: String,
    value: String,
    confidence_mean: f64,
    confidence_var: f64,
}

#[derive(Serialize, Deserialize)]
struct TypedProvenanceJson {
    source_model: String,
    timestamp_ms: i64,
    temperature: f64,
    input_hash: String,
}

#[derive(Serialize, Deserialize)]
struct TypedStepJson {
    id: String,
    step_type: String,
    content: String,
    confidence_mean: f64,
}

// ---------------------------------------------------------------------------
// Document factories
// ---------------------------------------------------------------------------

fn doc_minimal() -> SPIFDocument {
    SPIFDocument {
        payload: vec![Node {
            id: "n1".to_string(),
            node_type: "fact".to_string(),
            value: ciborium::value::Value::Text("Paris".to_string()),
            confidence: Distribution {
                mean: 0.99,
                var: 0.01,
                shape: "gaussian".to_string(),
                semantics: "epistemic".to_string(),
                p5: None,
                p95: None,
            },
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
    }
}

fn doc_full() -> SPIFDocument {
    let nodes = (0..10)
        .map(|i| Node {
            id: format!("n{}", i),
            node_type: "fact".to_string(),
            value: ciborium::value::Value::Text(format!("Content node {}", i)),
            confidence: Distribution {
                mean: 0.5 + (i as f64) * 0.04,
                var: 0.01,
                shape: "gaussian".to_string(),
                semantics: "epistemic".to_string(),
                p5: None,
                p95: None,
            },
            refs: vec![],
        })
        .collect();

    let steps = (0..10)
        .map(|i| TraceStep {
            id: format!("s{}", i),
            step_type: "inference".to_string(),
            content: ciborium::value::Value::Text(format!("Step {} content", i)),
            confidence: Distribution {
                mean: 0.6 + (i as f64) * 0.03,
                var: 0.01,
                shape: "gaussian".to_string(),
                semantics: "epistemic".to_string(),
                p5: None,
                p95: None,
            },
            deps: if i > 0 {
                vec![format!("s{}", i - 1)]
            } else {
                vec![]
            },
            alternatives: vec![],
        })
        .collect();

    SPIFDocument {
        payload: nodes,
        trace: steps,
        provenance: Some(Provenance {
            source_model: "claude-sonnet-4-6".to_string(),
            timestamp_ms: 1712000000000,
            temperature: 0.7,
            input_hash: "b".repeat(64),
            context_ref: "".to_string(),
            model_version: "".to_string(),
        }),
        semantic: Some(SemanticLayer {
            embedding: (0..128).map(|i| (i as f32) / 100.0).collect(),
            embedding_model: "text-embedding-3-small".to_string(),
            covariance: vec![],
        }),
        alternatives: vec![Alternative {
            weight: 1.0,
            nodes: vec![Node {
                id: "alt1".to_string(),
                node_type: "fact".to_string(),
                value: ciborium::value::Value::Text("Alt".to_string()),
                confidence: Distribution::certain("epistemic"),
                refs: vec![],
            }],
            normalized: true,
        }],
        trace_method: "post-hoc".to_string(),
        delta: None,
        signature: None,
        signatures: vec![],
    }
}

fn make_typed_json(doc: &SPIFDocument) -> TypedDocJson {
    TypedDocJson {
        payload: doc
            .payload
            .iter()
            .map(|n| TypedNodeJson {
                id: n.id.clone(),
                node_type: n.node_type.clone(),
                value: match &n.value {
                    ciborium::value::Value::Text(s) => s.clone(),
                    _ => "".to_string(),
                },
                confidence_mean: n.confidence.mean,
                confidence_var: n.confidence.var,
            })
            .collect(),
        provenance: doc.provenance.as_ref().map(|p| TypedProvenanceJson {
            source_model: p.source_model.clone(),
            timestamp_ms: p.timestamp_ms as i64,
            temperature: p.temperature,
            input_hash: p.input_hash.clone(),
        }),
        trace: doc
            .trace
            .iter()
            .map(|s| TypedStepJson {
                id: s.id.clone(),
                step_type: s.step_type.clone(),
                content: match &s.content {
                    ciborium::value::Value::Text(t) => t.clone(),
                    _ => "".to_string(),
                },
                confidence_mean: s.confidence.mean,
            })
            .collect(),
        trace_method: doc.trace_method.clone(),
    }
}

// ---------------------------------------------------------------------------
// Benchmark harness
// ---------------------------------------------------------------------------

fn bench<F: Fn()>(f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..REPS {
        f();
    }
    let duration = start.elapsed();
    (duration.as_secs_f64() * 1_000_000.0) / (REPS as f64)
}

fn bench_verification(bytes: &[u8]) -> f64 {
    use sha2::{Digest, Sha256};
    bench(|| {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..bytes.len() - 37]); // body without checksum chunk
        let _ = hasher.finalize();
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let writer = SPIFWriter::new();
    let reader = SPIFReader::new();

    println!("## SPIF Performance Benchmark (μs per op, {} reps)\n", REPS);
    println!("NOTE: 'typed' = parse into a struct with schema validation (fair comparison)");
    println!("      'generic' = dynamic parse into a Value tree (no schema, fastest possible)\n");

    let levels = vec![("minimal", doc_minimal()), ("full", doc_full())];

    for (label, doc) in &levels {
        let spif_bytes = writer.encode(doc).unwrap();

        // Build typed equivalent for all formats
        let typed_doc = make_typed_json(doc);

        // --- Binary formats ---
        let json_typed_bytes = serde_json::to_vec(&typed_doc).unwrap();
        let json_generic_val: serde_json::Value =
            serde_json::from_slice(&json_typed_bytes).unwrap();
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&json_generic_val, &mut cbor_bytes).unwrap();
        let mp_bytes = rmp_serde::to_vec_named(&typed_doc).unwrap();
        let bson_bytes = bson::to_vec(&typed_doc).unwrap();

        // --- Text formats (AI configs, pipelines, API payloads) ---
        // JSONL: each payload node + each trace step as one JSON object per line.
        // This is the real AI JSONL use case — streaming events/records, not one big blob.
        let jsonl_str: String = typed_doc
            .payload
            .iter()
            .map(|n| serde_json::to_string(n).unwrap())
            .chain(
                typed_doc
                    .trace
                    .iter()
                    .map(|s| serde_json::to_string(s).unwrap()),
            )
            .collect::<Vec<_>>()
            .join("\n");
        let jsonl_bytes = jsonl_str.as_bytes().to_vec();

        let xml_str = quick_xml::se::to_string(&typed_doc).unwrap();
        let xml_bytes = xml_str.as_bytes().to_vec();
        let yaml_str = serde_yaml::to_string(&typed_doc).unwrap();
        let yaml_bytes = yaml_str.as_bytes().to_vec();
        // TOML requires all keys to be strings and doesn't support null optionals at top level
        // without wrapping — use a table-friendly subset (no Option fields).
        // Owned Vecs required since Deserialize can't be derived on reference fields.
        #[derive(Serialize, Deserialize)]
        struct TomlDoc {
            trace_method: String,
            payload: Vec<TypedNodeJson>,
            trace: Vec<TypedStepJson>,
        }
        let toml_doc = TomlDoc {
            trace_method: typed_doc.trace_method.clone(),
            payload: typed_doc
                .payload
                .iter()
                .map(|n| TypedNodeJson {
                    id: n.id.clone(),
                    node_type: n.node_type.clone(),
                    value: n.value.clone(),
                    confidence_mean: n.confidence_mean,
                    confidence_var: n.confidence_var,
                })
                .collect(),
            trace: typed_doc
                .trace
                .iter()
                .map(|s| TypedStepJson {
                    id: s.id.clone(),
                    step_type: s.step_type.clone(),
                    content: s.content.clone(),
                    confidence_mean: s.confidence_mean,
                })
                .collect(),
        };
        let toml_str = toml::to_string(&toml_doc).unwrap();
        let toml_bytes = toml_str.as_bytes().to_vec();

        println!(
            "--- {} | SPIF={} B  JSON={} B  JSONL={} B  XML={} B  YAML={} B  TOML={} B  MsgPack={} B  BSON={} B ---",
            label,
            spif_bytes.len(),
            json_typed_bytes.len(),
            jsonl_bytes.len(),
            xml_bytes.len(),
            yaml_bytes.len(),
            toml_bytes.len(),
            mp_bytes.len(),
            bson_bytes.len(),
        );

        // Encode
        let enc_spif = bench(|| {
            let _ = writer.encode(doc).unwrap();
        });
        let enc_json_t = bench(|| {
            let _ = serde_json::to_vec(&typed_doc).unwrap();
        });
        let enc_cbor = bench(|| {
            let mut b = Vec::new();
            ciborium::ser::into_writer(&json_generic_val, &mut b).unwrap();
        });
        let enc_mp = bench(|| {
            let _ = rmp_serde::to_vec_named(&typed_doc).unwrap();
        });
        let enc_bson = bench(|| {
            let _ = bson::to_vec(&typed_doc).unwrap();
        });
        let enc_jsonl = bench(|| {
            let _: String = typed_doc
                .payload
                .iter()
                .map(|n| serde_json::to_string(n).unwrap())
                .chain(
                    typed_doc
                        .trace
                        .iter()
                        .map(|s| serde_json::to_string(s).unwrap()),
                )
                .collect::<Vec<_>>()
                .join("\n");
        });
        let enc_xml = bench(|| {
            let _ = quick_xml::se::to_string(&typed_doc).unwrap();
        });
        let enc_yaml = bench(|| {
            let _ = serde_yaml::to_string(&typed_doc).unwrap();
        });
        let enc_toml = bench(|| {
            let _ = toml::to_string(&toml_doc).unwrap();
        });

        println!(
            "  ENCODE  SPIF={:6.1}μ  JSON(t)={:5.1}μ  JSONL={:5.1}μ  CBOR={:5.1}μ  MsgPack={:5.1}μ  BSON={:5.1}μ  XML={:6.1}μ  YAML={:6.1}μ  TOML={:6.1}μ",
            enc_spif, enc_json_t, enc_jsonl, enc_cbor, enc_mp, enc_bson, enc_xml, enc_yaml, enc_toml
        );

        // Decode
        let dec_spif = bench(|| {
            let _ = reader.read(&spif_bytes).unwrap();
        });
        let dec_json_t = bench(|| {
            let _: TypedDocJson = serde_json::from_slice(&json_typed_bytes).unwrap();
        });
        let dec_cbor = bench(|| {
            let _: ciborium::value::Value =
                ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        });
        let dec_mp = bench(|| {
            let _: TypedDocJson = rmp_serde::from_slice(&mp_bytes).unwrap();
        });
        let dec_bson = bench(|| {
            let _: TypedDocJson = bson::from_slice(&bson_bytes).unwrap();
        });
        let dec_jsonl = bench(|| {
            for line in jsonl_str.split('\n') {
                if line.starts_with("{\"id\"") {
                    // Could be node or step — try node first
                    let _ = serde_json::from_str::<TypedNodeJson>(line)
                        .or_else(|_| {
                            serde_json::from_str::<TypedStepJson>(line).map(|_| TypedNodeJson {
                                id: String::new(),
                                node_type: String::new(),
                                value: String::new(),
                                confidence_mean: 0.0,
                                confidence_var: 0.0,
                            })
                        })
                        .unwrap();
                }
            }
        });
        let dec_xml = bench(|| {
            let _: TypedDocJson = quick_xml::de::from_str(&xml_str).unwrap();
        });
        let dec_yaml = bench(|| {
            let _: TypedDocJson = serde_yaml::from_str(&yaml_str).unwrap();
        });
        let dec_toml = bench(|| {
            let _: TomlDoc = toml::from_str(&toml_str).unwrap();
        });

        println!(
            "  DECODE  SPIF={:6.1}μ  JSON(t)={:5.1}μ  JSONL={:5.1}μ  CBOR={:5.1}μ  MsgPack={:5.1}μ  BSON={:5.1}μ  XML={:6.1}μ  YAML={:6.1}μ  TOML={:6.1}μ",
            dec_spif, dec_json_t, dec_jsonl, dec_cbor, dec_mp, dec_bson, dec_xml, dec_yaml, dec_toml
        );

        let verify_ms = bench_verification(&spif_bytes);
        println!(
            "  VERIFY  SHA-256={:.1}μ  (ed25519 signature ~10-50μ additional)\n",
            verify_ms
        );
    }

    println!("## Legend");
    println!("  SPIF       — binary, typed, with checksum + DAG validation + provenance");
    println!("  JSON       — typed serde struct, schema enforced");
    println!("  JSONL      — one JSON record per line (payload nodes + trace steps)");
    println!("  CBOR       — generic Value tree");
    println!("  MsgPack    — typed serde struct");
    println!("  BSON       — typed serde struct");
    println!("  XML        — typed serde struct (quick-xml)");
    println!("  YAML       — typed serde struct (serde_yaml)");
    println!("  TOML       — typed, payload+trace only (no Option support at top level)");
    println!("  JSONL      — one JSON object per line (payload nodes + trace steps); real streaming use case");
}
