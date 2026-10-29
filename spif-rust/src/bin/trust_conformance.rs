//! Conformance adapter for the SPIF v1.3 trust layer (vectors/ kit).
//!
//! Used by case 02 (cross_implementation_rust) of
//! `vectors/run_conformance.py`:
//!
//!   trust_conformance verify <artifact.spif>
//!       [--revocation-file F] [--tsa-keys F] [--known-keys F]
//!       [--bundle F ...]
//!       Prints the verification report as JSON with the same fields the
//!       Python adapter produces: {trust_status, signature_status,
//!       timestamp_status, forged_revocations, references:[{kind,status}]}.
//!
//!   trust_conformance sign <out.spif>
//!       Writes a signed artifact mirroring the vector builder's shape
//!       (one node n1/fact, provenance source_model="conformance-model",
//!       timestamp 1_700_000_000_000), signed with the published
//!       TEST-ONLY conformance key (seed sha256 of
//!       "spif-v13-conformance-test-key:signer", as in
//!       vectors/build_vectors.py). Never use that key for real artifacts.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use spif_rust::trust::{content_id, pubkey_b64, verify_artifact, VerifyOptions};
use spif_rust::types::*;
use spif_rust::SPIFWriter;
use std::collections::HashMap;
use std::path::PathBuf;

const TS0: u64 = 1_700_000_000_000;

fn test_signing_key() -> SigningKey {
    let seed = Sha256::digest(b"spif-v13-conformance-test-key:signer");
    SigningKey::from_bytes(seed.as_slice().try_into().expect("sha256 is 32 bytes"))
}

fn find_signature_chunk_offset(data: &[u8]) -> Option<usize> {
    let mut pos = MAGIC.len() + 2;
    while pos + 5 <= data.len() {
        let chunk_type = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().ok()?) as usize;
        if chunk_type == CHUNK_SIGNATURE {
            return Some(pos);
        }
        if chunk_type == CHUNK_CHECKSUM {
            return None;
        }
        pos = pos.checked_add(5 + len)?;
    }
    None
}

/// Two-pass signing, mirroring `spif.crypto.sign_document`: a dummy
/// 64-byte signature locks the document structure, the real signature
/// covers all bytes before the SIGNATURE chunk, then the document is
/// re-encoded with the real signature in place.
fn sign_document() -> Vec<u8> {
    let key = test_signing_key();
    let signer_id = pubkey_b64(&key.verifying_key());

    let mut doc = SPIFDocument {
        payload: vec![Node {
            id: "n1".to_string(),
            node_type: "fact".to_string(),
            value: Value::Text("conformance: valid signed artifact".to_string()),
            confidence: Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: Some(Provenance {
            source_model: "conformance-model".to_string(),
            timestamp_ms: TS0,
            temperature: 0.0,
            input_hash: String::new(),
            context_ref: String::new(),
            model_version: String::new(),
            attempt: 0,
            task_id: String::new(),
            risk_tier: String::new(),
            model_card: String::new(),
        }),
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: Some(Signature {
            algorithm: "ed25519".to_string(),
            signer: signer_id.clone(),
            signature: serde_bytes::ByteBuf::from(vec![0u8; 64]),
            key_id: String::new(),
        }),
        signatures: vec![],
        task_info: None,
        revocations: Vec::new(),
        timestamp_anchor: None,
    };

    let writer = SPIFWriter::new();
    let dummy = writer.encode(&doc).expect("encode dummy");
    let sig_offset = find_signature_chunk_offset(&dummy).expect("SIGNATURE chunk present");
    let body_to_sign = &dummy[..sig_offset];
    let signature = key.sign(body_to_sign);
    doc.signature = Some(Signature {
        algorithm: "ed25519".to_string(),
        signer: signer_id,
        signature: serde_bytes::ByteBuf::from(signature.to_bytes().to_vec()),
        key_id: String::new(),
    });
    writer.encode(&doc).expect("encode signed")
}

fn load_key_map(path: &str) -> HashMap<String, String> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read key map {path}: {e}");
        std::process::exit(2);
    });
    serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("cannot parse key map {path}: {e}");
        std::process::exit(2);
    })
}

fn cmd_verify(args: &[String]) -> i32 {
    let mut artifact: Option<PathBuf> = None;
    let mut opts = VerifyOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--revocation-file" => {
                i += 1;
                opts.revocation_file = Some(PathBuf::from(&args[i]));
            }
            "--tsa-keys" => {
                i += 1;
                opts.tsa_keys = load_key_map(&args[i]);
            }
            "--known-keys" => {
                i += 1;
                opts.known_keys = load_key_map(&args[i]);
            }
            "--bundle" => {
                i += 1;
                match std::fs::read(&args[i]) {
                    Ok(bytes) => opts.bundle.push(bytes),
                    Err(e) => {
                        eprintln!("cannot read bundle file {}: {e}", args[i]);
                        return 2;
                    }
                }
            }
            other if artifact.is_none() => artifact = Some(PathBuf::from(other)),
            other => {
                eprintln!("unexpected argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let path = match artifact {
        Some(p) => p,
        None => {
            eprintln!("usage: trust_conformance verify <artifact.spif> [options]");
            return 2;
        }
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return 2;
        }
    };
    let report = verify_artifact(&data, &opts);
    let out = serde_json::json!({
        "trust_status": report.trust_status,
        "signature_status": report.signature_status,
        "timestamp_status": report.timestamp_status,
        "forged_revocations": report.forged_revocations,
        "references": report.references.iter()
            .map(|r| serde_json::json!({"kind": r.kind, "status": r.status}))
            .collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string(&out).unwrap());
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: trust_conformance <verify|sign> ...");
        std::process::exit(2);
    }
    match args[0].as_str() {
        "verify" => std::process::exit(cmd_verify(&args[1..])),
        "content-id" => {
            if args.len() != 2 {
                eprintln!("usage: trust_conformance content-id <artifact.spif>");
                std::process::exit(2);
            }
            let data = std::fs::read(&args[1]).unwrap_or_else(|e| {
                eprintln!("cannot read {}: {e}", args[1]);
                std::process::exit(2);
            });
            match content_id(&data) {
                Ok(cid) => println!("{cid}"),
                Err(e) => {
                    eprintln!("content_id failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        "sign" => {
            if args.len() != 2 {
                eprintln!("usage: trust_conformance sign <out.spif>");
                std::process::exit(2);
            }
            let bytes = sign_document();
            if let Err(e) = std::fs::write(&args[1], &bytes) {
                eprintln!("cannot write {}: {e}", args[1]);
                std::process::exit(2);
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}
