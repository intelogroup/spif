//! v1.3 trust-layer parity tests (SPEC §7.7, §7.8, §8.1), run against
//! the conformance vectors in ../vectors — the same artifacts spif-py's
//! trust tests assert on. Python is the reference implementation.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use spif_rust::trust::*;
use std::collections::HashMap;
use std::path::PathBuf;

const TS0: u64 = 1_700_000_000_000;

fn vector(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn vector_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(rel)
}

/// The published TEST-ONLY conformance keys (vectors/build_vectors.py).
fn test_key(label: &str) -> SigningKey {
    let seed = Sha256::digest(format!("spif-v13-conformance-test-key:{label}").as_bytes());
    SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
}

fn default_opts() -> VerifyOptions {
    VerifyOptions::default()
}

// --- Case 01: valid ---------------------------------------------------------

#[test]
fn valid_artifact_reports_valid() {
    let report = verify_artifact(&vector("artifacts/01_valid_py.spif"), &default_opts());
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.signature_status, "valid");
    assert_eq!(report.timestamp_status, TS_ABSENT);
    assert_eq!(report.forged_revocations, 0);
    assert!(report.references.is_empty());
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
}

// --- Case 03: tampered --------------------------------------------------------

#[test]
fn tampered_artifact_reports_invalid() {
    let report = verify_artifact(&vector("artifacts/03_tampered.spif"), &default_opts());
    assert_eq!(report.trust_status, TRUST_INVALID);
    assert_eq!(report.signature_status, "invalid");
}

// --- Case 04: unsigned ---------------------------------------------------------

#[test]
fn unsigned_artifact_reports_unsigned() {
    let report = verify_artifact(&vector("artifacts/04_unsigned.spif"), &default_opts());
    assert_eq!(report.trust_status, TRUST_UNSIGNED);
    assert_eq!(report.signature_status, "unsigned");
}

// --- Case 05: revoked via out-of-band list --------------------------------------

#[test]
fn revoked_via_list_file_reports_revoked() {
    let mut opts = default_opts();
    opts.revocation_file = Some(vector_path("aux/revocations_05.json"));
    let report = verify_artifact(&vector("artifacts/01_valid_py.spif"), &opts);
    assert_eq!(report.trust_status, TRUST_REVOKED);
    assert_eq!(report.signature_status, "valid");
    assert_eq!(report.revocations_applied.len(), 1);
    assert_eq!(report.forged_revocations, 0);
}

// --- Case 06: revoked via embedded chunk -----------------------------------------

#[test]
fn revoked_embedded_reports_revoked() {
    let report = verify_artifact(
        &vector("artifacts/06_revoked_embedded.spif"),
        &default_opts(),
    );
    assert_eq!(report.trust_status, TRUST_REVOKED);
    assert_eq!(report.signature_status, "valid");
    assert_eq!(report.revocations_applied.len(), 1);
}

// --- Case 07: forged revocation ----------------------------------------------------

#[test]
fn forged_revocation_is_flagged_and_ignored() {
    let mut opts = default_opts();
    opts.revocation_file = Some(vector_path("aux/revocations_07_forged.json"));
    let report = verify_artifact(&vector("artifacts/01_valid_py.spif"), &opts);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.forged_revocations, 1);
    assert!(report.revocations_applied.is_empty());
}

#[test]
fn statement_by_non_signer_is_not_authoritative() {
    let data = vector("artifacts/01_valid_py.spif");
    let attacker = test_key("attacker");
    let stmt = create_revocation(&data, &attacker, "compromised", None, Some(TS0 + 60_000))
        .unwrap();
    let signer_ids: std::collections::HashSet<String> = verify_artifact(&data, &default_opts())
        .signers
        .into_iter()
        .collect();
    assert!(!statement_is_authoritative(&stmt, &signer_ids, None, None));

    // Supplied directly (not via file), it must count as forged, not apply.
    let mut opts = default_opts();
    opts.revocations = vec![stmt];
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.forged_revocations, 1);
}

// --- Revocation create/attach round-trip --------------------------------------------

#[test]
fn create_and_attach_revocation_round_trip() {
    let data = vector("artifacts/01_valid_py.spif");
    let signer = test_key("signer");
    let stmt = create_revocation(&data, &signer, "retracted", None, Some(TS0 + 60_000)).unwrap();

    // Standalone statement supplied out-of-band.
    let mut opts = default_opts();
    opts.revocations = vec![stmt.clone()];
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_REVOKED);

    // Embedded into the artifact: digest/signature unaffected, REVOKED.
    let embedded = attach_revocations(&data, &[stmt]).unwrap();
    assert_eq!(artifact_digest(&embedded), artifact_digest(&data));
    let extracted = extract_revocations(&embedded);
    assert_eq!(extracted.len(), 1);
    let report = verify_artifact(&embedded, &default_opts());
    assert_eq!(report.trust_status, TRUST_REVOKED);
    assert_eq!(report.signature_status, "valid");
}

#[test]
fn revocation_list_save_load_round_trip() {
    let data = vector("artifacts/01_valid_py.spif");
    let signer = test_key("signer");
    let stmt = create_revocation(&data, &signer, "superseded", None, Some(TS0 + 1)).unwrap();
    let path = std::env::temp_dir().join(format!(
        "spif-rust-revocations-{}.json",
        std::process::id()
    ));
    save_revocation_list(&[stmt.clone()], &path).unwrap();
    let loaded = load_revocation_statements(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded, vec![stmt]);

    // Absent file -> empty list (mirrors spif-py).
    let absent = std::env::temp_dir().join("spif-rust-definitely-absent-revocations.json");
    assert!(load_revocation_statements(&absent).unwrap().is_empty());
}

#[test]
fn create_revocation_rejects_unknown_reason() {
    let data = vector("artifacts/01_valid_py.spif");
    let signer = test_key("signer");
    assert!(create_revocation(&data, &signer, "bogus", None, None).is_err());
}

// --- Cases 08/09: timestamp ------------------------------------------------------------

#[test]
fn timestamp_verified_with_pinned_key_unverified_without() {
    let data = vector("artifacts/08_timestamped.spif");

    let mut opts = default_opts();
    let tsa_json: HashMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(vector_path("aux/tsa_pub.json")).unwrap(),
    )
    .unwrap();
    opts.tsa_keys = tsa_json;
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.timestamp_status, TS_VERIFIED);
    assert_eq!(report.trust_status, TRUST_VALID);

    let report = verify_artifact(&data, &default_opts());
    assert_eq!(report.timestamp_status, TS_UNVERIFIED);
    assert_eq!(report.trust_status, TRUST_VALID);
}

#[test]
fn create_and_attach_timestamp_round_trip() {
    let data = vector("artifacts/01_valid_py.spif");
    let tsa = test_key("tsa");
    let anchor = create_timestamp_anchor(&data, &tsa, None, Some(TS0 + 30_000));
    let stamped = attach_timestamp(&data, &anchor).unwrap();
    assert_eq!(extract_timestamp(&stamped), Some(anchor.clone()));

    let mut opts = default_opts();
    opts.tsa_keys.insert(
        anchor.authority.clone(),
        pubkey_b64(&tsa.verifying_key()),
    );
    let report = verify_artifact(&stamped, &opts);
    assert_eq!(report.timestamp_status, TS_VERIFIED);
    assert_eq!(report.trust_status, TRUST_VALID);

    // A token countersigned by a different key under the same authority
    // name must not verify.
    let other = test_key("attacker");
    let bad_anchor = create_timestamp_anchor(
        &data,
        &other,
        Some(anchor.authority.clone()),
        Some(TS0 + 30_000),
    );
    let bad = attach_timestamp(&data, &bad_anchor).unwrap();
    let report = verify_artifact(&bad, &opts);
    assert_eq!(report.timestamp_status, TS_UNVERIFIED);
}

// --- Cases 10/11: cross-document references ----------------------------------------------

#[test]
fn crossdoc_resolved_with_bundle_unresolved_without() {
    let downstream = vector("artifacts/10_downstream.spif");

    let mut opts = default_opts();
    opts.bundle = vec![vector("artifacts/10_upstream.spif")];
    let report = verify_artifact(&downstream, &opts);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.references.len(), 1);
    assert_eq!(report.references[0].kind, "cross-document");
    assert_eq!(report.references[0].status, "resolved");

    let report = verify_artifact(&downstream, &default_opts());
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.references.len(), 1);
    assert_eq!(report.references[0].status, "unresolved");
    assert_eq!(report.unresolved_references().len(), 1);
}

#[test]
fn content_id_matches_downstream_reference() {
    // The cid embedded in the downstream artifact's spif: ref (computed
    // by spif-py's writer) must equal the Rust-computed content_id of
    // the upstream artifact.
    let upstream = vector("artifacts/10_upstream.spif");
    let downstream = vector("artifacts/10_downstream.spif");
    let doc = spif_rust::SPIFReader::new().read(&downstream).unwrap();
    let ref_text = &doc.payload[0].refs[0];
    let cid_in_ref = ref_text
        .strip_prefix("spif:sha256:")
        .and_then(|rest| rest.split_once('#').map(|(cid, _)| cid.to_string()))
        .expect("cross-doc ref shape");
    assert_eq!(content_id(&upstream).unwrap(), cid_in_ref);
}

#[test]
fn content_id_of_rust_written_doc_matches_python() {
    // Build the same signed document trust_conformance's `sign` command
    // produces (plain-map confidence, plain-string refs, subset
    // provenance struct) and pin its content_id to the value spif-py's
    // compute_content_id produces for those exact bytes — computed with
    // spif-py 1.3.0: 33ccf3e9... This guards the normalization in
    // trust::content_id (Distribution tag wrapping, null p5/p95 drop,
    // provenance default fill).
    use ed25519_dalek::Signer;
    use spif_rust::types::*;
    use spif_rust::SPIFWriter;

    let key = test_key("signer");
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
    let dummy = writer.encode(&doc).unwrap();
    // Locate the SIGNATURE chunk (0x07) to find the signing body.
    let mut pos = 11usize;
    let sig_offset = loop {
        let ct = dummy[pos];
        let len = u32::from_be_bytes(dummy[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if ct == 0x07 {
            break pos;
        }
        pos += 5 + len;
    };
    let sig = key.sign(&dummy[..sig_offset]);
    doc.signature = Some(Signature {
        algorithm: "ed25519".to_string(),
        signer: signer_id,
        signature: serde_bytes::ByteBuf::from(sig.to_bytes().to_vec()),
        key_id: String::new(),
    });
    let data = writer.encode(&doc).unwrap();

    assert_eq!(
        content_id(&data).unwrap(),
        "33ccf3e9b83763c494e4d7fc139b5baadb1098ce804bebcc7cdf6720264cfdc0"
    );
    let report = verify_artifact(&data, &default_opts());
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.content_id, content_id(&data).unwrap());
}

#[test]
fn reader_accepts_crossdoc_downstream() {
    // Regression for the step-1 DAG exemption: spif: refs must not be
    // treated as dangling local references.
    let downstream = vector("artifacts/10_downstream.spif");
    assert!(spif_rust::SPIFReader::new().read(&downstream).is_ok());
}

// --- Phase B parity: statement cap, dedupe, parse-boundary types ----------------
// spif-py gained these semantics in Phase B (commits ab7150e, 5b7319d); the
// Rust side is pinned to the same behavior here.

fn dummy_statement(issued_ms: u64) -> spif_rust::RevocationStatement {
    spif_rust::RevocationStatement {
        artifact_digest: "00".repeat(32),
        signer: "dummy".to_string(),
        issued_ms,
        reason: "other".to_string(),
        signature: vec![0u8; 64],
    }
}

#[test]
fn revocation_chunk_at_cap_reads_over_cap_is_rejected() {
    let data = vector("artifacts/01_valid_py.spif");
    let cap = spif_rust::reader::MAX_REVOCATION_STATEMENTS;

    let at_cap: Vec<spif_rust::RevocationStatement> =
        (0..cap as u64).map(dummy_statement).collect();
    let embedded = attach_revocations(&data, &at_cap).unwrap();
    let doc = spif_rust::SPIFReader::new().read(&embedded).unwrap();
    assert_eq!(doc.revocations.len(), cap);

    let mut over_cap = at_cap;
    over_cap.push(dummy_statement(cap as u64));
    let embedded = attach_revocations(&data, &over_cap).unwrap();
    let err = spif_rust::SPIFReader::new().read(&embedded).unwrap_err();
    assert!(
        err.to_string().contains("exceeding the limit"),
        "error: {err}"
    );
}

#[test]
fn duplicate_revocation_candidates_are_processed_once() {
    let data = vector("artifacts/01_valid_py.spif");

    // A forged statement supplied three times counts once (pre-parity it
    // counted per copy, and each copy cost a signature verification).
    let attacker = test_key("attacker");
    let forged = create_revocation(&data, &attacker, "compromised", None, Some(TS0)).unwrap();
    let mut opts = default_opts();
    opts.revocations = vec![forged.clone(), forged.clone(), forged];
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.forged_revocations, 1);

    // An authoritative statement supplied three times applies once.
    let signer = test_key("signer");
    let stmt = create_revocation(&data, &signer, "retracted", None, Some(TS0)).unwrap();
    let mut opts = default_opts();
    opts.revocations = vec![stmt.clone(), stmt.clone(), stmt];
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_REVOKED);
    assert_eq!(report.revocations_applied.len(), 1);
}

#[test]
fn revocation_chunk_with_wrong_typed_field_is_rejected() {
    let data = vector("artifacts/01_valid_py.spif");
    // Hand-build a REVOCATION payload whose statement carries a CBOR array
    // where `signer` (a string field) belongs. Serde's typed decode is the
    // parse boundary: the reader must reject the document with a clean
    // error — never panic, never silently accept (spif-py Phase B, 5b7319d).
    let entry = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("artifact_digest".to_string()),
            ciborium::Value::Text("00".repeat(32)),
        ),
        (
            ciborium::Value::Text("signer".to_string()),
            ciborium::Value::Array(vec![]),
        ),
        (
            ciborium::Value::Text("issued_ms".to_string()),
            ciborium::Value::Integer(0.into()),
        ),
        (
            ciborium::Value::Text("reason".to_string()),
            ciborium::Value::Text("other".to_string()),
        ),
        (
            ciborium::Value::Text("signature".to_string()),
            ciborium::Value::Bytes(vec![0u8; 64]),
        ),
    ]);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Array(vec![entry]), &mut payload).unwrap();
    let crafted = attach_chunk(&data, spif_rust::CHUNK_REVOCATION, &payload).unwrap();
    assert!(spif_rust::SPIFReader::new().read(&crafted).is_err());
    // verify_artifact surfaces it as an INVALID report with errors.
    let report = verify_artifact(&crafted, &default_opts());
    assert_eq!(report.trust_status, TRUST_INVALID);
    assert!(!report.errors.is_empty());
}
