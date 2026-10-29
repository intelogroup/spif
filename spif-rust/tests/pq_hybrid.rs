//! v1.4 hybrid PQ parity tests (SPEC §7.9), run against the conformance
//! vectors in ../vectors (cases 12-15, produced by the Python reference
//! implementation) and the fixtures in tests/fixtures (a Python-produced
//! hybrid artifact + hybrid-signed revocation lists). These tests are
//! the cross-implementation proof for the Rust gate: the ML-DSA-65
//! component is verified by the RustCrypto `ml-dsa` crate, the artifacts
//! and statements were produced by spif-py + pqcrypto.
//!
//! Fixture provenance (tests/fixtures/hybrid_revoked.spif,
//! hybrid_revocations.json, hybrid_revocations_forged.json): generated
//! once with spif-py — `sign_document_hybrid` over a one-node document,
//! `create_revocation_hybrid(..., reason="compromised")`,
//! `save_revocation_list`; the forged twin flips one ML-DSA signature
//! byte (offset 100) in the list file. Keys were random test keys,
//! discarded after generation.

use spif_rust::trust::*;
use std::path::PathBuf;

fn vector(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn classical() -> VerifyOptions {
    VerifyOptions::default()
}

fn require_pq() -> VerifyOptions {
    VerifyOptions {
        require_pq: true,
        ..VerifyOptions::default()
    }
}

#[test]
fn backend_is_available_in_default_build() {
    assert!(pq_available(), "default features must include the pq gate");
}

// --- Conformance case 12: hybrid_valid --------------------------------------

#[test]
fn case12_hybrid_valid_both_modes() {
    let data = vector("artifacts/12_hybrid_valid.spif");
    let strict = verify_artifact(&data, &require_pq());
    assert_eq!(strict.trust_status, TRUST_VALID, "errors: {:?}", strict.errors);
    assert_eq!(strict.signature_status, "valid");
    let classical = verify_artifact(&data, &classical());
    assert_eq!(classical.trust_status, TRUST_VALID);
}

// --- Conformance case 13: ML-DSA component tampered --------------------------

#[test]
fn case13_tampered_ml_dsa_component() {
    let data = vector("artifacts/13_hybrid_tampered_ml_dsa.spif");
    // require_pq sees the tampered component: INVALID.
    let strict = verify_artifact(&data, &require_pq());
    assert_eq!(strict.trust_status, TRUST_INVALID);
    // The classical gate verifies the ed25519 component alone: VALID.
    // That asymmetry is the point of the gate modes (SPEC §7.9.2).
    let classical = verify_artifact(&data, &classical());
    assert_eq!(classical.trust_status, TRUST_VALID);
}

// --- Conformance case 14: ed25519 component tampered -------------------------

#[test]
fn case14_tampered_ed25519_component() {
    let data = vector("artifacts/14_hybrid_tampered_ed25519.spif");
    assert_eq!(
        verify_artifact(&data, &require_pq()).trust_status,
        TRUST_INVALID
    );
    assert_eq!(
        verify_artifact(&data, &classical()).trust_status,
        TRUST_INVALID
    );
}

// --- Conformance case 15: ed25519-only signature relabelled hybrid ----------

#[test]
fn case15_relabelled_signature_is_malformed() {
    let data = vector("artifacts/15_hybrid_ed25519_only_relabelled.spif");
    // Wrong total length for the declared algorithm: INVALID in both
    // modes (never "unverifiable"), per SPEC §7.9.2.
    assert_eq!(
        verify_artifact(&data, &require_pq()).trust_status,
        TRUST_INVALID
    );
    assert_eq!(
        verify_artifact(&data, &classical()).trust_status,
        TRUST_INVALID
    );
}

// --- Hybrid revocation (§7.9.4) ----------------------------------------------

#[test]
fn hybrid_revocation_applies_and_forgery_is_counted() {
    let data = std::fs::read(fixture("hybrid_revoked.spif")).unwrap();
    let mut opts = require_pq();
    opts.revocation_file = Some(fixture("hybrid_revocations.json"));
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_REVOKED, "errors: {:?}", report.errors);
    assert_eq!(report.revocations_applied.len(), 1);
    assert_eq!(report.forged_revocations, 0);

    let mut opts = require_pq();
    opts.revocation_file = Some(fixture("hybrid_revocations_forged.json"));
    let report = verify_artifact(&data, &opts);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert_eq!(report.forged_revocations, 1);
    assert!(report.revocations_applied.is_empty());
}

// --- Signer parsing (§7.9.1) ---------------------------------------------------

#[test]
fn signer_parsing_shapes() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let hybrid_id = STANDARD.encode(vec![7u8; 1984]);
    let (ed, ml) = parse_hybrid_signer(&hybrid_id).expect("hybrid shape parses");
    assert_eq!(ed.len(), 32);
    assert_eq!(ml.len(), 1952);
    assert!(parse_hybrid_signer(&STANDARD.encode(vec![7u8; 1952])).is_none());
    let pq_id = STANDARD.encode(vec![9u8; 1952]);
    assert_eq!(parse_pq_only_signer(&pq_id).unwrap().len(), 1952);
    assert!(parse_pq_only_signer(&hybrid_id).is_none());
    assert!(parse_hybrid_signer("not base64!!").is_none());
}
