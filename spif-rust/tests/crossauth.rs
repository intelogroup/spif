//! One attestation per document (SPIF-CROSSAUTH-SIGNER-EXPANSION-001).
//!
//! SIGNATURE and MULTISIG are two encodings of the same claim — the
//! signer set, which is part of a document's meaning (SPEC §7.2). The
//! reader previously verified every entry of *both* chunks against the
//! same public signing body and reported the union as the attested
//! signer set. Anyone holding a signed envelope could therefore append
//! the *other* auth chunk type carrying their own entry, signed with
//! their own key over that public body, recompute the CHECKSUM, and be
//! reported as an attested signer of a VALID document — and, because
//! signer-set membership confers revocation authority, revoke the
//! victim's document.
//!
//! The rule now: a document carries exactly one attestation. read()
//! rejects an envelope carrying both chunk types — so a decodable
//! document holds at most one auth chunk whose entries are reported,
//! and the reported signer set (and revocation authority) derives only
//! from it. Honest single-auth documents, and unsigned documents, are
//! unaffected. Mirrors spif-py's tests/test_crossauth.py.

use ed25519_dalek::{Signer, SigningKey};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use spif_rust::trust::{
    attach_revocations, create_revocation, pubkey_b64, verify_artifact, VerifyOptions,
    TRUST_INVALID, TRUST_REVOKED, TRUST_UNSIGNED, TRUST_VALID,
};
use spif_rust::types::*;
use spif_rust::{SPIFReader, SPIFWriter};
use std::path::PathBuf;

const TS: u64 = 1_700_000_000_000;

fn key(label: &str) -> SigningKey {
    let seed = Sha256::digest(format!("spif-crossauth-test-key:{label}").as_bytes());
    SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
}

fn b64(k: &SigningKey) -> String {
    pubkey_b64(&k.verifying_key())
}

fn base_doc(value: &str) -> SPIFDocument {
    SPIFDocument {
        payload: vec![Node {
            id: "n1".to_string(),
            node_type: "fact".to_string(),
            value: Value::Text(value.to_string()),
            confidence: Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: Some(Provenance {
            source_model: "m".to_string(),
            timestamp_ms: TS,
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
        signature: None,
        signatures: vec![],
        task_info: None,
        revocations: vec![],
        timestamp_anchor: None,
    }
}

/// (chunk_type, offset, payload) for each chunk up to and including CHECKSUM.
fn chunks(data: &[u8]) -> Vec<(u8, usize, &[u8])> {
    let mut out = Vec::new();
    let mut off = MAGIC.len() + 2;
    while off < data.len() {
        let ct = data[off];
        let ln = u32::from_be_bytes(data[off + 1..off + 5].try_into().unwrap()) as usize;
        out.push((ct, off, &data[off + 5..off + 5 + ln]));
        off += 5 + ln;
        if ct == CHUNK_CHECKSUM {
            break;
        }
    }
    out
}

fn body_of(data: &[u8]) -> &[u8] {
    for (ct, off, _) in chunks(data) {
        if ct == CHUNK_SIGNATURE || ct == CHUNK_MULTISIG {
            return &data[..off];
        }
    }
    panic!("no auth chunk");
}

fn insert_before_checksum(data: &[u8], ctype: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&data[..MAGIC.len() + 2]);
    for (ct, _, p) in chunks(data) {
        if ct == CHUNK_CHECKSUM {
            continue;
        }
        body.push(ct);
        body.extend_from_slice(&(p.len() as u32).to_be_bytes());
        body.extend_from_slice(p);
    }
    body.push(ctype);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(payload);
    let digest = Sha256::digest(&body);
    body.push(CHUNK_CHECKSUM);
    body.extend_from_slice(&32u32.to_be_bytes());
    body.extend_from_slice(&digest);
    body
}

fn entry(key: &SigningKey, body: &[u8]) -> Signature {
    Signature {
        algorithm: "ed25519".to_string(),
        signer: b64(key),
        signature: ByteBuf::from(key.sign(body).to_bytes().to_vec()),
        key_id: String::new(),
    }
}

fn cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

/// Two-pass single-signature signing, mirroring `spif.crypto.sign_document`.
fn sign_single(k: &SigningKey, value: &str) -> Vec<u8> {
    let mut doc = base_doc(value);
    doc.signature = Some(Signature {
        algorithm: "ed25519".to_string(),
        signer: b64(k),
        signature: ByteBuf::from(vec![0u8; 64]),
        key_id: String::new(),
    });
    let writer = SPIFWriter::new();
    let dummy = writer.encode(&doc).unwrap();
    let body = body_of(&dummy).to_vec();
    doc.signature = Some(entry(k, &body));
    writer.encode(&doc).unwrap()
}

fn genuine_multisig(k1: &SigningKey, k2: &SigningKey) -> Vec<u8> {
    let mut doc = base_doc("multi");
    let dummy = Signature {
        algorithm: "ed25519".to_string(),
        signer: "x".to_string(),
        signature: ByteBuf::from(vec![0u8; 64]),
        key_id: String::new(),
    };
    doc.signatures = vec![dummy.clone(), dummy];
    let writer = SPIFWriter::new();
    let dummy_bytes = writer.encode(&doc).unwrap();
    let body = body_of(&dummy_bytes).to_vec();
    doc.signatures = vec![entry(k1, &body), entry(k2, &body)];
    writer.encode(&doc).unwrap()
}

fn forged_single_plus_multi() -> Vec<u8> {
    let (victim, attacker) = (key("victim"), key("attacker"));
    let data = sign_single(&victim, "victim");
    let body = body_of(&data).to_vec();
    let payload = cbor(&vec![entry(&attacker, &body)]);
    insert_before_checksum(&data, CHUNK_MULTISIG, &payload)
}

fn forged_multi_plus_single() -> Vec<u8> {
    let (victim, second, attacker) = (key("victim"), key("second"), key("attacker"));
    let data = genuine_multisig(&victim, &second);
    let body = body_of(&data).to_vec();
    let payload = cbor(&entry(&attacker, &body));
    insert_before_checksum(&data, CHUNK_SIGNATURE, &payload)
}

fn opts() -> VerifyOptions {
    VerifyOptions::default()
}

// --- Co-presence is rejected, both directions ---------------------------

#[test]
fn appended_multisig_to_single_signature_doc_rejected() {
    let forged = forged_single_plus_multi();
    let err = SPIFReader::new().read(&forged).unwrap_err();
    assert!(
        format!("{err}").contains("must not both be present"),
        "unexpected error: {err}"
    );
    assert!(SPIFReader::new().verify_signature(&forged).is_err());
    let rep = verify_artifact(&forged, &opts());
    assert_eq!(rep.trust_status, TRUST_INVALID);
    assert!(rep.signers.is_empty(), "signers: {:?}", rep.signers);
    assert!(!rep.signers.contains(&b64(&key("attacker"))));
}

#[test]
fn appended_signature_to_multisig_doc_rejected() {
    let forged = forged_multi_plus_single();
    let err = SPIFReader::new().read(&forged).unwrap_err();
    assert!(
        format!("{err}").contains("must not both be present"),
        "unexpected error: {err}"
    );
    assert!(SPIFReader::new().verify_signature(&forged).is_err());
    let rep = verify_artifact(&forged, &opts());
    assert_eq!(rep.trust_status, TRUST_INVALID);
    assert!(rep.signers.is_empty(), "signers: {:?}", rep.signers);
    assert!(!rep.signers.contains(&b64(&key("attacker"))));
}

#[test]
fn conformance_crossauth_vectors_rejected() {
    // The shared corpus cases 24/25, asserted against the Rust trust
    // layer directly (the conformance runner drives them through
    // spif-py; these pin the same expectation on this implementation).
    for name in [
        "24_neg_crossauth_multisig_appended.spif",
        "25_neg_crossauth_signature_appended.spif",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vectors/artifacts")
            .join(name);
        let data = std::fs::read(&path).unwrap();
        let rep = verify_artifact(&data, &opts());
        assert_eq!(rep.trust_status, TRUST_INVALID, "{name}");
        assert_eq!(rep.signature_status, "invalid", "{name}");
        assert!(rep.signers.is_empty(), "{name} signers: {:?}", rep.signers);
    }
}

// --- The escalation: an appended signer gains no revocation authority ---

#[test]
fn appended_signer_cannot_revoke_victims_document() {
    let attacker = key("attacker");
    let forged = forged_single_plus_multi();
    let stmt = create_revocation(&forged, &attacker, "compromised", None, None).unwrap();
    let attached = attach_revocations(&forged, &[stmt]).unwrap();
    let rep = verify_artifact(&attached, &opts());
    assert_ne!(rep.trust_status, TRUST_REVOKED);
    assert_eq!(rep.trust_status, TRUST_INVALID);
    assert!(rep.revocations_applied.is_empty());
}

// --- Honest documents are unaffected -------------------------------------

#[test]
fn honest_single_signature_still_verifies() {
    let victim = key("victim");
    let data = sign_single(&victim, "victim");
    let rep = verify_artifact(&data, &opts());
    assert_eq!(rep.trust_status, TRUST_VALID);
    assert_eq!(rep.signers, vec![b64(&victim)]);
    assert_eq!(SPIFReader::new().verify_signature(&data).unwrap(), true);
}

#[test]
fn honest_multisig_still_verifies() {
    let (victim, second) = (key("victim"), key("second"));
    let data = genuine_multisig(&victim, &second);
    let rep = verify_artifact(&data, &opts());
    assert_eq!(rep.trust_status, TRUST_VALID);
    assert_eq!(rep.signers, vec![b64(&victim), b64(&second)]);
    assert_eq!(SPIFReader::new().verify_signature(&data).unwrap(), true);
}

#[test]
fn genuine_signer_revocation_still_applies() {
    // Revocation authority derives from the (single) accepted auth
    // chunk's signer set: the real signer can still revoke.
    let victim = key("victim");
    let data = sign_single(&victim, "victim");
    let stmt = create_revocation(&data, &victim, "retracted", None, None).unwrap();
    let attached = attach_revocations(&data, &[stmt]).unwrap();
    let rep = verify_artifact(&attached, &opts());
    assert_eq!(rep.trust_status, TRUST_REVOKED);
    assert_eq!(rep.revocations_applied.len(), 1);
}

#[test]
fn unsigned_document_unaffected() {
    let data = SPIFWriter::new().encode(&base_doc("unsigned")).unwrap();
    let rep = verify_artifact(&data, &opts());
    assert_eq!(rep.trust_status, TRUST_UNSIGNED);
    assert!(rep.signers.is_empty());
    assert_eq!(SPIFReader::new().verify_signature(&data).unwrap(), false);
}

// --- Same-type duplicates are rejected (signer substitution) -------------
//
// The co-presence rule above closes the *other-type* append. A second
// chunk of the SAME auth type was the remaining cousin: the reader
// assigned per chunk (last-wins), so an appended second SIGNATURE chunk
// silently REPLACED the victim as the reported signer of a VALID
// document, and an appended second MULTISIG did the same to a genuine
// multi-signer set. spif-py's decode() rejects a second chunk of any
// core type (0x00..=0x0F, plus CHECKSUM) at parse time; the Rust reader
// now mirrors that rule with the same scope and error.

fn forged_single_plus_second_signature() -> Vec<u8> {
    let (victim, attacker) = (key("victim"), key("attacker"));
    let data = sign_single(&victim, "victim");
    let body = body_of(&data).to_vec();
    let payload = cbor(&entry(&attacker, &body));
    insert_before_checksum(&data, CHUNK_SIGNATURE, &payload)
}

fn forged_multisig_plus_second_multisig() -> Vec<u8> {
    let (victim, second, attacker) = (key("victim"), key("second"), key("attacker"));
    let data = genuine_multisig(&victim, &second);
    let body = body_of(&data).to_vec();
    let payload = cbor(&vec![entry(&attacker, &body)]);
    insert_before_checksum(&data, CHUNK_MULTISIG, &payload)
}

#[test]
fn duplicate_signature_chunk_substitution_rejected() {
    let forged = forged_single_plus_second_signature();
    let err = SPIFReader::new().read(&forged).unwrap_err();
    assert!(
        format!("{err}").contains("Duplicate chunk of type 0x07 is not allowed"),
        "unexpected error: {err}"
    );
    assert!(SPIFReader::new().verify_signature(&forged).is_err());
    let rep = verify_artifact(&forged, &opts());
    assert_eq!(rep.trust_status, TRUST_INVALID);
    // Neither the attacker (substituted) nor the victim is reported:
    // the envelope is undecodable, so it attests nobody.
    assert!(rep.signers.is_empty(), "signers: {:?}", rep.signers);
    assert!(!rep.signers.contains(&b64(&key("attacker"))));
    assert!(!rep.signers.contains(&b64(&key("victim"))));
}

#[test]
fn duplicate_multisig_chunk_substitution_rejected() {
    let forged = forged_multisig_plus_second_multisig();
    let err = SPIFReader::new().read(&forged).unwrap_err();
    assert!(
        format!("{err}").contains("Duplicate chunk of type 0x08 is not allowed"),
        "unexpected error: {err}"
    );
    assert!(SPIFReader::new().verify_signature(&forged).is_err());
    let rep = verify_artifact(&forged, &opts());
    assert_eq!(rep.trust_status, TRUST_INVALID);
    assert!(rep.signers.is_empty(), "signers: {:?}", rep.signers);
    assert!(!rep.signers.contains(&b64(&key("attacker"))));
    assert!(!rep.signers.contains(&b64(&key("victim"))));
    assert!(!rep.signers.contains(&b64(&key("second"))));
}

#[test]
fn duplicate_non_auth_core_chunk_rejected() {
    // The mirrored Python rule is class-level, not auth-only: a second
    // chunk of any core type is a format error. Pin it on PAYLOAD in an
    // unsigned document (the rule is not gated on signedness).
    let data = SPIFWriter::new().encode(&base_doc("unsigned")).unwrap();
    let payload_chunk = chunks(&data)
        .into_iter()
        .find(|(ct, _, _)| *ct == CHUNK_PAYLOAD)
        .map(|(_, _, p)| p.to_vec())
        .unwrap();
    let forged = insert_before_checksum(&data, CHUNK_PAYLOAD, &payload_chunk);
    let err = SPIFReader::new().read(&forged).unwrap_err();
    assert!(
        format!("{err}").contains("Duplicate chunk of type 0x04 is not allowed"),
        "unexpected error: {err}"
    );
    let rep = verify_artifact(&forged, &opts());
    assert_eq!(rep.trust_status, TRUST_INVALID);
}
