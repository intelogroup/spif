//! Regression tests for SPIF-RUST-NONCANONICAL-ACCEPT-001.
//!
//! The Rust reader used to accept non-canonical CBOR re-encodings that
//! spif-py rejects (SPEC §4.1 / §12.4): when a document carries a
//! signature, every chunk's CBOR must be canonical — definite lengths,
//! shortest-form arguments — and duplicate map keys are ambiguous in
//! every document. Three surfaces were confirmed divergent, each in an
//! indefinite-length and a long-form variant:
//!
//!   1. SIGNATURE chunk value encodings (kit cases 18/19),
//!   2. MULTISIG chunk top-level array header,
//!   3. REVOCATION chunk header — worst case: Rust verified the
//!      artifact AND applied the revocation Python rejects.
//!
//! The fix is one form gate in SPIFReader::read (a port of spif-py's
//! `_scan_cbor`), so these tests assert at both the reader level
//! (read() must fail) and the trust level (verify_artifact must not
//! report VALID / REVOKED). The mutated fixtures are built in-test
//! from kit artifacts by re-encoding one chunk's top-level header,
//! fixing chunk lengths, and recomputing the trailing CHECKSUM — the
//! same construction as the adversarial probes that opened the card.
//! Canonical controls pin the no-over-rejection side: everything
//! Python accepts must still be accepted byte-for-byte.

use sha2::{Digest, Sha256};
use spif_rust::trust::{verify_artifact, VerifyOptions, TRUST_INVALID, TRUST_REVOKED, TRUST_UNSIGNED, TRUST_VALID};
use spif_rust::SPIFReader;
use std::path::PathBuf;

const CHUNK_PAYLOAD: u8 = 0x04;
const CHUNK_SIGNATURE: u8 = 0x07;
const CHUNK_MULTISIG: u8 = 0x08;
const CHUNK_REVOCATION: u8 = 0x0B;
const CHUNK_CHECKSUM: u8 = 0xFF;

fn vector(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn verify(data: &[u8]) -> spif_rust::trust::VerificationReport {
    verify_artifact(data, &VerifyOptions::default())
}

fn read(data: &[u8]) -> anyhow::Result<spif_rust::types::SPIFDocument> {
    SPIFReader::new().read(data)
}

// --- Fixture surgery (mirrors the probe construction) ----------------------

/// Split a document into (11-byte head, [(chunk_type, payload)]),
/// stopping after the CHECKSUM chunk.
fn parse_chunks(data: &[u8]) -> (Vec<u8>, Vec<(u8, Vec<u8>)>) {
    let mut pos = 11; // magic(9) + version(1) + flags(1)
    let mut chunks = Vec::new();
    while pos < data.len() {
        let ctype = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
        chunks.push((ctype, data[pos + 5..pos + 5 + len].to_vec()));
        pos += 5 + len;
        if ctype == CHUNK_CHECKSUM {
            break;
        }
    }
    (data[..11].to_vec(), chunks)
}

/// Reassemble chunks (CHECKSUM dropped), recomputing the SHA-256
/// checksum over head + body like the writer does.
fn rebuild(head: &[u8], chunks: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (ctype, payload) in chunks {
        if *ctype == CHUNK_CHECKSUM {
            continue;
        }
        body.push(*ctype);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(payload);
    }
    let mut signed = head.to_vec();
    signed.extend_from_slice(&body);
    let digest = Sha256::digest(&signed);
    signed.push(CHUNK_CHECKSUM);
    signed.extend_from_slice(&32u32.to_be_bytes());
    signed.extend_from_slice(&digest);
    signed
}

#[derive(Clone, Copy)]
enum Form {
    /// Container/string header rewritten as indefinite-length (ai=31)
    /// with a trailing break marker.
    Indefinite,
    /// Header argument rewritten in long form (ai=24) with the same value.
    LongForm,
}

/// Re-encode the top-level item's header (definite short form assumed)
/// in a non-canonical form; the payload's semantics are unchanged.
fn reencode_top_header(payload: &[u8], form: Form) -> Vec<u8> {
    let first = payload[0];
    let major = first >> 5;
    let ai = first & 0x1F;
    assert!(ai < 24, "top item not short-form: {first:#x}");
    match form {
        Form::LongForm => {
            let mut out = vec![(major << 5) | 24, ai];
            out.extend_from_slice(&payload[1..]);
            out
        }
        Form::Indefinite => {
            assert!(matches!(major, 2 | 3 | 4 | 5), "indefinite invalid for major {major}");
            let mut out = vec![(major << 5) | 31];
            out.extend_from_slice(&payload[1..]);
            out.push(0xFF);
            out
        }
    }
}

/// Re-encode the first chunk of `chunk_type` in `form`, fixing lengths
/// and the checksum.
fn mutate_chunk(data: &[u8], chunk_type: u8, form: Form) -> Vec<u8> {
    let (head, mut chunks) = parse_chunks(data);
    let mut hit = false;
    for (ctype, payload) in &mut chunks {
        if *ctype == chunk_type && !hit {
            *payload = reencode_top_header(payload, form);
            hit = true;
        }
    }
    assert!(hit, "chunk {chunk_type:#x} not found");
    rebuild(&head, &chunks)
}

/// Replace the SIGNATURE chunk (a map) with a MULTISIG chunk ([map]).
fn sig_to_multisig(data: &[u8]) -> Vec<u8> {
    let (head, mut chunks) = parse_chunks(data);
    let mut hit = false;
    for (ctype, payload) in &mut chunks {
        if *ctype == CHUNK_SIGNATURE && !hit {
            *ctype = CHUNK_MULTISIG;
            let mut wrapped = vec![0x81];
            wrapped.extend_from_slice(payload);
            *payload = wrapped;
            hit = true;
        }
    }
    assert!(hit, "no SIGNATURE chunk");
    rebuild(&head, &chunks)
}

/// Drop every chunk of `chunk_type` (checksum recomputed).
fn strip_chunk(data: &[u8], chunk_type: u8) -> Vec<u8> {
    let (head, chunks) = parse_chunks(data);
    let kept: Vec<(u8, Vec<u8>)> = chunks
        .into_iter()
        .filter(|(t, _)| *t != chunk_type)
        .collect();
    rebuild(&head, &kept)
}

/// Value-level variant: re-encode the 64-byte signature byte string
/// inside the SIGNATURE map as an indefinite-length string (0x5F …
/// 0xFF) with the same bytes.
fn sig_indefinite_bstr(data: &[u8]) -> Vec<u8> {
    let (head, mut chunks) = parse_chunks(data);
    let mut hit = false;
    for (ctype, payload) in &mut chunks {
        if *ctype == CHUNK_SIGNATURE && !hit {
            let idx = payload
                .windows(2)
                .position(|w| w == [0x58, 0x40])
                .expect("signature bstr header 0x58 0x40 not found");
            let raw = payload[idx + 2..idx + 2 + 64].to_vec();
            let mut newp = payload[..idx].to_vec();
            newp.extend_from_slice(&[0x5F, 0x58, 0x40]);
            newp.extend_from_slice(&raw);
            newp.push(0xFF);
            newp.extend_from_slice(&payload[idx + 2 + 64..]);
            *payload = newp;
            hit = true;
        }
    }
    assert!(hit, "no SIGNATURE chunk");
    rebuild(&head, &chunks)
}

// --- Surface 1: SIGNATURE chunk (kit cases 18/19) ---------------------------

#[test]
fn indefinite_signature_map_is_rejected() {
    let data = vector("artifacts/18_neg_indefinite_signature_map.spif");
    let err = read(&data).expect_err("non-canonical SIGNATURE must fail the reader");
    assert!(
        err.to_string().contains("Non-canonical CBOR in SIGNATURE chunk"),
        "unexpected error: {err}"
    );
    assert_eq!(verify(&data).trust_status, TRUST_INVALID);
}

#[test]
fn longform_signature_header_is_rejected() {
    let data = vector("artifacts/19_neg_longform_signature_header.spif");
    let err = read(&data).expect_err("non-canonical SIGNATURE must fail the reader");
    assert!(
        err.to_string().contains("Non-canonical CBOR in SIGNATURE chunk"),
        "unexpected error: {err}"
    );
    assert_eq!(verify(&data).trust_status, TRUST_INVALID);
}

#[test]
fn indefinite_signature_byte_string_value_is_rejected() {
    // Deeper than the chunk's top header: a value inside the entry.
    let data = sig_indefinite_bstr(&vector("artifacts/01_valid_py.spif"));
    assert!(read(&data).is_err());
    assert_eq!(verify(&data).trust_status, TRUST_INVALID);
}

// --- Surface 2: MULTISIG chunk top-level array header -----------------------

#[test]
fn multisig_canonical_header_still_valid() {
    // Control: the same document with the canonical header verifies.
    let data = sig_to_multisig(&vector("artifacts/01_valid_py.spif"));
    assert!(read(&data).is_ok());
    assert_eq!(verify(&data).trust_status, TRUST_VALID);
}

#[test]
fn multisig_indefinite_header_is_rejected() {
    let canonical = sig_to_multisig(&vector("artifacts/01_valid_py.spif"));
    let data = mutate_chunk(&canonical, CHUNK_MULTISIG, Form::Indefinite);
    let err = read(&data).expect_err("non-canonical MULTISIG must fail the reader");
    assert!(
        err.to_string().contains("Non-canonical CBOR in MULTISIG chunk"),
        "unexpected error: {err}"
    );
    assert_eq!(verify(&data).trust_status, TRUST_INVALID);
}

#[test]
fn multisig_longform_header_is_rejected() {
    let canonical = sig_to_multisig(&vector("artifacts/01_valid_py.spif"));
    let data = mutate_chunk(&canonical, CHUNK_MULTISIG, Form::LongForm);
    assert!(read(&data).is_err());
    assert_eq!(verify(&data).trust_status, TRUST_INVALID);
}

// --- Surface 3: REVOCATION chunk header (must not be applied) ---------------

#[test]
fn revocation_indefinite_header_is_not_applied() {
    let data = mutate_chunk(
        &vector("artifacts/06_revoked_embedded.spif"),
        CHUNK_REVOCATION,
        Form::Indefinite,
    );
    let err = read(&data).expect_err("non-canonical REVOCATION must fail the reader");
    assert!(
        err.to_string().contains("Non-canonical CBOR in REVOCATION chunk"),
        "unexpected error: {err}"
    );
    let status = verify(&data).trust_status;
    assert_eq!(status, TRUST_INVALID);
    assert_ne!(status, TRUST_REVOKED, "the revocation must not be applied");
}

#[test]
fn revocation_longform_header_is_not_applied() {
    let data = mutate_chunk(
        &vector("artifacts/06_revoked_embedded.spif"),
        CHUNK_REVOCATION,
        Form::LongForm,
    );
    assert!(read(&data).is_err());
    let status = verify(&data).trust_status;
    assert_eq!(status, TRUST_INVALID);
    assert_ne!(status, TRUST_REVOKED, "the revocation must not be applied");
}

// --- Controls: canonical traffic and prior verdicts are unchanged -----------

#[test]
fn canonical_controls_are_unchanged() {
    let valid = vector("artifacts/01_valid_py.spif");
    assert!(read(&valid).is_ok());
    let report = verify(&valid);
    assert_eq!(report.trust_status, TRUST_VALID);
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);

    // The unmutated revocation control still applies.
    let revoked = vector("artifacts/06_revoked_embedded.spif");
    assert!(read(&revoked).is_ok());
    assert_eq!(verify(&revoked).trust_status, TRUST_REVOKED);

    // Duplicate SIGNATURE key (ambiguity) and trailing bytes stay INVALID.
    assert_eq!(
        verify(&vector("artifacts/17_neg_duplicate_signature_key.spif")).trust_status,
        TRUST_INVALID
    );
    assert_eq!(
        verify(&vector("artifacts/20_neg_trailing_bytes_after_checksum.spif")).trust_status,
        TRUST_INVALID
    );

    let unsigned = vector("artifacts/04_unsigned.spif");
    assert!(read(&unsigned).is_ok());
    assert_eq!(verify(&unsigned).trust_status, TRUST_UNSIGNED);
}

// --- Unsigned leniency: form is free, ambiguity is not (§4.1/§12.1) ---------

#[test]
fn unsigned_longform_payload_is_still_accepted() {
    // No signature => no canonical requirement; a long-form PAYLOAD
    // header in an unsigned document decodes exactly as before.
    let data = mutate_chunk(
        &vector("artifacts/04_unsigned.spif"),
        CHUNK_PAYLOAD,
        Form::LongForm,
    );
    assert!(read(&data).is_ok());
    assert_eq!(verify(&data).trust_status, TRUST_UNSIGNED);
}

#[test]
fn unsigned_duplicate_map_key_is_still_rejected() {
    // Kit case 21 minus its SIGNATURE chunk: the duplicate PROVENANCE
    // key is ambiguity, rejected with or without a signature.
    let data = strip_chunk(
        &vector("artifacts/21_neg_duplicate_key_provenance.spif"),
        CHUNK_SIGNATURE,
    );
    let err = read(&data).expect_err("duplicate map key must fail the reader");
    assert!(
        err.to_string()
            .contains("Ambiguous CBOR in PROVENANCE chunk: duplicate map key"),
        "unexpected error: {err}"
    );
}
