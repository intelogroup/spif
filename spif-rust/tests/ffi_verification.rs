// The "valid" outcome (a genuine signature that verifies) is already covered by
// compat.rs::test_python_signed_fixtures_verify_in_rust, which exercises the same
// underlying SPIFReader::verify_signature() this file's spif_document_parse fix now
// calls. Reproducing a from-scratch, correctly-signed SPIF document here would mean
// reimplementing the private two-pass signing_body computation in reader.rs as test
// code — coupling the test to an internal detail instead of testing the public
// contract. This file focuses on the two states that were actually broken:
// unsigned documents, and documents carrying a structurally-present but
// cryptographically bogus signature (the exact bug — see below).

use anyhow::Result;
use spif_rust::ffi;
use spif_rust::{SPIFDocument, SPIFWriter};
use std::ffi::CStr;

fn make_doc(signature: Option<spif_rust::Signature>) -> SPIFDocument {
    SPIFDocument {
        payload: vec![spif_rust::Node {
            id: "n1".to_string(),
            node_type: "text".to_string(),
            value: spif_rust::Value::Text("hello".to_string()),
            confidence: spif_rust::Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature,
        signatures: vec![],
        task_info: None,
    }
}

unsafe fn status_of(bytes: &[u8]) -> String {
    let wrapper = ffi::spif_document_parse(bytes.as_ptr(), bytes.len());
    assert!(!wrapper.is_null(), "lenient parse should succeed on structurally valid bytes");
    let status_ptr = ffi::spif_document_get_verification_status(wrapper);
    let status = CStr::from_ptr(status_ptr).to_string_lossy().into_owned();
    ffi::spif_document_free(wrapper);
    status
}

#[test]
fn test_ffi_verification_status_unsigned() -> Result<()> {
    let bytes = SPIFWriter::new().encode(&make_doc(None))?;
    assert_eq!(unsafe { status_of(&bytes) }, "unsigned");
    Ok(())
}

#[test]
fn test_ffi_verification_status_invalid_for_forged_signature() -> Result<()> {
    // This is the exact bug: a SIGNATURE chunk that is structurally present but
    // cryptographically bogus (zeroed key, zeroed signature bytes) used to be
    // reported as "valid" by spif_document_get_verification_status because the
    // old code only checked chunk presence, never called verify_signature().
    let doc = make_doc(Some(spif_rust::Signature {
        algorithm: "ed25519".to_string(),
        signer: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]),
        signature: serde_bytes::ByteBuf::from(vec![0u8; 64]),
        key_id: String::new(),
    }));
    let bytes = SPIFWriter::new().encode(&doc)?;
    assert_eq!(unsafe { status_of(&bytes) }, "invalid");
    Ok(())
}

#[test]
fn test_ffi_parse_strict_rejects_forged_signature() {
    let doc = make_doc(Some(spif_rust::Signature {
        algorithm: "ed25519".to_string(),
        signer: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]),
        signature: serde_bytes::ByteBuf::from(vec![0u8; 64]),
        key_id: String::new(),
    }));
    let bytes = SPIFWriter::new().encode(&doc).expect("encode");
    let wrapper = unsafe { ffi::spif_document_parse_strict(bytes.as_ptr(), bytes.len()) };
    assert!(
        wrapper.is_null(),
        "strict parse must reject a document whose signature fails verification"
    );
}
