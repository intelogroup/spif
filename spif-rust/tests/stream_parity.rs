//! Permanent regression suite for SPIF-RUST-STREAM-PARITY-001.
//!
//! Converted verbatim (assertions unchanged) from the loop probe
//! loop_stream_parity.rs (cycle 2026-11-14-1722). Invariant: a streamed
//! partial that is replayed/out-of-order, carries a hostile seq, or
//! contradicts the payload that later verifies must NOT be emitted as
//! PartialText / followed by Verified — the stream must fail closed
//! with an Error event, exactly as the Python reader does.

use spif_rust::{
    streaming::{SPIFStreamReader, SPIFStreamWriter, StreamEvent, CHUNK_PARTIAL_TEXT},
    types::*,
};

fn minimal_doc(value: &str) -> SPIFDocument {
    SPIFDocument {
        payload: vec![Node {
            id: "n1".into(),
            node_type: "fact".into(),
            value: Value::Text(value.into()),
            confidence: Distribution::certain("logical"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
        revocations: Vec::new(),
        timestamp_anchor: None,
    }
}

// Minimal hand CBOR encoder for the shapes this probe needs.
fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() < 24);
    let mut v = vec![0x60 + b.len() as u8];
    v.extend_from_slice(b);
    v
}
fn cbor_uint(n: u64) -> Vec<u8> {
    assert!(n < 24);
    vec![n as u8]
}
fn cbor_neg1() -> Vec<u8> {
    vec![0x20] // -1
}
fn partial_chunk(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![CHUNK_PARTIAL_TEXT];
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}
fn partial_payload(node_id: &str, text: &str, seq: Vec<u8>) -> Vec<u8> {
    let mut v = vec![0xa3]; // map(3)
    v.extend(cbor_text("node_id"));
    v.extend(cbor_text(node_id));
    v.extend(cbor_text("text"));
    v.extend(cbor_text(text));
    v.extend(cbor_text("seq"));
    v.extend(seq);
    v
}

fn collect(data: &[u8]) -> Vec<StreamEvent> {
    SPIFStreamReader::new().feed(data)
}
fn has_error(evs: &[StreamEvent]) -> bool {
    evs.iter().any(|e| matches!(e, StreamEvent::Error(_)))
}
fn partials(evs: &[StreamEvent]) -> usize {
    evs.iter()
        .filter(|e| matches!(e, StreamEvent::PartialText { .. }))
        .count()
}
fn has_verified(evs: &[StreamEvent]) -> bool {
    evs.iter().any(|e| matches!(e, StreamEvent::Verified { .. }))
}

#[test]
fn control_genuine_stream_verifies() {
    let doc = minimal_doc("The sky is blue.");
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(w.partial_text("The sky ", "n1").unwrap());
    out.extend(w.partial_text("is blue.", "n1").unwrap());
    out.extend(w.commit(&doc).unwrap());
    let evs = collect(&out);
    assert_eq!(partials(&evs), 2, "events: {evs:?}");
    assert!(has_verified(&evs), "events: {evs:?}");
    assert!(!has_error(&evs), "events: {evs:?}");
}

#[test]
fn seq_replay_and_reorder_rejected() {
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(partial_chunk(&partial_payload("n1", "x", cbor_uint(5))));
    out.extend(partial_chunk(&partial_payload("n1", "x", cbor_uint(5)))); // replay
    out.extend(partial_chunk(&partial_payload("n1", "y", cbor_uint(2)))); // reorder
    let evs = collect(&out);
    assert!(
        has_error(&evs) && partials(&evs) <= 1,
        "replayed/reordered partials must fail closed, events: {evs:?}"
    );
}

#[test]
fn hostile_seq_coercion_rejected() {
    // seq = -1
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(partial_chunk(&partial_payload("n1", "x", cbor_neg1())));
    let evs = collect(&out);
    assert!(
        has_error(&evs) && partials(&evs) == 0,
        "negative seq must fail closed, events: {evs:?}"
    );
    // seq as text
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(partial_chunk(&partial_payload("n1", "x", cbor_text("3"))));
    let evs = collect(&out);
    assert!(
        has_error(&evs) && partials(&evs) == 0,
        "text seq must fail closed, events: {evs:?}"
    );
}

#[test]
fn partial_contradicting_payload_not_verified() {
    let doc = minimal_doc("TRANSFER DENIED");
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(w.partial_text("TRANSFER APPROVED", "n1").unwrap());
    out.extend(w.commit(&doc).unwrap());
    let evs = collect(&out);
    assert!(
        !has_verified(&evs) && has_error(&evs),
        "a partial contradicting the verified payload must fail closed, events: {evs:?}"
    );
}
