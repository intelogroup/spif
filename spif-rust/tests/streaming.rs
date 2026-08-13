//! Integration tests for sif-rust streaming (SSIF).

use spif_rust::{
    streaming::{
        SPIFStreamReader, SPIFStreamWriter, StreamEvent, CHUNK_PARTIAL_TEXT, FLAG_STREAMING,
    },
    types::*,
    SPIFReader,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn minimal_node() -> Node {
    Node {
        id: "n1".to_string(),
        node_type: "fact".to_string(),
        value: Value::Text("The sky is blue.".to_string()),
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

fn stream_doc(doc: &SPIFDocument, tokens: &[&str]) -> Vec<u8> {
    let mut writer = SPIFStreamWriter::new();
    let mut out = writer.open(None).unwrap();
    for tok in tokens {
        out.extend(writer.partial_text(tok, "n1").unwrap());
    }
    out.extend(writer.commit(doc).unwrap());
    out
}

fn collect_events(data: &[u8]) -> Vec<StreamEvent> {
    let mut reader = SPIFStreamReader::new();
    reader.feed(data)
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

#[test]
fn test_open_starts_with_sif_magic() {
    let mut w = SPIFStreamWriter::new();
    let header = w.open(None).unwrap();
    assert_eq!(&header[..MAGIC.len()], MAGIC);
}

#[test]
fn test_open_sets_streaming_flag() {
    let mut w = SPIFStreamWriter::new();
    let header = w.open(None).unwrap();
    let flags = header[MAGIC.len() + 1];
    assert_ne!(flags & FLAG_STREAMING, 0, "FLAG_STREAMING must be set");
}

#[test]
fn test_partial_text_chunk_type_is_0x10() {
    let mut w = SPIFStreamWriter::new();
    w.open(None).unwrap();
    let chunk = w.partial_text("hi", "n1").unwrap();
    assert_eq!(chunk[0], CHUNK_PARTIAL_TEXT);
}

#[test]
fn test_complete_stream_readable_by_sif_reader() {
    let data = stream_doc(&minimal_doc(), &["The sky ", "is blue."]);
    let doc = SPIFReader::new().read(&data).unwrap();
    assert_eq!(doc.payload[0].id, "n1");
}

#[test]
fn test_zero_partial_chunks_still_valid() {
    let mut w = SPIFStreamWriter::new();
    let mut out = w.open(None).unwrap();
    out.extend(w.commit(&minimal_doc()).unwrap());
    let doc = SPIFReader::new().read(&out).unwrap();
    assert!(!doc.payload.is_empty());
}

#[test]
fn test_open_twice_panics() {
    let mut w = SPIFStreamWriter::new();
    w.open(None).unwrap();
    assert!(w.open(None).is_err());
}

#[test]
fn test_commit_twice_errors() {
    let mut w = SPIFStreamWriter::new();
    w.open(None).unwrap();
    w.commit(&minimal_doc()).unwrap();
    assert!(w.commit(&minimal_doc()).is_err());
}

// ---------------------------------------------------------------------------
// Checksum integrity
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_checksum_rejected() {
    let mut data = stream_doc(&minimal_doc(), &["secret"]);
    // Flip a byte in the stored checksum (last 32 bytes)
    let n = data.len();
    data[n - 1] ^= 0xFF;
    assert!(SPIFReader::new().read(&data).is_err());
}

#[test]
fn test_partial_chunk_tampering_detected() {
    let mut data = stream_doc(&minimal_doc(), &["secret"]);
    // Find and corrupt the PARTIAL_TEXT chunk payload
    let mut pos = MAGIC.len() + 2;
    while pos + 5 < data.len() {
        let ct = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if ct == CHUNK_PARTIAL_TEXT {
            data[pos + 5] ^= 0x01;
            break;
        }
        pos += 5 + len;
    }
    assert!(SPIFReader::new().read(&data).is_err());
}

// ---------------------------------------------------------------------------
// Stream reader events
// ---------------------------------------------------------------------------

#[test]
fn test_opened_event_fired() {
    let data = stream_doc(&minimal_doc(), &["hi"]);
    let events = collect_events(&data);
    assert!(events.iter().any(|e| matches!(e, StreamEvent::Opened)));
}

#[test]
fn test_partial_text_events_emitted() {
    let tokens = &["The sky ", "is ", "blue."];
    let data = stream_doc(&minimal_doc(), tokens);
    let events = collect_events(&data);
    let partials: Vec<&StreamEvent> = events
        .iter()
        .filter(|e| matches!(e, StreamEvent::PartialText { .. }))
        .collect();
    assert_eq!(partials.len(), tokens.len());
}

#[test]
fn test_partial_text_seq_is_monotonic() {
    let tokens = &["a", "b", "c", "d"];
    let data = stream_doc(&minimal_doc(), tokens);
    let events = collect_events(&data);
    let seqs: Vec<u32> = events
        .iter()
        .filter_map(|e| {
            if let StreamEvent::PartialText { seq, .. } = e {
                Some(*seq)
            } else {
                None
            }
        })
        .collect();
    let expected: Vec<u32> = (0..tokens.len() as u32).collect();
    assert_eq!(seqs, expected);
}

#[test]
fn test_verified_event_fires_at_end() {
    let data = stream_doc(&minimal_doc(), &["hi"]);
    let events = collect_events(&data);
    assert!(events
        .iter()
        .any(|e| matches!(e, StreamEvent::Verified { .. })));
}

#[test]
fn test_verified_event_contains_document() {
    let data = stream_doc(&minimal_doc(), &["hi"]);
    let events = collect_events(&data);
    let verified = events
        .iter()
        .find(|e| matches!(e, StreamEvent::Verified { .. }))
        .unwrap();
    if let StreamEvent::Verified { document } = verified {
        assert_eq!(document.payload[0].id, "n1");
    }
}

#[test]
fn test_no_events_after_verified() {
    let data = stream_doc(&minimal_doc(), &["hi"]);
    let mut reader = SPIFStreamReader::new();
    reader.feed(&data);
    assert!(reader.is_done());
    assert!(reader.feed(b"garbage").is_empty());
}

#[test]
fn test_incremental_feed_same_as_bulk() {
    let data = stream_doc(&minimal_doc(), &["tok1", "tok2"]);

    let bulk = collect_events(&data);
    let bulk_types: Vec<&str> = bulk
        .iter()
        .map(|e| match e {
            StreamEvent::Opened => "opened",
            StreamEvent::PartialText { .. } => "partial_text",
            StreamEvent::Verified { .. } => "verified",
            StreamEvent::StepAccepted { .. } => "step_accepted",
            StreamEvent::Error(_) => "error",
        })
        .collect();

    let mut byte_reader = SPIFStreamReader::new();
    let mut byte_events = Vec::new();
    for byte in &data {
        byte_events.extend(byte_reader.feed(&[*byte]));
    }
    let byte_types: Vec<&str> = byte_events
        .iter()
        .map(|e| match e {
            StreamEvent::Opened => "opened",
            StreamEvent::PartialText { .. } => "partial_text",
            StreamEvent::Verified { .. } => "verified",
            StreamEvent::StepAccepted { .. } => "step_accepted",
            StreamEvent::Error(_) => "error",
        })
        .collect();

    assert_eq!(bulk_types, byte_types);
}

#[test]
fn test_invalid_magic_emits_error() {
    let mut data = stream_doc(&minimal_doc(), &[]);
    data[0] = 0x00;
    let events = collect_events(&data);
    assert!(events.iter().any(|e| matches!(e, StreamEvent::Error(_))));
}

#[test]
fn test_ordinary_sif_file_readable_by_stream_reader() {
    use spif_rust::SPIFWriter;
    let data = SPIFWriter::new().encode(&minimal_doc()).unwrap();
    let events = collect_events(&data);
    assert!(events.iter().any(|e| matches!(e, StreamEvent::Opened)));
    assert!(events
        .iter()
        .any(|e| matches!(e, StreamEvent::Verified { .. })));
    assert!(!events
        .iter()
        .any(|e| matches!(e, StreamEvent::PartialText { .. })));
}

// ---------------------------------------------------------------------------
// require_signature enforcement on SIFStreamReader
// ---------------------------------------------------------------------------

#[test]
fn test_strict_stream_reader_rejects_unsigned() {
    let data = stream_doc(&minimal_doc(), &["hello", " world"]);
    let mut reader = SPIFStreamReader::strict();
    let events = reader.feed(&data);
    let errors: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, StreamEvent::Error(_)))
        .collect();
    assert!(
        !errors.is_empty(),
        "strict reader must emit Error for unsigned document"
    );
    assert!(reader.is_done());
}

#[test]
fn test_default_stream_reader_accepts_unsigned() {
    let data = stream_doc(&minimal_doc(), &["hello", " world"]);
    let events = collect_events(&data);
    let verified: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, StreamEvent::Verified { .. }))
        .collect();
    assert_eq!(
        verified.len(),
        1,
        "default reader must accept unsigned document"
    );
}

// Cross-implementation: read a Python-generated .sif file
// ---------------------------------------------------------------------------

#[test]
fn test_python_fixture_reads_in_rust() {
    let data = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resumability_study.spif"),
    )
    .expect("fixture not found");

    let doc = SPIFReader::new()
        .read(&data)
        .expect("Python-generated SIF must be readable in Rust");
    assert!(
        !doc.payload.is_empty(),
        "fixture must have at least one payload node"
    );
    assert!(doc.provenance.is_some(), "fixture must have provenance");
}

#[test]
fn test_python_fixture_streams_in_rust() {
    let data = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resumability_study.spif"),
    )
    .expect("fixture not found");

    // Feed byte-by-byte to exercise incremental path
    let mut reader = SPIFStreamReader::new();
    let mut all_events: Vec<StreamEvent> = Vec::new();
    for byte in &data {
        all_events.extend(reader.feed(&[*byte]));
        if reader.is_done() {
            break;
        }
    }

    let verified: Vec<_> = all_events
        .iter()
        .filter(|e| matches!(e, StreamEvent::Verified { .. }))
        .collect();
    assert_eq!(
        verified.len(),
        1,
        "streaming a Python fixture must emit Verified"
    );
}

#[test]
fn test_strict_stream_reader_rejects_python_unsigned_fixture() {
    let data = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resumability_study.spif"),
    )
    .expect("fixture not found");

    let mut reader = SPIFStreamReader::strict();
    let events = reader.feed(&data);
    let errors: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, StreamEvent::Error(_)))
        .collect();
    assert!(
        !errors.is_empty(),
        "unsigned Python fixture must fail strict stream reader"
    );
}

// Document fidelity
// ---------------------------------------------------------------------------

#[test]
fn test_many_tokens_fidelity() {
    let words: Vec<String> = (0..100).map(|i| format!("word{i} ")).collect();
    let full_text = words.join("");
    let doc = SPIFDocument {
        payload: vec![Node {
            id: "r".into(),
            node_type: "text".into(),
            value: Value::Text(full_text.clone()),
            confidence: Distribution::certain("epistemic"),
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
    };
    let token_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
    let data = stream_doc(&doc, &token_refs);
    let restored = SPIFReader::new().read(&data).unwrap();
    if let Value::Text(v) = &restored.payload[0].value {
        assert_eq!(*v, full_text);
    } else {
        panic!("expected text value");
    }
}
