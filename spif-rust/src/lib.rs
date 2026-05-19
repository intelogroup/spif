pub mod reader;
pub mod renderer;
pub mod streaming;
pub mod types;
pub mod writer;

pub use reader::SPIFReader;
pub use renderer::SPIFRenderer;
pub use types::*;
pub use writer::SPIFWriter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let doc = SPIFDocument {
            payload: vec![Node {
                id: "test".to_string(),
                node_type: "fact".to_string(),
                value: Value::Text("Rust is great".to_string()),
                confidence: Distribution::certain("epistemic"),
                refs: vec![],
            }],
            provenance: Some(Provenance {
                source_model: "manual".to_string(),
                timestamp_ms: 123456789,
                temperature: 0.0,
                input_hash: "".to_string(),
                context_ref: "".to_string(),
                model_version: "".to_string(),
            }),
            semantic: None,
            trace: vec![],
            trace_method: "post-hoc".to_string(),
            alternatives: vec![],
            delta: None,
            signature: None,
            signatures: vec![],
        };

        let writer = SPIFWriter::new();
        let data = writer.encode(&doc).unwrap();

        let reader = SPIFReader::new();
        let restored = reader.read(&data).unwrap();

        assert_eq!(doc.payload.len(), restored.payload.len());
        assert_eq!(doc.payload[0].id, restored.payload[0].id);
        assert_eq!(doc.payload[0].value, restored.payload[0].value);
        assert_eq!(
            doc.provenance.as_ref().unwrap().timestamp_ms,
            restored.provenance.as_ref().unwrap().timestamp_ms
        );
    }
}
