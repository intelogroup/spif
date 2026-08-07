use crate::SPIFReader;
use wasm_bindgen::prelude::*;

/// Verify a .spif file's bytes. Mirrors `spif-viewer inspect --json`'s
/// _signed/_verified contract so the web verifier and CLI never disagree.
#[wasm_bindgen]
pub fn verify(data: &[u8]) -> Result<String, JsError> {
    let doc = SPIFReader::new()
        .read(data)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let signed = doc.signature.is_some() || !doc.signatures.is_empty();
    let verified = signed.then(|| SPIFReader::strict().read(data).is_ok());

    let mut value = serde_json::to_value(&doc).map_err(|e| JsError::new(&e.to_string()))?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert("_signed".to_string(), serde_json::json!(signed));
        map.insert("_verified".to_string(), serde_json::json!(verified));
    }

    serde_json::to_string_pretty(&value).map_err(|e| JsError::new(&e.to_string()))
}
