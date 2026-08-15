use std::ffi::CString;
use std::os::raw::{c_char, c_double, c_int};
use std::slice;
use crate::{SPIFReader, SPIFDocument, Value};

/// Opaque wrapper struct that caches CStrings for FFI string accessors.
/// This prevents memory leaks and dangling pointers by linking their lifetime
/// to the wrapper lifecycle.
pub struct SpifDocumentWrapper {
    pub doc: SPIFDocument,
    pub source_model: CString,
    pub model_version: CString,
    pub prompt_hash: CString,
    pub task_id: CString,
    pub signer: CString,
    pub verification_status: CString,
    pub overall_confidence_mean: f64,
    pub overall_confidence_var: f64,
    pub cached_tool_calls: Vec<CachedToolCall>,
}

pub struct CachedToolCall {
    pub name: CString,
    pub is_error: bool,
    pub latency_ms: f64,
}

// Map helper to extract values from ciborium Value::Map
fn get_map_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Text(v_str) = v {
                    return Some(v_str);
                }
            }
        }
    }
    None
}

fn get_map_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                if let Value::Bool(b) = v {
                    return Some(*b);
                }
            }
        }
    }
    None
}

fn get_map_f64(map: &[(Value, Value)], key: &str) -> Option<f64> {
    for (k, v) in map {
        if let Value::Text(k_str) = k {
            if k_str == key {
                match v {
                    Value::Float(f) => return Some(*f),
                    Value::Integer(i) => {
                        let val: i128 = (*i).into();
                        return Some(val as f64);
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

impl SpifDocumentWrapper {
    /// `verification_status_str` must reflect an actual cryptographic verification
    /// outcome ("valid"/"unsigned"/"invalid"), computed by the caller — never derived
    /// here from mere presence of a SIGNATURE/MULTISIG chunk. A chunk being present
    /// only means the bytes deserialized as a Signature struct; it says nothing about
    /// whether they verify. See spif_document_parse / spif_document_parse_strict.
    fn new(doc: SPIFDocument, verification_status_str: &str) -> Self {
        let (source_model, model_version, prompt_hash, task_id) = if let Some(ref prov) = doc.provenance {
            (
                CString::new(prov.source_model.as_str()).unwrap_or_else(|_| CString::new("").unwrap()),
                CString::new(prov.model_version.as_str()).unwrap_or_else(|_| CString::new("").unwrap()),
                CString::new(prov.input_hash.as_str()).unwrap_or_else(|_| CString::new("").unwrap()),
                CString::new(prov.task_id.as_str()).unwrap_or_else(|_| CString::new("").unwrap()),
            )
        } else {
            (
                CString::new("").unwrap(),
                CString::new("").unwrap(),
                CString::new("").unwrap(),
                CString::new("").unwrap(),
            )
        };

        // Determine signer identity
        let signer_str = if !doc.signatures.is_empty() {
            doc.signatures
                .iter()
                .map(|s| s.signer.as_str())
                .collect::<Vec<&str>>()
                .join(",")
        } else if let Some(ref sig) = doc.signature {
            sig.signer.clone()
        } else {
            "".to_string()
        };
        let signer = CString::new(signer_str).unwrap_or_else(|_| CString::new("").unwrap());

        let verification_status = CString::new(verification_status_str).unwrap_or_else(|_| CString::new("invalid").unwrap());

        // Calculate confidence averages
        let mut total_mean = 0.0;
        let mut total_var = 0.0;
        let node_count = doc.payload.len();
        for node in &doc.payload {
            total_mean += node.confidence.mean;
            total_var += node.confidence.var;
        }
        let overall_confidence_mean = if node_count > 0 { total_mean / node_count as f64 } else { 1.0 };
        let overall_confidence_var = if node_count > 0 { total_var / node_count as f64 } else { 0.0 };

        // Parse tool calls in payload
        let mut cached_tool_calls = Vec::new();
        for node in &doc.payload {
            if node.node_type == "tool_call" {
                if let Value::Map(ref map) = node.value {
                    let name = get_map_str(map, "name").unwrap_or("");
                    let call_id = get_map_str(map, "call_id").unwrap_or("");

                    // Find corresponding tool_result node in payload
                    let mut is_error = false;
                    let mut latency_ms = 0.0;
                    for res_node in &doc.payload {
                        if res_node.node_type == "tool_result" {
                            if let Value::Map(ref res_map) = res_node.value {
                                if let Some(res_call_id) = get_map_str(res_map, "call_id") {
                                    if res_call_id == call_id {
                                        is_error = get_map_bool(res_map, "is_error").unwrap_or(false);
                                        latency_ms = get_map_f64(res_map, "latency_ms").unwrap_or(0.0);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    cached_tool_calls.push(CachedToolCall {
                        name: CString::new(name).unwrap_or_else(|_| CString::new("").unwrap()),
                        is_error,
                        latency_ms,
                    });
                }
            }
        }

        Self {
            doc,
            source_model,
            model_version,
            prompt_hash,
            task_id,
            signer,
            verification_status,
            overall_confidence_mean,
            overall_confidence_var,
            cached_tool_calls,
        }
    }
}

/// Parse a SPIF document in lenient/standard mode.
///
/// Unlike a bare structural presence check, this actively verifies any present
/// SIGNATURE/MULTISIG chunk and reports the real outcome via
/// spif_document_get_verification_status ("valid" / "unsigned" / "invalid") — a
/// signature chunk existing in the bytes is not itself proof of anything.
/// Verification failure does NOT fail the parse in lenient mode; use
/// spif_document_parse_strict to reject unsigned/invalid documents outright.
/// Returns a pointer to a SPIF document wrapper on success, or NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn spif_document_parse(
    data: *const u8,
    size: usize,
) -> *mut SpifDocumentWrapper {
    if data.is_null() || size == 0 {
        return std::ptr::null_mut();
    }
    let slice = slice::from_raw_parts(data, size);
    let reader = SPIFReader::new();
    match reader.read(slice) {
        Ok(doc) => {
            let status = match reader.verify_signature(slice) {
                Ok(true) => "valid",
                Ok(false) => "unsigned",
                Err(_) => "invalid",
            };
            Box::into_raw(Box::new(SpifDocumentWrapper::new(doc, status)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Parse a SPIF document in strict mode (requires a signature that verifies).
/// Returns a pointer to a SPIF document wrapper on success, or NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn spif_document_parse_strict(
    data: *const u8,
    size: usize,
) -> *mut SpifDocumentWrapper {
    if data.is_null() || size == 0 {
        return std::ptr::null_mut();
    }
    let slice = slice::from_raw_parts(data, size);
    let reader = SPIFReader::strict();
    match reader.read(slice) {
        // read() with require_signature=true already verified every present
        // signature before returning Ok, so "valid" is not an assumption here.
        Ok(doc) => Box::into_raw(Box::new(SpifDocumentWrapper::new(doc, "valid"))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free the SPIF document wrapper and release all associated memory.
#[no_mangle]
pub unsafe extern "C" fn spif_document_free(wrapper: *mut SpifDocumentWrapper) {
    if !wrapper.is_null() {
        let _ = Box::from_raw(wrapper);
    }
}

/// Get the cryptographic verification status of the SPIF document:
/// "valid" (a present signature verified), "unsigned" (no signature chunk),
/// or "invalid" (a signature chunk is present but failed verification).
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_verification_status(
    wrapper: *const SpifDocumentWrapper,
) -> *const c_char {
    wrapper.as_ref().map_or(std::ptr::null(), |w| w.verification_status.as_ptr())
}

/// Get the comma-separated signer public keys or identifiers.
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_signer(
    wrapper: *const SpifDocumentWrapper,
) -> *const c_char {
    wrapper.as_ref().map_or(std::ptr::null(), |w| w.signer.as_ptr())
}

/// Get the source model identifier.
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_model_id(
    wrapper: *const SpifDocumentWrapper,
) -> *const c_char {
    wrapper.as_ref().map_or(std::ptr::null(), |w| w.source_model.as_ptr())
}

/// Get the source model version/revision.
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_model_version(
    wrapper: *const SpifDocumentWrapper,
) -> *const c_char {
    wrapper.as_ref().map_or(std::ptr::null(), |w| w.model_version.as_ptr())
}

/// Get the input prompt hash (SHA-256).
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_prompt_hash(
    wrapper: *const SpifDocumentWrapper,
) -> *const c_char {
    wrapper.as_ref().map_or(std::ptr::null(), |w| w.prompt_hash.as_ptr())
}

/// Get the mean confidence score of the document payload assertions.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_confidence_mean(
    wrapper: *const SpifDocumentWrapper,
) -> c_double {
    wrapper.as_ref().map_or(0.0, |w| w.overall_confidence_mean)
}

/// Get the confidence variance score of the document payload assertions.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_confidence_var(
    wrapper: *const SpifDocumentWrapper,
) -> c_double {
    wrapper.as_ref().map_or(0.0, |w| w.overall_confidence_var)
}

/// Get the total number of tool calls in the document.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_tool_count(
    wrapper: *const SpifDocumentWrapper,
) -> c_int {
    wrapper.as_ref().map_or(0, |w| w.cached_tool_calls.len() as c_int)
}

/// Get the function/tool name at the given index.
/// Returned pointer points to memory owned by the wrapper.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_tool_call_name(
    wrapper: *const SpifDocumentWrapper,
    index: c_int,
) -> *const c_char {
    if index < 0 {
        return std::ptr::null();
    }
    wrapper.as_ref().map_or(std::ptr::null(), |w| {
        w.cached_tool_calls.get(index as usize).map_or(std::ptr::null(), |t| t.name.as_ptr())
    })
}

/// Check if the tool call at the given index failed.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_tool_call_error(
    wrapper: *const SpifDocumentWrapper,
    index: c_int,
) -> bool {
    if index < 0 {
        return false;
    }
    wrapper.as_ref().map_or(false, |w| {
        w.cached_tool_calls.get(index as usize).map_or(false, |t| t.is_error)
    })
}

/// Get the latency (in milliseconds) of the tool call at the given index.
#[no_mangle]
pub unsafe extern "C" fn spif_document_get_tool_call_latency(
    wrapper: *const SpifDocumentWrapper,
    index: c_int,
) -> c_double {
    if index < 0 {
        return 0.0;
    }
    wrapper.as_ref().map_or(0.0, |w| {
        w.cached_tool_calls.get(index as usize).map_or(0.0, |t| t.latency_ms)
    })
}

