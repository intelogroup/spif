pub use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub const MAGIC: &[u8] = b"\x89SPIF\r\n\x1a\n";
pub const FORMAT_VERSION: u8 = 0x02;
pub const SUPPORTED_VERSIONS: &[u8] = &[0x01, 0x02];

// Chunk type IDs
pub const CHUNK_HEADER: u8 = 0x00;
pub const CHUNK_PROVENANCE: u8 = 0x01;
pub const CHUNK_SEMANTIC: u8 = 0x02;
pub const CHUNK_TRACE: u8 = 0x03;
pub const CHUNK_PAYLOAD: u8 = 0x04;
pub const CHUNK_ALTS: u8 = 0x05;
pub const CHUNK_DELTA: u8 = 0x06;
pub const CHUNK_SIGNATURE: u8 = 0x07;
pub const CHUNK_MULTISIG: u8 = 0x08;
pub const CHUNK_TASK: u8 = 0x09;
pub const CHUNK_CHECKSUM: u8 = 0xFF;

// Flags bitmask
/// Extended flags byte 2 (in HEADER chunk): chunk payloads are zlib-compressed.
pub const FLAG_COMPRESSED: u8 = 0b00000001;
pub const FLAG_ZSTD: u8 = 0b00000010;
pub const FLAG_HAS_TASK: u8 = 0b00000100;

pub const FLAG_PROVENANCE: u8 = 0b00000001;
pub const FLAG_SEMANTIC: u8 = 0b00000010;
pub const FLAG_TRACE: u8 = 0b00000100;
pub const FLAG_ALTS: u8 = 0b00001000;
pub const FLAG_DELTA: u8 = 0b00010000;
pub const FLAG_SIGNATURE: u8 = 0b00100000;
pub const FLAG_MULTISIG: u8 = 0b01000000;

pub const TAG_DISTRIBUTION: u64 = 1000;
pub const TAG_NODEREF: u64 = 1001;
pub const TAG_EMBEDDING: u64 = 1002;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Distribution {
    pub mean: f64,
    #[serde(default)]
    pub var: f64,
    #[serde(default = "default_shape")]
    pub shape: String,
    #[serde(default = "default_semantics")]
    pub semantics: String,
    pub p5: Option<f64>,
    pub p95: Option<f64>,
}

fn default_shape() -> String {
    "gaussian".to_string()
}
fn default_semantics() -> String {
    "epistemic".to_string()
}

impl Distribution {
    pub fn certain(semantics: &str) -> Self {
        Self {
            mean: 1.0,
            var: 0.0,
            shape: "point".to_string(),
            semantics: semantics.to_string(),
            p5: None,
            p95: None,
        }
    }

    /// Validates distribution field constraints.
    /// Returns an error if `mean` is outside [0.0, 1.0] or `var` is negative.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.mean) {
            return Err(format!(
                "Distribution.mean must be in [0.0, 1.0], got {}",
                self.mean
            ));
        }
        if self.var < 0.0 {
            return Err(format!("Distribution.var must be >= 0.0, got {}", self.var));
        }
        Ok(())
    }
}

/// Custom deserializer for `Node.refs` that accepts both plain CBOR strings
/// and CBOR Tag(1001, str) (Python NodeRef encoding) transparently.
fn deser_refs<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values: Vec<Value> = Vec::deserialize(d)?;
    values
        .into_iter()
        .map(|v| match v {
            Value::Text(s) => Ok(s),
            Value::Tag(tag, inner) if tag == TAG_NODEREF => {
                if let Value::Text(s) = *inner {
                    Ok(s)
                } else {
                    Err(serde::de::Error::custom(
                        "NodeRef tag (1001) must contain a text string",
                    ))
                }
            }
            other => Err(serde::de::Error::custom(format!(
                "refs element must be a string or NodeRef tag(1001), got {:?}",
                other
            ))),
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Node {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub value: Value,
    pub confidence: Distribution,
    #[serde(default, deserialize_with = "deser_refs")]
    pub refs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TraceStep {
    pub id: String,
    #[serde(rename = "type")]
    pub step_type: String,
    pub content: Value,
    pub confidence: Distribution,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default)]
    pub alternatives: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Provenance {
    pub source_model: String,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub temperature: f64,
    #[serde(default)]
    pub input_hash: String,
    #[serde(default)]
    pub context_ref: String,
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub attempt: u32,
    #[serde(default)]
    pub task_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TaskInfo {
    pub task_id: String,
    #[serde(default)]
    pub attempt: u32,
    #[serde(default = "default_task_status")]
    pub status: String,
    #[serde(default)]
    pub total_ms: u64,
    #[serde(default)]
    pub tool_count: u32,
    #[serde(default)]
    pub error_count: u32,
}

fn default_task_status() -> String {
    "ok".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SemanticLayer {
    pub embedding: Vec<f32>,
    #[serde(default)]
    pub embedding_model: String,
    #[serde(default)]
    pub covariance: Vec<Vec<f32>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Alternative {
    pub weight: f64,
    pub nodes: Vec<Node>,
    #[serde(default = "default_true")]
    pub normalized: bool,
}

pub fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Delta {
    pub base_hash: String,
    pub changes: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Signature {
    pub algorithm: String,
    pub signer: String,
    pub signature: ByteBuf,
    #[serde(default)]
    pub key_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SPIFDocument {
    pub payload: Vec<Node>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticLayer>,
    #[serde(default)]
    pub trace: Vec<TraceStep>,
    #[serde(default = "default_trace_method")]
    pub trace_method: String,
    #[serde(default)]
    pub alternatives: Vec<Alternative>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(default)]
    pub signatures: Vec<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_info: Option<TaskInfo>,
}

fn default_trace_method() -> String {
    "post-hoc".to_string()
}
