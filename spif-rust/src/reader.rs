use crate::types::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use byteorder::{BigEndian, ReadBytesExt};
use ciborium::de::from_reader;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use flate2::read::ZlibDecoder;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read};

/// Deserializes SPIF documents from raw bytes.
///
/// # Security model
///
/// SHA-256 checksums detect *accidental* corruption (bit rot, truncation).
/// They do **not** protect against an attacker who modifies content and
/// recomputes the checksum.  Set `require_signature = true` in production
/// pipelines where tamper-evidence against intentional substitution matters.
pub struct SPIFReader {
    pub require_signature: bool,
}

impl Default for SPIFReader {
    fn default() -> Self {
        Self {
            require_signature: false,
        }
    }
}

impl SPIFReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a reader that rejects unsigned documents.
    pub fn strict() -> Self {
        Self {
            require_signature: true,
        }
    }

    pub fn read(&self, data: &[u8]) -> Result<SPIFDocument> {
        // 1. Minimum length: magic (8) + version (1) + flags (1)
        if data.len() < MAGIC.len() + 2 {
            return Err(anyhow!("Data too short to be a SPIF document"));
        }

        // 2. Magic bytes
        if &data[0..MAGIC.len()] != MAGIC {
            return Err(anyhow!(
                "Invalid magic bytes: {} (expected {})",
                hex::encode(&data[0..MAGIC.len()]),
                hex::encode(MAGIC)
            ));
        }

        let mut cursor = Cursor::new(&data[MAGIC.len()..]);
        let version = cursor.read_u8()?;
        let _flags = cursor.read_u8()?;

        // 3. Version check
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(anyhow!("Unsupported SIF version: 0x{:02x}", version));
        }

        let mut document_data = SPIFDocument {
            payload: Vec::new(),
            provenance: None,
            semantic: None,
            trace: Vec::new(),
            trace_method: "post-hoc".to_string(),
            alternatives: Vec::new(),
            delta: None,
            signature: None,
            signatures: Vec::new(),
            task_info: None,
        };

        let mut checksum_seen = false;
        let mut compressed = false; // set when FLAG_COMPRESSED is seen in HEADER chunk
        let mut current_pos = MAGIC.len() + 2;

        while current_pos < data.len() {
            let mut chunk_cursor = Cursor::new(&data[current_pos..]);
            let chunk_type = chunk_cursor.read_u8()?;
            let chunk_len = chunk_cursor.read_u32::<BigEndian>()?;
            let payload_start = current_pos + 5;
            let payload_end = payload_start + chunk_len as usize;

            if payload_end > data.len() {
                return Err(anyhow!(
                    "Chunk 0x{:02x} claims {} bytes but only {} remain",
                    chunk_type,
                    chunk_len,
                    data.len().saturating_sub(payload_start)
                ));
            }

            let payload = &data[payload_start..payload_end];

            match chunk_type {
                CHUNK_HEADER => {
                    // Parse flags2 to detect compression.
                    // HEADER CBOR is: {"version": u8, "flags": u8, "flags2": u8, "created_ms": u64}
                    #[derive(serde::Deserialize, Default)]
                    struct HeaderPayload {
                        #[serde(default)]
                        flags2: u8,
                    }
                    if let Ok(h) = from_reader::<HeaderPayload, _>(payload) {
                        if h.flags2 & FLAG_COMPRESSED != 0 {
                            compressed = true;
                        }
                    }
                }
                CHUNK_PROVENANCE => {
                    // PROVENANCE is never compressed — read raw.
                    document_data.provenance = Some(from_reader(payload)?);
                }
                CHUNK_SEMANTIC => {
                    document_data.semantic =
                        Some(from_reader(&*cbor_payload(payload, compressed)?)?);
                }
                CHUNK_TRACE => {
                    #[derive(serde::Deserialize)]
                    struct TraceWrapper {
                        method: String,
                        steps: Vec<TraceStep>,
                    }
                    let tw: TraceWrapper = from_reader(&*cbor_payload(payload, compressed)?)?;
                    document_data.trace_method = tw.method;
                    document_data.trace = tw.steps;
                }
                CHUNK_PAYLOAD => {
                    document_data.payload = from_reader(&*cbor_payload(payload, compressed)?)?;
                }
                CHUNK_ALTS => {
                    // The outer wrapper carries `normalized` (Python format).
                    // Each alt only has `weight` + `nodes` in Python-written files.
                    // We read the outer normalized and apply it to each alternative.
                    #[derive(serde::Deserialize)]
                    #[allow(dead_code)] // `normalized` is deserialized but outer wrapper takes precedence
                    struct AltItem {
                        weight: f64,
                        nodes: Vec<Node>,
                        // Per-element normalized (present in Rust-written files); overridden by
                        // the outer wrapper's normalized to match Python format semantics.
                        #[serde(default = "crate::types::default_true")]
                        normalized: bool,
                    }
                    #[derive(serde::Deserialize)]
                    struct AltsWrapper {
                        #[serde(default = "crate::types::default_true")]
                        normalized: bool,
                        alts: Vec<AltItem>,
                    }
                    let aw: AltsWrapper = from_reader(&*cbor_payload(payload, compressed)?)?;
                    let outer_normalized = aw.normalized;
                    document_data.alternatives = aw
                        .alts
                        .into_iter()
                        .map(|a| Alternative {
                            weight: a.weight,
                            nodes: a.nodes,
                            normalized: outer_normalized,
                        })
                        .collect();
                }
                CHUNK_DELTA => {
                    document_data.delta = Some(from_reader(&*cbor_payload(payload, compressed)?)?);
                }
                CHUNK_SIGNATURE => {
                    document_data.signature = Some(from_reader(payload)?);
                }
                CHUNK_MULTISIG => {
                    document_data.signatures = from_reader(payload)?;
                }
                CHUNK_TASK => {
                    document_data.task_info = Some(from_reader(payload)?);
                }
                CHUNK_CHECKSUM => {
                    let expected_checksum = payload;
                    let body = &data[0..current_pos];
                    let mut hasher = Sha256::new();
                    hasher.update(body);
                    let actual_checksum = hasher.finalize();
                    if actual_checksum.as_slice() != expected_checksum {
                        return Err(anyhow!(
                            "Checksum mismatch: stored={}, computed={}",
                            hex::encode(expected_checksum),
                            hex::encode(actual_checksum)
                        ));
                    }
                    checksum_seen = true;
                }
                _ => {
                    // Unknown chunk — skip for forward compatibility.
                }
            }

            current_pos = payload_end;
        }

        // 4. CHECKSUM is mandatory
        if !checksum_seen {
            return Err(anyhow!(
                "No CHECKSUM chunk found — document may be truncated or corrupted"
            ));
        }

        // 5. PAYLOAD is mandatory (spec requires at least one node)
        if document_data.payload.is_empty() {
            return Err(anyhow!("Missing or empty required PAYLOAD chunk"));
        }

        // 6. Validate Distribution fields in all nodes and trace steps
        for node in &document_data.payload {
            node.confidence
                .validate()
                .map_err(|e| anyhow!("Node '{}': {}", node.id, e))?;
        }
        for step in &document_data.trace {
            step.confidence
                .validate()
                .map_err(|e| anyhow!("TraceStep '{}': {}", step.id, e))?;
        }

        // 7. DAG cycle/dangling-dep validation
        validate_payload_dag(&document_data.payload)?;
        if !document_data.trace.is_empty() {
            validate_trace_dag(&document_data.trace)?;
        }

        // 8. Signature enforcement
        let mut signatures: Vec<&crate::types::Signature> = Vec::new();
        if let Some(signature) = document_data.signature.as_ref() {
            signatures.push(signature);
        }
        signatures.extend(document_data.signatures.iter());

        if self.require_signature {
            if signatures.is_empty() {
                return Err(anyhow!(
                    "Document is unsigned. SPIFReader was created with require_signature=true \
                     — sign the document before distributing it."
                ));
            }
            self.verify_signatures_internal(&signatures, data)?;
        }

        Ok(document_data)
    }

    fn verify_signatures_internal(&self, signatures: &[&crate::types::Signature], data: &[u8]) -> Result<()> {
        if signatures.is_empty() {
            return Ok(());
        }

        let auth_offset = find_first_auth_chunk_offset(data).ok_or_else(|| {
            anyhow!(
                "Document advertises signature data but no SIGNATURE/MULTISIG chunk \
                 was found before CHECKSUM"
            )
        })?;
        let body_to_sign = &data[..auth_offset];

        for signature in signatures {
            if signature.algorithm != "ed25519" {
                return Err(anyhow!(
                    "Unsupported signature algorithm '{}'; only ed25519 is supported",
                    signature.algorithm
                ));
            }

            let pub_bytes = STANDARD.decode(signature.signer.as_bytes()).map_err(|e| {
                anyhow!("Signature verification failed: invalid base64 signer: {e}")
            })?;
            let pub_bytes: [u8; 32] = pub_bytes.as_slice().try_into().map_err(|_| {
                anyhow!("Signature verification failed: signer public key must decode to 32 bytes")
            })?;
            let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
                .map_err(|e| anyhow!("Signature verification failed: invalid public key: {e}"))?;
            let signature_bytes = Ed25519Signature::try_from(signature.signature.as_ref())
                .map_err(|e| {
                    anyhow!("Signature verification failed: invalid signature bytes: {e}")
                })?;
            verifying_key
                .verify(body_to_sign, &signature_bytes)
                .map_err(|e| anyhow!("Signature verification failed: invalid signature: {e}"))?;
        }

        Ok(())
    }

    /// Verify all present ed25519 signatures against the raw signing body.
    ///
    /// The signing body is every byte from MAGIC through the byte immediately
    /// before the first SIGNATURE or MULTISIG chunk. Returns `Ok(false)` when
    /// the document is unsigned, and an error if any present signature fails.
    pub fn verify_signature(&self, data: &[u8]) -> Result<bool> {
        let document = self.read(data)?;

        let mut signatures: Vec<&crate::types::Signature> = Vec::new();
        if let Some(signature) = document.signature.as_ref() {
            signatures.push(signature);
        }
        signatures.extend(document.signatures.iter());

        if signatures.is_empty() {
            return Ok(false);
        }

        self.verify_signatures_internal(&signatures, data)?;
        Ok(true)
    }
}

/// Return the CBOR payload bytes for a chunk, decompressing with zlib if needed.
/// PROVENANCE, SIGNATURE, MULTISIG, and CHECKSUM are never compressed; callers
/// that handle those pass the raw slice directly rather than calling this.
///
/// Returns `Cow::Borrowed` when uncompressed (zero copy) and `Cow::Owned` after
/// decompression. All callers immediately call `.as_slice()` and pass to
/// `from_reader()`, so the lifetime is always satisfied.
fn cbor_payload<'a>(payload: &'a [u8], compressed: bool) -> Result<Cow<'a, [u8]>> {
    if !compressed {
        return Ok(Cow::Borrowed(payload));
    }
    let mut decoder = ZlibDecoder::new(payload);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow!("zlib decompress failed: {}", e))?;
    Ok(Cow::Owned(decompressed))
}

fn find_first_auth_chunk_offset(data: &[u8]) -> Option<usize> {
    let mut pos = MAGIC.len() + 2;
    while pos + 5 <= data.len() {
        let chunk_type = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().ok()?) as usize;
        if chunk_type == CHUNK_SIGNATURE || chunk_type == CHUNK_MULTISIG {
            return Some(pos);
        }
        if chunk_type == CHUNK_CHECKSUM {
            return None;
        }
        pos = pos.checked_add(5 + len)?;
    }
    None
}

/// Validates the trace DAG using Kahn's topological sort algorithm.
/// Rejects duplicate step IDs, dangling dependency references, and cycles.
fn validate_trace_dag(steps: &[TraceStep]) -> Result<()> {
    // Check for duplicate IDs
    let mut seen: HashSet<&str> = HashSet::new();
    for s in steps {
        if !seen.insert(s.id.as_str()) {
            return Err(anyhow!("Duplicate TraceStep id: '{}'", s.id));
        }
    }

    // Fast-path: if no steps have any dependencies, return early
    if !steps.iter().any(|s| !s.deps.is_empty()) {
        return Ok(());
    }

    // Check for dangling deps
    let ids: HashSet<&str> = steps.iter().map(|s| s.id.as_str()).collect();
    for s in steps {
        for dep in &s.deps {
            if !ids.contains(dep.as_str()) {
                return Err(anyhow!(
                    "TraceStep '{}' references unknown dep '{}'",
                    s.id,
                    dep
                ));
            }
        }
    }

    // Kahn's algorithm — cycle detection
    let mut in_degree: HashMap<&str, usize> =
        steps.iter().map(|s| (s.id.as_str(), 0usize)).collect();
    let mut dependents: HashMap<&str, Vec<&str>> =
        steps.iter().map(|s| (s.id.as_str(), vec![])).collect();

    for s in steps {
        for dep in &s.deps {
            *in_degree.get_mut(s.id.as_str()).unwrap() += 1;
            dependents
                .get_mut(dep.as_str())
                .unwrap()
                .push(s.id.as_str());
        }
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut visited = 0usize;
    while let Some(node) = queue.pop_front() {
        visited += 1;
        for &child in dependents.get(node).map(Vec::as_slice).unwrap_or(&[]) {
            let deg = in_degree.get_mut(child).unwrap();
            *deg -= 1;
            if *deg == 0 {
                queue.push_back(child);
            }
        }
    }

    if visited != steps.len() {
        let cycle_members: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg > 0)
            .map(|(&id, _)| id)
            .collect();
        return Err(anyhow!(
            "Cycle detected in trace DAG involving steps: {:?}",
            cycle_members
        ));
    }

    Ok(())
}

/// Validates the payload DAG references using Kahn's topological sort algorithm.
/// Rejects duplicate node IDs, dangling references, and cycles.
fn validate_payload_dag(nodes: &[Node]) -> Result<()> {
    // Check for duplicate IDs
    let mut seen: HashSet<&str> = HashSet::new();
    for n in nodes {
        if !seen.insert(n.id.as_str()) {
            return Err(anyhow!("Duplicate Node id: '{}'", n.id));
        }
    }

    // Fast-path: if no nodes have references, return early
    if !nodes.iter().any(|n| !n.refs.is_empty()) {
        return Ok(());
    }

    // Check for dangling refs
    let ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    for n in nodes {
        for ref_id in &n.refs {
            if !ids.contains(ref_id.as_str()) {
                return Err(anyhow!(
                    "Node '{}' references unknown node_id '{}'",
                    n.id,
                    ref_id
                ));
            }
        }
    }

    // Kahn's algorithm — cycle detection
    let mut in_degree: HashMap<&str, usize> =
        nodes.iter().map(|n| (n.id.as_str(), 0usize)).collect();
    let mut dependents: HashMap<&str, Vec<&str>> =
        nodes.iter().map(|n| (n.id.as_str(), vec![])).collect();

    for n in nodes {
        for ref_id in &n.refs {
            *in_degree.get_mut(n.id.as_str()).unwrap() += 1;
            dependents
                .get_mut(ref_id.as_str())
                .unwrap()
                .push(n.id.as_str());
        }
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut visited = 0usize;
    while let Some(node) = queue.pop_front() {
        visited += 1;
        for &child in dependents.get(node).map(Vec::as_slice).unwrap_or(&[]) {
            let deg = in_degree.get_mut(child).unwrap();
            *deg -= 1;
            if *deg == 0 {
                queue.push_back(child);
            }
        }
    }

    if visited != nodes.len() {
        let cycle_members: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg > 0)
            .map(|(&id, _)| id)
            .collect();
        return Err(anyhow!(
            "Cycle detected in payload Node refs involving nodes: {:?}",
            cycle_members
        ));
    }

    Ok(())
}
