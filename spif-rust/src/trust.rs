//! SPIF v1.3 trust layer — revocation statements, timestamp anchors, and
//! the verification report. Rust parity for `spif.trust` in spif-py.
//!
//! Implements SPEC §7.7 (revocation), §7.8 (timestamp anchoring), and §8.1
//! (cross-document resolution policy). Everything here is offline by
//! construction: no function in this module performs network I/O.
//! Revocations arrive embedded in the artifact (REVOCATION chunk, 0x0B)
//! or out-of-band in a revocation-list file the caller supplies;
//! cross-document references resolve only from a caller-supplied local
//! bundle.
//!
//! Trust statuses (distinct from raw signature validity):
//!
//! ```text
//! VALID        signature valid, no valid revocation applies
//! REVOKED      signature cryptographically valid, but a valid
//!              signer-issued revocation applies — never reported as
//!              VALID, never conflated with INVALID
//! INVALID      a present signature fails, or the checksum fails
//! UNSIGNED     no signature present
//! UNVERIFIABLE a signature is present under an algorithm or key this
//!              verifier cannot check
//! ```

use crate::reader::SPIFReader;
use crate::types::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ciborium::de::from_reader;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const TRUST_VALID: &str = "VALID";
pub const TRUST_INVALID: &str = "INVALID";
pub const TRUST_REVOKED: &str = "REVOKED";
pub const TRUST_UNSIGNED: &str = "UNSIGNED";
pub const TRUST_UNVERIFIABLE: &str = "UNVERIFIABLE";

pub const TS_VERIFIED: &str = "verified";
pub const TS_UNVERIFIED: &str = "unverified";
pub const TS_ABSENT: &str = "absent";

pub const REASON_CODES: &[&str] = &["compromised", "retracted", "superseded", "other"];

pub const CROSS_DOC_PREFIX: &str = "spif:sha256:";

const MAX_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024; // mirrors reader.rs / spif-py

// ---------------------------------------------------------------------------
// Canonical CBOR (RFC 8949 deterministic encoding, matching cbor2
// canonical=True as used by spif-py)
// ---------------------------------------------------------------------------

fn encode_major(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn f16_to_f64(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((bits >> 10) & 0x1f) as i32;
    let frac = (bits & 0x3ff) as f64;
    match exp {
        0 => sign * (frac / 1024.0) * 2f64.powi(-14),
        31 => {
            if frac == 0.0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        e => sign * (1.0 + frac / 1024.0) * 2f64.powi(e - 15),
    }
}

/// Convert f32 to f16 bits with round-to-nearest-even. Only used after an
/// exact round-trip check, so rounding never affects emitted bytes.
fn f32_to_f16_bits(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let frac = bits & 0x7f_ffff;
    if exp == 0xff {
        // inf / nan
        return sign | if frac == 0 { 0x7c00 } else { 0x7e00 };
    }
    let e = exp - 112; // rebias: 127 -> 15
    if e >= 31 {
        return sign | 0x7c00; // overflow -> inf (round-trip check will reject)
    }
    if e <= 0 {
        // subnormal f16 or zero
        if e < -10 {
            return sign;
        }
        let m = frac | 0x80_0000;
        let shift = 14 - e;
        let mut half_frac = m >> shift;
        let round_bit = (m >> (shift - 1)) & 1;
        let sticky = m & ((1u32 << (shift - 1)) - 1);
        if round_bit == 1 && (sticky != 0 || half_frac & 1 == 1) {
            half_frac += 1;
        }
        return sign | half_frac as u16;
    }
    let mut half_frac = frac >> 13;
    let round_bit = (frac >> 12) & 1;
    let sticky = frac & 0xfff;
    if round_bit == 1 && (sticky != 0 || half_frac & 1 == 1) {
        half_frac += 1;
        if half_frac == 0x400 {
            // mantissa overflow bumps the exponent
            return sign | (((e as u16) + 1) << 10);
        }
    }
    sign | ((e as u16) << 10) | half_frac as u16
}

fn encode_float(out: &mut Vec<u8>, f: f64) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    if f.is_infinite() {
        if f > 0.0 {
            out.extend_from_slice(&[0xf9, 0x7c, 0x00]);
        } else {
            out.extend_from_slice(&[0xf9, 0xfc, 0x00]);
        }
        return;
    }
    // Shrink to f16, then f32, when the round-trip is exact (cbor2 canonical).
    let half = f32_to_f16_bits(f as f32);
    if f16_to_f64(half) == f {
        out.push(0xf9);
        out.extend_from_slice(&half.to_be_bytes());
        return;
    }
    let f32v = f as f32;
    if f32v as f64 == f {
        out.push(0xfa);
        out.extend_from_slice(&f32v.to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&f.to_be_bytes());
}

/// Canonically encode a ciborium `Value` (RFC 8949 §4.2 deterministic
/// encoding): shortest-form integers, shortest round-tripping floats,
/// map keys sorted by their encoded bytes.
pub fn canonical_cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out);
    out
}

fn encode_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Integer(i) => {
            let v: i128 = i128::from(i.clone());
            if v >= 0 {
                encode_major(out, 0, v as u64);
            } else {
                encode_major(out, 1, (-1 - v) as u64);
            }
        }
        Value::Float(f) => encode_float(out, *f),
        Value::Bytes(b) => {
            encode_major(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            encode_major(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            encode_major(out, 4, items.len() as u64);
            for item in items {
                encode_value(item, out);
            }
        }
        Value::Map(entries) => {
            encode_major(out, 5, entries.len() as u64);
            let mut keyed: Vec<(Vec<u8>, &Value)> = entries
                .iter()
                .map(|(k, v)| (canonical_cbor(k), v))
                .collect();
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            for (kbytes, v) in keyed {
                out.extend_from_slice(&kbytes);
                encode_value(v, out);
            }
        }
        Value::Tag(tag, inner) => {
            encode_major(out, 6, *tag);
            encode_value(inner, out);
        }
        _ => {
            // ciborium Value is non-exhaustive in 0.2; no other variant is
            // produced by SPIF documents.
            out.push(0xf6);
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk scanning helpers (raw byte level, mirroring spif-py's reader helpers)
// ---------------------------------------------------------------------------

/// Iterate framed chunks from the start of `data`, tolerantly: stops at
/// the first truncated header/payload. Returns (type, chunk_offset,
/// payload) triples.
fn scan_chunks(data: &[u8]) -> Vec<(u8, usize, &[u8])> {
    let mut out = Vec::new();
    let mut pos = MAGIC.len() + 2;
    while pos + 5 <= data.len() {
        let chunk_type = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let end = match (pos + 5).checked_add(len) {
            Some(e) if e <= data.len() => e,
            _ => break,
        };
        out.push((chunk_type, pos, &data[pos + 5..end]));
        pos = end;
    }
    out
}

fn find_first_auth_chunk_offset(data: &[u8]) -> Option<usize> {
    for (chunk_type, offset, _) in scan_chunks(data) {
        if chunk_type == CHUNK_SIGNATURE || chunk_type == CHUNK_MULTISIG {
            return Some(offset);
        }
        if chunk_type == CHUNK_CHECKSUM {
            return None;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Artifact identity
// ---------------------------------------------------------------------------

/// The byte range covered by the artifact's signature(s): all bytes
/// before the first SIGNATURE/MULTISIG chunk; for an unsigned document,
/// all bytes before the CHECKSUM chunk. Stable under post-signature
/// chunk attachment (REVOCATION / TIMESTAMP) and checksum recomputation.
pub fn signing_body_of(data: &[u8]) -> &[u8] {
    if let Some(offset) = find_first_auth_chunk_offset(data) {
        return &data[..offset];
    }
    for (chunk_type, offset, _) in scan_chunks(data) {
        if chunk_type == CHUNK_CHECKSUM {
            return &data[..offset];
        }
    }
    data
}

/// SHA-256 hex of the signing body — the digest revocations bind (SPEC §7.7).
pub fn artifact_digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(signing_body_of(data)))
}

fn decompress_chunk(payload: &[u8], compressed: bool) -> Result<Vec<u8>> {
    if !compressed {
        return Ok(payload.to_vec());
    }
    let decoder = ZlibDecoder::new(payload);
    let mut limited = decoder.take(MAX_DECOMPRESSED_SIZE + 1);
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("zlib decompress failed: {e}"))?;
    if out.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(anyhow!(
            "Decompressed data size exceeds safety limit of {} bytes",
            MAX_DECOMPRESSED_SIZE
        ));
    }
    Ok(out)
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

/// Wrap a plain-map `confidence` value in the Distribution tag (1000),
/// mirroring `spif.writer._encode_node` / `_encode_step`. Already-tagged
/// values (Python-written documents) pass through unchanged.
///
/// Plain-map confidences come from serde-struct writers (spif-rust's own
/// `Distribution`), which serialize `p5`/`p95` as explicit nulls; Python
/// decodes those to None and `Distribution.to_dict()` omits them on
/// re-encode, so null p5/p95 entries are dropped here to match.
fn tag_confidence(v: &Value) -> Value {
    match v {
        Value::Map(entries) => {
            let filtered: Vec<(Value, Value)> = entries
                .iter()
                .filter(|(k, val)| {
                    !(matches!(k, Value::Text(t) if t == "p5" || t == "p95")
                        && matches!(val, Value::Null))
                })
                .map(|(k, val)| (k.clone(), val.clone()))
                .collect();
            Value::Tag(TAG_DISTRIBUTION, Box::new(Value::Map(filtered)))
        }
        _ => v.clone(),
    }
}

/// Tag plain-string refs as NodeRef (1001), mirroring `_encode_node`.
fn tag_ref(v: &Value) -> Value {
    match v {
        Value::Text(_) => Value::Tag(TAG_NODEREF, Box::new(v.clone())),
        _ => v.clone(),
    }
}

fn normalize_content_node(v: &Value) -> Value {
    if let Value::Map(entries) = v {
        let entries = entries
            .iter()
            .map(|(k, val)| {
                let new_val = match k {
                    Value::Text(t) if t == "confidence" => tag_confidence(val),
                    Value::Text(t) if t == "refs" => match val {
                        Value::Array(refs) => {
                            Value::Array(refs.iter().map(tag_ref).collect())
                        }
                        _ => val.clone(),
                    },
                    _ => val.clone(),
                };
                (k.clone(), new_val)
            })
            .collect();
        Value::Map(entries)
    } else {
        v.clone()
    }
}

fn normalize_content_step(v: &Value) -> Value {
    if let Value::Map(entries) = v {
        let entries = entries
            .iter()
            .map(|(k, val)| {
                let new_val = match k {
                    Value::Text(t) if t == "confidence" => tag_confidence(val),
                    _ => val.clone(),
                };
                (k.clone(), new_val)
            })
            .collect();
        Value::Map(entries)
    } else {
        v.clone()
    }
}

/// Content ID of a raw artifact: SHA-256 of the canonical CBOR of
/// `{payload, trace, provenance}`, mirroring
/// `SPIFWriter.compute_content_id` in spif-py (SPEC: content addressing).
///
/// Computed from the raw chunk values rather than the decoded document:
/// the wire provenance chunk carries fields the Rust `Provenance` struct
/// does not model (`training_data_hash`, `energy_wh`, `human_oversight`,
/// `nonce`), and Python's `compute_content_id` includes all 14 keys,
/// filling defaults for any a foreign writer omitted.
pub fn content_id(data: &[u8]) -> Result<String> {
    let chunks = scan_chunks(data);
    let mut compressed = false;
    let mut payload_raw: Option<&[u8]> = None;
    let mut trace_raw: Option<&[u8]> = None;
    let mut provenance_raw: Option<&[u8]> = None;
    for (chunk_type, _, payload) in &chunks {
        match *chunk_type {
            CHUNK_CHECKSUM => break,
            CHUNK_HEADER if !compressed => {
                if let Ok(hdr) = from_reader::<Value, _>(*payload) {
                    if let Value::Map(m) = &hdr {
                        if let Some(Value::Integer(f2)) = map_get(m, "flags2") {
                            compressed = i128::from(f2.clone()) & (FLAG_COMPRESSED as i128) != 0;
                        }
                    }
                }
            }
            CHUNK_PAYLOAD if payload_raw.is_none() => payload_raw = Some(payload),
            CHUNK_TRACE if trace_raw.is_none() => trace_raw = Some(payload),
            CHUNK_PROVENANCE if provenance_raw.is_none() => provenance_raw = Some(payload),
            _ => {}
        }
    }

    let payload_bytes = payload_raw.ok_or_else(|| anyhow!("Missing required PAYLOAD chunk"))?;
    let payload_val: Value = from_reader(&*decompress_chunk(payload_bytes, compressed)?)?;
    let payload_norm = match &payload_val {
        Value::Array(nodes) => {
            Value::Array(nodes.iter().map(normalize_content_node).collect())
        }
        _ => return Err(anyhow!("PAYLOAD chunk must decode to a list")),
    };

    let mut trace_norm = Value::Array(Vec::new());
    if let Some(raw) = trace_raw {
        let trace_val: Value = from_reader(&*decompress_chunk(raw, compressed)?)?;
        let steps = match &trace_val {
            Value::Array(steps) => Some(steps.clone()),
            Value::Map(m) => match map_get(m, "steps") {
                Some(Value::Array(steps)) => Some(steps.clone()),
                _ => None,
            },
            _ => None,
        };
        if let Some(steps) = steps {
            trace_norm = Value::Array(steps.iter().map(normalize_content_step).collect());
        }
    }

    let provenance_norm = match provenance_raw {
        None => Value::Null,
        Some(raw) => {
            let prov_val: Value = from_reader(raw)?;
            match prov_val {
                Value::Map(mut entries) => {
                    // Python's compute_content_id always emits all 14 keys;
                    // fill the defaults Python's Provenance would supply
                    // for keys a writer omitted.
                    let defaults: Vec<(&str, Value)> = vec![
                        ("model_version", Value::Text(String::new())),
                        ("temperature", Value::Float(0.0)),
                        ("input_hash", Value::Text(String::new())),
                        ("context_ref", Value::Text(String::new())),
                        ("attempt", Value::Integer(0.into())),
                        ("task_id", Value::Text(String::new())),
                        ("risk_tier", Value::Text(String::new())),
                        ("model_card", Value::Text(String::new())),
                        ("training_data_hash", Value::Text(String::new())),
                        ("energy_wh", Value::Float(0.0)),
                        ("human_oversight", Value::Text(String::new())),
                        ("nonce", Value::Text(String::new())),
                    ];
                    for (key, default) in defaults {
                        if map_get(&entries, key).is_none() {
                            entries.push((Value::Text(key.to_string()), default));
                        }
                    }
                    Value::Map(entries)
                }
                other => other,
            }
        }
    };

    let content = Value::Map(vec![
        (Value::Text("payload".to_string()), payload_norm),
        (Value::Text("trace".to_string()), trace_norm),
        (Value::Text("provenance".to_string()), provenance_norm),
    ]);
    Ok(hex::encode(Sha256::digest(canonical_cbor(&content))))
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

pub fn pubkey_b64(key: &VerifyingKey) -> String {
    STANDARD.encode(key.to_bytes())
}

/// Parse a base64 raw ed25519 public key; None if `text` is not one.
pub fn pubkey_from_b64(text: &str) -> Option<VerifyingKey> {
    let raw = STANDARD.decode(text).ok()?;
    let bytes: [u8; 32] = raw.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Resolve a signer id to its public key: caller-supplied map first,
/// then the self-describing form (the id itself is a base64 raw key).
fn resolve_signer_key(
    signer_id: &str,
    known_keys: Option<&HashMap<String, String>>,
) -> Option<VerifyingKey> {
    if let Some(map) = known_keys {
        if let Some(mapped) = map.get(signer_id) {
            return pubkey_from_b64(mapped);
        }
    }
    pubkey_from_b64(signer_id)
}

fn verify_ed25519(key: &VerifyingKey, signature_bytes: &[u8], body: &[u8]) -> bool {
    match Ed25519Signature::try_from(signature_bytes) {
        Ok(sig) => key.verify(body, &sig).is_ok(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Revocation statements
// ---------------------------------------------------------------------------

fn statement_signing_bytes(stmt: &RevocationStatement) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Text("artifact_digest".to_string()),
            Value::Text(stmt.artifact_digest.clone()),
        ),
        (
            Value::Text("signer".to_string()),
            Value::Text(stmt.signer.clone()),
        ),
        (
            Value::Text("issued_ms".to_string()),
            Value::Integer(stmt.issued_ms.into()),
        ),
        (
            Value::Text("reason".to_string()),
            Value::Text(stmt.reason.clone()),
        ),
    ]);
    canonical_cbor(&map)
}

/// Create a signed revocation statement for `artifact` (raw SPIF bytes).
/// Mirrors `spif.trust.create_revocation`: `signer_id` defaults to the
/// base64 raw public key; `issued_ms` defaults to now.
pub fn create_revocation(
    artifact: &[u8],
    private_key: &SigningKey,
    reason: &str,
    signer_id: Option<String>,
    issued_ms: Option<u64>,
) -> Result<RevocationStatement> {
    if !REASON_CODES.contains(&reason) {
        return Err(anyhow!(
            "reason must be one of {:?}, got {:?}",
            REASON_CODES, reason
        ));
    }
    let signer = signer_id.unwrap_or_else(|| pubkey_b64(&private_key.verifying_key()));
    let issued = issued_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    let mut stmt = RevocationStatement {
        artifact_digest: artifact_digest(artifact),
        signer,
        issued_ms: issued,
        reason: reason.to_string(),
        signature: Vec::new(),
    };
    let sig = private_key.sign(&statement_signing_bytes(&stmt));
    stmt.signature = sig.to_bytes().to_vec();
    Ok(stmt)
}

/// True iff the statement was issued by one of the artifact's signers
/// and its signature verifies under that signer's key.
pub fn statement_is_authoritative(
    stmt: &RevocationStatement,
    artifact_signer_ids: &HashSet<String>,
    known_keys: Option<&HashMap<String, String>>,
) -> bool {
    if !artifact_signer_ids.contains(&stmt.signer) {
        return false;
    }
    let key = match resolve_signer_key(&stmt.signer, known_keys) {
        Some(k) => k,
        None => return false,
    };
    verify_ed25519(&key, &stmt.signature, &statement_signing_bytes(stmt))
}

/// Write statements as a distributable revocation-list file (JSON):
/// `{"revocations": [...]}` with base64 signatures (SPEC §7.7).
pub fn save_revocation_list(statements: &[RevocationStatement], path: &Path) -> Result<()> {
    let items: Vec<serde_json::Value> = statements
        .iter()
        .map(|s| {
            serde_json::json!({
                "artifact_digest": s.artifact_digest,
                "signer": s.signer,
                "issued_ms": s.issued_ms,
                "reason": s.reason,
                "signature": STANDARD.encode(&s.signature),
            })
        })
        .collect();
    let payload = serde_json::json!({ "revocations": items });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

/// Load statements from a revocation-list file written by
/// `save_revocation_list`. Returns an empty list if the file is absent.
pub fn load_revocation_statements(path: &Path) -> Result<Vec<RevocationStatement>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let data: serde_json::Value = serde_json::from_str(&text)?;
    let mut out = Vec::new();
    if let Some(items) = data.get("revocations").and_then(|v| v.as_array()) {
        for item in items {
            let get_str = |k: &str| -> Result<String> {
                item.get(k)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow!("revocation entry missing string field {k:?}"))
            };
            out.push(RevocationStatement {
                artifact_digest: get_str("artifact_digest")?,
                signer: get_str("signer")?,
                issued_ms: item
                    .get("issued_ms")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("revocation entry missing issued_ms"))?,
                reason: get_str("reason")?,
                signature: STANDARD.decode(get_str("signature")?)?,
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Post-signature chunk attach / extract (REVOCATION / TIMESTAMP)
// ---------------------------------------------------------------------------

fn chunk_bytes(chunk_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(chunk_type);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Insert or replace a post-signature chunk before CHECKSUM and
/// recompute the checksum. The signing body is untouched, so existing
/// signatures remain valid.
pub fn attach_chunk(data: &[u8], chunk_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut parts: Vec<u8> = data[..MAGIC.len() + 2].to_vec();
    let mut inserted = false;
    let mut saw_checksum = false;
    for (ctype, _, chunk_payload) in scan_chunks(data) {
        if ctype == CHUNK_CHECKSUM {
            if !inserted {
                parts.extend_from_slice(&chunk_bytes(chunk_type, payload));
            }
            saw_checksum = true;
            break;
        }
        if ctype == chunk_type {
            if !inserted {
                parts.extend_from_slice(&chunk_bytes(chunk_type, payload));
                inserted = true;
            }
            // drop any duplicate of the same chunk type
        } else {
            parts.extend_from_slice(&chunk_bytes(ctype, chunk_payload));
        }
    }
    if !saw_checksum {
        return Err(anyhow!("no CHECKSUM chunk found"));
    }
    let checksum = Sha256::digest(&parts);
    parts.extend_from_slice(&chunk_bytes(CHUNK_CHECKSUM, &checksum));
    Ok(parts)
}

/// Return a copy of the artifact with `statements` embedded in its
/// REVOCATION chunk (merged with any already embedded, replacing the
/// chunk).
pub fn attach_revocations(data: &[u8], statements: &[RevocationStatement]) -> Result<Vec<u8>> {
    let existing = extract_revocations(data);
    let mut merged = existing.clone();
    for s in statements {
        if !merged.contains(s) {
            merged.push(s.clone());
        }
    }
    let value = Value::Array(
        merged
            .iter()
            .map(|s| {
                Value::Map(vec![
                    (
                        Value::Text("artifact_digest".to_string()),
                        Value::Text(s.artifact_digest.clone()),
                    ),
                    (
                        Value::Text("signer".to_string()),
                        Value::Text(s.signer.clone()),
                    ),
                    (
                        Value::Text("issued_ms".to_string()),
                        Value::Integer(s.issued_ms.into()),
                    ),
                    (
                        Value::Text("reason".to_string()),
                        Value::Text(s.reason.clone()),
                    ),
                    (
                        Value::Text("signature".to_string()),
                        Value::Bytes(s.signature.clone()),
                    ),
                ])
            })
            .collect(),
    );
    attach_chunk(data, CHUNK_REVOCATION, &canonical_cbor(&value))
}

/// Statements embedded in the artifact's REVOCATION chunk (raw scan —
/// does not require the document to decode cleanly).
pub fn extract_revocations(data: &[u8]) -> Vec<RevocationStatement> {
    let mut out = Vec::new();
    for (chunk_type, _, payload) in scan_chunks(data) {
        if chunk_type == CHUNK_CHECKSUM {
            break;
        }
        if chunk_type == CHUNK_REVOCATION {
            if let Ok(stmts) = from_reader::<Vec<RevocationStatement>, _>(payload) {
                out.extend(stmts);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Timestamp anchors (SPEC §6.13 / §7.8)
// ---------------------------------------------------------------------------

fn timestamp_token_body(digest: &str, time_ms: u64) -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Text("artifact_digest".to_string()),
            Value::Text(digest.to_string()),
        ),
        (
            Value::Text("time_ms".to_string()),
            Value::Integer(time_ms.into()),
        ),
    ]);
    canonical_cbor(&map)
}

/// Create a TSA countersignature anchor for `artifact` (raw SPIF bytes).
/// `authority` defaults to the base64 raw public key of the TSA key;
/// `time_ms` defaults to now. No network protocol is involved (§7.8).
pub fn create_timestamp_anchor(
    artifact: &[u8],
    tsa_private_key: &SigningKey,
    authority: Option<String>,
    time_ms: Option<u64>,
) -> TimestampAnchor {
    let authority =
        authority.unwrap_or_else(|| pubkey_b64(&tsa_private_key.verifying_key()));
    let t = time_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    let token = tsa_private_key.sign(&timestamp_token_body(&artifact_digest(artifact), t));
    TimestampAnchor {
        authority,
        time_ms: t,
        token: token.to_bytes().to_vec(),
    }
}

/// Return a copy of the artifact with `anchor` embedded in its
/// TIMESTAMP chunk (replacing any existing one).
pub fn attach_timestamp(data: &[u8], anchor: &TimestampAnchor) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::Text("authority".to_string()),
            Value::Text(anchor.authority.clone()),
        ),
        (
            Value::Text("time_ms".to_string()),
            Value::Integer(anchor.time_ms.into()),
        ),
        (Value::Text("token".to_string()), Value::Bytes(anchor.token.clone())),
    ]);
    attach_chunk(data, CHUNK_TIMESTAMP, &canonical_cbor(&value))
}

/// The artifact's embedded TIMESTAMP anchor, or None (raw scan).
pub fn extract_timestamp(data: &[u8]) -> Option<TimestampAnchor> {
    for (chunk_type, _, payload) in scan_chunks(data) {
        if chunk_type == CHUNK_CHECKSUM {
            break;
        }
        if chunk_type == CHUNK_TIMESTAMP {
            if let Ok(anchor) = from_reader::<TimestampAnchor, _>(payload) {
                return Some(anchor);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Verification report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReferenceResolution {
    /// The NodeRef string as it appears in the document.
    #[serde(rename = "ref")]
    pub ref_text: String,
    /// "local" | "cross-document"
    pub kind: String,
    /// "local" | "resolved" | "unresolved"
    pub status: String,
    /// Cross-document only.
    pub content_id: String,
    /// Cross-document only.
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerificationReport {
    /// "valid" | "invalid" | "unsigned" | "unverifiable"
    pub signature_status: String,
    /// VALID | INVALID | REVOKED | UNSIGNED | UNVERIFIABLE
    pub trust_status: String,
    /// "verified" | "unverified" | "absent"
    pub timestamp_status: String,
    pub artifact_digest: String,
    pub content_id: String,
    pub signers: Vec<String>,
    pub revocations_applied: Vec<RevocationStatement>,
    pub forged_revocations: usize,
    pub references: Vec<ReferenceResolution>,
    pub errors: Vec<String>,
}

impl VerificationReport {
    pub fn unresolved_references(&self) -> Vec<&ReferenceResolution> {
        self.references
            .iter()
            .filter(|r| r.status == "unresolved")
            .collect()
    }
}

/// Inputs to `verify_artifact` — the Rust counterpart of the keyword
/// arguments of `spif.trust.verify_artifact`.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Candidate revocation statements supplied out-of-band.
    pub revocations: Vec<RevocationStatement>,
    /// A revocation-list file (see `save_revocation_list`).
    pub revocation_file: Option<PathBuf>,
    /// Pinned TSA keys: authority -> base64 raw public key (SPEC §7.8).
    pub tsa_keys: HashMap<String, String>,
    /// Local bundle of raw SPIF artifacts for cross-document reference
    /// resolution (SPEC §8.1). Nothing is ever fetched.
    pub bundle: Vec<Vec<u8>>,
    /// Key resolution for non-self-describing (e.g. URL) signer ids:
    /// signer_id -> base64 raw public key.
    pub known_keys: HashMap<String, String>,
}

/// Verify an artifact end-to-end and report trust, not just signatures.
/// Mirrors `spif.trust.verify_artifact` semantics exactly.
pub fn verify_artifact(data: &[u8], opts: &VerifyOptions) -> VerificationReport {
    let digest = artifact_digest(data);
    let mut report = VerificationReport {
        signature_status: "invalid".to_string(),
        trust_status: TRUST_INVALID.to_string(),
        timestamp_status: TS_ABSENT.to_string(),
        artifact_digest: digest.clone(),
        content_id: String::new(),
        signers: Vec::new(),
        revocations_applied: Vec::new(),
        forged_revocations: 0,
        references: Vec::new(),
        errors: Vec::new(),
    };

    // --- Parse -------------------------------------------------------------
    let doc = match SPIFReader::new().read(data) {
        Ok(d) => d,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("Checksum") {
                report.errors.push(format!("checksum: {msg}"));
            } else {
                report.errors.push(format!("parse: {msg}"));
            }
            return report;
        }
    };
    report.content_id = content_id(data).unwrap_or_default();

    let mut sigs: Vec<&Signature> = Vec::new();
    if let Some(s) = doc.signature.as_ref() {
        sigs.push(s);
    }
    sigs.extend(doc.signatures.iter());
    report.signers = sigs.iter().map(|s| s.signer.clone()).collect();
    let signer_ids: HashSet<String> = report.signers.iter().cloned().collect();

    // --- Signature validity --------------------------------------------------
    if sigs.is_empty() {
        report.signature_status = "unsigned".to_string();
        report.trust_status = TRUST_UNSIGNED.to_string();
    } else {
        let body = signing_body_of(data);
        let mut any_invalid = false;
        let mut any_unverifiable = false;
        let mut verified = 0usize;
        for sig in &sigs {
            if sig.algorithm != "ed25519" {
                any_unverifiable = true;
                continue;
            }
            let key = match resolve_signer_key(&sig.signer, Some(&opts.known_keys)) {
                Some(k) => k,
                None => {
                    any_unverifiable = true;
                    continue;
                }
            };
            if verify_ed25519(&key, sig.signature.as_ref(), body) {
                verified += 1;
            } else {
                any_invalid = true;
            }
        }
        let _ = any_unverifiable; // folded into the verified==len check, as in Python
        if any_invalid {
            report.signature_status = "invalid".to_string();
            report.trust_status = TRUST_INVALID.to_string();
        } else if verified == sigs.len() {
            report.signature_status = "valid".to_string();
            report.trust_status = TRUST_VALID.to_string();
        } else {
            report.signature_status = "unverifiable".to_string();
            report.trust_status = TRUST_UNVERIFIABLE.to_string();
        }
    }

    // --- Revocations -----------------------------------------------------------
    let mut candidates: Vec<RevocationStatement> = doc.revocations.clone();
    candidates.extend(opts.revocations.iter().cloned());
    if let Some(file) = &opts.revocation_file {
        match load_revocation_statements(file) {
            Ok(stmts) => candidates.extend(stmts),
            Err(e) => report
                .errors
                .push(format!("revocation_file: {e}")),
        }
    }
    // Identical statements (same signed fields + same signature) are one
    // statement however many times they are supplied: process each unique
    // statement once so duplicates cannot amplify verification cost or
    // inflate the forgery count. Mirrors spif-py's verify_artifact
    // (Phase B parity); identity is the canonical signing bytes + signature.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut unique: Vec<RevocationStatement> = Vec::with_capacity(candidates.len());
    for stmt in candidates {
        let mut identity = statement_signing_bytes(&stmt);
        identity.extend_from_slice(b"|");
        identity.extend_from_slice(&stmt.signature);
        if seen.insert(identity) {
            unique.push(stmt);
        }
    }
    let candidates = unique;
    for stmt in &candidates {
        if stmt.artifact_digest != digest {
            continue; // about a different artifact — not a forgery signal
        }
        if statement_is_authoritative(stmt, &signer_ids, Some(&opts.known_keys)) {
            if !report.revocations_applied.contains(stmt) {
                report.revocations_applied.push(stmt.clone());
            }
        } else {
            report.forged_revocations += 1;
        }
    }
    if !report.revocations_applied.is_empty() && report.trust_status == TRUST_VALID {
        report.trust_status = TRUST_REVOKED.to_string();
    }

    // --- Timestamp (SPEC §7.8) ---------------------------------------------------
    report.timestamp_status = timestamp_status(&doc, &digest, &opts.tsa_keys);

    // --- Cross-document references (SPEC §8.1) ------------------------------------
    report.references = resolve_references(&doc, &opts.bundle);

    report
}

fn timestamp_status(
    doc: &SPIFDocument,
    digest: &str,
    tsa_keys: &HashMap<String, String>,
) -> String {
    let anchor = match &doc.timestamp_anchor {
        Some(a) => a,
        None => return TS_ABSENT.to_string(),
    };
    let pinned = match tsa_keys.get(&anchor.authority) {
        Some(k) => k,
        None => return TS_UNVERIFIED.to_string(),
    };
    let key = match pubkey_from_b64(pinned) {
        Some(k) => k,
        None => return TS_UNVERIFIED.to_string(),
    };
    if verify_ed25519(&key, &anchor.token, &timestamp_token_body(digest, anchor.time_ms)) {
        TS_VERIFIED.to_string()
    } else {
        TS_UNVERIFIED.to_string()
    }
}

fn resolve_references(doc: &SPIFDocument, bundle: &[Vec<u8>]) -> Vec<ReferenceResolution> {
    // Index the bundle by content_id -> payload node ids. An undecodable
    // bundle entry resolves nothing (mirrors spif-py).
    let mut bundle_index: HashMap<String, Vec<String>> = HashMap::new();
    for item in bundle {
        if let Ok(bdoc) = SPIFReader::new().read(item) {
            if let Ok(cid) = content_id(item) {
                bundle_index
                    .entry(cid)
                    .or_insert_with(|| bdoc.payload.iter().map(|n| n.id.clone()).collect());
            }
        }
    }

    let mut out = Vec::new();
    for node in &doc.payload {
        for ref_text in &node.refs {
            if ref_text.starts_with(CROSS_DOC_PREFIX) && ref_text.contains('#') {
                let rest = &ref_text[CROSS_DOC_PREFIX.len()..];
                let (cid, node_id) = match rest.split_once('#') {
                    Some((c, n)) => (c.to_string(), n.to_string()),
                    None => (rest.to_string(), String::new()),
                };
                let resolved = bundle_index
                    .get(&cid)
                    .map(|ids| ids.iter().any(|id| id == &node_id))
                    .unwrap_or(false);
                out.push(ReferenceResolution {
                    ref_text: ref_text.clone(),
                    kind: "cross-document".to_string(),
                    status: if resolved {
                        "resolved".to_string()
                    } else {
                        "unresolved".to_string()
                    },
                    content_id: cid,
                    node_id,
                });
            } else {
                out.push(ReferenceResolution {
                    ref_text: ref_text.clone(),
                    kind: "local".to_string(),
                    status: "local".to_string(),
                    content_id: String::new(),
                    node_id: String::new(),
                });
            }
        }
    }
    out
}
