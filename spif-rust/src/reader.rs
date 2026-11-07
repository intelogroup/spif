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

/// Cap on decompressed chunk payload size, mirroring `MAX_DECOMPRESSED_SIZE` in
/// spif-py's reader.py. Without this, a small zlib-bombed chunk (SEMANTIC, TRACE,
/// PAYLOAD, ALTS, or DELTA) drives unbounded allocation via `read_to_end`.
const MAX_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024; // 10MB

/// Cap on embedded REVOCATION statements, mirroring
/// `MAX_REVOCATION_STATEMENTS` in spif-py's reader.py (Phase B parity).
/// Without this, a document could embed an unbounded number of statements
/// and amplify verification cost for every verifier.
pub const MAX_REVOCATION_STATEMENTS: usize = 4096;

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

        // Canonical-form gate (SPEC §4.1 / §12.4), mirroring spif-py's
        // decode(): when the document carries a signature, every chunk's
        // CBOR must be canonical (definite lengths, shortest-form
        // arguments); duplicate map keys are rejected in every document.
        // The auth chunk sits after the content chunks in the stream, so
        // signed-ness is determined by a framing pre-scan
        // (find_first_auth_chunk_offset) before any chunk is decoded, and
        // each chunk payload is form-scanned at its decode site below.
        let canonical_required = find_first_auth_chunk_offset(data).is_some();

        // Wire 0x03 (SPEC §4.1): a signed document is additionally held
        // to the full IETF deterministic form. Legacy versions keep the
        // subset their writers promised.
        let deterministic = canonical_required && version == 0x03;

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
            revocations: Vec::new(),
            timestamp_anchor: None,
        };

        let mut checksum_seen = false;
        let mut signature_chunk_seen = false;
        let mut multisig_chunk_seen = false;
        let mut seen_core_chunks = [false; 0x10];
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

            // One chunk of each core type — mirrors spif-py's decode()
            // rule (`chunk_type <= 0x0F or chunk_type == CHUNK_CHECKSUM`):
            // a second chunk of any type in the core range 0x00..=0x0F,
            // or a second CHECKSUM (0xFF — Python's scan terminates at
            // CHECKSUM and rejects trailing bytes, so a repeated
            // CHECKSUM is never accepted there either), is a format
            // error, never last-wins. Without this check a repeated
            // SIGNATURE or MULTISIG chunk silently REPLACED the attested
            // signer set with the later chunk's entries
            // (SPIF-CROSSAUTH-SIGNER-EXPANSION-001, same-type cousin).
            // Extension chunk types (> 0x0F) are not covered, exactly as
            // in Python: they may repeat and are skipped below.
            if chunk_type <= 0x0F {
                if seen_core_chunks[chunk_type as usize] {
                    return Err(anyhow!(
                        "Duplicate chunk of type 0x{chunk_type:02x} is not allowed"
                    ));
                }
                seen_core_chunks[chunk_type as usize] = true;
            } else if chunk_type == CHUNK_CHECKSUM && checksum_seen {
                return Err(anyhow!(
                    "Duplicate chunk of type 0x{chunk_type:02x} is not allowed"
                ));
            }

            match chunk_type {
                CHUNK_HEADER => {
                    // Parse flags2 to detect compression.
                    // HEADER CBOR is: {"version": u8, "flags": u8, "flags2": u8, "created_ms": u64}
                    #[derive(serde::Deserialize, Default)]
                    struct HeaderPayload {
                        #[serde(default)]
                        flags2: u8,
                    }
                    assert_cbor_form(payload, "HEADER", canonical_required, deterministic)?;
                    if let Ok(h) = from_reader::<HeaderPayload, _>(payload) {
                        // zstd support (v1.1, FLAG_ZSTD) is not yet implemented in
                        // spif-rust — spif-py can write it, so without this check a
                        // zstd-compressed document would silently fall through to
                        // cbor_payload() as if uncompressed and fail with a confusing
                        // "Malformed CBOR" error instead of naming the real cause.
                        if h.flags2 & FLAG_ZSTD != 0 {
                            return Err(anyhow!(
                                "Document uses zstd compression (FLAG_ZSTD), which spif-rust \
                                 does not yet support reading. Only zlib-compressed \
                                 (FLAG_COMPRESSED) and uncompressed documents can be read."
                            ));
                        }
                        if h.flags2 & FLAG_COMPRESSED != 0 {
                            compressed = true;
                        }
                    }
                }
                CHUNK_PROVENANCE => {
                    // PROVENANCE is never compressed — read raw.
                    assert_cbor_form(payload, "PROVENANCE", canonical_required, deterministic)?;
                    document_data.provenance = Some(from_reader(payload)?);
                }
                CHUNK_SEMANTIC => {
                    let raw = cbor_payload(payload, compressed)?;
                    assert_cbor_form(&raw, "SEMANTIC", canonical_required, deterministic)?;
                    document_data.semantic = Some(from_reader(&*raw)?);
                }
                CHUNK_TRACE => {
                    #[derive(serde::Deserialize)]
                    struct TraceWrapper {
                        method: String,
                        steps: Vec<TraceStep>,
                    }
                    let raw = cbor_payload(payload, compressed)?;
                    assert_cbor_form(&raw, "TRACE", canonical_required, deterministic)?;
                    let tw: TraceWrapper = from_reader(&*raw)?;
                    document_data.trace_method = tw.method;
                    document_data.trace = tw.steps;
                }
                CHUNK_PAYLOAD => {
                    let raw = cbor_payload(payload, compressed)?;
                    assert_cbor_form(&raw, "PAYLOAD", canonical_required, deterministic)?;
                    document_data.payload = from_reader(&*raw)?;
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
                    let raw = cbor_payload(payload, compressed)?;
                    assert_cbor_form(&raw, "ALTS", canonical_required, deterministic)?;
                    let aw: AltsWrapper = from_reader(&*raw)?;
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
                    let raw = cbor_payload(payload, compressed)?;
                    assert_cbor_form(&raw, "DELTA", canonical_required, deterministic)?;
                    document_data.delta = Some(from_reader(&*raw)?);
                }
                CHUNK_SIGNATURE => {
                    signature_chunk_seen = true;
                    assert_cbor_form(payload, "SIGNATURE", canonical_required, deterministic)?;
                    document_data.signature = Some(from_reader(payload)?);
                }
                CHUNK_MULTISIG => {
                    multisig_chunk_seen = true;
                    assert_cbor_form(payload, "MULTISIG", canonical_required, deterministic)?;
                    document_data.signatures = from_reader(payload)?;
                }
                CHUNK_TASK => {
                    assert_cbor_form(payload, "TASK", canonical_required, deterministic)?;
                    document_data.task_info = Some(from_reader(payload)?);
                }
                CHUNK_ROLES => {
                    // spif-rust does not decode ROLES content (a
                    // pre-existing content gap, unchanged here), but the
                    // chunk's CBOR form is gated exactly as in spif-py,
                    // whose decode() loads — and therefore form-scans —
                    // the chunk.
                    assert_cbor_form(payload, "ROLES", canonical_required, deterministic)?;
                }
                CHUNK_REVOCATION => {
                    // Post-signature chunk (v1.3, SPEC §6.12): CBOR array of
                    // signed revocation statements. Never compressed.
                    assert_cbor_form(payload, "REVOCATION", canonical_required, deterministic)?;
                    document_data.revocations = from_reader(payload)?;
                    if document_data.revocations.len() > MAX_REVOCATION_STATEMENTS {
                        return Err(anyhow!(
                            "REVOCATION chunk has {} statements, exceeding the limit of {}",
                            document_data.revocations.len(),
                            MAX_REVOCATION_STATEMENTS
                        ));
                    }
                }
                CHUNK_TIMESTAMP => {
                    // Post-signature chunk (v1.3, SPEC §6.13): TSA timestamp
                    // anchor map. Never compressed.
                    assert_cbor_form(payload, "TIMESTAMP", canonical_required, deterministic)?;
                    document_data.timestamp_anchor = Some(from_reader(payload)?);
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
                    // CHECKSUM is the terminal chunk (mirrors spif-py's
                    // decode() step 3a): parsing stops here, and any bytes
                    // after it are a format error — never parsed. The
                    // checksum above and the signing-body scan both stop
                    // at the first CHECKSUM, so a WELL-FORMED chunk
                    // appended after it is invisible to every integrity
                    // check; if the loop went on, its last-wins assignment
                    // would silently replace signed content or the signer
                    // set (SPIF-POSTCHECKSUM-ACCEPT-001). The check is
                    // deliberately type-blind: it fires for appended chunk
                    // types the duplicate-chunk rule has never seen in
                    // this document, and for raw trailing garbage alike.
                    if payload_end != data.len() {
                        return Err(anyhow!(
                            "{} trailing byte(s) after CHECKSUM chunk",
                            data.len() - payload_end
                        ));
                    }
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

        // 4a. One document, one attestation (SPEC §7.2): SIGNATURE and
        // MULTISIG are two encodings of the same claim — the signer set,
        // which is part of the document's meaning. If both were accepted,
        // their entries would union into a signer set no signer attested:
        // any holder of a signed envelope could append the *other* auth
        // chunk type carrying their own entry, signed over the public
        // signing body, and be reported as an attested signer — gaining
        // the authority signer-set membership confers, e.g. revocation
        // (SPIF-CROSSAUTH-SIGNER-EXPANSION-001). Mirrors spif-py's
        // decode() rejection of the same envelope.
        if signature_chunk_seen && multisig_chunk_seen {
            return Err(anyhow!(
                "SIGNATURE and MULTISIG chunks must not both be present: \
                 a document carries exactly one attestation"
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
            if verifying_key.is_weak() {
                // Small-order keys are never legitimate signers, and
                // cofactored verification can accept forgeries under
                // them (see verify_ed25519 in trust.rs).
                return Err(anyhow!(
                    "Signature verification failed: signer public key is a weak (small-order) key"
                ));
            }
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
    let decoder = ZlibDecoder::new(payload);
    // Read one byte past the cap so a bomb that produces exactly MAX_DECOMPRESSED_SIZE
    // bytes isn't silently truncated into looking like a valid, in-limit payload.
    let mut limited = decoder.take(MAX_DECOMPRESSED_SIZE + 1);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow!("zlib decompress failed: {}", e))?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(anyhow!(
            "Decompressed data size exceeds safety limit of {} bytes",
            MAX_DECOMPRESSED_SIZE
        ));
    }
    Ok(Cow::Owned(decompressed))
}

/// Identity of a map key for duplicate detection, mirroring spif-py's
/// `_key_identity`: the canonical re-encoding of the decoded key, so two
/// byte-different encodings of the same key (short vs long-form length,
/// f32 vs f64) still collide. Falls back to the raw span when the key
/// cannot be round-tripped.
fn key_identity(span: &[u8]) -> Vec<u8> {
    match ciborium::de::from_reader::<ciborium::value::Value, _>(span) {
        Ok(value) => crate::trust::canonical_cbor(&value),
        Err(_) => span.to_vec(),
    }
}

/// One container frame of the CBOR form scan (see `assert_cbor_form`).
struct ScanFrame {
    /// Items still expected; `None` for an indefinite-length container
    /// (closed by a break marker instead of counting down). A map frame's
    /// count covers keys and values, so it starts at 2 * pair_count.
    remaining: Option<u64>,
    is_map: bool,
    next_is_key: bool,
    seen_keys: HashSet<Vec<u8>>,
    start: usize,
    /// The previous key's encoded span, for the deterministic
    /// (wire 0x03) key-order check.
    last_key: Option<Vec<u8>>,
}

/// Iterative raw-encoding CBOR scan — a faithful port of spif-py's
/// `_scan_cbor` (reader.py), run on one chunk's payload bytes before the
/// ciborium decode, exactly as `_cbor_load` runs it before cbor2.
///
/// Always enforced (every document, signed or unsigned): no duplicate
/// map keys — a duplicate is *ambiguity*, not encoding variability, and
/// decoders disagree on whether the first or last value wins.
///
/// Additionally enforced when `canonical` is true (the caller passes it
/// for every chunk of a document that carries a signature, which makes
/// §12.4's writer rule — canonical CBOR for all chunks when a signature
/// is present — reader-verifiable): definite lengths only and
/// shortest-form arguments — RFC 8949 §4.2 core deterministic encoding,
/// minus key sorting, which the legacy writers do not promise. Unsigned
/// documents keep §4.1/§12.1's accept-both leniency for indefinite-length
/// items and non-minimal forms.
///
/// Additionally enforced when `deterministic` is true (wire 0x03 signed
/// documents): the full IETF deterministic form — map keys in bytewise
/// order of their encodings, shortest-form floats with the single
/// canonical NaN, and minimal bignums (serialization checking in
/// draft-ietf-cbor-serialization's Appendix G sense).
///
/// The scan also rejects structural malformations ciborium would
/// otherwise tolerate in a chunk payload (reserved additional
/// information, a break marker outside an indefinite item, trailing
/// bytes after the chunk's single CBOR item), matching the failures
/// cbor2 + the scan produce in spif-py.
struct CborFormScan<'a> {
    data: &'a [u8],
    chunk_name: &'a str,
    canonical: bool,
    deterministic: bool,
    pos: usize,
    stack: Vec<ScanFrame>,
    root_done: bool,
    pending_bignum: bool,
}

impl CborFormScan<'_> {
    fn fail(&self, reason: &str) -> anyhow::Error {
        if self.canonical {
            anyhow!(
                "Non-canonical CBOR in {} chunk: {reason}",
                self.chunk_name
            )
        } else {
            anyhow!("Malformed CBOR in {} chunk: {reason}", self.chunk_name)
        }
    }

    fn fail_duplicate_key(&self) -> anyhow::Error {
        if self.canonical {
            anyhow!(
                "Non-canonical CBOR in {} chunk: duplicate map key",
                self.chunk_name
            )
        } else {
            anyhow!(
                "Ambiguous CBOR in {} chunk: duplicate map key",
                self.chunk_name
            )
        }
    }

    /// Account one finished item (span `data[start..end]`) to its parent,
    /// cascading upward while containers complete.
    fn complete_item(&mut self, mut start: usize, end: usize) -> Result<()> {
        loop {
            if self.stack.is_empty() {
                self.root_done = true;
                return Ok(());
            }
            let frame_start = self.stack.last().unwrap().start;
            {
                let frame = self.stack.last_mut().unwrap();
                if frame.is_map && frame.next_is_key {
                    let identity = key_identity(&self.data[start..end]);
                    if !frame.seen_keys.insert(identity) {
                        return Err(self.fail_duplicate_key());
                    }
                    if self.deterministic {
                        let span = &self.data[start..end];
                        if let Some(last) = &frame.last_key {
                            if span <= last.as_slice() {
                                return Err(self
                                    .fail("map keys out of deterministic (bytewise) order"));
                            }
                        }
                        frame.last_key = Some(span.to_vec());
                    }
                    frame.next_is_key = false;
                } else if frame.is_map {
                    frame.next_is_key = true;
                }
                match frame.remaining {
                    None => return Ok(()), // indefinite: no countdown
                    Some(r) => {
                        frame.remaining = Some(r - 1);
                        if r - 1 > 0 {
                            return Ok(());
                        }
                    }
                }
            }
            self.stack.pop();
            start = frame_start;
        }
    }

    /// Consume the argument of an item whose additional-information value
    /// is 24..27, applying the shortest-form checks in canonical mode.
    /// Float payloads (major 7) are handled by the caller.
    fn read_argument(&mut self, ai: u8, major: u8) -> Result<u64> {
        let n = self.data.len();
        if ai == 24 {
            if self.pos + 1 > n {
                return Err(self.fail("unexpected end of data"));
            }
            let arg = self.data[self.pos] as u64;
            self.pos += 1;
            if self.canonical {
                if major == 7 {
                    if arg < 32 {
                        return Err(self.fail("non-minimal simple-value encoding"));
                    }
                } else if arg < 24 {
                    return Err(self.fail("non-minimal argument encoding"));
                }
            }
            return Ok(arg);
        }
        let width: usize = match ai {
            25 => 2,
            26 => 4,
            _ => 8, // 27
        };
        if self.pos + width > n {
            return Err(self.fail("unexpected end of data"));
        }
        let mut arg: u64 = 0;
        for i in 0..width {
            arg = (arg << 8) | self.data[self.pos + i] as u64;
        }
        self.pos += width;
        if self.canonical && arg < (1u64 << (8 * (width / 2))) {
            return Err(self.fail("non-minimal argument encoding"));
        }
        Ok(arg)
    }

    /// Deterministic float form (wire 0x03): shortest exact width, and
    /// the only NaN is the half-precision 0x7e00 payload. Mirrors
    /// spif-py's `check_float` in `_scan_cbor`.
    fn check_float(&self, ai: u8, payload: &[u8]) -> Result<()> {
        match ai {
            25 => {
                let bits = u16::from_be_bytes([payload[0], payload[1]]);
                if crate::trust::f16_to_f64(bits).is_nan() && payload != [0x7e, 0x00] {
                    return Err(self.fail("non-canonical NaN encoding"));
                }
            }
            26 => {
                let v = f32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as f64;
                if v.is_nan() || v.is_infinite() {
                    return Err(self.fail("non-minimal floating-point encoding"));
                }
                let half = crate::trust::f32_to_f16_bits(v as f32);
                if crate::trust::f16_to_f64(half) == v {
                    return Err(self.fail("non-minimal floating-point encoding"));
                }
            }
            _ => {
                let v = f64::from_be_bytes(payload.try_into().unwrap());
                if v.is_nan() || v.is_infinite() {
                    return Err(self.fail("non-minimal floating-point encoding"));
                }
                let half = crate::trust::f32_to_f16_bits(v as f32);
                if crate::trust::f16_to_f64(half) == v || (v as f32) as f64 == v {
                    return Err(self.fail("non-minimal floating-point encoding"));
                }
            }
        }
        Ok(())
    }

    fn run(mut self) -> Result<()> {
        let n = self.data.len();
        let mut item_start: Option<usize> = None;
        while !self.root_done {
            if self.pos >= n {
                return Err(self.fail("unexpected end of data"));
            }
            if item_start.is_none() {
                item_start = Some(self.pos);
            }
            let initial = self.data[self.pos];

            if initial == 0xFF {
                // Break marker: closes an indefinite item.
                if self.canonical {
                    return Err(self.fail("indefinite-length items are not canonical"));
                }
                self.pos += 1;
                match self.stack.last() {
                    Some(f) if f.remaining.is_none() => {
                        if f.is_map && !f.next_is_key {
                            return Err(
                                self.fail("break marker after a map key with no value")
                            );
                        }
                    }
                    _ => {
                        return Err(
                            self.fail("break marker outside an indefinite-length item")
                        )
                    }
                }
                let frame = self.stack.pop().unwrap();
                self.complete_item(frame.start, self.pos)?;
                item_start = None;
                continue;
            }

            self.pos += 1;
            let major = initial >> 5;
            let ai = initial & 0x1F;

            if ai == 31 {
                // Indefinite-length form.
                if self.canonical {
                    return Err(self.fail("indefinite-length items are not canonical"));
                }
                if major == 2 || major == 3 {
                    // Indefinite-length string: definite-length chunks of
                    // the same major type, closed by a break marker. The
                    // whole sequence is one item with one span.
                    loop {
                        if self.pos >= n {
                            return Err(self.fail("unexpected end of data"));
                        }
                        if self.data[self.pos] == 0xFF {
                            self.pos += 1;
                            break;
                        }
                        let chunk_head = self.data[self.pos];
                        if chunk_head >> 5 != major {
                            return Err(self
                                .fail("indefinite-length string chunk of the wrong type"));
                        }
                        let chunk_ai = chunk_head & 0x1F;
                        if chunk_ai == 31 || chunk_ai >= 28 {
                            return Err(self
                                .fail("malformed chunk inside an indefinite-length string"));
                        }
                        self.pos += 1;
                        let chunk_len = if chunk_ai < 24 {
                            chunk_ai as u64
                        } else {
                            self.read_argument(chunk_ai, major)?
                        };
                        if chunk_len > (n - self.pos) as u64 {
                            return Err(self.fail("unexpected end of data"));
                        }
                        self.pos += chunk_len as usize;
                    }
                    self.complete_item(item_start.unwrap(), self.pos)?;
                    item_start = None;
                    continue;
                }
                if major == 4 {
                    self.stack.push(ScanFrame {
                        remaining: None,
                        is_map: false,
                        next_is_key: false,
                        seen_keys: HashSet::new(),
                        start: item_start.unwrap(),
                        last_key: None,
                    });
                    item_start = None;
                    continue;
                }
                if major == 5 {
                    self.stack.push(ScanFrame {
                        remaining: None,
                        is_map: true,
                        next_is_key: true,
                        seen_keys: HashSet::new(),
                        start: item_start.unwrap(),
                        last_key: None,
                    });
                    item_start = None;
                    continue;
                }
                return Err(self.fail(
                    "indefinite-length form is only valid for strings, arrays, and maps",
                ));
            }

            let arg: u64 = if ai < 24 {
                ai as u64
            } else if ai == 24 || (25..=27).contains(&ai) {
                if major == 7 && (25..=27).contains(&ai) {
                    // Float payload — its width is the encoding, no argument.
                    let width: usize = match ai {
                        25 => 2,
                        26 => 4,
                        _ => 8,
                    };
                    if self.pos + width > n {
                        return Err(self.fail("unexpected end of data"));
                    }
                    if self.deterministic {
                        self.check_float(ai, &self.data[self.pos..self.pos + width])?;
                    }
                    self.pos += width;
                    self.complete_item(item_start.unwrap(), self.pos)?;
                    item_start = None;
                    continue;
                }
                self.read_argument(ai, major)?
            } else {
                // 28..30 are reserved in every major type.
                return Err(self.fail("reserved additional information"));
            };

            if self.pending_bignum {
                // The item after a tag 2/3 head: deterministic bignums
                // are minimal — non-empty, no leading zero, and too
                // large for major type 0/1 (draft Appendix G.2).
                self.pending_bignum = false;
                if major == 2 && arg <= (n - self.pos) as u64 {
                    if arg == 0 {
                        return Err(self.fail("empty bignum encoding is not deterministic"));
                    }
                    if self.data[self.pos] == 0 {
                        return Err(
                            self.fail("bignum with a leading zero is not deterministic")
                        );
                    }
                    if arg <= 8 {
                        return Err(self.fail("bignum value fits in major type 0/1"));
                    }
                }
            }

            if major == 6 {
                // A tag prefixes the following item: the span keeps the
                // tag bytes and the parent slot is consumed by the
                // tagged item (item_start is retained).
                if self.deterministic && (arg == 2 || arg == 3) {
                    self.pending_bignum = true;
                }
                continue;
            }
            if major == 0 || major == 1 || major == 7 {
                self.complete_item(item_start.unwrap(), self.pos)?;
                item_start = None;
            } else if major == 2 || major == 3 {
                if arg > (n - self.pos) as u64 {
                    return Err(self.fail("unexpected end of data"));
                }
                self.pos += arg as usize;
                self.complete_item(item_start.unwrap(), self.pos)?;
                item_start = None;
            } else if arg == 0 {
                // Empty array or map completes immediately.
                self.complete_item(item_start.unwrap(), self.pos)?;
                item_start = None;
            } else if major == 4 {
                self.stack.push(ScanFrame {
                    remaining: Some(arg),
                    is_map: false,
                    next_is_key: false,
                    seen_keys: HashSet::new(),
                    start: item_start.unwrap(),
                        last_key: None,
                });
                item_start = None;
            } else {
                // major == 5
                self.stack.push(ScanFrame {
                    remaining: Some(arg.saturating_mul(2)),
                    is_map: true,
                    next_is_key: true,
                    seen_keys: HashSet::new(),
                    start: item_start.unwrap(),
                        last_key: None,
                });
                item_start = None;
            }
        }
        if self.pos != n {
            return Err(self.fail("trailing bytes after the CBOR item"));
        }
        Ok(())
    }
}

/// Form-gate one chunk's CBOR payload, mirroring spif-py's
/// `_assert_canonical_cbor` (when `canonical`) and
/// `_assert_unambiguous_cbor` (when not). See `CborFormScan`.
fn assert_cbor_form(
    data: &[u8],
    chunk_name: &str,
    canonical: bool,
    deterministic: bool,
) -> Result<()> {
    CborFormScan {
        data,
        chunk_name,
        canonical,
        deterministic,
        pos: 0,
        stack: Vec::new(),
        root_done: false,
        pending_bignum: false,
    }
    .run()
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

/// True for cross-document NodeRefs (SPEC §8.1), which are external to the
/// containing document's DAG.
fn is_cross_doc_ref(ref_id: &str) -> bool {
    ref_id.starts_with("spif:")
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

    // Check for dangling refs. Cross-document references (SPEC §8.1:
    // "spif:sha256:<content_id>#<node_id>") point outside this document by
    // design: exempt from the local dangling check and the local cycle
    // graph, exactly as in spif-py's reader. Whether they resolve is a
    // verification-time question (crate::trust), never a parse error.
    let ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    for n in nodes {
        for ref_id in &n.refs {
            if is_cross_doc_ref(ref_id) {
                continue;
            }
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
            if is_cross_doc_ref(ref_id) {
                continue;
            }
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
