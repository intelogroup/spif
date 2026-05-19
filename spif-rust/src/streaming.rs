//! SPIF Streaming (SSPIF) — incremental delivery for Rust.
//!
//! See the Python `spif.streaming` module for the full protocol description.
//!
//! ## Writer
//!
//! ```ignore
//! use spif_rust::streaming::SPIFStreamWriter;
//! use spif_rust::types::*;
//!
//! let mut writer = SPIFStreamWriter::new();
//! let header = writer.open(None).unwrap();              // send header bytes
//! let tok = writer.partial_text("hello", "main").unwrap(); // send each token
//! let tail = writer.commit(&my_doc).unwrap();           // send PAYLOAD + CHECKSUM
//! ```
//!
//! ## Reader
//!
//! ```ignore
//! use spif_rust::streaming::{SPIFStreamReader, StreamEvent};
//!
//! let mut reader = SPIFStreamReader::new();
//! for chunk in incoming_bytes {
//!     for event in reader.feed(chunk) {
//!         match event {
//!             StreamEvent::PartialText { text, .. } => print!("{text}"),
//!             StreamEvent::Verified { document }    => println!("\ndone: {document:?}"),
//!             StreamEvent::Error(e)                 => eprintln!("error: {e}"),
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use crate::reader::SPIFReader;
use crate::types::*;
use crate::writer::SPIFWriter;
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, WriteBytesExt};
use ciborium::ser::into_writer;
use sha2::{Digest, Sha256};

pub const CHUNK_PARTIAL_TEXT: u8 = 0x10;
pub const CHUNK_STREAM_META: u8 = 0x11;
pub const FLAG_STREAMING: u8 = 0b10000000;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// An event emitted by [`SPIFStreamReader`] as bytes arrive.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Magic bytes and header were valid; the stream is a SPIF document.
    Opened,
    /// One text fragment (token) received from a PARTIAL_TEXT chunk.
    PartialText {
        node_id: String,
        text: String,
        seq: u32,
    },
    /// The full document has been verified (checksum matched).
    Verified { document: Box<SPIFDocument> },
    /// An unrecoverable error occurred; the stream is done.
    Error(String),
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Produces a streaming SPIF byte sequence piece by piece.
///
/// The resulting byte stream is a valid SPIF document readable by any
/// [`SPIFReader`] — it just skips the unknown `PARTIAL_TEXT` chunks.
pub struct SPIFStreamWriter {
    body: Vec<u8>,
    seq: u32,
    opened: bool,
    committed: bool,
}

impl Default for SPIFStreamWriter {
    fn default() -> Self {
        Self {
            body: Vec::new(),
            seq: 0,
            opened: false,
            committed: false,
        }
    }
}

impl SPIFStreamWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit the stream header.  Must be called exactly once.
    pub fn open(&mut self, provenance: Option<&Provenance>) -> Result<Vec<u8>> {
        if self.opened {
            return Err(anyhow!("SPIFStreamWriter::open() called twice"));
        }
        self.opened = true;

        let mut flags = FLAG_STREAMING;
        if provenance.is_some() {
            flags |= FLAG_PROVENANCE;
        }

        let ts = provenance.map(|p| p.timestamp_ms).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });

        let mut parts: Vec<Vec<u8>> = vec![MAGIC.to_vec(), vec![FORMAT_VERSION, flags]];

        // HEADER chunk
        let mut header_map = std::collections::BTreeMap::new();
        header_map.insert("version", Value::Integer(FORMAT_VERSION.into()));
        header_map.insert("flags", Value::Integer(flags.into()));
        header_map.insert("created_ms", Value::Integer(ts.into()));
        parts.push(Self::cbor_chunk(CHUNK_HEADER, &header_map)?);

        // PROVENANCE chunk
        if let Some(p) = provenance {
            parts.push(Self::cbor_chunk(CHUNK_PROVENANCE, p)?);
        }

        let data: Vec<u8> = parts.into_iter().flatten().collect();
        self.body.extend_from_slice(&data);
        Ok(data)
    }

    /// Emit a PARTIAL_TEXT chunk for one text fragment.
    pub fn partial_text(&mut self, text: &str, node_id: &str) -> Result<Vec<u8>> {
        self.require_open()?;
        let seq = self.seq;
        self.seq += 1;

        let mut map = std::collections::BTreeMap::new();
        map.insert("node_id", Value::Text(node_id.to_string()));
        map.insert("seq", Value::Integer(seq.into()));
        map.insert("text", Value::Text(text.to_string()));

        let chunk = Self::cbor_chunk(CHUNK_PARTIAL_TEXT, &map)?;
        self.body.extend_from_slice(&chunk);
        Ok(chunk)
    }

    /// Finalize the stream: emit PAYLOAD + remaining chunks + CHECKSUM.
    pub fn commit(&mut self, doc: &SPIFDocument) -> Result<Vec<u8>> {
        self.require_open()?;
        if self.committed {
            return Err(anyhow!("SPIFStreamWriter::commit() called twice"));
        }
        self.committed = true;

        // Encode the document body chunks (everything after magic+header)
        // by reusing SPIFWriter, then stripping its first 10 + HEADER_CHUNK bytes.
        // It's simpler and safer to re-use the writer for the tail.
        let full_bytes = SPIFWriter::new().encode(doc)?;

        // The SPIFWriter output is:
        //   MAGIC(9) + VERSION+FLAGS(2) + HEADER_CHUNK + ... + CHECKSUM
        // We want everything from PAYLOAD onwards (not the checksum — we compute our own).
        // Find where PAYLOAD chunk starts and the body ends (before writer's checksum).
        let tail_bytes = extract_tail_from_spif_bytes(&full_bytes)?;

        self.body.extend_from_slice(&tail_bytes);

        // Compute checksum over our accumulated body
        let checksum = Sha256::digest(&self.body);
        let mut checksum_chunk = Vec::new();
        checksum_chunk.push(CHUNK_CHECKSUM);
        checksum_chunk.write_u32::<BigEndian>(checksum.len() as u32)?;
        checksum_chunk.extend_from_slice(&checksum);

        let mut result = tail_bytes;
        result.extend_from_slice(&checksum_chunk);
        Ok(result)
    }

    fn require_open(&self) -> Result<()> {
        if !self.opened {
            return Err(anyhow!("Call open() before writing chunks"));
        }
        if self.committed {
            return Err(anyhow!("Stream already committed"));
        }
        Ok(())
    }

    fn cbor_chunk<T: serde::Serialize>(chunk_type: u8, data: &T) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        into_writer(data, &mut payload)?;
        let mut chunk = Vec::new();
        chunk.push(chunk_type);
        chunk.write_u32::<BigEndian>(payload.len() as u32)?;
        chunk.extend_from_slice(&payload);
        Ok(chunk)
    }
}

/// Extract the payload-through-body bytes from a SPIFWriter output,
/// stopping before the final CHECKSUM chunk.
fn extract_tail_from_spif_bytes(data: &[u8]) -> Result<Vec<u8>> {
    // Skip: MAGIC(9) + VERSION+FLAGS(2) = 11 bytes preamble,
    // then HEADER chunk (type=0x00).
    let mut pos = MAGIC.len() + 2;

    // Skip the HEADER chunk
    if pos + 5 > data.len() {
        return Err(anyhow!("SPIF data too short to contain HEADER chunk"));
    }
    let first_chunk_type = data[pos];
    if first_chunk_type != CHUNK_HEADER {
        return Err(anyhow!(
            "Expected HEADER chunk first, got 0x{:02x}",
            first_chunk_type
        ));
    }
    let first_chunk_len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
    pos += 5 + first_chunk_len;

    // Skip optional PROVENANCE chunk if present (written by SPIFWriter when provenance exists)
    if pos + 5 <= data.len() && data[pos] == CHUNK_PROVENANCE {
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
        pos += 5 + len;
    }

    // From `pos` to just before the final CHECKSUM chunk is our tail.
    // The CHECKSUM chunk (0xFF) is the last chunk — find it from the end.
    let checksum_start = find_checksum_chunk_start(data)?;
    if checksum_start <= pos {
        return Err(anyhow!(
            "No payload chunks found between header and checksum"
        ));
    }

    Ok(data[pos..checksum_start].to_vec())
}

fn find_checksum_chunk_start(data: &[u8]) -> Result<usize> {
    let mut pos = MAGIC.len() + 2;
    while pos + 5 <= data.len() {
        let ct = data[pos];
        let len = u32::from_be_bytes(data[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if ct == CHUNK_CHECKSUM {
            return Ok(pos);
        }
        pos += 5 + len;
    }
    Err(anyhow!("No CHECKSUM chunk found in SPIF bytes"))
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Incremental SPIF stream reader.  Feed bytes as they arrive; receive events.
pub struct SPIFStreamReader {
    buf: Vec<u8>,
    pos: usize,
    state: ReaderState,
    require_signature: bool,
}

#[derive(PartialEq)]
enum ReaderState {
    Header,
    Chunks,
    Done,
}

impl Default for SPIFStreamReader {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            state: ReaderState::Header,
            require_signature: false,
        }
    }
}

impl SPIFStreamReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a stream reader that rejects unsigned documents.
    pub fn strict() -> Self {
        Self {
            require_signature: true,
            ..Self::default()
        }
    }

    /// Feed bytes.  Returns any events emitted during this call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<StreamEvent> {
        if self.state == ReaderState::Done {
            return vec![];
        }
        self.buf.extend_from_slice(data);
        let mut events = Vec::new();
        self.pump(&mut events);
        events
    }

    /// True once a `Verified` or `Error` event has been emitted.
    pub fn is_done(&self) -> bool {
        self.state == ReaderState::Done
    }

    fn pump(&mut self, events: &mut Vec<StreamEvent>) {
        if self.state == ReaderState::Header {
            if self.buf.len() < MAGIC.len() + 2 {
                return;
            }
            if &self.buf[..MAGIC.len()] != MAGIC {
                events.push(StreamEvent::Error(format!(
                    "Invalid magic bytes: {}",
                    hex::encode(&self.buf[..MAGIC.len()])
                )));
                self.state = ReaderState::Done;
                return;
            }
            self.pos = MAGIC.len() + 2;
            self.state = ReaderState::Chunks;
            events.push(StreamEvent::Opened);
        }

        while self.state == ReaderState::Chunks {
            if self.pos + 5 > self.buf.len() {
                return;
            }
            let chunk_type = self.buf[self.pos];
            let chunk_len =
                u32::from_be_bytes(self.buf[self.pos + 1..self.pos + 5].try_into().unwrap())
                    as usize;
            let payload_start = self.pos + 5;
            let payload_end = payload_start + chunk_len;

            if payload_end > self.buf.len() {
                return; // wait for more data
            }

            let payload = self.buf[payload_start..payload_end].to_vec();
            let advance_to = payload_end;
            self.dispatch(chunk_type, &payload, advance_to, events);
            self.pos = advance_to;
        }
    }

    fn dispatch(
        &mut self,
        chunk_type: u8,
        payload: &[u8],
        payload_end: usize,
        events: &mut Vec<StreamEvent>,
    ) {
        match chunk_type {
            CHUNK_PARTIAL_TEXT => {
                match ciborium::de::from_reader::<ciborium::value::Value, _>(payload) {
                    Ok(ciborium::value::Value::Map(fields)) => {
                        let mut node_id = "main".to_string();
                        let mut text = String::new();
                        let mut seq = 0u32;
                        for (k, v) in &fields {
                            if let ciborium::value::Value::Text(key) = k {
                                match key.as_str() {
                                    "node_id" => {
                                        if let ciborium::value::Value::Text(s) = v {
                                            node_id = s.clone();
                                        }
                                    }
                                    "text" => {
                                        if let ciborium::value::Value::Text(s) = v {
                                            text = s.clone();
                                        }
                                    }
                                    "seq" => {
                                        if let ciborium::value::Value::Integer(n) = v {
                                            seq = u32::try_from(*n).unwrap_or(0);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        events.push(StreamEvent::PartialText { node_id, text, seq });
                    }
                    Err(e) => {
                        events.push(StreamEvent::Error(format!(
                            "Malformed PARTIAL_TEXT chunk: {e}"
                        )));
                        self.state = ReaderState::Done;
                    }
                    _ => {
                        events.push(StreamEvent::Error(
                            "PARTIAL_TEXT chunk is not a CBOR map".to_string(),
                        ));
                        self.state = ReaderState::Done;
                    }
                }
            }

            CHUNK_CHECKSUM => {
                // Stream complete — decode full accumulated buffer
                let full = &self.buf[..payload_end];
                let reader = SPIFReader {
                    require_signature: self.require_signature,
                };
                match reader.read(full) {
                    Ok(doc) => events.push(StreamEvent::Verified {
                        document: Box::new(doc),
                    }),
                    Err(e) => events.push(StreamEvent::Error(e.to_string())),
                }
                self.state = ReaderState::Done;
            }

            _ => {
                // Unknown or known-but-non-streaming chunk — buffer silently.
            }
        }
    }
}
