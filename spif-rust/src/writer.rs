use crate::types::*;
use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use ciborium::ser::into_writer;
use flate2::{write::ZlibEncoder, Compression};
use sha2::{Digest, Sha256};
use std::io::Write;

pub struct SPIFWriter {
    compress: bool,
}

impl Default for SPIFWriter {
    fn default() -> Self {
        Self { compress: false }
    }
}

impl SPIFWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn compressed() -> Self {
        Self { compress: true }
    }

    pub fn encode(&self, doc: &SPIFDocument) -> Result<Vec<u8>> {
        let mut flags: u8 = 0;
        let mut flags2: u8 = 0;
        if doc.provenance.is_some() {
            flags |= FLAG_PROVENANCE;
        }
        if doc.semantic.is_some() {
            flags |= FLAG_SEMANTIC;
        }
        if !doc.trace.is_empty() {
            flags |= FLAG_TRACE;
        }
        if !doc.alternatives.is_empty() {
            flags |= FLAG_ALTS;
        }
        if doc.delta.is_some() {
            flags |= FLAG_DELTA;
        }
        if doc.signature.is_some() {
            flags |= FLAG_SIGNATURE;
        }
        if !doc.signatures.is_empty() {
            flags |= FLAG_MULTISIG;
        }
        if self.compress {
            flags2 |= FLAG_COMPRESSED;
        }

        // Pre-allocate a single buffer sized for the typical document to avoid reallocations.
        let capacity = 512
            + doc.payload.len() * 128
            + doc.trace.len() * 80
            + doc
                .semantic
                .as_ref()
                .map_or(0, |s| s.embedding.len() * 4 + 64);
        let mut buf = Vec::with_capacity(capacity);

        // Magic bytes + version + flags
        buf.extend_from_slice(MAGIC);
        buf.push(FORMAT_VERSION);
        buf.push(flags);

        // HEADER chunk
        let mut header_data = std::collections::BTreeMap::new();
        header_data.insert("version", Value::Integer(FORMAT_VERSION.into()));
        header_data.insert("flags", Value::Integer(flags.into()));
        header_data.insert("flags2", Value::Integer(flags2.into()));
        let timestamp_ms = if let Some(ref p) = doc.provenance {
            p.timestamp_ms
        } else {
            0
        };
        header_data.insert("created_ms", Value::Integer(timestamp_ms.into()));
        Self::write_chunk(&mut buf, CHUNK_HEADER, &header_data, false)?;

        // PROVENANCE chunk
        if let Some(ref p) = doc.provenance {
            Self::write_chunk(&mut buf, CHUNK_PROVENANCE, p, false)?;
        }

        // SEMANTIC chunk
        if let Some(ref s) = doc.semantic {
            Self::write_chunk(&mut buf, CHUNK_SEMANTIC, s, self.compress)?;
        }

        // TRACE chunk
        if !doc.trace.is_empty() {
            #[derive(serde::Serialize)]
            struct TraceWrapper<'a> {
                method: &'a str,
                steps: &'a Vec<TraceStep>,
            }
            Self::write_chunk(
                &mut buf,
                CHUNK_TRACE,
                &TraceWrapper {
                    method: &doc.trace_method,
                    steps: &doc.trace,
                },
                self.compress,
            )?;
        }

        // PAYLOAD chunk
        Self::write_chunk(&mut buf, CHUNK_PAYLOAD, &doc.payload, self.compress)?;

        // ALTS chunk
        if !doc.alternatives.is_empty() {
            #[derive(serde::Serialize)]
            struct AltsWrapper<'a> {
                normalized: bool,
                alts: &'a Vec<Alternative>,
            }
            Self::write_chunk(
                &mut buf,
                CHUNK_ALTS,
                &AltsWrapper {
                    normalized: doc.alternatives[0].normalized,
                    alts: &doc.alternatives,
                },
                self.compress,
            )?;
        }

        // DELTA chunk
        if let Some(ref d) = doc.delta {
            Self::write_chunk(&mut buf, CHUNK_DELTA, d, self.compress)?;
        }

        // SIGNATURE chunk
        if let Some(ref s) = doc.signature {
            Self::write_chunk(&mut buf, CHUNK_SIGNATURE, s, false)?;
        }

        // MULTISIG chunk
        if !doc.signatures.is_empty() {
            Self::write_chunk(&mut buf, CHUNK_MULTISIG, &doc.signatures, false)?;
        }

        // CHECKSUM: SHA-256 over everything written so far
        let checksum = Sha256::digest(&buf);
        buf.push(CHUNK_CHECKSUM);
        buf.write_u32::<BigEndian>(checksum.len() as u32)?;
        buf.extend_from_slice(&checksum);

        Ok(buf)
    }

    /// Serialize `data` as CBOR and append a framed chunk to `buf`.
    /// Uses a scratch Vec for the payload only (required to know its length before writing
    /// the 4-byte length prefix). One alloc per chunk instead of two.
    fn write_chunk<T: serde::Serialize>(
        buf: &mut Vec<u8>,
        chunk_type: u8,
        data: &T,
        compress: bool,
    ) -> Result<()> {
        let mut payload = Vec::new();
        into_writer(data, &mut payload)?;
        if compress {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&payload)?;
            payload = encoder.finish()?;
        }
        buf.push(chunk_type);
        buf.write_u32::<BigEndian>(payload.len() as u32)?;
        buf.extend_from_slice(&payload);
        Ok(())
    }
}
