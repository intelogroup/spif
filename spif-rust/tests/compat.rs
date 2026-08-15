use anyhow::{anyhow, Result};
use serde::Deserialize;
use sha2::Digest;
use spif_rust::{SPIFReader, SPIFWriter};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct Manifest {
    fixtures: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    name: String,
    filename: String,
    sha256: String,
    bytes: usize,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sif-rust should live under the repo root")
        .to_path_buf()
}

fn find_python_with_spif_deps() -> Result<PathBuf> {
    if let Ok(py) = std::env::var("SPIF_PYTHON") {
        return Ok(PathBuf::from(py));
    }

    let candidates = [
        "python3",
        "python",
        "/opt/homebrew/bin/python3",
        "/usr/bin/python3",
    ];

    for candidate in candidates {
        let output = Command::new(candidate)
            .arg("-c")
            .arg(
                "import importlib.util, sys; \
                 ok = all(importlib.util.find_spec(m) for m in ('cbor2', 'cryptography')); \
                 raise SystemExit(0 if ok else 1)",
            )
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                return Ok(PathBuf::from(candidate));
            }
        }
    }

    Err(anyhow!(
        "could not find a Python interpreter with both cbor2 and cryptography installed; \
         set SPIF_PYTHON to override"
    ))
}

fn generate_fixtures() -> Result<(PathBuf, Manifest)> {
    let root = repo_root();
    let script = root.join("spif-py/compat/generate_compat_fixtures.py");
    let python = find_python_with_spif_deps()?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("system clock error: {e}"))?
        .as_nanos();
    let out_dir = std::env::temp_dir().join(format!("spif-rust-fixtures-{unique}"));
    fs::create_dir_all(&out_dir)?;

    let output = Command::new(&python)
        .arg(script)
        .arg(&out_dir)
        .current_dir(&root)
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "fixture generator failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    let manifest_bytes = fs::read(out_dir.join("manifest.json"))?;
    let manifest = serde_json::from_slice(&manifest_bytes)?;
    Ok((out_dir, manifest))
}

#[test]
fn test_python_conformance_fixtures_roundtrip_in_rust() -> Result<()> {
    let (fixture_dir, manifest) = generate_fixtures()?;
    let reader = SPIFReader::new();

    for fixture in manifest.fixtures {
        let path = fixture_dir.join(&fixture.filename);
        let bytes = fs::read(&path)?;
        assert_eq!(
            bytes.len(),
            fixture.bytes,
            "fixture byte length mismatch for {}",
            fixture.name
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&bytes)),
            fixture.sha256,
            "fixture sha256 mismatch for {}",
            fixture.name
        );

        let document = reader.read(&bytes)?;
        assert!(
            !document.payload.is_empty(),
            "fixture {} must decode to a non-empty payload",
            fixture.name
        );
    }

    Ok(())
}

#[test]
fn test_python_signed_fixtures_verify_in_rust() -> Result<()> {
    let (fixture_dir, _) = generate_fixtures()?;
    let reader = SPIFReader::new();

    for filename in ["signed_single.spif", "multisig.spif"] {
        let bytes = fs::read(fixture_dir.join(filename))?;
        assert!(reader.verify_signature(&bytes)?, "{filename} should verify");
    }

    Ok(())
}

#[test]
fn test_tampered_python_signed_fixture_is_rejected() -> Result<()> {
    let (fixture_dir, _) = generate_fixtures()?;
    let reader = SPIFReader::new();
    let mut bytes = fs::read(fixture_dir.join("signed_single.spif"))?;

    let tamper_at = bytes
        .windows("Minimal fixture".len())
        .position(|window| window == b"Minimal fixture")
        .ok_or_else(|| anyhow!("could not locate fixture payload bytes to tamper"))?;
    bytes[tamper_at] ^= 0x01;

    assert!(
        reader.read(&bytes).is_err(),
        "checksum validation should fail first"
    );
    assert!(
        reader.verify_signature(&bytes).is_err(),
        "signature verification should reject tampering"
    );
    Ok(())
}

#[test]
fn test_writer_emits_compressed_chunks_and_flags2() -> Result<()> {
    let doc = spif_rust::SPIFDocument {
        payload: vec![spif_rust::Node {
            id: "blob".to_string(),
            node_type: "text".to_string(),
            value: spif_rust::Value::Text("x".repeat(4096)),
            confidence: spif_rust::Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: Some(spif_rust::Provenance {
            source_model: "test".to_string(),
            timestamp_ms: 123,
            temperature: 0.0,
            input_hash: String::new(),
            context_ref: String::new(),
            model_version: String::new(),
            attempt: 0,
            task_id: String::new(),
            model_card: String::new(),
            risk_tier: String::new(),
        }),
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    let plain = SPIFWriter::new().encode(&doc)?;
    let compressed = SPIFWriter::compressed().encode(&doc)?;
    assert!(
        compressed.len() < plain.len(),
        "compressed output should be smaller"
    );

    let restored = SPIFReader::new().read(&compressed)?;
    assert_eq!(restored.payload[0].id, "blob");
    assert_eq!(
        restored.payload[0].value,
        spif_rust::Value::Text("x".repeat(4096))
    );

    let header_len = u32::from_be_bytes(compressed[12..16].try_into().unwrap()) as usize;
    let header_payload = &compressed[16..16 + header_len];
    #[derive(Deserialize)]
    struct HeaderPayload {
        #[serde(default)]
        flags2: u8,
    }
    let header: HeaderPayload = ciborium::de::from_reader(header_payload)?;
    assert_ne!(header.flags2 & spif_rust::FLAG_COMPRESSED, 0);

    Ok(())
}

#[test]
fn test_reader_names_zstd_as_unsupported_instead_of_malformed_cbor() -> Result<()> {
    // spif-rust cannot read FLAG_ZSTD documents yet (no zstd dependency wired up),
    // even though spif-py can write them (v1.1). Without an explicit check, the
    // reader would silently treat the zstd-compressed bytes as uncompressed CBOR
    // and fail with a confusing "Malformed CBOR" error instead of naming the real
    // cause. This constructs a document whose HEADER declares FLAG_ZSTD (by
    // flipping the flags2 byte in an otherwise-valid encoded document and
    // recomputing the checksum) and asserts the reader names the actual problem.
    let doc = spif_rust::SPIFDocument {
        payload: vec![spif_rust::Node {
            id: "n1".to_string(),
            node_type: "text".to_string(),
            value: spif_rust::Value::Text("hello".to_string()),
            confidence: spif_rust::Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };
    let mut bytes = SPIFWriter::new().encode(&doc)?;

    let header_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let header_start = 16;
    let header_payload = &bytes[header_start..header_start + header_len];
    // BTreeMap key order in writer.rs is alphabetical, so "flags2" is present as a
    // CBOR text key (0x66 'f' 'l' 'a' 'g' 's' '2') immediately followed by its
    // single-byte integer value (0x00, since this doc is uncompressed).
    let key_pattern = b"\x66flags2";
    let key_offset = header_payload
        .windows(key_pattern.len())
        .position(|w| w == key_pattern)
        .ok_or_else(|| anyhow!("could not locate 'flags2' key in HEADER CBOR"))?;
    let value_offset = header_start + key_offset + key_pattern.len();
    assert_eq!(bytes[value_offset], 0, "expected flags2 == 0 on an uncompressed doc");
    bytes[value_offset] = spif_rust::FLAG_ZSTD;

    let checksum_len = bytes.len() - 32;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes[..checksum_len]);
    let new_checksum = hasher.finalize();
    bytes[checksum_len..].copy_from_slice(&new_checksum);

    let err = SPIFReader::new()
        .read(&bytes)
        .expect_err("reader must reject a FLAG_ZSTD document it cannot decompress");
    let msg = err.to_string();
    assert!(
        msg.contains("zstd"),
        "error should name zstd as the actual unsupported feature, got: {msg}"
    );
    assert!(
        !msg.contains("Malformed CBOR"),
        "error should not misreport this as a CBOR parsing problem, got: {msg}"
    );

    Ok(())
}

#[test]
fn test_reader_rejects_decompression_bomb() -> Result<()> {
    // Highly repetitive text compresses to a tiny fraction of its size, so this is a
    // small document on the wire but decompresses past reader.rs's 10MB safety cap.
    let huge_text = "a".repeat(11 * 1024 * 1024);
    let doc = spif_rust::SPIFDocument {
        payload: vec![spif_rust::Node {
            id: "bomb".to_string(),
            node_type: "text".to_string(),
            value: spif_rust::Value::Text(huge_text),
            confidence: spif_rust::Distribution::certain("epistemic"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: vec![],
        trace_method: "post-hoc".to_string(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };

    let compressed = SPIFWriter::compressed().encode(&doc)?;
    assert!(
        compressed.len() < 1024 * 1024,
        "highly repetitive payload should compress far below the decompressed cap, got {} bytes",
        compressed.len()
    );

    let err = SPIFReader::new()
        .read(&compressed)
        .expect_err("reader must reject a payload that decompresses past the safety limit");
    assert!(
        err.to_string().contains("safety limit"),
        "unexpected error: {err}"
    );

    Ok(())
}
