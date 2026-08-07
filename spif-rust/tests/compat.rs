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
        "/Users/kalinovdameus/miniforge3/bin/python3",
        "/Users/kalinovdameus/miniforge3/bin/python",
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
    let script = root.join("spfx/compat/generate_compat_fixtures.py");
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

    for filename in ["signed_single.spfx", "multisig.spfx"] {
        let bytes = fs::read(fixture_dir.join(filename))?;
        assert!(reader.verify_signature(&bytes)?, "{filename} should verify");
    }

    Ok(())
}

#[test]
fn test_tampered_python_signed_fixture_is_rejected() -> Result<()> {
    let (fixture_dir, _) = generate_fixtures()?;
    let reader = SPIFReader::new();
    let mut bytes = fs::read(fixture_dir.join("signed_single.spfx"))?;

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
