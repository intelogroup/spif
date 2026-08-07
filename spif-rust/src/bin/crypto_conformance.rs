//! Ed25519 conformance + throughput bench for the verify path in reader.rs.
//! Runs RFC 8032 Section 7.1 vectors and the Wycheproof eddsa_test.json corpus
//! against ed25519-dalek 2.1 (the crate spif-rust wraps).
//!
//! Usage: cargo run --release --bin crypto_conformance -- <path-to-bench/external/crypto>

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::env;
use std::fs;
use std::time::Instant;

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{}': {}", s, e))
}

// ---------------------------------------------------------------------------
// RFC 8032 7.1 vectors (colon-separated: sk : pk : msg : sig ++ msg)
// TEST 1 / TEST 2 / TEST 3 in the RFC body use "SECRET KEY:" / "PUBLIC KEY:" /
// "MESSAGE:" / "SIGNATURE:" labels; the well-known compact form (used by most
// implementations testing against this RFC) is sk:pk:msg:sig. We parse the
// labelled RFC text directly instead of relying on a third-party reformat.
// ---------------------------------------------------------------------------
fn parse_rfc8032(text: &str) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut sk: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut msg: Option<Vec<u8>> = None;
    let mut sig: Option<Vec<u8>> = None;

    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim();
        // RFC text wraps across page boundaries: blank lines, page-footer/header
        // boilerplate ("Josefsson & Liusvaara ... [Page N]", "RFC 8032 ...") can
        // appear mid-hex-block. Skip those rather than treating them as the end
        // of the block; only stop on a real label line or a genuinely empty
        // MESSAGE (length 0 bytes) case.
        let grab_hex = |first: &str, lines: &mut std::iter::Peekable<std::str::Lines>| -> String {
            let mut hexstr = first.to_string();
            loop {
                let Some(next) = lines.peek() else { break };
                let nt = next.trim();
                if nt.starts_with("SECRET KEY")
                    || nt.starts_with("PUBLIC KEY")
                    || nt.starts_with("MESSAGE")
                    || nt.starts_with("SIGNATURE")
                    || nt.starts_with("ALGORITHM")
                    || nt.starts_with("-----TEST")
                    || nt.starts_with("7.")
                {
                    break;
                }
                // RFC hex dumps are always lowercase; this also rejects section
                // titles like "Ed448" that would otherwise pass is_ascii_hexdigit.
                if nt.is_empty() || !nt.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
                    // blank line or non-hex boilerplate (page header/footer) — skip and continue
                    lines.next();
                    continue;
                }
                hexstr.push_str(nt);
                lines.next();
            }
            hexstr
        };

        if let Some(rest) = t.strip_prefix("SECRET KEY:") {
            sk = Some(hex_decode(&grab_hex(rest.trim(), &mut lines)));
        } else if let Some(rest) = t.strip_prefix("PUBLIC KEY:") {
            pk = Some(hex_decode(&grab_hex(rest.trim(), &mut lines)));
        } else if t.starts_with("MESSAGE (length") {
            // "MESSAGE (length N bytes):" then hex on following lines (may be empty)
            let after_colon = t.splitn(2, "):").nth(1).unwrap_or("").trim();
            msg = Some(hex_decode(&grab_hex(after_colon, &mut lines)));
        } else if let Some(rest) = t.strip_prefix("SIGNATURE:") {
            sig = Some(hex_decode(&grab_hex(rest.trim(), &mut lines)));
        }

        if sk.is_some() && pk.is_some() && msg.is_some() && sig.is_some() {
            out.push((sk.take().unwrap(), pk.take().unwrap(), msg.take().unwrap(), sig.take().unwrap()));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Wycheproof eddsa_test.json (v1 schema)
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
struct WycheproofFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
struct WycheproofGroup {
    #[serde(rename = "publicKey")]
    key: WycheproofKey,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize)]
struct WycheproofKey {
    pk: String,
}

#[derive(Deserialize)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    sig: String,
    result: String, // "valid" | "invalid" | "acceptable"
}

fn main() {
    let dir = env::args()
        .nth(1)
        .unwrap_or_else(|| "bench/external/crypto".to_string());

    // --- RFC 8032 ---
    let rfc_path = format!("{}/rfc8032.txt", dir);
    let rfc_text = fs::read_to_string(&rfc_path)
        .unwrap_or_else(|e| panic!("read {}: {}", rfc_path, e));
    // Restrict to the Ed25519 subsection (7.1) — 7.2/7.3 cover Ed448 with
    // different key/sig lengths and would otherwise pollute the hex scan.
    // The string also appears once in the table of contents; skip past that
    // to the real section body, which is immediately followed by "-----TEST 1".
    let toc_hit = rfc_text.find("7.1.  Test Vectors for Ed25519").expect("find 7.1 header");
    let start = rfc_text[toc_hit + 1..]
        .find("7.1.  Test Vectors for Ed25519")
        .map(|i| toc_hit + 1 + i)
        .expect("find 7.1 section body (2nd occurrence)");
    let end = rfc_text[start..]
        .find("7.2.")
        .map(|i| start + i)
        .unwrap_or(rfc_text.len());
    let section = &rfc_text[start..end];
    let vectors = parse_rfc8032(section);
    println!("RFC 8032 7.1: parsed {} Ed25519 vectors", vectors.len());
    assert!(vectors.len() >= 3, "expected at least TEST 1/2/3, got {}", vectors.len());

    let mut rfc_pass = 0;
    let mut rfc_fail = 0;
    for (i, (_sk, pk, msg, sig)) in vectors.iter().enumerate() {
        let vk = match VerifyingKey::from_bytes(pk.as_slice().try_into().expect("pk len")) {
            Ok(v) => v,
            Err(e) => {
                println!("  [{}] bad public key: {}", i, e);
                rfc_fail += 1;
                continue;
            }
        };
        let signature = Signature::from_bytes(sig.as_slice().try_into().expect("sig len"));
        match vk.verify(msg, &signature) {
            Ok(()) => rfc_pass += 1,
            Err(e) => {
                println!("  [{}] FAIL verify: {}", i, e);
                rfc_fail += 1;
            }
        }
    }
    println!("RFC 8032: {} pass, {} fail", rfc_pass, rfc_fail);
    assert_eq!(rfc_fail, 0, "RFC 8032 vectors must all verify");

    // --- Wycheproof ---
    let wp_path = format!("{}/wycheproof_ed25519_test.json", dir);
    let wp_text = fs::read_to_string(&wp_path).unwrap_or_else(|e| panic!("read {}: {}", wp_path, e));
    let wp: WycheproofFile = serde_json::from_str(&wp_text).expect("parse wycheproof json");

    let mut total = 0;
    let mut mismatches = Vec::new();
    for group in &wp.test_groups {
        let pk_bytes = hex_decode(&group.key.pk);
        let vk = match pk_bytes.len() {
            32 => VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()).ok(),
            _ => None, // e.g. DER-wrapped keys some groups use elsewhere; skip if not raw 32B
        };
        for t in &group.tests {
            total += 1;
            let msg = hex_decode(&t.msg);
            let sig_bytes = hex_decode(&t.sig);
            let expect_valid = t.result == "valid";

            let actual_valid = match (&vk, sig_bytes.len()) {
                (Some(vk), 64) => {
                    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
                    vk.verify(&msg, &signature).is_ok()
                }
                _ => false,
            };

            // "acceptable" results are implementation-defined; don't fail on those.
            if t.result != "acceptable" && actual_valid != expect_valid {
                mismatches.push((t.tc_id, t.result.clone(), actual_valid));
            }
        }
    }
    println!(
        "Wycheproof: {} tests, {} mismatches (excluding 'acceptable')",
        total,
        mismatches.len()
    );
    for (id, expected, actual) in mismatches.iter().take(20) {
        println!("  tcId {} expected={} actual_valid={}", id, expected, actual);
    }
    assert!(mismatches.is_empty(), "{} wycheproof mismatches", mismatches.len());

    // --- Throughput bench (verify only — sign is not part of spif-rust's public surface) ---
    let (sk_bytes, pk_bytes, _msg, _sig) = &vectors[1]; // TEST 2, has non-empty message
    let signing_key = ed25519_dalek::SigningKey::from_bytes(sk_bytes.as_slice()[..32].try_into().unwrap());
    let verifying_key = signing_key.verifying_key();
    assert_eq!(verifying_key.to_bytes().to_vec(), *pk_bytes);

    let msg = b"benchmark message for spif-rust ed25519 throughput";
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(msg);

    const N: u32 = 20_000;
    let start = Instant::now();
    for _ in 0..N {
        let _ = signing_key.sign(msg);
    }
    let sign_elapsed = start.elapsed();
    let sign_per_sec = N as f64 / sign_elapsed.as_secs_f64();

    let start = Instant::now();
    for _ in 0..N {
        verifying_key.verify(msg, &sig).unwrap();
    }
    let verify_elapsed = start.elapsed();
    let verify_per_sec = N as f64 / verify_elapsed.as_secs_f64();

    println!(
        "Sign:   {:.0} us/op, {:.0}/sec",
        sign_elapsed.as_secs_f64() * 1e6 / N as f64,
        sign_per_sec
    );
    println!(
        "Verify: {:.0} us/op, {:.0}/sec",
        verify_elapsed.as_secs_f64() * 1e6 / N as f64,
        verify_per_sec
    );
    println!("Baseline claim: 70,000+ verify/sec, up to 150k sign/sec (modern HW).");
    if verify_per_sec < 10_000.0 {
        println!("WARNING: verify/sec < 10k — investigate before trusting sign/verify path.");
    }
}
