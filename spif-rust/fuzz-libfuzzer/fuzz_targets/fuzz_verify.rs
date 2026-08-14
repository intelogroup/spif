#![no_main]

use libfuzzer_sys::fuzz_target;
use spif_rust::SPIFReader;

// Isolates the signature-verification path (base64/key decode, ed25519 verify,
// multisig loop, unknown-algorithm handling per SPEC.md §7.2) from general chunk
// parsing so mutation effort concentrates on crypto-adjacent code, not framing bytes.
fuzz_target!(|data: &[u8]| {
    let reader = SPIFReader::new();
    let _ = reader.verify_signature(data);
});
