//! Signature-tamper-detection sweep: stand-in for WAVES/tamper-robustness
//! testing since spif-rust has no watermarking code. Flips every byte of a
//! valid signed .spif, one at a time, and confirms the strict reader
//! (require_signature=true) rejects every mutation (no silent accept, no panic).

use spif_rust::SPIFReader;
use std::fs;
use std::panic;


fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../sample_valid.spif".to_string());
    let original = fs::read(&path).expect("read fixture");
    let reader = SPIFReader::strict();

    // Sanity: original must verify clean.
    reader
        .read(&original)
        .expect("baseline fixture must pass strict verify");

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut panicked = 0usize;
    let mut silent_offsets = Vec::new();
    let mut panic_offsets = Vec::new();

    panic::set_hook(Box::new(|_| {})); // suppress panic spam during sweep

    for offset in 0..original.len() {
        for bit in 0..8u8 {
            let mut mutated = original.clone();
            mutated[offset] ^= 1 << bit;

            let result = panic::catch_unwind(|| reader.read(&mutated));
            match result {
                Ok(Ok(_)) => {
                    accepted += 1;
                    silent_offsets.push((offset, bit));
                }
                Ok(Err(_)) => rejected += 1,
                Err(_) => {
                    panicked += 1;
                    panic_offsets.push((offset, bit));
                }
            }
        }
    }
    let _ = panic::take_hook();

    // Truncation sweep: does a cut-off file error cleanly (no panic)?
    let mut trunc_panicked = 0usize;
    let mut trunc_panic_offsets = Vec::new();
    for cut in 1..original.len() {
        let mutated = &original[..cut];
        let result = panic::catch_unwind(|| reader.read(mutated));
        if result.is_err() {
            trunc_panicked += 1;
            trunc_panic_offsets.push(cut);
        }
    }

    let total = accepted + rejected + panicked;
    println!("=== Bit-flip sweep ({} bytes x 8 bits = {} mutations) ===", original.len(), total);
    println!("rejected (correct):     {}", rejected);
    println!("silently accepted (BAD): {}", accepted);
    println!("panicked (BAD, should Err not panic): {}", panicked);
    if !silent_offsets.is_empty() {
        println!("silent-accept offsets: {:?}", &silent_offsets[..silent_offsets.len().min(20)]);
    }
    if !panic_offsets.is_empty() {
        println!("panic offsets: {:?}", &panic_offsets[..panic_offsets.len().min(20)]);
    }
    println!(
        "silent-accept rate: {:.4}%",
        100.0 * accepted as f64 / total as f64
    );

    println!();
    println!("=== Truncation sweep ({} cut points) ===", original.len() - 1);
    println!("clean errors (no panic): {} / {}", original.len() - 1 - trunc_panicked, original.len() - 1);
    println!("panicked on truncation:  {}", trunc_panicked);
    if !trunc_panic_offsets.is_empty() {
        println!("truncation panic cut points: {:?}", &trunc_panic_offsets[..trunc_panic_offsets.len().min(20)]);
    }
}
