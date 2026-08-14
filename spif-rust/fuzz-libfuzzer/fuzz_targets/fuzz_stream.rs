#![no_main]

use libfuzzer_sys::fuzz_target;
use spif_rust::SPIFStreamReader;

// Feeds the input in small, deterministic chunks rather than all at once so the
// fuzzer exercises the reader's partial-buffer / resume state machine (ReaderState::Header
// vs Chunks, incremental DAG checking), not just single-shot parsing.
fuzz_target!(|data: &[u8]| {
    const CHUNK: usize = 7;
    let mut reader = SPIFStreamReader::new();
    for piece in data.chunks(CHUNK) {
        let _ = reader.feed(piece);
        if reader.is_done() {
            break;
        }
    }
});
