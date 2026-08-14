#![no_main]

use libfuzzer_sys::fuzz_target;
use spif_rust::streaming::SPIFStreamReader;

fuzz_target!(|data: &[u8]| {
    const CHUNK: usize = 7;
    let mut reader = SPIFStreamReader::strict();
    for piece in data.chunks(CHUNK) {
        let _ = reader.feed(piece);
        if reader.is_done() {
            break;
        }
    }
});
