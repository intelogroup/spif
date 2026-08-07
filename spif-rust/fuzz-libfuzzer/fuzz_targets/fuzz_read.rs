#![no_main]

use libfuzzer_sys::fuzz_target;
use spif_rust::SPIFReader;

fuzz_target!(|data: &[u8]| {
    let reader = SPIFReader::new();
    let _ = reader.read(data);
});
