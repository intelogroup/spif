use afl::fuzz;
use spif_rust::SPIFReader;

fn main() {
    let reader = SPIFReader::new();
    fuzz!(|data: &[u8]| {
        let _ = reader.read(data);
    });
}
