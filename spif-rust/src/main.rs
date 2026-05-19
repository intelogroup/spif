use anyhow::Result;
use spif_rust::{SPIFReader, SPIFRenderer};
use std::env;
use std::fs;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let file_path = if args.len() > 1 {
        &args[1]
    } else {
        "sample.spif"
    };

    if !std::path::Path::new(file_path).exists() {
        eprintln!("Error: File not found: {}", file_path);
        eprintln!("Usage: sif-viewer [path_to_sif_file]");
        std::process::exit(1);
    }

    let data = fs::read(file_path)?;
    let reader = SPIFReader::new();
    let doc = reader.read(&data)?;

    let renderer = SPIFRenderer::new();
    println!("{}", renderer.render(&doc));

    Ok(())
}
