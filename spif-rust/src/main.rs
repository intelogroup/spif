use anyhow::Result;
use spif_rust::{SPIFReader, SPIFRenderer};
use std::env;
use std::fs;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "inspect" {
        return inspect(&args[2..]);
    }

    let file_path = if args.len() > 1 {
        &args[1]
    } else {
        "sample.spif"
    };

    if !std::path::Path::new(file_path).exists() {
        eprintln!("Error: File not found: {}", file_path);
        eprintln!("Usage: spif-viewer [path_to_sif_file]");
        eprintln!("       spif-viewer inspect [--json|--pretty] <path_to_sif_file>");
        std::process::exit(1);
    }

    let data = fs::read(file_path)?;
    let reader = SPIFReader::new();
    let doc = reader.read(&data)?;

    let renderer = SPIFRenderer::new();
    println!("{}", renderer.render(&doc));

    Ok(())
}

// ponytail: manual flag parse, no clap dep for two flags + a path
fn inspect(args: &[String]) -> Result<()> {
    let mut pretty = false;
    let mut file_path: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--json" => pretty = false,
            "--pretty" => pretty = true,
            other => file_path = Some(other),
        }
    }
    let file_path = file_path.unwrap_or("sample.spif");

    if !std::path::Path::new(file_path).exists() {
        eprintln!("Error: File not found: {}", file_path);
        std::process::exit(1);
    }

    let data = fs::read(file_path)?;
    let doc = SPIFReader::new().read(&data)?;

    let signed = doc.signature.is_some() || !doc.signatures.is_empty();
    let verified = signed.then(|| SPIFReader::strict().read(&data).is_ok());

    let mut value = serde_json::to_value(&doc)?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert("_signed".to_string(), serde_json::json!(signed));
        map.insert("_verified".to_string(), serde_json::json!(verified));
    }

    let out = if pretty {
        serde_json::to_string_pretty(&value)?
    } else {
        serde_json::to_string(&value)?
    };
    println!("{}", out);
    Ok(())
}
