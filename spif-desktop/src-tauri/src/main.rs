#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use sif_rust::{SIFReader, SIFDocument};
use std::fs;

#[tauri::command]
fn open_sif_file(path: String) -> Result<SIFDocument, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let reader = SIFReader::new();
    let doc = reader.read(&data).map_err(|e| format!("Failed to parse SIF: {}", e))?;
    Ok(doc)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![open_sif_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
