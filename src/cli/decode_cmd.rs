//! `unico decode` — decode a U30 or E4 module from binary to JSON

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use unico_runtime::{decode, decode_e4};

pub fn decode_module(
    file: &Path,
    output: Option<&Path>,
    verbose: bool,
) -> anyhow::Result<()> {
    let data = fs::read(file)?;

    if verbose {
        eprintln!("Reading {:?} ({} bytes)", file, data.len());
    }

    // Auto-detect format by magic bytes
    let json = if data.len() >= 4 && &data[0..4] == b"E4XX" {
        let module = decode_e4(&data)
            .map_err(|e| anyhow::anyhow!("E4 decode error: {e}"))?;
        if verbose {
            eprintln!("Detected: E4 binary ({} functions, {} bytes memory)",
                module.functions.len(), module.memory.len());
        }
        serde_json::to_string_pretty(&module)
            .map_err(|e| anyhow::anyhow!("JSON serialize error: {e}"))?
    } else {
        let module = decode(&data)
            .map_err(|e| anyhow::anyhow!("U30 decode error: {e}"))?;
        if verbose {
            eprintln!("Detected: U30 binary ({} functions, {} regions, {} tables)",
                module.functions.len(), module.regions.len(), module.tables.len());
        }
        serde_json::to_string_pretty(&module)
            .map_err(|e| anyhow::anyhow!("JSON serialize error: {e}"))?
    };

    if verbose {
        eprintln!("JSON: {} chars", json.len());
    }

    // Write output
    if let Some(out) = output {
        fs::write(out, &json)?;
    } else {
        io::stdout().write_all(json.as_bytes())?;
        println!();
    }

    Ok(())
}
