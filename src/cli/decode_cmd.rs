//! `unico decode` — decode a U30 module from binary to JSON

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use unico_runtime::decode;

pub fn decode_module(
    file: &Path,
    output: Option<&Path>,
    verbose: bool,
) -> anyhow::Result<()> {
    let data = fs::read(file)?;

    if verbose {
        eprintln!("Reading {:?} ({} bytes)", file, data.len());
    }

    let module = decode(&data)
        .map_err(|e| anyhow::anyhow!("decode error: {e}"))?;

    if verbose {
        eprintln!("Module: {} functions, {} regions, {} tables",
            module.functions.len(), module.regions.len(), module.tables.len());
    }

    // Serialize to JSON with pretty formatting
    let json = serde_json::to_string_pretty(&module)
        .map_err(|e| anyhow::anyhow!("JSON serialize error: {e}"))?;

    // Write output
    if let Some(out) = output {
        fs::write(out, &json)?;
    } else {
        io::stdout().write_all(json.as_bytes())?;
        println!();
    }

    Ok(())
}
