//! `unico encode` — encode a U30 module from JSON to binary

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use unico_runtime::ser::encode;
use unico_runtime::U30Module;

pub fn encode_module(
    source: &Path,
    output: Option<&Path>,
    verbose: bool,
) -> anyhow::Result<()> {
    // Read JSON from file or stdin
    let json = if source.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        fs::read_to_string(source)?
    };

    if verbose {
        eprintln!("Parsing JSON from {:?} ({} chars)", source, json.len());
    }

    // Parse JSON into U30Module
    let module: U30Module = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?;

    if verbose {
        eprintln!("Module: {} functions, {} regions, {} tables",
            module.functions.len(), module.regions.len(), module.tables.len());
    }

    // Encode to binary
    let binary = encode(&module);

    if verbose {
        eprintln!("Encoded: {} bytes", binary.len());
    }

    // Write output
    if let Some(out) = output {
        fs::write(out, &binary)?;
    } else {
        // Write hex to stdout
        println!("{}", hex::encode(&binary));
    }

    Ok(())
}
