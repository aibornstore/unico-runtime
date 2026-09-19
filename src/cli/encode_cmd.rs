//! `unico encode` — encode a U30 or E4 module from JSON to binary

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use unico_runtime::ser::encode;
use unico_runtime::{encode_e4, U30Module, E4Module};

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

    // Try E4 first (has "memory" field), then U30
    let binary = if let Ok(e4_module) = serde_json::from_str::<E4Module>(&json) {
        if verbose {
            eprintln!("Detected: E4 module ({} functions, {} bytes memory)",
                e4_module.functions.len(), e4_module.memory.len());
        }
        encode_e4(&e4_module)
    } else {
        let module: U30Module = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("JSON parse error (not U30 either): {e}"))?;
        if verbose {
            eprintln!("Detected: U30 module ({} functions, {} regions, {} tables)",
                module.functions.len(), module.regions.len(), module.tables.len());
        }
        encode(&module)
    };

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
