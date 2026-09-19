//! `unico assemble` — assemble U30 assembly text into binary

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use unico_runtime::assembler::assemble;
use unico_runtime::ser::encode;

pub fn assemble_file(
    source: &Path,
    output: Option<&Path>,
    verbose: bool,
) -> anyhow::Result<()> {
    let asm = if source.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        fs::read_to_string(source)?
    };

    if verbose {
        eprintln!("Assembling {} ({} chars)", source.display(), asm.len());
    }

    let module = assemble(&asm).map_err(|e| anyhow::anyhow!("assembly error: {e}"))?;
    let binary = encode(&module);

    if verbose {
        eprintln!("Assembled: {} bytes ({} functions, {} regions)",
            binary.len(), module.functions.len(), module.regions.len());
    }

    if let Some(out) = output {
        fs::write(out, &binary)?;
    } else {
        println!("{}", hex::encode(&binary));
    }

    Ok(())
}
