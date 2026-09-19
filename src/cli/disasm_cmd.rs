//! `unico disasm` — disassemble U30/E4 binary to readable text

use std::fs;
use std::path::Path;
use unico_runtime::decode;
use unico_runtime::decode_disasm_opts;
use unico_runtime::e4_disasm::FmtOpts as E4DisasmOpts;
use unico_runtime::fmt_module_opts;
use unico_runtime::pretty::FmtOpts;

pub fn disasm_file(file: &Path, no_colors: bool, show_memory: bool, show_region_data: bool) -> anyhow::Result<()> {
    let data = fs::read(file)?;
    let text = disasm_bytes(&data, no_colors, show_memory, show_region_data)?;
    println!("{}", text);
    Ok(())
}

fn disasm_bytes(data: &[u8], no_colors: bool, show_memory: bool, show_region_data: bool) -> anyhow::Result<String> {
    if data.len() >= 4 && &data[0..4] == b"E4XX" {
        let opts = E4DisasmOpts {
            colors: !no_colors,
            show_memory,
            hex_cols: 16,
        };
        decode_disasm_opts(data, opts).map_err(|e| anyhow::anyhow!("disasm error: {e}"))
    } else if data.len() >= 4 && &data[0..4] == b"U30X" {
        let opts = FmtOpts {
            colors: !no_colors,
            show_region_data,
            show_tables: true,
            hex_cols: 32,
        };
        let module = decode(data).map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
        Ok(fmt_module_opts(&module, opts))
    } else if data.len() >= 6 && &data[0..6] == b"UNICO\x03" {
        anyhow::bail!("E3 binary disassembly not supported (use `unico run` for execution)")
    } else {
        anyhow::bail!("unknown module format")
    }
}
