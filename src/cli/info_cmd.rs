//! `unico info` — show module information

use std::fs;
use std::path::Path;
use unico_runtime::exec::e3::E3Module;
use unico_runtime::decode;

pub fn info_module(file: &Path, profile: &str, verbose: bool) -> anyhow::Result<()> {
    let data = fs::read(file)?;
    let prof = detect_profile(&data, profile)?;

    if verbose {
        println!("File: {:?}", file);
        println!("Size: {} bytes", data.len());
        println!("Profile: {prof}");
    }

    match prof.as_str() {
        "e3" => info_e3(&data),
        "u30" => info_u30(&data),
        _ => anyhow::bail!("unsupported profile: {prof}"),
    }
}

fn detect_profile(data: &[u8], hint: &str) -> anyhow::Result<String> {
    if hint != "auto" {
        return Ok(hint.to_string());
    }
    if data.len() >= 6 && &data[0..6] == b"UNICO\x03" {
        Ok("e3".to_string())
    } else if data.len() >= 4 && &data[0..4] == b"U30X" {
        Ok("u30".to_string())
    } else if data.len() >= 6 && &data[0..6] == b"UNICO\x04" {
        Ok("e4".to_string())
    } else {
        anyhow::bail!("unknown module format")
    }
}

fn info_e3(data: &[u8]) -> anyhow::Result<()> {
    let module = E3Module::parse(data).map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
    println!("E3 Module");
    println!("  Functions: {}", module.functions.len());
    for (i, f) in module.functions.iter().enumerate() {
        println!(
            "  Function {i}: params={}, results={}, regs={}, code_len={}",
            f.param_count, f.result_count, f.register_count, f.code.len()
        );
    }
    println!("  Memory: {} bytes", module.memory.len());
    Ok(())
}

fn info_u30(data: &[u8]) -> anyhow::Result<()> {
    let module = decode(data).map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
    println!("U30 Module");
    println!("  Functions: {}", module.functions.len());
    for (i, f) in module.functions.iter().enumerate() {
        println!(
            "  Function {i}: params={}, results={}, blocks={}, entry={}",
            f.params.len(),
            f.results.len(),
            f.blocks.len(),
            f.entry_block
        );
        if i < 3 {
            for (j, b) in f.blocks.iter().enumerate() {
                println!("    Block {j}: {} ops, terminator={:?}", b.ops.len(), b.terminator);
            }
        }
    }
    println!("  Regions: {}", module.regions.len());
    for r in &module.regions {
        println!(
            "    Region {}: size={}, readable={}, writable={}, initial_len={}",
            r.id,
            r.size,
            r.readable,
            r.writable,
            r.initial.len()
        );
    }
    println!("  Tables: {}", module.tables.len());
    for (i, t) in module.tables.iter().enumerate() {
        println!("    Table {i} (id={}): {} targets", t.id, t.targets.len());
    }
    Ok(())
}
