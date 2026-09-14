//! `unico run` — execute a UNICO module

use std::fs;
use std::path::Path;
use unico_runtime::exec::e3::{E3Executor, E3Module};
use unico_runtime::runtime::U30Runtime;
use unico_runtime::decode;

pub fn run_module(
    file: &Path,
    profile: &str,
    fuel: u64,
    _args: Option<&str>,
    verbose: bool,
) -> anyhow::Result<()> {
    let data = fs::read(file)?;

    if verbose {
        eprintln!("File: {:?} ({} bytes)", file, data.len());
        eprintln!("Profile hint: {}", profile);
        eprintln!("Fuel limit: {}", fuel);
    }

    let prof = detect_profile(&data, profile)?;

    match prof.as_str() {
        "e3" => run_e3(&data, verbose),
        "u30" => run_u30(&data, fuel, verbose),
        _ => anyhow::bail!("profile '{}' run not supported in CLI (E4 requires JSON input)", prof),
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
    } else if data.len() >= 6 && &data[0..6] == b"UNICO\x02" {
        Ok("e2".to_string())
    } else if data.len() >= 6 && &data[0..6] == b"UNICO\x01" {
        Ok("e1".to_string())
    } else {
        anyhow::bail!("unknown module format (magic: {:02x?})", &data[..data.len().min(8)])
    }
}

fn run_e3(data: &[u8], verbose: bool) -> anyhow::Result<()> {
    let module = E3Module::parse(data).map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
    let mut exec = E3Executor::new();
    let result = exec.execute(&module).map_err(|e| anyhow::anyhow!("execute error: {e}"))?;

    println!("Status: {:?}", result.status);
    if let Some(v) = result.value {
        println!("Result: {}", v);
    }
    if let Some(err) = &result.error {
        println!("Error: {}", err);
    }
    if verbose {
        println!(
            "Provenance: instructions=?, duration={:.3}ms",
            result.provenance.duration_us as f64 / 1_000.0
        );
    }
    Ok(())
}

fn run_u30(data: &[u8], fuel: u64, verbose: bool) -> anyhow::Result<()> {
    let module = decode(data).map_err(|e| anyhow::anyhow!("decode error: {e}"))?;

    let runtime = U30Runtime { fuel_limit: fuel };
    let result = runtime.execute_experimental(&module, &[])
        .map_err(|e| anyhow::anyhow!("execute error: {e}"))?;

    // Derive status from whether fuel was exhausted
    let steps = result.steps;
    let status = if steps >= fuel { "fuel_exhausted" } else { "ok" };
    println!("Status: {}", status);
    if !result.results.is_empty() {
        println!("Results:");
        for (i, v) in result.results.iter().enumerate() {
            println!("  r{} = {:?}", i, v);
        }
    }
    if verbose {
        println!("Steps: {}", steps);
        println!("Regions: {:?}", result.regions.keys().collect::<Vec<_>>());
    }
    Ok(())
}
