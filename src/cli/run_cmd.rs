//! `unico run` — execute a UNICO module

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use unico_runtime::decode;
use unico_runtime::decode_e4;
use unico_runtime::exec::e3::{E3Executor, E3Module};
use unico_runtime::exec::e4::{E4Executor, E4Value};
use unico_runtime::runtime::U30Runtime;

pub fn run_module(
    file: &Path,
    profile: &str,
    fuel: u64,
    _args: Option<&str>,
    host_fns: &[String],
    verbose: bool,
) -> anyhow::Result<()> {
    let data = fs::read(file)?;

    if verbose {
        eprintln!("File: {:?} ({} bytes)", file, data.len());
        eprintln!("Profile hint: {}", profile);
        eprintln!("Fuel limit: {}", fuel);
        if !host_fns.is_empty() {
            eprintln!("Host functions: {:?}", host_fns);
        }
    }

    let prof = detect_profile(&data, profile)?;

    match prof.as_str() {
        "e3" => run_e3(&data, verbose),
        "u30" => run_u30(&data, fuel, verbose),
        "e4" => run_e4(&data, host_fns, verbose),
        _ => anyhow::bail!("profile '{}' run not supported in CLI", prof),
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

fn run_e4(data: &[u8], host_fns: &[String], verbose: bool) -> anyhow::Result<()> {
    let module = decode_e4(data).map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
    let mut exec = E4Executor::default();

    // Register built-in host functions
    for name in host_fns {
        register_host_fn(&mut exec, name)?;
    }

    let result = exec
        .execute(&module, 0)
        .map_err(|e| anyhow::anyhow!("execute error: {e}"))?;

    println!("Status: {:?}", result.status);
    if let Some(v) = result.value {
        println!("Result: {}", v);
    }
    if let Some(err) = &result.error {
        println!("Error: {}", err);
    }
    if verbose {
        println!(
            "Host calls: {}, duration={:.3}ms",
            result.provenance.host_calls,
            result.provenance.duration_us as f64 / 1_000.0
        );
    }
    Ok(())
}

/// Register a built-in host function by name.
fn register_host_fn(exec: &mut E4Executor, name: &str) -> anyhow::Result<()> {
    match name {
        "print_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                if let Some(&E4Value::I32(v)) = args.first() {
                    println!("[host] print_i32: {}", v);
                }
                E4Value::I32(0)
            });
            eprintln!("[host] registered print_i32 as id {}", id);
        }
        "add_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                let a = args.first().and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                let b = args.get(1).and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                E4Value::I32(a.wrapping_add(b))
            });
            eprintln!("[host] registered add_i32 as id {}", id);
        }
        "mul_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                let a = args.first().and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                let b = args.get(1).and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                E4Value::I32(a.wrapping_mul(b))
            });
            eprintln!("[host] registered mul_i32 as id {}", id);
        }
        "sub_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                let a = args.first().and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                let b = args.get(1).and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                E4Value::I32(a.wrapping_sub(b))
            });
            eprintln!("[host] registered sub_i32 as id {}", id);
        }
        "div_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                let a = args.first().and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                let b = args.get(1).and_then(|v| match v { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(1);
                if b == 0 {
                    E4Value::I32(i32::MAX) // div by zero guard
                } else {
                    E4Value::I32(a.wrapping_div(b))
                }
            });
            eprintln!("[host] registered div_i32 as id {}", id);
        }
        "read_i32" => {
            use std::io::{self, Write};
            let id = exec.host_functions_mut().register(move |_args: &[E4Value]| -> E4Value {
                print!("[host] read_i32> ");
                let _ = io::stdout().flush();
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_ok() {
                    if let Ok(v) = input.trim().parse::<i32>() {
                        return E4Value::I32(v);
                    }
                }
                E4Value::I32(0)
            });
            eprintln!("[host] registered read_i32 as id {}", id);
        }
        "write_i32" => {
            let id = exec.host_functions_mut().register(|args: &[E4Value]| -> E4Value {
                let v = args.first().and_then(|val| match val { E4Value::I32(i) => Some(*i), _ => None }).unwrap_or(0);
                let _ = writeln!(&mut io::stdout(), "[host] write_i32: {}", v);
                E4Value::I32(v)
            });
            eprintln!("[host] registered write_i32 as id {}", id);
        }
        other => anyhow::bail!("unknown host function: '{}'. Available: print_i32, add_i32, mul_i32, sub_i32, div_i32, read_i32, write_i32", other),
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
