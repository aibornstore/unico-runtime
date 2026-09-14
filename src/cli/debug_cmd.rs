//! `unico debug` — interactive U30 debugger

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use unico_runtime::decode;
use unico_runtime::debugger::{U30Debugger, Breakpoint, U30DebugEvent};

pub fn debug_module(file: &Path, fuel: u64, verbose: bool) -> anyhow::Result<()> {
    let data = fs::read(file)?;
    let module = decode(&data).map_err(|e| anyhow::anyhow!("decode error: {e}"))?;

    if verbose {
        eprintln!("Debugging {:?} ({} functions)", file, module.functions.len());
        for (i, f) in module.functions.iter().enumerate() {
            eprintln!("  fn{i}: {} blocks, {} params, {} results",
                f.blocks.len(), f.params.len(), f.results.len());
        }
    }

    let mut dbg = U30Debugger::new(module, &[], fuel)
        .map_err(|e| anyhow::anyhow!("init error: {e}"))?;

    println!("U30 Debugger — type 'help' for commands");
    println!("{}", dbg.show_registers());

    let stdin = io::stdin();
    let mut input = String::new();

    loop {
        print!("(dbg) ");
        io::stdout().flush()?;
        input.clear();
        let n = stdin.read_line(&mut input)?;
        if n == 0 { break; }
        let input = input.trim();
        if input.is_empty() { continue; }

        let parts: Vec<&str> = input.split_whitespace().collect();
        let cmd = parts.first().copied().unwrap_or("");

        match cmd {
            "help" | "h" => {
                println!("Commands:");
                println!("  s, step              — step one operation");
                println!("  n, next              — step over calls");
                println!("  c, continue          — continue to next breakpoint");
                println!("  r, regs              — show registers");
                println!("  x <region> [addr]    — show memory region");
                println!("  bt, backtrace         — show call stack");
                println!("  b <fn> <block> <op>   — set breakpoint");
                println!("  b <fn> <block>        — breakpoint at block entry");
                println!("  del <fn> <block> <op> — delete breakpoint");
                println!("  list                  — list breakpoints");
                println!("  finish               — run to completion");
                println!("  q, quit              — quit debugger");
            }
            "step" | "s" => {
                match dbg.step() {
                    Ok(event) => { print_event(&event); println!("{}", dbg.show_registers()); }
                    Err(e) => { println!("Error: {e}"); }
                }
            }
            "next" | "n" => {
                match dbg.step_over() {
                    Ok(event) => { print_event(&event); println!("{}", dbg.show_registers()); }
                    Err(e) => { println!("Error: {e}"); }
                }
            }
            "continue" | "c" => {
                match dbg.continue_exec() {
                    Ok(event) => { print_event(&event); }
                    Err(e) => { println!("Error: {e}"); }
                }
            }
            "regs" | "r" => {
                println!("{}", dbg.show_registers());
            }
            "x" => {
                let region = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                println!("{}", dbg.show_memory(region));
            }
            "backtrace" | "bt" => {
                println!("{}", dbg.show_backtrace());
            }
            "b" | "break" => {
                let fn_idx = parts.get(1).and_then(|s| s.parse().ok());
                let block_idx = parts.get(2).and_then(|s| s.parse().ok());
                let op_idx = parts.get(3).and_then(|s| s.parse().ok());
                let bp = Breakpoint {
                    fn_idx: fn_idx,
                    block_idx,
                    op_idx,
                };
                dbg.set_breakpoint(bp);
                println!("Breakpoint set");
            }
            "del" | "delete" => {
                let fn_idx = parts.get(1).and_then(|s| s.parse().ok());
                let block_idx = parts.get(2).and_then(|s| s.parse().ok());
                let op_idx = parts.get(3).and_then(|s| s.parse().ok());
                let bp = Breakpoint { fn_idx, block_idx, op_idx };
                dbg.remove_breakpoint(&bp);
                println!("Breakpoint removed");
            }
            "list" | "l" => {
                for bp in dbg.breakpoints() {
                    println!("  {bp:?}");
                }
            }
            "finish" | "f" => {
                match dbg.run_to_completion() {
                    Ok(out) => {
                        println!("Halted: {} steps, {} bytes allocated", out.steps, out.regions.len());
                    }
                    Err(e) => { println!("Error: {e}"); }
                }
            }
            "quit" | "q" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Unknown command: {cmd}. Type 'help' for commands.");
            }
        }
    }

    Ok(())
}

fn print_event(event: &U30DebugEvent) {
    match event {
        U30DebugEvent::Halted { reason } => {
            println!("[Halted: {reason}]");
        }
        U30DebugEvent::Breakpoint { fn_idx, block_idx, op_idx } => {
            println!("[Breakpoint hit: fn{fn_idx}:block{block_idx}:op{op_idx}]");
        }
        U30DebugEvent::Step { fn_idx, block_idx, op_idx, op } => {
            println!("  fn{fn_idx}:block{block_idx}:op{op_idx}  {op:?}");
        }
        U30DebugEvent::OutOfFuel => {
            println!("[Out of fuel]");
        }
    }
}
