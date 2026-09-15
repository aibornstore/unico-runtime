//! UNICO CLI — Command-line interface to run UNICO modules
//!
//! Usage:
//!   unico run <module-file> [--profile e3|e4|u30] [--fuel N] [--verbose]
//!   unico debug <module-file> [--fuel N]
//!   unico disasm <module-file> [--no-colors] [--show-memory]
//!   unico encode <source-json> [--output <file>]
//!   unico decode <module-file> [--output <file>]  # auto-detects U30/E4
//!   unico info <module-file>

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod run_cmd;
mod info_cmd;
mod encode_cmd;
mod decode_cmd;
mod debug_cmd;
mod disasm_cmd;
mod assemble_cmd;

pub use run_cmd::run_module;
pub use info_cmd::info_module;
pub use encode_cmd::encode_module;
pub use decode_cmd::decode_module;
pub use debug_cmd::debug_module;
pub use disasm_cmd::disasm_file;
pub use assemble_cmd::assemble_file;

#[derive(Parser)]
#[command(name = "unico")]
#[command(version = "0.1.0")]
#[command(about = "UNICO v3.0 execution runtime CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a UNICO module and print results
    Run {
        /// Module file path
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Module profile: e3 (default), e4, u30
        #[arg(short, long, default_value = "auto")]
        profile: String,

        /// Fuel limit (default: 1,000,000)
        #[arg(short, long, default_value = "1000000")]
        fuel: u64,

        /// Hex-encoded input arguments (for E3/E4, e.g. "0a 00 2a")
        #[arg(short, long)]
        args: Option<String>,

        /// Register built-in host functions (e4 only):
        /// print_i32, add_i32, mul_i32, sub_i32, div_i32, read_i32, write_i32
        #[arg(long, value_delimiter = ',', default_value = "")]
        host_fn: Vec<String>,
    },
    /// Interactive debugger for U30 modules
    Debug {
        /// Module file path (U30 binary)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Fuel limit (default: 1,000,000)
        #[arg(short, long, default_value = "1000000")]
        fuel: u64,
    },
    /// Show module information (functions, memory size, regions)
    Info {
        /// Module file path
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Module profile
        #[arg(short, long, default_value = "auto")]
        profile: String,
    },
    /// Encode a U30 or E4 module from JSON (auto-detects format)
    Encode {
        /// JSON source file (or - for stdin)
        #[arg(value_name = "FILE")]
        source: PathBuf,

        /// Output file (or stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decode a U30 or E4 module to JSON (auto-detects format)
    Decode {
        /// Module file path
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Output file (or stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Disassemble a U30 or E4 binary to readable text
    Disasm {
        /// Module file path
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Disable ANSI color codes
        #[arg(short, long)]
        no_colors: bool,

        /// Show memory hex dump (E4 only)
        #[arg(long)]
        show_memory: bool,
    },
    /// Assemble U30 assembly text into binary
    Assemble {
        /// Assembly source file (or - for stdin)
        #[arg(value_name = "FILE")]
        source: PathBuf,

        /// Output file (or stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let verbose = cli.verbose;

    let result = match cli.command {
        Commands::Run { file, profile, fuel, args, host_fn } => {
            run_module(&file, &profile, fuel, args.as_deref(), &host_fn, verbose)
        }
        Commands::Debug { file, fuel } => {
            debug_module(&file, fuel, verbose)
        }
        Commands::Info { file, profile } => {
            info_module(&file, &profile, verbose)
        }
        Commands::Encode { source, output } => {
            encode_module(&source, output.as_deref(), verbose)
        }
        Commands::Decode { file, output } => {
            decode_module(&file, output.as_deref(), verbose)
        }
        Commands::Disasm { file, no_colors, show_memory } => {
            disasm_file(&file, no_colors, show_memory, verbose)
        }
        Commands::Assemble { source, output } => {
            assemble_file(&source, output.as_deref(), verbose)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
