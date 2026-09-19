//! UNICO v3.0 Runtime
//! 
//! Execution engine for UNICO modules (E0/E1/E2/E3 profiles)
//! 
//! Based on UNICO v3.0 Execution Contract

pub mod assembler;
pub mod debugger;
pub mod e4_disasm;
pub mod e4_ser;
pub mod error;
pub mod exec;
pub mod host;
pub mod ir;
pub mod leb128;
pub mod pretty;
pub mod runtime;
pub mod ser;
pub mod trace;
pub mod types;
pub mod verify;

pub use e4_disasm::{decode_disasm, decode_disasm_opts, fmt_module as fmt_e4_module, FmtOpts as E4DisasmOpts};
pub use e4_ser::{decode_e4, encode_e4};
pub use error::{Error, Result};
pub use exec::{E0Executor, E0Module, E1Executor, E1Module, E2Executor, E2Module, E3Executor, E3Module, E4Executor, E4Module};
pub use pretty::{fmt_module, fmt_module_opts, FmtOpts};
pub use ser::{decode, encode};
pub use debugger::{Breakpoint, U30DebugEvent, U30DebugState, U30Debugger};
pub use ir::U30Module;
pub use trace::{SemanticTrace, TraceEffect, TraceEvent, TraceValue, TRACE_SCHEMA};
pub use types::{I64, Profile, Provenance, Status};
