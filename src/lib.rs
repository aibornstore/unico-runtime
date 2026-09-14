//! UNICO v3.0 Runtime
//! 
//! Execution engine for UNICO modules (E0/E1/E2/E3 profiles)
//! 
//! Based on UNICO v3.0 Execution Contract

pub mod error;
pub mod exec;
pub mod leb128;
pub mod verify;
pub mod host;
pub mod ir;
pub mod types;
pub mod runtime;
pub mod ser;

pub use error::{Error, Result};
pub use exec::{E0Executor, E0Module, E1Executor, E1Module, E2Executor, E2Module, E3Executor, E3Module};
pub use ser::{encode, decode};
pub use ir::U30Module;
pub use types::{I64, Profile, Status, Provenance};
