//! UNICO Error Types
//! 
//! Canonical error taxonomy matching execution contract

use thiserror::Error;

/// UNICO Error Codes (from execution contract)
/// Unique discriminant values per error code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    // E0 errors
    E0T001Explicit = 1,  // TRAP instruction
    E0T002Structural = 2, // Container format error
    E0T003Canonical = 3,   // Non-minimal LEB encoding
    
    // E1 errors
    E1T001Explicit = 11,   // TRAP
    E1T002Fuel = 12,       // Dispatch budget exhausted
    E1T003CFG = 13,        // Unreachable instruction
    E1T004Type = 14,       // Register type mismatch
    
    // E2 errors
    E2T001Explicit = 21,   // TRAP
    E2T002Fuel = 22,       // Dispatch exhausted
    E2T003MemoryOOB = 23,  // Memory out of bounds
    E2T004MemoryAlign = 24, // Alignment error
    E2T005CallDepth = 25,  // Depth exceeded
    
    // Host errors
    H0001CapabilityDenied = 101,
    H0002BudgetExceeded = 102,
    H0003InvalidRequest = 103,
}

impl ErrorCode {
    /// Exit code based on error class
    pub fn exit_code(&self) -> u8 {
        match self {
            // E0/E1/E2 explicit traps
            ErrorCode::E0T001Explicit |
            ErrorCode::E1T001Explicit |
            ErrorCode::E2T001Explicit => 6,
            
            // Structural/verifier errors
            ErrorCode::E0T002Structural |
            ErrorCode::E0T003Canonical |
            ErrorCode::E1T003CFG |
            ErrorCode::E1T004Type => 4,
            
            // Runtime traps (fuel, memory)
            ErrorCode::E1T002Fuel |
            ErrorCode::E2T002Fuel |
            ErrorCode::E2T003MemoryOOB |
            ErrorCode::E2T004MemoryAlign |
            ErrorCode::E2T005CallDepth => 6,
            
            // Host errors
            ErrorCode::H0001CapabilityDenied |
            ErrorCode::H0002BudgetExceeded |
            ErrorCode::H0003InvalidRequest => 7,
        }
    }
    
    /// Error family name
    pub fn family(&self) -> &'static str {
        match self {
            ErrorCode::E0T001Explicit | ErrorCode::E0T002Structural | ErrorCode::E0T003Canonical => "E0",
            ErrorCode::E1T001Explicit | ErrorCode::E1T002Fuel | ErrorCode::E1T003CFG | ErrorCode::E1T004Type => "E1",
            ErrorCode::E2T001Explicit | ErrorCode::E2T002Fuel | ErrorCode::E2T003MemoryOOB | ErrorCode::E2T004MemoryAlign | ErrorCode::E2T005CallDepth => "E2",
            ErrorCode::H0001CapabilityDenied | ErrorCode::H0002BudgetExceeded | ErrorCode::H0003InvalidRequest => "HOST",
        }
    }
}

/// UNICO Error
#[derive(Debug, Error)]
pub enum Error {
    #[error("Module format error: {0}")]
    Format(String),
    
    #[error("Canonical form violation: {0}")]
    Canonical(String),
    
    #[error("Static verification failed: {0}")]
    Verification(String),
    
    #[error("Runtime trap: {0:?}")]
    Trap(ErrorCode),
    
    #[error("Host capability denied: {0}")]
    HostDenied(String),
    
    #[error("Host budget exceeded: {0}")]
    HostBudgetExceeded(String),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Not yet implemented: {0}")]
    Unimplemented(String),

    /// Generic error with a message string
    #[error("{0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for u8 {
    fn from(err: Error) -> Self {
        match err {
            Error::Trap(code) => code.exit_code(),
            Error::Format(_) | Error::Canonical(_) | Error::Verification(_) | Error::Generic(_) => 4,
            Error::HostDenied(_) | Error::HostBudgetExceeded(_) => 7,
            Error::Io(_) => 70,
            Error::Unimplemented(_) => 4,
        }
    }
}
