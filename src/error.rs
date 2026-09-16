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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_exit_code_explicit_trap() {
        assert_eq!(ErrorCode::E0T001Explicit.exit_code(), 6);
        assert_eq!(ErrorCode::E1T001Explicit.exit_code(), 6);
        assert_eq!(ErrorCode::E2T001Explicit.exit_code(), 6);
    }

    #[test]
    fn test_error_code_exit_code_structural() {
        assert_eq!(ErrorCode::E0T002Structural.exit_code(), 4);
        assert_eq!(ErrorCode::E0T003Canonical.exit_code(), 4);
        assert_eq!(ErrorCode::E1T003CFG.exit_code(), 4);
        assert_eq!(ErrorCode::E1T004Type.exit_code(), 4);
    }

    #[test]
    fn test_error_code_exit_code_runtime() {
        assert_eq!(ErrorCode::E1T002Fuel.exit_code(), 6);
        assert_eq!(ErrorCode::E2T002Fuel.exit_code(), 6);
        assert_eq!(ErrorCode::E2T003MemoryOOB.exit_code(), 6);
        assert_eq!(ErrorCode::E2T004MemoryAlign.exit_code(), 6);
        assert_eq!(ErrorCode::E2T005CallDepth.exit_code(), 6);
    }

    #[test]
    fn test_error_code_exit_code_host() {
        assert_eq!(ErrorCode::H0001CapabilityDenied.exit_code(), 7);
        assert_eq!(ErrorCode::H0002BudgetExceeded.exit_code(), 7);
        assert_eq!(ErrorCode::H0003InvalidRequest.exit_code(), 7);
    }

    #[test]
    fn test_error_code_family() {
        assert_eq!(ErrorCode::E0T001Explicit.family(), "E0");
        assert_eq!(ErrorCode::E1T002Fuel.family(), "E1");
        assert_eq!(ErrorCode::E2T003MemoryOOB.family(), "E2");
        assert_eq!(ErrorCode::H0001CapabilityDenied.family(), "HOST");
    }

    #[test]
    fn test_error_from_conversion() {
        let err = Error::Trap(ErrorCode::E1T001Explicit);
        let code: u8 = err.into();
        assert_eq!(code, 6);

        let err = Error::Format("bad format".into());
        let code: u8 = err.into();
        assert_eq!(code, 4);

        let err = Error::Generic("generic error".into());
        let code: u8 = err.into();
        assert_eq!(code, 4);

        let err = Error::Unimplemented("not implemented".into());
        let code: u8 = err.into();
        assert_eq!(code, 4);
    }

    #[test]
    fn test_error_display() {
        let err = Error::Format("test".into());
        assert!(err.to_string().contains("test"));

        let err = Error::Canonical("canon".into());
        assert!(err.to_string().contains("canon"));

        let err = Error::Verification("verify".into());
        assert!(err.to_string().contains("verify"));

        let err = Error::Trap(ErrorCode::E0T001Explicit);
        assert!(err.to_string().contains("Runtime trap"));

        let err = Error::HostDenied("capability".into());
        assert!(err.to_string().contains("capability"));

        let err = Error::HostBudgetExceeded("budget".into());
        assert!(err.to_string().contains("budget"));

        let err = Error::Generic("generic".into());
        assert!(err.to_string().contains("generic"));

        let err = Error::Unimplemented("unimp".into());
        assert!(err.to_string().contains("unimp"));
    }
}
