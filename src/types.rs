//! UNICO Core Types
//! 
//! Based on UNICO v3.0 Execution Contract

/// UNICO Integer (i64)
pub type I64 = i64;

/// UNICO Unsigned Integer (u64)
pub type U64 = u64;

/// UNICO Profile (version)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    E0,
    E1,
    E2,
    /// E3 pending gate decision
    E3Pending,
}

impl Profile {
    pub fn from_magic(magic: &[u8; 6]) -> Option<Self> {
        match &magic[4..6] {
            b"\xe0" => Some(Profile::E0),
            b"\xe1" => Some(Profile::E1),
            b"\xe2" => Some(Profile::E2),
            b"\xe3" => Some(Profile::E3Pending),
            _ => None,
        }
    }
    
    pub fn magic(&self) -> [u8; 6] {
        match self {
            Profile::E0 => *b"UNICO\xe0",
            Profile::E1 => *b"UNICO\xe1",
            Profile::E2 => *b"UNICO\xe2",
            Profile::E3Pending => *b"UNICO\xe3",
        }
    }
}

/// Execution Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
}

/// Execution Provenance
#[derive(Debug, Clone)]
pub struct Provenance {
    /// Instructions executed
    pub instructions: u64,
    
    /// Fuel remaining
    pub fuel_remaining: u64,
    
    /// Host calls made
    pub host_calls: u32,
    
    /// Execution time in microseconds
    pub duration_us: u64,
    
    /// Whether execution was deterministic
    pub deterministic: bool,
}

impl Default for Provenance {
    fn default() -> Self {
        Self {
            instructions: 0,
            fuel_remaining: 100_000,
            host_calls: 0,
            duration_us: 0,
            deterministic: true,
        }
    }
}

/// Execution Result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub status: Status,
    pub value: Option<I64>,
    pub memory: Option<Vec<u8>>,
    pub provenance: Provenance,
    pub error: Option<String>,
}

impl ExecutionResult {
    pub fn pass(value: I64, provenance: Provenance) -> Self {
        Self {
            status: Status::Pass,
            value: Some(value),
            memory: None,
            provenance,
            error: None,
        }
    }
    
    pub fn pass_with_memory(value: I64, memory: Vec<u8>, provenance: Provenance) -> Self {
        Self {
            status: Status::Pass,
            value: Some(value),
            memory: Some(memory),
            provenance,
            error: None,
        }
    }
    
    pub fn fail(error: String, provenance: Provenance) -> Self {
        Self {
            status: Status::Fail,
            value: None,
            memory: None,
            provenance,
            error: Some(error),
        }
    }
}

/// Register Value
#[derive(Debug, Clone, Copy)]
pub enum RegisterValue {
    I64(I64),
    Bool(bool),
}

impl RegisterValue {
    pub fn as_i64(&self) -> Option<I64> {
        match self {
            RegisterValue::I64(v) => Some(*v),
            _ => None,
        }
    }
    
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            RegisterValue::Bool(v) => Some(*v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_magic_bytes() {
        // Test that magic() returns correct prefix and last byte
        let magic = Profile::E0.magic();
        assert_eq!(magic[0], 85);  // 'U'
        assert_eq!(magic[1], 78);  // 'N'
        assert_eq!(magic[2], 73);  // 'I'
        assert_eq!(magic[3], 67);  // 'C'
        assert_eq!(magic[4], 79);  // 'O'
        assert_eq!(magic[5], 224); // \xe0
    }

    #[test]
    fn test_profile_all_variants() {
        // Test all profile variants can be created and have magic
        let profiles = [Profile::E0, Profile::E1, Profile::E2, Profile::E3Pending];
        for p in profiles {
            let magic = p.magic();
            assert_eq!(magic.len(), 6);
        }
    }

    #[test]
    fn test_profile_magic_e1() {
        let magic = Profile::E1.magic();
        assert_eq!(magic, *b"UNICO\xe1");
    }

    #[test]
    fn test_profile_magic_e2() {
        let magic = Profile::E2.magic();
        assert_eq!(magic, *b"UNICO\xe2");
    }

    #[test]
    fn test_profile_magic_e3_pending() {
        let magic = Profile::E3Pending.magic();
        assert_eq!(magic, *b"UNICO\xe3");
    }

    #[test]
    fn test_provenance_default() {
        let p = Provenance::default();
        assert_eq!(p.instructions, 0);
        assert_eq!(p.fuel_remaining, 100_000);
        assert_eq!(p.host_calls, 0);
        assert_eq!(p.duration_us, 0);
        assert!(p.deterministic);
    }

    #[test]
    fn test_provenance_custom() {
        let p = Provenance {
            instructions: 1000,
            fuel_remaining: 50000,
            host_calls: 5,
            duration_us: 12345,
            deterministic: false,
        };
        assert_eq!(p.instructions, 1000);
        assert_eq!(p.fuel_remaining, 50000);
        assert_eq!(p.host_calls, 5);
        assert_eq!(p.duration_us, 12345);
        assert!(!p.deterministic);
    }

    #[test]
    fn test_execution_result_debug() {
        let provenance = Provenance::default();
        let result = ExecutionResult::pass(42, provenance);
        // Debug output should not panic
        let _dbg = format!("{:?}", result);
    }

    #[test]
    fn test_status_debug() {
        // Test Status enum debug output
        let _pass = format!("{:?}", Status::Pass);
        let _fail = format!("{:?}", Status::Fail);
    }

    #[test]
    fn test_profile_debug() {
        // Test Profile enum debug output
        let _e0 = format!("{:?}", Profile::E0);
        let _e1 = format!("{:?}", Profile::E1);
        let _e2 = format!("{:?}", Profile::E2);
        let _e3 = format!("{:?}", Profile::E3Pending);
    }

    #[test]
    fn test_register_value_debug() {
        // Test RegisterValue enum debug output
        let _i64 = format!("{:?}", RegisterValue::I64(42));
        let _true = format!("{:?}", RegisterValue::Bool(true));
        let _false = format!("{:?}", RegisterValue::Bool(false));
    }

    #[test]
    fn test_execution_result_fail_with_memory() {
        // Even on failure, memory should be None
        let provenance = Provenance::default();
        let result = ExecutionResult::fail("error".into(), provenance);
        assert!(result.memory.is_none());
    }

    #[test]
    fn test_provenance_debug() {
        let p = Provenance::default();
        let _ = format!("{:?}", p);
    }

    #[test]
    fn test_execution_result_pass_memory_none() {
        // When pass() is called, memory should be None
        let provenance = Provenance::default();
        let result = ExecutionResult::pass(100, provenance);
        assert!(result.memory.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_execution_result_fail_error_contains() {
        let provenance = Provenance::default();
        let result = ExecutionResult::fail("specific error message".into(), provenance);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("specific error"));
    }

    #[test]
    fn test_execution_result_pass_with_memory_verifies() {
        let provenance = Provenance::default();
        let mem = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = ExecutionResult::pass_with_memory(123, mem.clone(), provenance);
        assert_eq!(result.memory, Some(mem));
    }

    #[test]
    fn test_profile_family_name() {
        // Test that all profile variants have expected family names
        // via the magic() method
        assert_eq!(Profile::E0.magic()[5], 0xE0);
        assert_eq!(Profile::E1.magic()[5], 0xE1);
        assert_eq!(Profile::E2.magic()[5], 0xE2);
        assert_eq!(Profile::E3Pending.magic()[5], 0xE3);
    }

    #[test]
    fn test_status_variants() {
        // Test Status variants
        assert!(matches!(Status::Pass, Status::Pass));
        assert!(matches!(Status::Fail, Status::Fail));
    }

    #[test]
    fn test_profile_partial_eq() {
        assert_eq!(Profile::E0, Profile::E0);
        assert_eq!(Profile::E1, Profile::E1);
        assert_eq!(Profile::E2, Profile::E2);
        assert_eq!(Profile::E3Pending, Profile::E3Pending);
        assert_ne!(Profile::E0, Profile::E1);
        assert_ne!(Profile::E1, Profile::E2);
        assert_ne!(Profile::E2, Profile::E3Pending);
    }

    #[test]
    fn test_register_value_clone() {
        let rv1 = RegisterValue::I64(42);
        let _rv2 = rv1.clone();

        let rv3 = RegisterValue::Bool(true);
        let _rv4 = rv3.clone();
    }

    #[test]
    fn test_execution_result_pass() {
        let provenance = Provenance::default();
        let result = ExecutionResult::pass(42, provenance.clone());
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_execution_result_fail() {
        let provenance = Provenance::default();
        let result = ExecutionResult::fail("test error".into(), provenance);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("test error"));
    }

    #[test]
    fn test_execution_result_pass_with_memory() {
        let provenance = Provenance::default();
        let mem = vec![1, 2, 3];
        let result = ExecutionResult::pass_with_memory(42, mem.clone(), provenance);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.memory, Some(mem));
    }

    #[test]
    fn test_register_value_as_i64() {
        let rv = RegisterValue::I64(42);
        assert_eq!(rv.as_i64(), Some(42));
        assert_eq!(rv.as_bool(), None);

        let rv = RegisterValue::Bool(true);
        assert_eq!(rv.as_i64(), None);
    }

    #[test]
    fn test_register_value_as_bool() {
        let rv = RegisterValue::Bool(true);
        assert_eq!(rv.as_bool(), Some(true));

        let rv = RegisterValue::Bool(false);
        assert_eq!(rv.as_bool(), Some(false));

        let rv = RegisterValue::I64(0);
        assert_eq!(rv.as_bool(), None);
    }
}
