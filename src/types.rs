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
