//! UNICO Host Boundary v2
//!
//! Defines the interface for host functions that E4 modules can call.
//! E4 modules can invoke host functions by index — the boundary mediates
//! all cross-sandbox calls and tracks them in Provenance.

use crate::exec::e4::E4Value;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_functions_new() {
        let hf = HostFunctions::new();
        assert!(hf.is_empty());
        assert_eq!(hf.len(), 0);
    }

    #[test]
    fn test_host_functions_register() {
        let mut hf = HostFunctions::new();
        let id0 = hf.register(|_| E4Value::I32(42));
        let id1 = hf.register(|_| E4Value::F32(1.5));
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(hf.len(), 2);
        assert!(!hf.is_empty());
    }

    #[test]
    fn test_host_functions_call() {
        let mut hf = HostFunctions::new();
        hf.register(|args| {
            if args.is_empty() {
                E4Value::I32(99)
            } else {
                args[0].clone()
            }
        });
        let result = hf.call(0, &[]).unwrap();
        assert_eq!(result.as_i32().unwrap(), 99);

        let result = hf.call(0, &[E4Value::I32(77)]).unwrap();
        assert_eq!(result.as_i32().unwrap(), 77);
    }

    #[test]
    fn test_host_functions_call_not_found() {
        let mut hf = HostFunctions::new();
        hf.register(|_| E4Value::I32(1));
        let result = hf.call(99, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("host function 99 not found"));
    }

    #[test]
    fn test_host_functions_multiple_calls() {
        let mut hf = HostFunctions::new();
        hf.register(|args| {
            let a = if args.is_empty() { 0 } else { args[0].as_i32().unwrap_or(0) };
            E4Value::I32(a * 2)
        });
        hf.register(|args| {
            let a = if args.is_empty() { 0 } else { args[0].as_i32().unwrap_or(0) };
            E4Value::I32(a + 100)
        });

        let r0 = hf.call(0, &[E4Value::I32(5)]).unwrap();
        assert_eq!(r0.as_i32().unwrap(), 10);

        let r1 = hf.call(1, &[E4Value::I32(5)]).unwrap();
        assert_eq!(r1.as_i32().unwrap(), 105);
    }

    #[test]
    fn test_host_functions_different_types() {
        let mut hf = HostFunctions::new();
        let id = hf.register(|_| E4Value::F64(3.14));
        let result = hf.call(id, &[]).unwrap();
        assert!((result.as_f64().unwrap() - 3.14).abs() < 0.001);
    }

    #[test]
    fn test_host_functions_is_empty() {
        let mut hf = HostFunctions::new();
        assert!(hf.is_empty());
        hf.register(|_| E4Value::I32(0));
        assert!(!hf.is_empty());
    }

    #[test]
    fn test_host_functions_len() {
        let mut hf = HostFunctions::new();
        assert_eq!(hf.len(), 0);
        hf.register(|_| E4Value::I32(0));
        assert_eq!(hf.len(), 1);
        hf.register(|_| E4Value::I32(0));
        assert_eq!(hf.len(), 2);
        hf.register(|_| E4Value::I32(0));
        assert_eq!(hf.len(), 3);
    }

    #[test]
    fn test_host_functions_default() {
        let hf: HostFunctions = Default::default();
        assert!(hf.is_empty());
        assert_eq!(hf.len(), 0);
    }

    #[test]
    fn test_host_functions_call_with_args() {
        let mut hf = HostFunctions::new();
        hf.register(|_args| {
            E4Value::I32(42)
        });

        let result = hf.call(0, &[E4Value::I32(5)]).unwrap();
        assert_eq!(result.as_i32().unwrap(), 42);
    }

    #[test]
    fn test_host_functions_call_with_multiple_args() {
        let mut hf = HostFunctions::new();
        hf.register(|_args| {
            E4Value::I32(100)
        });

        let result = hf.call(0, &[E4Value::I32(10), E4Value::I32(20)]).unwrap();
        assert_eq!(result.as_i32().unwrap(), 100);
    }
}

/// A host function that can be called from E4 execution.
/// Takes a slice of register values and returns a register value.
pub type HostFn = fn(&[E4Value]) -> E4Value;

/// Boxed host function for storage in a vector.
type BoxedHostFn = Box<dyn Fn(&[E4Value]) -> E4Value>;

/// Registry of host functions indexed by ID.
/// E4 `HostCall` instructions refer to these by index.
#[derive(Default)]
pub struct HostFunctions {
    functions: Vec<BoxedHostFn>,
}

impl HostFunctions {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self { functions: Vec::new() }
    }

    /// Register a host function, returning its assigned ID.
    pub fn register<F>(&mut self, f: F) -> u32
    where
        F: Fn(&[E4Value]) -> E4Value + 'static,
    {
        let id = self.functions.len() as u32;
        self.functions.push(Box::new(f));
        id
    }

    /// Call a host function by ID, passing register values as arguments.
    /// Returns the result register value, or an error if the ID is out of bounds.
    pub fn call(&self, id: u32, args: &[E4Value]) -> Result<E4Value, String> {
        self.functions
            .get(id as usize)
            .map(|f| f(args))
            .ok_or_else(|| format!("E4: host function {} not found", id))
    }

    /// Number of registered functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// True if no functions are registered.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}
