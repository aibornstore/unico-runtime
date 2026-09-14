//! UNICO Host Boundary v2
//!
//! Defines the interface for host functions that E4 modules can call.
//! E4 modules can invoke host functions by index — the boundary mediates
//! all cross-sandbox calls and tracks them in Provenance.

use crate::exec::e4::E4Value;

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
