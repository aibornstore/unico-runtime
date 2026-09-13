//! Execution Module
//! 
//! Executors for UNICO profiles (E0, E1, E2, E3, E5, E6, E7)

pub mod crypto_slot;
pub mod e0;
pub mod e1;
pub mod e2;
pub mod e3;
pub mod e5;
pub mod e6;
pub mod e7;

pub use crypto_slot::CryptoSlot;

pub use e0::{E0Executor, Module as E0Module, Function as E0Function, Instruction as E0Instruction};
pub use e1::{E1Executor, Module as E1Module, Function as E1Function, Instruction as E1Instruction};
pub use e2::{E2Executor, Module as E2Module, Function as E2Function, Instruction as E2Instruction};
pub use e3::{E3Executor, E3Module, E3FunctionDef as E3Function, Instruction as E3Instruction};
pub use e5::{E5Executor, E5Module, E5FunctionDef as E5Function, Instruction as E5Instruction};
pub use e6::{E6Executor, E6Module, E6FunctionDef as E6Function, Instruction as E6Instruction};
pub use e7::{E7Executor, E7Module, E7FunctionDef as E7Function, Instruction as E7Instruction};
