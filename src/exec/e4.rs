//! E4 Executor — Floating-Point Scalar Profile
//!
//! Scalar f32/f64 arithmetic extending E3 integer operations:
//! - FADD, FSUB, FMUL, FDIV, FSQRT (binary f32)
//! - FNEG, FABS, FROUND (unary f32)
//! - FCMP (comparison: lt, le, gt, ge, eq, ne)
//! - I2F, F2I, U2F, F2U (type conversions)
//! - FIMM (f32 immediate)
//!
//! E4 opcodes:
//!   0x40 => FADD    0x41 => FSUB    0x42 => FMUL    0x43 => FDIV
//!   0x44 => FSQRT   0x45 => FNEG    0x46 => FABS    0x47 => FROUND
//!   0x48 => FCMP    0x49 => I2F     0x4A => F2I
//!   0x4B => U2F     0x4C => F2U     0x4D => FIMM
//!   (E1)  0x01 => BR       0x02 => BR_IF   0x03 => RET    0x04 => TRAP
//!   (E1)  0x05 => CMP
//!   (E2)  0x90 => LOAD.I64 0x91 => STORE.I64

use crate::error::{Error, Result};
use crate::host::HostFunctions;
use crate::types::{ExecutionResult, Provenance};
#[allow(unused_imports)]
use crate::types::Status;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ---------------------------------------------------------------------------
// E4 types
// ---------------------------------------------------------------------------

/// E4 instruction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    // E1 control flow (baseline)
    Br { target: u32 },
    BrIf { cond: u32, target: u32 },
    Ret { dst: u32 },
    Trap,
    Cmp { pred: u8, dst: u32, a: u32, b: u32 },
    // E2 memory
    LoadI64 { dst: u32, addr: u32 },
    StoreI64 { addr: u32, src: u32 },
    // E4 integer arithmetic (i32)
    IAdd { dst: u32, a: u32, b: u32 },
    ISub { dst: u32, a: u32, b: u32 },
    IMul { dst: u32, a: u32, b: u32 },
    IDiv { dst: u32, a: u32, b: u32 },
    // E4 floating-point binary (f32)
    FAdd { dst: u32, a: u32, b: u32 },
    FSub { dst: u32, a: u32, b: u32 },
    FMul { dst: u32, a: u32, b: u32 },
    FDiv { dst: u32, a: u32, b: u32 },
    // E4 floating-point unary
    FSqrt { dst: u32, a: u32 },
    FNeg { dst: u32, a: u32 },
    FAbs { dst: u32, a: u32 },
    FRound { dst: u32, a: u32 },
    // E4 floating-point comparison
    FCmp { pred: u8, dst: u32, a: u32, b: u32 },
    // E4 type conversions
    I2F { dst: u32, a: u32 },  // i32 → f32
    F2I { dst: u32, a: u32 },  // f32 → i32 (truncates)
    U2F { dst: u32, a: u32 },  // u32 → f32
    F2U { dst: u32, a: u32 },   // f32 → u32 (truncates)
    // E4 move (copy register to register)
    Mov { dst: u32, src: u32 },
    // E4 immediate (f32)
    FImm { dst: u32, imm: f32 },
    // E4 f64 floating-point binary
    FAddF64 { dst: u32, a: u32, b: u32 },
    FSubF64 { dst: u32, a: u32, b: u32 },
    FMulF64 { dst: u32, a: u32, b: u32 },
    FDivF64 { dst: u32, a: u32, b: u32 },
    // E4 f64 unary (same ops work on both f32/f64 via as_f64)
    FSqrtF64 { dst: u32, a: u32 },
    FNegF64 { dst: u32, a: u32 },
    FAbsF64 { dst: u32, a: u32 },
    FRoundF64 { dst: u32, a: u32 },
    // E4 f64 comparison
    FCmpF64 { pred: u8, dst: u32, a: u32, b: u32 },
    // E4 type conversions
    I2F64 { dst: u32, a: u32 },  // i32 → f64
    F642I { dst: u32, a: u32 },  // f64 → i32 (truncates)
    U2F64 { dst: u32, a: u32 },  // u32 → f64
    F642U { dst: u32, a: u32 },  // f64 → u32 (truncates)
    // E4 f64 immediate
    FImmF64 { dst: u32, imm: f64 },
    // E4 host boundary v2: call a host function
    // id = host function index, args = register indices, results = register indices
    HostCall { id: u32, args: Vec<u32>, results: Vec<u32> },
}

/// E4 function definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E4FunctionDef {
    pub param_count: usize,
    pub result_count: usize,
    pub register_count: usize,
    pub code: Vec<Instruction>,
}

/// E4 module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E4Module {
    pub functions: Vec<E4FunctionDef>,
    pub memory: Vec<u8>, // 4096 bytes
}

// ---------------------------------------------------------------------------
// E4 register
// ---------------------------------------------------------------------------

/// E4 register: i32, f32, or f64
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum E4Value {
    I32(i32),
    F32(f32),
    F64(f64),
}

impl E4Value {
    pub(crate) fn as_i32(&self) -> Result<i32> {
        match self {
            Self::I32(v) => Ok(*v),
            _ => Err(Error::Generic("E4: expected i32".into())),
        }
    }

    pub(crate) fn as_f32(&self) -> Result<f32> {
        match self {
            Self::F32(v) => Ok(*v),
            Self::F64(v) => Ok(*v as f32),
            _ => Err(Error::Generic("E4: expected f32".into())),
        }
    }

    pub(crate) fn as_f64(&self) -> Result<f64> {
        match self {
            Self::F64(v) => Ok(*v),
            Self::F32(v) => Ok(*v as f64),
            _ => Err(Error::Generic("E4: expected f64".into())),
        }
    }

    fn as_bool(&self) -> Result<bool> {
        match self {
            Self::I32(v) => Ok(*v != 0),
            _ => Err(Error::Generic("E4: expected bool (i32)".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// E4 executor
// ---------------------------------------------------------------------------

pub struct E4Executor {
    start: Instant,
    fuel: u64,
    host_functions: HostFunctions,
    host_calls: u32,
}

impl Default for E4Executor {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            fuel: 100_000,
            host_functions: HostFunctions::new(),
            host_calls: 0,
        }
    }
}

impl E4Executor {
    fn provenance(&self) -> Provenance {
        Provenance {
            instructions: 0,
            fuel_remaining: self.fuel,
            host_calls: self.host_calls,
            duration_us: self.start.elapsed().as_micros() as u64,
            deterministic: true,
        }
    }

    /// Access the host function registry for registration.
    pub fn host_functions_mut(&mut self) -> &mut HostFunctions {
        &mut self.host_functions
    }

    pub fn execute(&mut self, module: &E4Module, _function_index: usize) -> Result<ExecutionResult> {
        if module.functions.is_empty() {
            return Ok(ExecutionResult::fail("E4: no functions".into(), self.provenance()));
        }
        let def = &module.functions[0];
        let mut regs: Vec<E4Value> = vec![E4Value::I32(0); def.register_count.max(16)];
        let mut memory = module.memory.clone();
        let mut pc = 0usize;

        loop {
            if pc >= def.code.len() {
                return Ok(ExecutionResult::fail("E4: unexpected end".into(), self.provenance()));
            }
            if self.fuel == 0 {
                return Ok(ExecutionResult::fail("E4: fuel exhausted".into(), self.provenance()));
            }
            self.fuel -= 1;

            match &def.code[pc] {
                Instruction::Br { target } => pc = *target as usize,
                Instruction::BrIf { cond, target } => {
                    if regs[*cond as usize].as_bool()? {
                        pc = *target as usize;
                    } else {
                        pc += 1;
                    }
                }
                Instruction::Ret { dst } => {
                    let val = match regs[*dst as usize] {
                        E4Value::I32(v) => v as i64,
                        E4Value::F32(v) => v.to_bits() as i64,
                        E4Value::F64(v) => v.to_bits() as i64,
                    };
                    return Ok(ExecutionResult::pass(val, self.provenance()));
                }
                Instruction::Trap => {
                    return Ok(ExecutionResult::fail("E4: trap".into(), self.provenance()));
                }
                Instruction::Cmp { pred, dst, a, b } => {
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    let r = match pred {
                        0 => a == b,
                        1 => a != b,
                        2 => a < b,
                        3 => a >= b,
                        _ => return Err(Error::Generic(format!("E4: unknown cmp pred {pred}"))),
                    };
                    regs[*dst as usize] = E4Value::I32(if r { 1 } else { 0 });
                    pc += 1;
                }
                Instruction::LoadI64 { dst, addr } => {
                    let addr = regs[*addr as usize].as_i32()? as usize;
                    if addr + 8 > memory.len() {
                        return Ok(ExecutionResult::fail("E4: load out of bounds".into(), self.provenance()));
                    }
                    let bytes: [u8; 8] = memory[addr..addr+8].try_into().unwrap();
                    let val = i64::from_le_bytes(bytes);
                    regs[*dst as usize] = E4Value::I32(val as i32);
                    pc += 1;
                }
                Instruction::StoreI64 { addr, src } => {
                    let addr = regs[*addr as usize].as_i32()? as usize;
                    let val = regs[*src as usize].as_i32()? as i64;
                    if addr + 8 > memory.len() {
                        return Ok(ExecutionResult::fail("E4: store out of bounds".into(), self.provenance()));
                    }
                    memory[addr..addr+8].copy_from_slice(&val.to_le_bytes());
                    pc += 1;
                }
                Instruction::IAdd { dst, a, b } => {
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_add(b));
                    pc += 1;
                }
                Instruction::ISub { dst, a, b } => {
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_sub(b));
                    pc += 1;
                }
                Instruction::IMul { dst, a, b } => {
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_mul(b));
                    pc += 1;
                }
                Instruction::IDiv { dst, a, b } => {
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    if b == 0 {
                        return Ok(ExecutionResult::fail("E4: division by zero".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a.wrapping_div(b));
                    pc += 1;
                }
                Instruction::FAdd { dst, a, b } => {
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a + b);
                    pc += 1;
                }
                Instruction::FSub { dst, a, b } => {
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a - b);
                    pc += 1;
                }
                Instruction::FMul { dst, a, b } => {
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a * b);
                    pc += 1;
                }
                Instruction::FDiv { dst, a, b } => {
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    if b == 0.0 {
                        return Ok(ExecutionResult::fail("E4: division by zero".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::F32(a / b);
                    pc += 1;
                }
                Instruction::FSqrt { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.sqrt());
                    pc += 1;
                }
                Instruction::FNeg { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(-a);
                    pc += 1;
                }
                Instruction::FAbs { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.abs());
                    pc += 1;
                }
                Instruction::FRound { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.round());
                    pc += 1;
                }
                Instruction::FCmp { pred, dst, a, b } => {
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    let r = match pred {
                        0 => a < b,
                        1 => a <= b,
                        2 => a > b,
                        3 => a >= b,
                        4 => a == b,
                        5 => a != b,
                        _ => return Err(Error::Generic(format!("E4: unknown fcmp pred {pred}"))),
                    };
                    regs[*dst as usize] = E4Value::I32(if r { 1 } else { 0 });
                    pc += 1;
                }
                Instruction::I2F { dst, a } => {
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F32(a as f32);
                    pc += 1;
                }
                Instruction::F2I { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    if a.is_nan() || a < (i32::MIN as f32) || a > (i32::MAX as f32) {
                        return Ok(ExecutionResult::fail("E4: f2i conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a as i32);
                    pc += 1;
                }
                Instruction::U2F { dst, a } => {
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F32((a as u32) as f32);
                    pc += 1;
                }
                Instruction::F2U { dst, a } => {
                    let a = regs[*a as usize].as_f32()?;
                    if a.is_nan() || a < 0.0 || a > (u32::MAX as f32) {
                        return Ok(ExecutionResult::fail("E4: f2u conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32((a as u32) as i32);
                    pc += 1;
                }
                Instruction::Mov { dst, src } => {
                    regs[*dst as usize] = regs[*src as usize];
                    pc += 1;
                }
                Instruction::FImm { dst, imm } => {
                    regs[*dst as usize] = E4Value::F32(*imm);
                    pc += 1;
                }
                // ---- E4 f64 floating-point binary ----
                Instruction::FAddF64 { dst, a, b } => {
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a + b);
                    pc += 1;
                }
                Instruction::FSubF64 { dst, a, b } => {
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a - b);
                    pc += 1;
                }
                Instruction::FMulF64 { dst, a, b } => {
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a * b);
                    pc += 1;
                }
                Instruction::FDivF64 { dst, a, b } => {
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a / b);
                    pc += 1;
                }
                Instruction::FSqrtF64 { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.sqrt());
                    pc += 1;
                }
                Instruction::FNegF64 { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(-a);
                    pc += 1;
                }
                Instruction::FAbsF64 { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.abs());
                    pc += 1;
                }
                Instruction::FRoundF64 { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.round());
                    pc += 1;
                }
                Instruction::FCmpF64 { pred, dst, a, b } => {
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    let r = match pred {
                        0 => a < b,
                        1 => a <= b,
                        2 => a > b,
                        3 => a >= b,
                        4 => a == b,
                        5 => a != b,
                        _ => return Err(Error::Generic(format!("E4: unknown fcmp.f64 pred {pred}"))),
                    };
                    regs[*dst as usize] = E4Value::I32(if r { 1 } else { 0 });
                    pc += 1;
                }
                Instruction::I2F64 { dst, a } => {
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F64(a as f64);
                    pc += 1;
                }
                Instruction::F642I { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    if a.is_nan() || a < (i32::MIN as f64) || a > (i32::MAX as f64) {
                        return Ok(ExecutionResult::fail("E4: f64→i32 conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a as i32);
                    pc += 1;
                }
                Instruction::U2F64 { dst, a } => {
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F64((a as u32) as f64);
                    pc += 1;
                }
                Instruction::F642U { dst, a } => {
                    let a = regs[*a as usize].as_f64()?;
                    if a.is_nan() || a < 0.0 || a > (u32::MAX as f64) {
                        return Ok(ExecutionResult::fail("E4: f64→u32 conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32((a as u32) as i32);
                    pc += 1;
                }
                Instruction::FImmF64 { dst, imm } => {
                    regs[*dst as usize] = E4Value::F64(*imm);
                    pc += 1;
                }
                Instruction::HostCall { id, args, results } => {
                    // Read arguments from registers
                    let arg_vals: Vec<E4Value> = args
                        .iter()
                        .map(|&r| regs[r as usize].clone())
                        .collect();
                    // Call the host function
                    match self.host_functions.call(*id, &arg_vals) {
                        Ok(result) => {
                            // Write result(s) back to registers
                            for &dst_reg in results.iter() {
                                regs[dst_reg as usize] = result.clone();
                            }
                            self.host_calls += 1;
                        }
                        Err(e) => {
                            return Ok(ExecutionResult::fail(e, self.provenance()));
                        }
                    }
                    pc += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E4 tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostFunctions;

    fn make_module(code: Vec<Instruction>) -> E4Module {
        E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code,
            }],
            memory: vec![0u8; 4096],
        }
    }

    fn make_module_with_memory(code: Vec<Instruction>, memory_size: usize) -> E4Module {
        E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code,
            }],
            memory: vec![0u8; memory_size],
        }
    }

    /// Helper to test FP ops: loads two f32 values into regs via i2f
    /// We use FImm to set f32 values directly (stored as bits in i32)
    fn fbits(f: f32) -> i32 {
        f.to_bits() as i32
    }

    fn fimm(v: f32) -> Instruction {
        Instruction::FImm { dst: 0, imm: v }
    }

    #[test]
    fn test_e4_fadd() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.5 },
            Instruction::FImm { dst: 1, imm: 2.5 },
            Instruction::FAdd { dst: 2, a: 0, b: 1 },
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_ok(), "execution should succeed");
        let r = result.unwrap();
        let bits = r.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 4.0).abs() < 0.001, "expected 4.0, got {f}");
    }

    #[test]
    fn test_e4_fsub() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 5.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FSub { dst: 2, a: 0, b: 1 },
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 2.0).abs() < 0.001, "expected 2.0, got {f}");
    }

    #[test]
    fn test_e4_fmul() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.0 },
            Instruction::FImm { dst: 1, imm: 4.0 },
            Instruction::FMul { dst: 2, a: 0, b: 1 },
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 12.0).abs() < 0.001, "expected 12.0, got {f}");
    }

    #[test]
    fn test_e4_fdiv() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 10.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::FDiv { dst: 2, a: 0, b: 1 },
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 5.0).abs() < 0.001, "expected 5.0, got {f}");
    }

    #[test]
    fn test_e4_fsqrt() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 16.0 },
            Instruction::FSqrt { dst: 1, a: 0 },
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 4.0).abs() < 0.001, "expected 4.0, got {f}");
    }

    #[test]
    fn test_e4_fneg() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.5 },
            Instruction::FNeg { dst: 1, a: 0 },
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - (-3.5)).abs() < 0.001, "expected -3.5, got {f}");
    }

    #[test]
    fn test_e4_fabs() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: -3.5 },
            Instruction::FAbs { dst: 1, a: 0 },
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 3.5).abs() < 0.001, "expected 3.5, got {f}");
    }

    #[test]
    fn test_e4_fcmp_lt() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 2.0 },
            Instruction::FImm { dst: 1, imm: 5.0 },
            Instruction::FCmp { pred: 0, dst: 2, a: 0, b: 1 }, // 2.0 < 5.0
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_fcmp_eq() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FCmp { pred: 4, dst: 2, a: 0, b: 1 }, // 3.0 == 3.0
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_fcmp_gt() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 10.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FCmp { pred: 2, dst: 2, a: 0, b: 1 }, // 10.0 > 3.0
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_fcmp_false() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 5.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FCmp { pred: 0, dst: 2, a: 0, b: 1 }, // 5.0 < 3.0 = false
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.value.unwrap(), 0);
    }

    #[test]
    fn test_e4_fround() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.7 },
            Instruction::FRound { dst: 1, a: 0 },
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 4.0).abs() < 0.001, "expected 4.0, got {f}");
    }

    #[test]
    fn test_e4_fdiv_by_zero() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 0.0 },
            Instruction::FDiv { dst: 2, a: 0, b: 1 },
            Instruction::Mov { dst: 10, src: 2 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail, "should fail on div by zero");
        assert!(result.error.as_ref().unwrap().contains("division by zero"));
    }

    #[test]
    fn test_e4_i2f() {
        let mut exec = E4Executor::default();
        // I2F: convert I32 to F32. Set register 0 to I32(1) using Cmp
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // 0==0 = 1
            Instruction::I2F { dst: 1, a: 0 }, // 1 -> 1.0
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 1.0).abs() < 0.001, "expected 1.0, got {f}");
    }

    #[test]
    fn test_e4_u2f() {
        let mut exec = E4Executor::default();
        // U2F: convert U32 to F32. Set register 0 to I32(1) using Cmp
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // 0==0 = 1
            Instruction::U2F { dst: 1, a: 0 }, // 1 -> 1.0
            Instruction::Mov { dst: 10, src: 1 },
            Instruction::Mov { dst: 0, src: 10 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 1.0).abs() < 0.001, "expected 1.0, got {f}");
    }

    #[test]
    fn test_e4_trap() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Trap,
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
    }

    #[test]
    fn test_e4_no_functions() {
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![],
            memory: vec![0u8; 4096],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.unwrap().contains("no functions"));
    }

    #[test]
    fn test_e4_hostcall_works() {
        // HostCall to a registered host function that returns I32(42)
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(42));
        let module = make_module(vec![
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 42);
        assert_eq!(result.provenance.host_calls, 1);
    }

    #[test]
    fn test_e4_hostcall_with_args() {
        // HostCall receives arguments from registers and returns a value
        let mut exec = E4Executor::default();
        // Host function: doubles its f32 argument
        exec.host_functions_mut().register(|args| {
            let v = match &args[0] {
                E4Value::F32(n) => *n as i32 * 2,
                _ => 0,
            };
            E4Value::I32(v)
        });
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 21.0 }, // r0 = 21.0
            Instruction::HostCall { id: 0, args: vec![0], results: vec![1] },
            Instruction::Ret { dst: 1 }, // reads from result register (r1)
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 42);
    }

    #[test]
    fn test_e4_hostcall_oob_fails() {
        // HostCall with out-of-bounds function ID returns error
        let mut exec = E4Executor::default();
        // No host functions registered
        let module = make_module(vec![
            Instruction::HostCall { id: 99, args: vec![], results: vec![0] },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.unwrap().contains("not found"));
        assert_eq!(result.provenance.host_calls, 0);
    }

    #[test]
    fn test_e4_hostcall_multiple() {
        // Multiple host calls increment provenance correctly
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(1));
        let module = make_module(vec![
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] },
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.provenance.host_calls, 2);
    }

    // -------------------------------------------------------------------------
    // Missing instruction tests (T30)
    // -------------------------------------------------------------------------

    #[test]
    fn test_e4_br() {
        // Unconditional branch: Br jumps to Ret, skipping the trap
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::Br { target: 3 }, // jump to Ret (pc=3)
            Instruction::Trap,             // skipped
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u32;
        assert!((f32::from_bits(bits) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_e4_brif_taken() {
        // BrIf taken: Cmp with pred=3 (>=) on r0,r1 (both 0) gives r2=1
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 3, dst: 2, a: 0, b: 1 }, // r2 = 1 (0>=0 = true)
            Instruction::BrIf { cond: 2, target: 3 },          // taken → skip Trap
            Instruction::Trap,
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u32;
        assert!((f32::from_bits(bits) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_e4_brif_not_taken() {
        // BrIf not taken: falls through to Trap (NOT taken → pc=2 = Trap)
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 1, dst: 2, a: 0, b: 1 }, // r2 = 0 (0!=0 = false)
            Instruction::BrIf { cond: 2, target: 3 },          // not taken → pc=2
            Instruction::Trap,                                   // pc=2: Trap
            Instruction::Ret { dst: 2 },                        // pc=3: Ret (skipped if taken)
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail, "should hit trap");
    }

    #[test]
    fn test_e4_cmp_eq() {
        // Cmp pred=4: equal
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FCmp { pred: 4, dst: 2, a: 0, b: 1 }, // 3.0 == 3.0 = 1
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_load_store_i64() {
        // LoadI64/StoreI64: store i32 to memory, load back
        // Cmp writes to r2 (not r0) so r0 stays as initial I32(0)
        let mut exec = E4Executor::default();
        let module = make_module_with_memory(vec![
            Instruction::Cmp { pred: 0, dst: 2, a: 0, b: 0 }, // r2 = 1, r0 stays I32(0)
            Instruction::StoreI64 { addr: 8, src: 0 },           // store r0 (I32=0) at addr 8
            Instruction::LoadI64 { dst: 1, addr: 8 },           // load from addr 8 → I32(0)
            Instruction::Ret { dst: 1 },
        ], 256);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 0); // stored 0, loaded 0
    }

    #[test]
    fn test_e4_f2i_truncates() {
        // F2I: f32 → i32 (truncates fractional part)
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.9 }, // 3.9
            Instruction::F2I { dst: 1, a: 0 }, // truncates to 3
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        // The f32 bits 0x4079999A represent 3.9, F2I truncates → 3
        assert_eq!(result.value.unwrap(), 3);
    }

    #[test]
    fn test_e4_f2u_truncates() {
        // F2U: f32 → u32 (truncates, rejects negative)
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.9 }, // 3.9
            Instruction::F2U { dst: 1, a: 0 }, // truncates to 3
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 3);
    }

    #[test]
    fn test_e4_register_count_enough() {
        // Execution succeeds when register_count >= highest used register
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 7, imm: 1.0 }, // use register 7
            Instruction::Ret { dst: 7 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u32;
        assert!((f32::from_bits(bits) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_e4_multiple_host_functions() {
        // Register multiple host functions, call them by index
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(10));
        exec.host_functions_mut().register(|_args| E4Value::I32(20));
        exec.host_functions_mut().register(|_args| E4Value::I32(30));
        let module = make_module(vec![
            Instruction::HostCall { id: 1, args: vec![], results: vec![0] }, // returns 20
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 20);
        assert_eq!(result.provenance.host_calls, 1);
    }

    #[test]
    fn test_e4_mixed_host_and_float() {
        // Mix HostCall and float ops
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(5));
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 2.0 },
            Instruction::HostCall { id: 0, args: vec![], results: vec![1] }, // r1 = 5
            Instruction::FImm { dst: 2, imm: 3.0 }, // r2 = 3.0
            Instruction::FAdd { dst: 3, a: 0, b: 2 }, // r3 = 5.0
            Instruction::Ret { dst: 3 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u32;
        assert!((f32::from_bits(bits) - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_e4_rexecute_reuses_registers() {
        // Re-executing the same module resets registers
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 7.0 },
            Instruction::Ret { dst: 0 },
        ]);
        let r1 = exec.execute(&module, 0).unwrap();
        let r2 = exec.execute(&module, 0).unwrap(); // execute again
        let bits1 = r1.value.unwrap() as u32;
        let bits2 = r2.value.unwrap() as u32;
        assert!((f32::from_bits(bits1) - 7.0).abs() < 0.001);
        assert!((f32::from_bits(bits2) - 7.0).abs() < 0.001);
    }

    #[test]
    fn test_e4_empty_code() {
        // Function with empty code fails
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![],
            }],
            memory: vec![0u8; 256],
        };
        let mut exec = E4Executor::default();
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
    }

    #[test]
    fn test_e4_f64_fimm() {
        // FImmF64: load f64 immediate
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::FImmF64 { dst: 0, imm: 3.14159265358979 }, // pi
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        // Result is f64 bits as i64
        let val = result.value.unwrap();
        let pi_bits = 3.14159265358979_f64.to_bits() as i64;
        assert_eq!(val, pi_bits);
    }

    #[test]
    fn test_e4_f64_arithmetic() {
        // FAddF64, FMulF64: f64 arithmetic
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::FImmF64 { dst: 0, imm: 2.0 },
            Instruction::FImmF64 { dst: 1, imm: 3.0 },
            Instruction::FAddF64 { dst: 2, a: 0, b: 1 }, // r2 = 5.0
            Instruction::FMulF64 { dst: 3, a: 2, b: 1 }, // r3 = 15.0
            Instruction::Ret { dst: 3 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let val = result.value.unwrap() as u64;
        let expected = 15.0_f64.to_bits();
        assert_eq!(val, expected);
    }

    #[test]
    fn test_e4_deterministic_execution() {
        // Property: executing the same module 10 times gives the same result
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 2.5 },
            Instruction::FImm { dst: 1, imm: 2.5 },
            Instruction::FMul { dst: 2, a: 0, b: 1 }, // r2 = 2.5 * 2.5
            Instruction::Ret { dst: 2 },
        ]);
        let results: Vec<_> = (0..10).map(|_| {
            let mut e = E4Executor::default();
            e.host_functions_mut().register(|_args| E4Value::I32(0));
            e.execute(&module, 0).unwrap()
        }).collect();
        // All runs should have same status
        let statuses: Vec<_> = results.iter().map(|r| r.status).collect();
        assert!(statuses.iter().all(|s| *s == Status::Pass), "all runs should pass");
        // All values should be identical
        let first_val = results[0].value;
        for (i, r) in results.iter().enumerate().skip(1) {
            assert_eq!(r.value, first_val, "run {} should have same value", i);
        }
    }

    #[test]
    fn test_e4_memory_independent() {
        // Property: memory is reset between executions
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let mut m1 = make_module_with_memory(vec![
            Instruction::StoreI64 { addr: 8, src: 0 }, // store I32(0) at addr 8
            Instruction::LoadI64 { dst: 1, addr: 8 },  // load back
            Instruction::Ret { dst: 1 },
        ], 256);
        // First execution
        let r1 = exec.execute(&m1, 0).unwrap();
        // Second execution — memory reset, same result
        let r2 = exec.execute(&m1, 0).unwrap();
        assert_eq!(r1.status, r2.status);
        assert_eq!(r1.value, r2.value);
    }

    #[test]
    fn test_e4_f64_sqrt() {
        // FSqrtF64: f64 square root
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::FImmF64 { dst: 0, imm: 16.0 },
            Instruction::FSqrtF64 { dst: 1, a: 0 }, // r1 = 4.0
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let val = result.value.unwrap() as u64;
        let expected = 4.0_f64.to_bits();
        assert_eq!(val, expected);
    }

    #[test]
    fn test_e4_f64_conversion() {
        // I2F64 and F642I: i32 <-> f64 conversion
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::I2F64 { dst: 0, a: 0 }, // r0=0 -> f64(0)
            Instruction::FImmF64 { dst: 1, imm: 3.7 }, // r1 = 3.7
            Instruction::F642I { dst: 2, a: 1 }, // r2 = f64(3.7) -> i32(3)
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 3);
    }

    #[test]
    fn test_e4_iadd() {
        // IAdd: integer add using Cmp to produce non-zero values
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (0==0 = true)
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
            Instruction::IAdd { dst: 2, a: 0, b: 1 }, // r2 = 1 + 1 = 2
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
    }

    #[test]
    fn test_e4_isub() {
        // ISub: integer subtraction
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
            Instruction::ISub { dst: 2, a: 0, b: 1 }, // r2 = 1 - 1 = 0
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 0);
    }

    #[test]
    fn test_e4_imul() {
        // IMul: integer multiply
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 2
            Instruction::IMul { dst: 2, a: 0, b: 1 }, // r2 = 1 * 2 = 2
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
    }

    #[test]
    fn test_e4_idiv() {
        // IDiv: integer division
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 2
            Instruction::IDiv { dst: 2, a: 1, b: 0 }, // r2 = 2 / 1 = 2
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
    }

    #[test]
    fn test_e4_idiv_by_zero() {
        // IDiv: division by zero fails (use host fn to get r0=0)
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 0
            Instruction::IDiv { dst: 1, a: 0, b: 0 }, // 0 / 0 = error
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.unwrap().contains("division by zero"));
    }
}
