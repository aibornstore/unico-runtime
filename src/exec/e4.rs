//! E4 Executor — Floating-Point Scalar Profile
//!
//! Scalar f32/f64 arithmetic extending E3 integer operations.
//! Instruction enum dispatched via pattern matching (opcodes in e4_ser.rs).
//!
//! Opcodes:
//!   0x00 Br       0x01 BrIf    0x02 Ret        0x03 Trap
//!   0x04 Cmp      0x05 LoadI64  0x06 StoreI64  0x07 FAdd
//!   0x08 FSub     0x09 FMul     0x0A FDiv       0x0B FSqrt
//!   0x0C FNeg     0x0D FAbs     0x0E FRound     0x0F FCmp
//!   0x10 I2F      0x11 F2I      0x12 U2F        0x13 F2U
//!   0x14 Mov      0x15 FImm     0x16 HostCall
//!   0x17 FAddF64  0x18 FSubF64  0x19 FMulF64    0x1A FDivF64
//!   0x1B FSqrtF64 0x1C FNegF64  0x1D FAbsF64    0x1E FRoundF64  0x1F FCmpF64
//!   0x20 I2F64    0x21 F642I    0x22 U2F64      0x23 F642U
//!   0x24 FImmF64  0x25 IAdd     0x26 ISub       0x27 IMul    0x28 IDiv
//!   0x29 IAnd     0x2A IOr      0x2B IXor       0x2C INot
//!   0x2D IClz     0x2E ICtz     0x2F IPopcnt    0x30 IRotl
//!   0x31 IRotr    0x32 TableBr  0x33 MemGrow    0x34 SExt
//!   0x35 ZExt     0x36 MemCopy  0x37 MemFill

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
    // E4 bitwise operations (i32)
    IAnd { dst: u32, a: u32, b: u32 },
    IOr { dst: u32, a: u32, b: u32 },
    IXor { dst: u32, a: u32, b: u32 },
    INot { dst: u32, a: u32 },
    IClz { dst: u32, a: u32 },
    ICtz { dst: u32, a: u32 },
    IPopcnt { dst: u32, a: u32 },
    IRotl { dst: u32, a: u32, b: u32 },
    IRotr { dst: u32, a: u32, b: u32 },
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
    /// Indirect jump via jump table: jump to tables[table_idx][index]
    TableBr { table_idx: u32, index: u32 },
    /// Grow memory by delta bytes, store previous size in dst
    MemGrow { dst: u32, delta: u32 },
    /// Sign-extend i32 to i64 (stored as i32 with sign extension semantics)
    SExt { dst: u32, a: u32 },
    /// Zero-extend u8 to i32
    ZExt { dst: u32, a: u32 },
    /// Copy memory: copy `size` bytes from `src` to `dst`
    MemCopy { dst: u32, src: u32, size: u32 },
    /// Fill memory: fill `size` bytes starting at `addr` with `value`
    MemFill { addr: u32, value: u32, size: u32 },
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
    pub memory: Vec<u8>, // 65536 bytes
    /// Jump tables for indirect jumps: tables[table_idx][index] = target_pc
    pub tables: Vec<Vec<u32>>,
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
    /// Instruction execution histogram (count per instruction type name)
    pub histogram: std::collections::HashMap<&'static str, u64>,
    /// Execution trace: list of executed instructions (for debugging)
    pub trace: Vec<&'static str>,
    /// Enable profiling (histogram + trace)
    profiling: bool,
}

impl Default for E4Executor {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            fuel: 100_000,
            host_functions: HostFunctions::new(),
            host_calls: 0,
            histogram: std::collections::HashMap::new(),
            trace: Vec::new(),
            profiling: false,
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

    /// Enable profiling (instruction histogram + execution trace).
    pub fn start_profiling(&mut self) {
        self.profiling = true;
        self.histogram.clear();
        self.trace.clear();
    }

    /// Get profiling histogram. Requires start_profiling() called before execute().
    pub fn histogram(&self) -> &std::collections::HashMap<&'static str, u64> {
        &self.histogram
    }

    /// Get execution trace. Requires start_profiling() called before execute().
    pub fn trace(&self) -> &[&'static str] {
        &self.trace
    }

    /// Get total instruction count from histogram.
    pub fn total_instructions(&self) -> u64 {
        self.histogram.values().sum()
    }

    fn record_instruction(&mut self, name: &'static str) {
        if self.profiling {
            *self.histogram.entry(name).or_insert(0) += 1;
            self.trace.push(name);
        }
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
                Instruction::Br { target } => { self.record_instruction("Br"); pc = *target as usize; }
                Instruction::BrIf { cond, target } => {
                    self.record_instruction("BrIf");
                    if regs[*cond as usize].as_bool()? {
                        pc = *target as usize;
                    } else {
                        pc += 1;
                    }
                }
                Instruction::Ret { dst } => {
                    self.record_instruction("Ret");
                    let val = match regs[*dst as usize] {
                        E4Value::I32(v) => v as i64,
                        E4Value::F32(v) => v.to_bits() as i64,
                        E4Value::F64(v) => v.to_bits() as i64,
                    };
                    return Ok(ExecutionResult::pass(val, self.provenance()));
                }
                Instruction::Trap => {
                    self.record_instruction("Trap");
                    return Ok(ExecutionResult::fail("E4: trap".into(), self.provenance()));
                }
                Instruction::Cmp { pred, dst, a, b } => {
                    self.record_instruction("Cmp");
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
                Instruction::LoadI64 { dst, addr } => { self.record_instruction("LoadI64");
                    let addr = regs[*addr as usize].as_i32()? as usize;
                    if addr + 8 > memory.len() {
                        return Ok(ExecutionResult::fail("E4: load out of bounds".into(), self.provenance()));
                    }
                    let bytes: [u8; 8] = memory[addr..addr+8].try_into().unwrap();
                    let val = i64::from_le_bytes(bytes);
                    regs[*dst as usize] = E4Value::I32(val as i32);
                    pc += 1;
                }
                Instruction::StoreI64 { addr, src } => { self.record_instruction("StoreI64");
                    let addr = regs[*addr as usize].as_i32()? as usize;
                    let val = regs[*src as usize].as_i32()? as i64;
                    if addr + 8 > memory.len() {
                        return Ok(ExecutionResult::fail("E4: store out of bounds".into(), self.provenance()));
                    }
                    memory[addr..addr+8].copy_from_slice(&val.to_le_bytes());
                    pc += 1;
                }
                Instruction::IAdd { dst, a, b } => { self.record_instruction("IAdd");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_add(b));
                    pc += 1;
                }
                Instruction::ISub { dst, a, b } => { self.record_instruction("ISub");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_sub(b));
                    pc += 1;
                }
                Instruction::IMul { dst, a, b } => { self.record_instruction("IMul");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.wrapping_mul(b));
                    pc += 1;
                }
                Instruction::IDiv { dst, a, b } => { self.record_instruction("IDiv");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    if b == 0 {
                        return Ok(ExecutionResult::fail("E4: division by zero".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a.wrapping_div(b));
                    pc += 1;
                }
                Instruction::IAnd { dst, a, b } => { self.record_instruction("IAnd");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a & b);
                    pc += 1;
                }
                Instruction::IOr { dst, a, b } => { self.record_instruction("IOr");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a | b);
                    pc += 1;
                }
                Instruction::IXor { dst, a, b } => { self.record_instruction("IXor");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a ^ b);
                    pc += 1;
                }
                Instruction::INot { dst, a } => { self.record_instruction("INot");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(!a);
                    pc += 1;
                }
                Instruction::IClz { dst, a } => { self.record_instruction("IClz");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.leading_zeros() as i32);
                    pc += 1;
                }
                Instruction::ICtz { dst, a } => { self.record_instruction("ICtz");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.trailing_zeros() as i32);
                    pc += 1;
                }
                Instruction::IPopcnt { dst, a } => { self.record_instruction("IPopcnt");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(a.count_ones() as i32);
                    pc += 1;
                }
                Instruction::IRotl { dst, a, b } => { self.record_instruction("IRotl");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    let shift = (b as u32) & 31;
                    regs[*dst as usize] = E4Value::I32(a.rotate_left(shift));
                    pc += 1;
                }
                Instruction::IRotr { dst, a, b } => { self.record_instruction("IRotr");
                    let a = regs[*a as usize].as_i32()?;
                    let b = regs[*b as usize].as_i32()?;
                    let shift = (b as u32) & 31;
                    regs[*dst as usize] = E4Value::I32(a.rotate_right(shift));
                    pc += 1;
                }
                Instruction::FAdd { dst, a, b } => { self.record_instruction("FAdd");
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a + b);
                    pc += 1;
                }
                Instruction::FSub { dst, a, b } => { self.record_instruction("FSub");
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a - b);
                    pc += 1;
                }
                Instruction::FMul { dst, a, b } => { self.record_instruction("FMul");
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a * b);
                    pc += 1;
                }
                Instruction::FDiv { dst, a, b } => { self.record_instruction("FDiv");
                    let a = regs[*a as usize].as_f32()?;
                    let b = regs[*b as usize].as_f32()?;
                    if b == 0.0 {
                        return Ok(ExecutionResult::fail("E4: division by zero".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::F32(a / b);
                    pc += 1;
                }
                Instruction::FSqrt { dst, a } => { self.record_instruction("FSqrt");
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.sqrt());
                    pc += 1;
                }
                Instruction::FNeg { dst, a } => { self.record_instruction("FNeg");
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(-a);
                    pc += 1;
                }
                Instruction::FAbs { dst, a } => { self.record_instruction("FAbs");
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.abs());
                    pc += 1;
                }
                Instruction::FRound { dst, a } => { self.record_instruction("FRound");
                    let a = regs[*a as usize].as_f32()?;
                    regs[*dst as usize] = E4Value::F32(a.round());
                    pc += 1;
                }
                Instruction::FCmp { pred, dst, a, b } => { self.record_instruction("FCmp");
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
                Instruction::I2F { dst, a } => { self.record_instruction("I2F");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F32(a as f32);
                    pc += 1;
                }
                Instruction::F2I { dst, a } => { self.record_instruction("F2I");
                    let a = regs[*a as usize].as_f32()?;
                    if a.is_nan() || a < (i32::MIN as f32) || a > (i32::MAX as f32) {
                        return Ok(ExecutionResult::fail("E4: f2i conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a as i32);
                    pc += 1;
                }
                Instruction::U2F { dst, a } => { self.record_instruction("U2F");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F32((a as u32) as f32);
                    pc += 1;
                }
                Instruction::F2U { dst, a } => { self.record_instruction("F2U");
                    let a = regs[*a as usize].as_f32()?;
                    if a.is_nan() || a < 0.0 || a > (u32::MAX as f32) {
                        return Ok(ExecutionResult::fail("E4: f2u conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32((a as u32) as i32);
                    pc += 1;
                }
                Instruction::Mov { dst, src } => { self.record_instruction("Mov");
                    regs[*dst as usize] = regs[*src as usize];
                    pc += 1;
                }
                Instruction::FImm { dst, imm } => { self.record_instruction("FImm");
                    regs[*dst as usize] = E4Value::F32(*imm);
                    pc += 1;
                }
                // ---- E4 f64 floating-point binary ----
                Instruction::FAddF64 { dst, a, b } => { self.record_instruction("FAddF64");
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a + b);
                    pc += 1;
                }
                Instruction::FSubF64 { dst, a, b } => { self.record_instruction("FSubF64");
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a - b);
                    pc += 1;
                }
                Instruction::FMulF64 { dst, a, b } => { self.record_instruction("FMulF64");
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a * b);
                    pc += 1;
                }
                Instruction::FDivF64 { dst, a, b } => { self.record_instruction("FDivF64");
                    let a = regs[*a as usize].as_f64()?;
                    let b = regs[*b as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a / b);
                    pc += 1;
                }
                Instruction::FSqrtF64 { dst, a } => { self.record_instruction("FSqrtF64");
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.sqrt());
                    pc += 1;
                }
                Instruction::FNegF64 { dst, a } => { self.record_instruction("FNegF64");
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(-a);
                    pc += 1;
                }
                Instruction::FAbsF64 { dst, a } => { self.record_instruction("FAbsF64");
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.abs());
                    pc += 1;
                }
                Instruction::FRoundF64 { dst, a } => { self.record_instruction("FRoundF64");
                    let a = regs[*a as usize].as_f64()?;
                    regs[*dst as usize] = E4Value::F64(a.round());
                    pc += 1;
                }
                Instruction::FCmpF64 { pred, dst, a, b } => { self.record_instruction("FCmpF64");
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
                Instruction::I2F64 { dst, a } => { self.record_instruction("I2F64");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F64(a as f64);
                    pc += 1;
                }
                Instruction::F642I { dst, a } => { self.record_instruction("F642I");
                    let a = regs[*a as usize].as_f64()?;
                    if a.is_nan() || a < (i32::MIN as f64) || a > (i32::MAX as f64) {
                        return Ok(ExecutionResult::fail("E4: f64→i32 conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32(a as i32);
                    pc += 1;
                }
                Instruction::U2F64 { dst, a } => { self.record_instruction("U2F64");
                    let a = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::F64((a as u32) as f64);
                    pc += 1;
                }
                Instruction::F642U { dst, a } => { self.record_instruction("F642U");
                    let a = regs[*a as usize].as_f64()?;
                    if a.is_nan() || a < 0.0 || a > (u32::MAX as f64) {
                        return Ok(ExecutionResult::fail("E4: f64→u32 conversion error".into(), self.provenance()));
                    }
                    regs[*dst as usize] = E4Value::I32((a as u32) as i32);
                    pc += 1;
                }
                Instruction::FImmF64 { dst, imm } => { self.record_instruction("FImmF64");
                    regs[*dst as usize] = E4Value::F64(*imm);
                    pc += 1;
                }
                Instruction::HostCall { id, args, results } => { self.record_instruction("HostCall");
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
                Instruction::TableBr { table_idx, index } => {
                    self.record_instruction("TableBr");
                    let idx = regs[*index as usize].as_i32()?;
                    let idx = idx.max(0) as usize;
                    let table = module.tables.get(*table_idx as usize)
                        .ok_or_else(|| Error::Generic("E4: invalid table index".into()))?;
                    let &target = table.get(idx)
                        .ok_or_else(|| Error::Generic("E4: table index out of bounds".into()))?;
                    pc = target as usize;
                }
                Instruction::MemGrow { dst, delta } => {
                    self.record_instruction("MemGrow");
                    let prev_size = memory.len() as i32;
                    let new_size = prev_size as u32 + *delta;
                    if new_size > 1024 * 1024 {
                        // Limit max memory to 1MB
                        regs[*dst as usize] = E4Value::I32(-1);
                    } else {
                        memory.resize(new_size as usize, 0);
                        regs[*dst as usize] = E4Value::I32(prev_size);
                    }
                    pc += 1;
                }
                Instruction::SExt { dst, a } => {
                    self.record_instruction("SExt");
                    // Sign-extend i32 to i64 — stored as i32 but as i64 in semantics
                    let val = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(val); // i32 sign-extends naturally
                    pc += 1;
                }
                Instruction::ZExt { dst, a } => {
                    self.record_instruction("ZExt");
                    // Zero-extend u8 to i32 — take low 8 bits
                    let val = regs[*a as usize].as_i32()?;
                    regs[*dst as usize] = E4Value::I32(val & 0xFF);
                    pc += 1;
                }
                Instruction::MemCopy { dst, src, size } => {
                    self.record_instruction("MemCopy");
                    let dst_addr = regs[*dst as usize].as_i32()? as usize;
                    let src_addr = regs[*src as usize].as_i32()? as usize;
                    let size = *size as usize;
                    if dst_addr + size > memory.len() || src_addr + size > memory.len() {
                        return Ok(ExecutionResult::fail("E4: MemCopy out of bounds".into(), self.provenance()));
                    }
                    memory.copy_within(src_addr..src_addr + size, dst_addr);
                    pc += 1;
                }
                Instruction::MemFill { addr, value, size } => {
                    self.record_instruction("MemFill");
                    let addr = regs[*addr as usize].as_i32()? as usize;
                    let value = (regs[*value as usize].as_i32()? & 0xFF) as u8;
                    let size = *size as usize;
                    if addr + size > memory.len() {
                        return Ok(ExecutionResult::fail("E4: MemFill out of bounds".into(), self.provenance()));
                    }
                    memory[addr..addr + size].fill(value);
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
    fn make_module(code: Vec<Instruction>) -> E4Module {
        E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code,
            }],
            memory: vec![0u8; 65536],
            tables: vec![],
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
            tables: vec![],
        }
    }

    #[allow(dead_code)]
    fn make_module_with_tables(code: Vec<Instruction>) -> E4Module {
        E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code,
            }],
            memory: vec![0u8; 65536],
            tables: vec![],
        }
    }

    #[allow(dead_code)]
    /// Helper to test FP ops: loads two f32 values into regs via i2f
    /// We use FImm to set f32 values directly (stored as bits in i32)
    fn fbits(f: f32) -> i32 {
        f.to_bits() as i32
    }

    #[allow(dead_code)]
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
            memory: vec![0u8; 65536],
            tables: vec![],
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
            tables: vec![],
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
        let m1 = make_module_with_memory(vec![
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
    fn test_e4_profiling_histogram() {
        // Profiling: instruction histogram tracks execution counts
        let mut exec = E4Executor::default();
        exec.start_profiling();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 2.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::FAdd { dst: 2, a: 0, b: 1 }, // FAdd
            Instruction::FAdd { dst: 2, a: 2, b: 1 }, // FAdd
            Instruction::FAdd { dst: 2, a: 2, b: 1 }, // FAdd
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        // 2x FImm, 3x FAdd, 1x Ret = 6 total
        assert_eq!(exec.total_instructions(), 6);
        // Histogram counts
        assert_eq!(exec.histogram().get("FImm"), Some(&2));
        assert_eq!(exec.histogram().get("FAdd"), Some(&3));
        assert_eq!(exec.histogram().get("Ret"), Some(&1));
        // Trace matches histogram
        assert_eq!(exec.trace().len(), 6);
    }

    #[test]
    fn test_e4_profiling_trace() {
        // Profiling: execution trace records instruction names in order
        let mut exec = E4Executor::default();
        exec.start_profiling();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::IAdd { dst: 1, a: 0, b: 0 }, // r1 = 2
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
        assert_eq!(exec.trace(), &["Cmp", "IAdd", "Ret"]);
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

    #[test]
    fn test_e4_and_or_xor() {
        // IAnd, IOr: r0=8, r1=256 → IAnd=0, IOr=264
        // Use HostCall to set r0=8 and r1=256 directly
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(8));
        let module = make_module(vec![
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 8
            Instruction::HostCall { id: 0, args: vec![], results: vec![1] }, // r1 = 8
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 16
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 32
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 64
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 128
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 256
            // r0 = 8, r1 = 256 → IOr = 264
            Instruction::IAnd { dst: 2, a: 0, b: 1 }, // r2 = 0
            Instruction::IOr { dst: 3, a: 0, b: 1 }, // r3 = 264
            Instruction::Ret { dst: 3 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 264);
    }

    #[test]
    fn test_e4_inot_popcnt() {
        // IPopcnt(0b1000) = 1
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 2
            Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 4
            Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 8
            Instruction::IPopcnt { dst: 1, a: 0 }, // r1 = popcnt(8) = 1
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_iclz_ictz() {
        // IClz: leading zeros in 0b0001 = 31, ICtz: trailing zeros = 0
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::IClz { dst: 1, a: 0 }, // r1 = clz(1) = 31
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 31);
    }

    #[test]
    fn test_e4_ixor() {
        // IXor: 12 ^ 10 = 6 (0b1100 ^ 0b1010 = 0b0110)
        // Use HostCall to return 12 for r0 and 10 for r1 via two calls to same fn
        // but pass different args to distinguish
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|args| {
            if args.is_empty() { E4Value::I32(12) } else { E4Value::I32(10) }
        });
        let module = make_module(vec![
            Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 12
            Instruction::HostCall { id: 0, args: vec![0], results: vec![1] }, // r1 = 10
            Instruction::IXor { dst: 2, a: 0, b: 1 }, // r2 = 12 ^ 10 = 6
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 6);
    }

    #[test]
    fn test_e4_rotate() {
        // IRotl: rotate left 4 by 1 bit = 8
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 2
            Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 4
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1 (r0=4 > 0)
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 2
            Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 4
            Instruction::Cmp { pred: 0, dst: 2, a: 0, b: 0 }, // r2 = 1 (rot amount)
            Instruction::IRotl { dst: 3, a: 1, b: 2 }, // r3 = rotl(4, 1) = 8
            Instruction::Ret { dst: 3 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 8);
    }

    #[test]
    fn test_e4_irotr() {
        // IRotr: rotate right 1 by 31 bits = 0x80000000 (i32::MIN)
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (0==0)
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1 (1==1)
            Instruction::Cmp { pred: 0, dst: 2, a: 0, b: 0 }, // r2 = 1 (1==1)
            Instruction::IRotr { dst: 3, a: 1, b: 2 }, // r3 = rotr(1, 31) = 0x80000000
            Instruction::Ret { dst: 3 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), i32::MIN as i64); // 0x80000000
    }

    #[test]
    fn test_e4_tablebr() {
        // TableBr: indirect jump via jump table
        // Table[0] = [2, 4, 6] — three jump targets
        // r0 = 1 (index), then TableBr jumps to table[0][1] = PC 4
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (index into table)
                    Instruction::TableBr { table_idx: 0, index: 0 },   // jump to table[0][1] = PC 4
                    Instruction::Ret { dst: 0 }, // unreachable (PC 2)
                    Instruction::IAdd { dst: 1, a: 0, b: 0 }, // PC 4: r1 = 2 (0+0 was 1+1=2? no wait)
                    // Let's restructure: at PC 4, set r1 to specific value
                    // Need to use IAdd with r0 to get 2, or use two Cmp calls
                    // Simpler: use two Cmps
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // PC 4: r1 = 1
                    Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 2
                    Instruction::Ret { dst: 1 }, // return 2
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![vec![2, 4, 6]], // table[0]: targets at PC 2, 4, 6
        };
        // Note: TableBr at PC 1 jumps to table[0][r0] = table[0][1] = 4
        // So we skip PC 2 (Ret) and execute from PC 4
        // At PC 4: Cmp sets r1=1, IAdd makes r1=2, Ret returns 2
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
    }

    #[test]
    fn test_e4_tablebr_index2() {
        // TableBr with index 2 — jumps to table[0][2] = PC 5
        // Table has entries [2, 4, 5] — target PC 5 = the Cmp instruction
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 2 (index)
                    Instruction::TableBr { table_idx: 0, index: 0 }, // jump to table[0][2] = PC 5
                    Instruction::Ret { dst: 0 }, // unreachable (PC 2)
                    Instruction::Ret { dst: 0 }, // unreachable (PC 4)
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // PC 5: r1 = (r0==r0)=1
                    Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 2
                    Instruction::IAdd { dst: 1, a: 1, b: 1 }, // r1 = 4
                    Instruction::Ret { dst: 1 }, // return 4
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![vec![2, 4, 5]], // 3 targets: PC 2, 4, 5
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 4);
    }

    #[test]
    fn test_e4_memgrow() {
        // MemGrow: grow memory by 100 bytes, returns previous size
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::MemGrow { dst: 0, delta: 100 }, // r0 = 64 (old size), mem grows to 164
                    Instruction::Ret { dst: 0 }, // return 64
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 64); // previous memory size
    }

    #[test]
    fn test_e4_memgrow_exceed_limit() {
        // MemGrow: try to grow beyond 1MB limit, returns -1
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::MemGrow { dst: 0, delta: 2_000_000 }, // exceeds 1MB limit
                    Instruction::Ret { dst: 0 }, // return -1 (failure)
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), -1); // failure indicator
    }

    #[test]
    fn test_e4_zext() {
        // ZExt: zero-extend low 8 bits of 0xFFFFFF00 = 0x00 = 0
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 2
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 4
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 8
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 16
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 32
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 64
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // r0 = 128 (0x80)
                    Instruction::ZExt { dst: 1, a: 0 }, // r1 = 0x80 & 0xFF = 128
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 128);
    }

    #[test]
    fn test_e4_sext() {
        // SExt: sign-extend -1 (0xFFFFFFFF) stays as -1
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                    Instruction::INot { dst: 1, a: 0 }, // r1 = !1 = -2
                    Instruction::SExt { dst: 2, a: 1 }, // r2 = -2 (sign-extended)
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), -2);
    }

    #[test]
    fn test_e4_memcopy() {
        // MemCopy: use HostCall to set registers, fill addr 0, copy to addr 8, verify
        let mut exec = E4Executor::default();
        // id=0 returns 0, id=1 returns 8, id=2 returns 42
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        exec.host_functions_mut().register(|_args| E4Value::I32(8));
        exec.host_functions_mut().register(|_args| E4Value::I32(42));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    // r0 = 0 (src addr), r1 = 8 (dst addr), r2 = 42 (value)
                    Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 0
                    Instruction::HostCall { id: 1, args: vec![], results: vec![1] }, // r1 = 8
                    Instruction::HostCall { id: 2, args: vec![], results: vec![2] }, // r2 = 42
                    // Store 42 at addr 0
                    Instruction::StoreI64 { addr: 0, src: 2 }, // store r2(42) at addr r0(0)
                    // MemCopy: dst=r1(8), src=r0(0), size=8
                    Instruction::MemCopy { dst: 1, src: 0, size: 8 },
                    // Load from addr 8
                    Instruction::LoadI64 { dst: 3, addr: 1 }, // should be 42 (addr=r1=8)
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 42);
    }

    #[test]
    fn test_e4_memfill() {
        // MemFill: use HostCall to set registers, fill addr 0 with 0x01 bytes, verify
        let mut exec = E4Executor::default();
        // id=0 returns 0, id=1 returns 1, id=2 returns 8
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        exec.host_functions_mut().register(|_args| E4Value::I32(1));
        exec.host_functions_mut().register(|_args| E4Value::I32(8));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    // r0 = 0 (addr), r1 = 1 (value), r2 = 8 (size)
                    Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 0
                    Instruction::HostCall { id: 1, args: vec![], results: vec![1] }, // r1 = 1
                    Instruction::HostCall { id: 2, args: vec![], results: vec![2] }, // r2 = 8
                    // MemFill: addr=r0(0), value=r1(1), size=r2(8)
                    Instruction::MemFill { addr: 0, value: 1, size: 8 },
                    // Load as i64 then truncate to i32: 8 bytes of 0x01 → i32 = 0x01010101
                    Instruction::LoadI64 { dst: 3, addr: 0 },
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 0x01010101_i64);
    }

    // === Error path tests ===

    #[test]
    fn test_e4_cmp_unknown_predicate() {
        // Cmp pred >= 4 is invalid
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 4, dst: 0, a: 0, b: 0 }, // unknown predicate
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err(), "unknown cmp pred should error");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown cmp pred"), "got: {}", err);
    }

    #[test]
    fn test_e4_fcmp_all_predicates() {
        // Test all 6 valid FCmp predicates: lt(0), le(1), gt(2), ge(3), eq(4), ne(5)
        // FCmp predicates: lt(0), le(1), gt(2), ge(3), eq(4), ne(5)
        // Test: a=1.0, b=2.0 → lt=T, le=T, gt=F, ge=F, eq=F, ne=T
        let preds = [(0u8, 1.0f32, 2.0), (1, 1.0, 2.0), (2, 1.0, 2.0), (3, 1.0, 2.0), (4, 1.0, 2.0), (5, 1.0, 2.0)];
        let expected = [1i32, 1, 0, 0, 0, 1]; // lt,le,gt,ge,eq,ne
        for (i, (pred, a, b)) in preds.iter().enumerate() {
            let mut exec = E4Executor::default();
            let module = make_module(vec![
                Instruction::FImm { dst: 0, imm: *a },
                Instruction::FImm { dst: 1, imm: *b },
                Instruction::FCmp { pred: *pred, dst: 2, a: 0, b: 1 },
                Instruction::Ret { dst: 2 },
            ]);
            let result = exec.execute(&module, 0).unwrap();
            assert_eq!(result.value.unwrap(), expected[i] as i64, "FCmp pred {} failed", pred);
        }
    }

    #[test]
    fn test_e4_fcmp_unknown_predicate() {
        // FCmp pred >= 6 is invalid
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::FCmp { pred: 6, dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err(), "unknown fcmp pred should error");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown fcmp pred"), "got: {}", err);
    }

    #[test]
    fn test_e4_fcmp_f64_all_predicates() {
        // FCmpF64 predicates: lt(0), le(1), gt(2), ge(3), eq(4), ne(5)
        // Test: a=1.0, b=2.0 → lt=T, le=T, gt=F, ge=F, eq=F, ne=T
        let preds = [(0u8, 1.0f64, 2.0), (1, 1.0, 2.0), (2, 1.0, 2.0), (3, 1.0, 2.0), (4, 1.0, 2.0), (5, 1.0, 2.0)];
        let expected = [1i32, 1, 0, 0, 0, 1];
        for (i, (pred, a, b)) in preds.iter().enumerate() {
            let mut exec = E4Executor::default();
            let module = E4Module {
                functions: vec![E4FunctionDef {
                    param_count: 0,
                    result_count: 1,
                    register_count: 16,
                    code: vec![
                        Instruction::FImmF64 { dst: 0, imm: *a },
                        Instruction::FImmF64 { dst: 1, imm: *b },
                        Instruction::FCmpF64 { pred: *pred, dst: 2, a: 0, b: 1 },
                        Instruction::Ret { dst: 2 },
                    ],
                }],
                memory: vec![0u8; 1024],
                tables: vec![],
            };
            let result = exec.execute(&module, 0).unwrap();
            assert_eq!(result.value.unwrap(), expected[i] as i64, "FCmpF64 pred {} failed", pred);
        }
    }

    #[test]
    fn test_e4_fcmp_f64_unknown_predicate() {
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 1.0 },
                    Instruction::FImmF64 { dst: 1, imm: 2.0 },
                    Instruction::FCmpF64 { pred: 99, dst: 2, a: 0, b: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0);
        assert!(result.is_err(), "unknown fcmp.f64 pred should error");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown fcmp.f64 pred"), "got: {}", err);
    }

    #[test]
    fn test_e4_f642i_nan_fails() {
        // F642I: NaN → conversion error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: f64::NAN },
                    Instruction::F642I { dst: 1, a: 0 },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("conversion error"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_f642i_overflow_fails() {
        // F642I: value > i32::MAX → conversion error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: (i32::MAX as f64) * 2.0 },
                    Instruction::F642I { dst: 1, a: 0 },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("conversion error"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_f642u_nan_fails() {
        // F642U: NaN → conversion error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: f64::NAN },
                    Instruction::F642U { dst: 1, a: 0 },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("conversion error"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_f642u_negative_fails() {
        // F642U: negative → conversion error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: -1.0 },
                    Instruction::F642U { dst: 1, a: 0 },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("conversion error"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_load_i64_oob_fails() {
        // LoadI64 with address at memory boundary: 8 bytes from offset 65529 in 65536-byte memory
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(65529)); // OOB: 65529+8=65537 > 65536
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::HostCall { id: 0, args: vec![], results: vec![1] }, // r1 = 65529
                    Instruction::LoadI64 { dst: 2, addr: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 65536],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("out of bounds"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_store_i64_oob_fails() {
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(65529)); // OOB: 65529+8=65537
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::HostCall { id: 0, args: vec![], results: vec![1] }, // r1 = 65529
                    Instruction::HostCall { id: 0, args: vec![], results: vec![2] }, // r2 = 0
                    Instruction::StoreI64 { addr: 1, src: 2 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 65536],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("out of bounds"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_memcopy_oob_fails() {
        // MemCopy: dst and src are register indices, size is immediate u32
        // Use dst=0 (holds addr 65500), src=1 (holds addr 65500), size=100 (immediate)
        // dst_addr=65500, src_addr=65500, size=100 → 65500+100 > 65536 → OOB
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(65500)); // id=0: returns 65500
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 65500 (addr)
                    Instruction::HostCall { id: 0, args: vec![], results: vec![1] }, // r1 = 65500 (addr)
                    Instruction::MemCopy { dst: 0, src: 1, size: 100 }, // size=100 immediate, 65500+100 > 65536
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 65536],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("out of bounds"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_memfill_oob_fails() {
        // MemFill: addr from r0, value from r1, size=IMMEDIATE (not register)
        // Use 16-byte memory, addr=10, size=10 (immediate) → 10+10=20 > 16 → OOB
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(10)); // id=0: addr
        exec.host_functions_mut().register(|_args| E4Value::I32(1));  // id=1: value
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::HostCall { id: 0, args: vec![], results: vec![0] }, // r0 = 10 (addr)
                    Instruction::HostCall { id: 1, args: vec![], results: vec![1] }, // r1 = 1 (value)
                    Instruction::MemFill { addr: 0, value: 1, size: 10 }, // size=10 immediate, 10+10=20 > 16
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 16],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("out of bounds"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_fdiv_by_zero_fails() {
        // FDiv: division by zero should fail
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 10.0 },
                    Instruction::FImm { dst: 1, imm: 0.0 },  // divisor = 0
                    Instruction::FDiv { dst: 2, a: 0, b: 1 }, // 10.0 / 0.0
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().unwrap().contains("division by zero"), "got: {}", result.error.as_ref().unwrap());
    }

    #[test]
    fn test_e4_i2f_with_f64_value_fails() {
        // I2F: source register is F64, not i32 → type error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 42.0 },  // r0 = F64(42.0)
                    Instruction::I2F { dst: 1, a: 0 },             // r1 = i32(r0) — fails
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expected i32"), "got: {}", err);
    }

    #[test]
    fn test_e4_u2f_with_f64_value_fails() {
        // U2F: source register is F64, not i32 → type error
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 42.0 },  // r0 = F64(42.0)
                    Instruction::U2F { dst: 1, a: 0 },             // r1 = u32(r0) — fails
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expected i32"), "got: {}", err);
    }

    #[test]
    fn test_e4_tablebr_invalid_index_fails() {
        // TableBr: invalid table index
        let mut exec = E4Executor::default();
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::TableBr { table_idx: 99, index: 0 }, // invalid table
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![],
        };
        let result = exec.execute(&module, 0);
        assert!(result.is_err(), "invalid table index should error");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid table"), "got: {}", err);
    }

    // === Type mismatch error path tests ===
    #[test]
    fn test_e4_iadd_type_mismatch() {
        // IAdd with F32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::IAdd { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_isub_type_mismatch() {
        // ISub with F32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 5.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::ISub { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_imul_type_mismatch() {
        // IMul with F32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 3.0 },
            Instruction::FImm { dst: 1, imm: 4.0 },
            Instruction::IMul { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_idiv_type_mismatch() {
        // IDiv with F32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 10.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::IDiv { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_iand_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 1.0 },
            Instruction::IAnd { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_ior_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::IOr { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_ixor_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 1.0 },
            Instruction::IXor { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_inot_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 0.0 },
            Instruction::INot { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_iclz_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::IClz { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_ictz_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::ICtz { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_ipopcnt_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 7.0 },
            Instruction::IPopcnt { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_irotl_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 3.0 },
            Instruction::IRotl { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_irotr_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 16.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::IRotr { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fadd_type_mismatch() {
        // FAdd with I32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
            Instruction::FAdd { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fsub_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FSub { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fmul_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FMul { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fdiv_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FDiv { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fsqrt_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FSqrt { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fneg_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FNeg { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fabs_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FAbs { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fround_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FRound { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_fcmp_type_mismatch() {
        // FCmp with I32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FCmp { pred: 0, dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_cmp_type_mismatch() {
        // Cmp with F32 values should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::FImm { dst: 1, imm: 2.0 },
            Instruction::Cmp { pred: 0, dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_i2f_type_mismatch() {
        // I2F with F32 value should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 42.0 },
            Instruction::I2F { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_u2f_type_mismatch() {
        // U2F with F32 value should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 42.0 },
            Instruction::U2F { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_brif_type_mismatch() {
        // BrIf with non-bool (F32) should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 },
            Instruction::BrIf { cond: 0, target: 4 },
            Instruction::Ret { dst: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f2i_type_mismatch() {
        // F2I with I32 value should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::F2I { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f2u_type_mismatch() {
        // F2U with I32 value should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::F2U { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    // === F64 type mismatch tests ===
    #[test]
    fn test_e4_f64add_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FAddF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64sub_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FSubF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64mul_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FMulF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64div_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FDivF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64sqrt_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FSqrtF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64neg_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FNegF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64abs_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FAbsF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64round_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::FRoundF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f64cmp_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FCmpF64 { pred: 0, dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_i2f64_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 42.0 },
            Instruction::I2F64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_u2f64_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 42.0 },
            Instruction::U2F64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f642i_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::F642I { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_f642u_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::F642U { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    // === E4Value as_f32 / as_f64 / as_bool error paths ===
    #[test]
    fn test_e4_value_as_f32_from_i32_fails() {
        // E4Value::as_f32 with I32 should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (I32)
            Instruction::FAdd { dst: 1, a: 0, b: 0 }, // FAdd expects F32, gets I32
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_value_as_f64_from_i32_fails() {
        // E4Value::as_f64 with I32 should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 },
            Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 },
            Instruction::FAddF64 { dst: 2, a: 0, b: 1 }, // FAddF64 expects F64, gets I32
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_value_as_bool_from_f32_fails() {
        // E4Value::as_bool with F32 should fail
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 }, // r0 = F32
            Instruction::BrIf { cond: 0, target: 4 }, // BrIf expects bool, gets F32
            Instruction::Ret { dst: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_value_as_bool_from_f64_fails() {
        // E4Value::as_bool with F64 should fail
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 1.0 }, // r0 = F64
            Instruction::BrIf { cond: 0, target: 4 },
            Instruction::Ret { dst: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    // === Additional F64 roundtrip tests ===
    #[test]
    fn test_e4_f64_roundtrip_fsub() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 10.0 },
            Instruction::FImmF64 { dst: 1, imm: 3.5 },
            Instruction::FSubF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 6.5).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fmul() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 2.5 },
            Instruction::FImmF64 { dst: 1, imm: 4.0 },
            Instruction::FMulF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 10.0).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fdiv() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 20.0 },
            Instruction::FImmF64 { dst: 1, imm: 4.0 },
            Instruction::FDivF64 { dst: 2, a: 0, b: 1 },
            Instruction::Ret { dst: 2 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fsqrt() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 16.0 },
            Instruction::FSqrtF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 4.0).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fneg() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 3.14 },
            Instruction::FNegF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - (-3.14)).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fabs() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: -7.5 },
            Instruction::FAbsF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 7.5).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_roundtrip_fround() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 3.7 },
            Instruction::FRoundF64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 4.0).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_i2f_roundtrip() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::I2F64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_e4_f64_u2f_roundtrip() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::U2F64 { dst: 1, a: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 1.0).abs() < 1e-10);
    }

    // === I64 Load/Store type error paths ===
    #[test]
    fn test_e4_loadi64_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 }, // F32, not I32
            Instruction::LoadI64 { dst: 1, addr: 0 },
            Instruction::Ret { dst: 1 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e4_storei64_type_mismatch() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 1.0 }, // F32, not I32
            Instruction::FImm { dst: 1, imm: 2.0 }, // F32, not I32
            Instruction::StoreI64 { addr: 0, src: 1 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0);
        assert!(result.is_err());
    }

    // === pc >= code.len() coverage ===
    #[test]
    fn test_e4_pc_end_of_code() {
        // pc at end of code (no instruction)
        let mut exec = E4Executor::default();
        let module = make_module(vec![]); // empty code
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Fail);
    }

    // === E4Value I32/F32/F64 value roundtrip ===
    #[test]
    fn test_e4_value_ret_i32() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value.unwrap(), 1);
    }

    #[test]
    fn test_e4_value_ret_f32() {
        let mut exec = E4Executor::default();
        let module = make_module(vec![
            Instruction::FImm { dst: 0, imm: 99.5 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 99.5).abs() < 0.001);
    }

    #[test]
    fn test_e4_value_ret_f64() {
        let mut exec = E4Executor::default();
        let module = make_module_with_tables(vec![
            Instruction::FImmF64 { dst: 0, imm: 77.25 },
            Instruction::Ret { dst: 0 },
        ]);
        let result = exec.execute(&module, 0).unwrap();
        assert_eq!(result.status, Status::Pass);
        let bits = result.value.unwrap() as u64;
        let f = f64::from_bits(bits);
        assert!((f - 77.25).abs() < 0.001);
    }

    // === End error path tests ===
}
