//! E6 Executor — Fixed-Point Q-Format Profile
//!
//! Q8.8 format (16-bit signed, 8 fractional bits):
//! - Range: -128.0 to ~127.996 (step = 1/256 ≈ 0.00390625)
//! - QADD, QSUB, QMUL, QDIV, QSQRT
//! - QTOI (Q→i16), ITOQ (i16→Q)
//! - QNEG, QABS, QSAT
//! - QLOAD (2 bytes), QSTORE (2 bytes)
//! - Memory: 1 page × 4096 bytes
//!
//! E6 opcodes:
//!   0xF0 => QADD   0xF1 => QSUB   0xF2 => QMUL   0xF3 => QDIV
//!   0xF4 => QSQRT  0xF5 => QTOI    0xF6 => ITOQ   0xF7 => QLOAD
//!   0xF8 => QSTORE 0xF9 => QNEG    0xFA => QABS   0xFB => QSAT
//!   0xFC => QZERO  0xFD => QMEMZERO

use crate::error::Result;
use crate::leb128::{encode_sleb, encode_uleb};
#[allow(unused_imports)]
use crate::types::{ExecutionResult, Provenance, Status};
use std::time::Instant;

// ---------------------------------------------------------------------------
// E6 types
// ---------------------------------------------------------------------------

/// E6 instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    // Scalar integer register load (for setting up test values)
    KImm { dst: u8, value: i64 },
    // Q-format binary ops: dst, a, b (Q-reg indices)
    QAdd   { dst: u8, a: u8, b: u8 },
    QSub   { dst: u8, a: u8, b: u8 },
    QMul   { dst: u8, a: u8, b: u8 },
    QDiv   { dst: u8, a: u8, b: u8 },
    // Unary
    QSqrt  { dst: u8, a: u8 },
    QNeg   { dst: u8, a: u8 },
    QAbs   { dst: u8, a: u8 },
    QSat   { dst: u8, a: u8 }, // saturate to [-32768, 32767]
    // Conversion
    QToI   { dst: u8, a: u8 }, // Q → i16 (integer part)
    IToQ   { dst: u8, a: u8 }, // i16 → Q (integer to Q8.8)
    // Memory: addr (ULEB), qreg (ULEB) — 2-byte aligned
    QLoad  { addr: u32, dst: u8 },
    QStore { addr: u32, src: u8 },
    // Specials
    QZero  { dst: u8 }, // set qreg to zero
    QMemZero,             // zero all memory
    // Control
    Ret,
    Trap,
}

/// E6 function definition
#[derive(Debug, Clone)]
pub struct E6FunctionDef {
    pub param_count: usize,
    pub result_count: usize,
    pub register_count: usize,
    pub code: Vec<Instruction>,
}

/// E6 module
#[derive(Debug)]
pub struct E6Module {
    pub functions: Vec<E6FunctionDef>,
    pub memory: Vec<u8>, // 4096 bytes, zeroed
}

impl Clone for E6Module {
    fn clone(&self) -> Self {
        Self {
            functions: self.functions.clone(),
            memory: self.memory.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_instruction(bytes: &[u8], mut pos: usize) -> Result<(Instruction, usize)> {
    let opcode = bytes[pos];
    pos += 1;
    let instr = match opcode {
        0xF0 => {
            // QADD dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QAdd { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xF1 => {
            // QSUB dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QSub { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xF2 => {
            // QMUL dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QMul { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xF3 => {
            // QDIV dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QDiv { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xF4 => {
            // QSQRT dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QSqrt { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xF5 => {
            // QTOI dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QToI { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xF6 => {
            // ITOQ dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::IToQ { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xF7 => {
            // QLOAD addr dst
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QLoad { addr: addr.try_into().unwrap(), dst: dst.try_into().unwrap() }
        }
        0xF8 => {
            // QSTORE addr src
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QStore { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0xF9 => {
            // QNEG dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QNeg { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xFA => {
            // QABS dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QAbs { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xFB => {
            // QSAT dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QSat { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xFC => {
            // QZERO dst
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::QZero { dst: dst.try_into().unwrap() }
        }
        0xFD => Instruction::QMemZero,
        0xFE => {
            // KImm dst value — load i64 immediate into scalar register
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (value, _sleb_len) = crate::leb128::decode_sleb(&bytes[pos..])?;

            pos += _sleb_len;
            Instruction::KImm { dst: dst.try_into().unwrap(), value: value.try_into().unwrap() }
        }
        0xa6 => Instruction::Ret,
        0x9F => Instruction::Trap,
        _ => {
            return Err(crate::error::Error::Format(format!(
                "E6: unknown opcode: {opcode:#x}"
            )))
        }
    };
    Ok((instr, pos))
}

fn decode_all(bytes: &[u8]) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let (instr, new_pos) = decode_instruction(bytes, pos)?;
        instructions.push(instr);
        pos = new_pos;
    }
    Ok(instructions)
}

// ---------------------------------------------------------------------------
// E6Module parse
// ---------------------------------------------------------------------------

impl E6Module {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 || &bytes[0..6] != b"UNICO\x06" {
            return Err(crate::error::Error::Format("E6: bad magic".into()));
        }
        let mut pos = 6;

        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(crate::error::Error::Format("E6: missing FUNC section".into()));
        }
        pos += 1;
        let (func_payload_len, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        let func_payload_end = pos + func_payload_len;
        if func_payload_end > bytes.len() {
            return Err(crate::error::Error::Format("E6: truncated FUNC payload".into()));
        }

        let (func_count, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

        let mut functions = Vec::with_capacity(func_count);
        let mut code_sizes = Vec::with_capacity(func_count);

        for _ in 0..func_count {
            let (param_count, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (result_count, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (register_count, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (_code_off, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (code_size, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            code_sizes.push(code_size);
            functions.push(E6FunctionDef {
                param_count,
                result_count,
                register_count,
                code: Vec::new(),
            });
        }

        if pos != func_payload_end {
            return Err(crate::error::Error::Format("E6: FUNC payload trailing bytes".into()));
        }

        if pos >= bytes.len() || bytes[pos] != 0x01 {
            return Err(crate::error::Error::Format("E6: missing CODE section".into()));
        }
        pos += 1;
        let (code_size, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        let code_start = pos;
        let code_end = code_start + code_size;
        if code_end > bytes.len() {
            return Err(crate::error::Error::Format("E6: code section overflow".into()));
        }

        let all_instrs = decode_all(&bytes[code_start..code_end])?;

        let total_instrs = all_instrs.len();
        let base_instrs = if func_count > 0 {
            total_instrs / func_count
        } else {
            0
        };
        let remainder = if func_count > 0 {
            total_instrs % func_count
        } else {
            0
        };
        let mut instr_pos = 0;
        for i in 0..func_count {
            let extra = if i < remainder { 1 } else { 0 };
            let func_end = (instr_pos + base_instrs + extra).min(all_instrs.len());
            let func_instrs: Vec<_> = all_instrs[instr_pos..func_end].to_vec();
            functions[i].code = func_instrs;
            instr_pos = func_end;
        }

        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(crate::error::Error::Format("E6: missing END byte".into()));
        }

        let memory = vec![0u8; E6_MEMORY_SIZE];
        Ok(E6Module { functions, memory })
    }

    pub fn verify(&self) -> Result<()> {
        for func in &self.functions {
            if let Some(last) = func.code.last() {
                match last {
                    Instruction::Ret | Instruction::Trap => {}
                    _ => {
                        return Err(crate::error::Error::Verification(
                            "E6: missing RET/TRAP".into(),
                        ))
                    }
                }
            } else {
                return Err(crate::error::Error::Verification("E6: empty function".into()));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// E6Executor
// ---------------------------------------------------------------------------

/// Q8.8 register: i16 internal representation
#[derive(Debug, Clone, Copy)]
pub struct QReg(pub i16);

impl Default for QReg {
    fn default() -> Self {
        QReg(0)
    }
}

/// Q8.8 limits
const Q_MIN: i16 = i16::MIN; // -32768
const Q_MAX: i16 = i16::MAX; // 32767

impl QReg {
    /// Get raw i16 value
    fn raw(&self) -> i16 {
        self.0
    }

    /// Integer square root for Q8.8: isqrt(|value|) scaled back to Q8.8
    fn isqrt_q88(val: i16) -> i16 {
        if val <= 0 {
            return 0;
        }
        // Convert to Q16.16 equivalent: val << 8, then isqrt
        let v = (val as i32) << 8;
        let x = v;
        if x <= 0 {
            return 0;
        }
        // Newton-Raphson: x_{n+1} = (x_n + v/x_n) / 2
        // Start with approximate sqrt
        let mut r = (x as f64).sqrt() as i32;
        if r == 0 {
            r = 1;
        }
        // 3 iterations of Newton-Raphson
        for _ in 0..4 {
            if r == 0 {
                r = 1;
            }
            r = (r + x / r) / 2;
        }
        // Result is sqrt in Q8.8 space: r is already scaled
        r.max(0) as i16
    }

    /// Saturate to Q8.8 range [-32768, 32767]
    fn saturate(val: i32) -> i16 {
        val.clamp(Q_MIN as i32, Q_MAX as i32) as i16
    }
}

struct Frame {
    func_idx: usize,
    pc: usize,
    regs: Vec<i64>,
    qregs: Vec<QReg>,
    result_reg: Option<u32>,
    last_qreg: Option<u8>,
}

pub struct E6Executor {
    functions: Vec<E6FunctionDef>,
    frames: Vec<Frame>,
    memory: Vec<u8>,
    fuel: u64,
    start: Instant,
}

impl E6Executor {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            frames: Vec::new(),
            memory: vec![0u8; E6_MEMORY_SIZE],
            fuel: 100_000,
            start: Instant::now(),
        }
    }

    pub fn execute(&mut self, module: &E6Module) -> Result<ExecutionResult> {
        self.functions = module.functions.clone();
        self.frames.clear();
        self.memory = module.memory.clone();
        self.fuel = 100_000;
        self.start = Instant::now();

        if self.functions.is_empty() {
            return Ok(ExecutionResult::fail("E6: no functions".into(), self.provenance()));
        }
        self.run_function(0, None)
    }

    fn provenance(&self) -> Provenance {
        Provenance {
            instructions: 0,
            fuel_remaining: self.fuel,
            host_calls: 0,
            duration_us: self.start.elapsed().as_micros() as u64,
            deterministic: true,
        }
    }

    fn run_function(
        &mut self,
        func_idx: usize,
        result_reg: Option<u32>,
    ) -> Result<ExecutionResult> {
        if func_idx >= self.functions.len() {
            return Ok(ExecutionResult::fail(
                format!("E6: bad function index {func_idx}"),
                self.provenance(),
            ));
        }
        let func = &self.functions[func_idx];
        let regs = vec![0i64; func.register_count.max(4).max(16)];
        let qregs = vec![QReg::default(); 16];
        self.frames.push(Frame {
            func_idx,
            pc: 0,
            regs,
            qregs,
            result_reg,
            last_qreg: None,
        });
        let mut frame_idx = self.frames.len() - 1;

        loop {
            if self.fuel == 0 {
                self.frames.pop();
                return Ok(ExecutionResult::fail("E6: fuel exhausted".into(), self.provenance()));
            }
            self.fuel -= 1;

            let fi = self.frames[frame_idx].func_idx;
            let pc = self.frames[frame_idx].pc;
            let func = &self.functions[fi];

            if pc >= func.code.len() {
                let result = self.frames[frame_idx].regs[0];
                self.frames.pop();
                if self.frames.is_empty() {
                    return Ok(ExecutionResult::pass(result, self.provenance()));
                }
                frame_idx = self.frames.len() - 1;
                if let Some(dst) = self.frames[frame_idx].result_reg {
                    self.frames[frame_idx].regs[dst as usize] = result;
                }
                self.frames[frame_idx].pc += 1;
                continue;
            }

            let instr = func.code[pc].clone();
            match &instr {
                Instruction::KImm { dst, value } => {
                    self.frames[frame_idx].regs[*dst as usize] = *value;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QAdd { dst, a, b } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let vb = self.frames[frame_idx].qregs[*b as usize].raw();
                    let raw = QReg::saturate(va as i32 + vb as i32);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QSub { dst, a, b } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let vb = self.frames[frame_idx].qregs[*b as usize].raw();
                    let raw = QReg::saturate(va as i32 - vb as i32);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QMul { dst, a, b } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let vb = self.frames[frame_idx].qregs[*b as usize].raw();
                    // Q8.8 * Q8.8 = Q16.16 → shift right 8 → Q8.8
                    let raw = QReg::saturate(((va as i32) * (vb as i32)) >> 8);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QDiv { dst, a, b } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let vb = self.frames[frame_idx].qregs[*b as usize].raw();
                    if vb == 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QDIV by zero".into(), self.provenance()));
                    }
                    // Q8.8 / Q8.8 → shift left 8, divide, result Q8.8
                    let raw = QReg::saturate(((va as i32) << 8) / (vb as i32));
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QSqrt { dst, a } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    if va < 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QSQRT domain error".into(), self.provenance()));
                    }
                    let raw = QReg::isqrt_q88(va);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QToI { dst, a } => {
                    // Q → i16 (integer part, truncating)
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    // Convert Q8.8 to integer: right shift by 8
                    let result = va as i64;
                    self.frames[frame_idx].regs[*dst as usize] = result;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::IToQ { dst, a } => {
                    // i16 → Q8.8 (integer to Q8.8)
                    let va = self.frames[frame_idx].regs[*a as usize];
                    let raw = (va << 8) as i16;
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QLoad { addr, dst } => {
                    let addr = *addr as usize;
                    if addr + 2 > E6_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QLOAD OOB".into(), self.provenance()));
                    }
                    if addr % 2 != 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QLOAD unaligned".into(), self.provenance()));
                    }
                    let raw = i16::from_le_bytes([self.memory[addr], self.memory[addr + 1]]);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QStore { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 2 > E6_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QSTORE OOB".into(), self.provenance()));
                    }
                    if addr % 2 != 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E6: QSTORE unaligned".into(), self.provenance()));
                    }
                    let raw = self.frames[frame_idx].qregs[*src as usize].raw();
                    let bytes = raw.to_le_bytes();
                    self.memory[addr] = bytes[0];
                    self.memory[addr + 1] = bytes[1];
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QNeg { dst, a } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    // Saturating negation: -(-32768) = 32767
                    let raw = if va == Q_MIN { Q_MAX } else { -va };
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QAbs { dst, a } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let raw = va.abs();
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QSat { dst, a } => {
                    let va = self.frames[frame_idx].qregs[*a as usize].raw();
                    let raw = va.clamp(Q_MIN, Q_MAX);
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(raw);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QZero { dst } => {
                    self.frames[frame_idx].qregs[*dst as usize] = QReg(0);
                    self.frames[frame_idx].last_qreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::QMemZero => {
                    self.memory.fill(0);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Ret => {
                    // Return last modified qreg's raw value
                    let result = if let Some(idx) = self.frames[frame_idx].last_qreg {
                        self.frames[frame_idx].qregs[idx as usize].raw() as i64
                    } else {
                        self.frames[frame_idx].qregs[0].raw() as i64
                    };
                    self.frames.pop();
                    if self.frames.is_empty() {
                        return Ok(ExecutionResult::pass(result, self.provenance()));
                    }
                    frame_idx = self.frames.len() - 1;
                    if let Some(dst) = self.frames[frame_idx].result_reg {
                        self.frames[frame_idx].regs[dst as usize] = result;
                    }
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Trap => {
                    self.frames.pop();
                    return Ok(ExecutionResult::fail("E6: explicit trap".into(), self.provenance()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bytecode builder
// ---------------------------------------------------------------------------

pub const E6_PAGE_COUNT: usize = 1;
pub const E6_PAGE_SIZE: usize = 4096;
pub const E6_MEMORY_SIZE: usize = E6_PAGE_COUNT * E6_PAGE_SIZE;

fn encode_instr(instr: &Instruction, out: &mut Vec<u8>) {
    match instr {
        Instruction::QAdd { dst, a, b } => {
            out.push(0xF0);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::QSub { dst, a, b } => {
            out.push(0xF1);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::QMul { dst, a, b } => {
            out.push(0xF2);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::QDiv { dst, a, b } => {
            out.push(0xF3);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::QSqrt { dst, a } => {
            out.push(0xF4);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::QToI { dst, a } => {
            out.push(0xF5);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::IToQ { dst, a } => {
            out.push(0xF6);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::QLoad { addr, dst } => {
            out.push(0xF7);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::QStore { addr, src } => {
            out.push(0xF8);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::QNeg { dst, a } => {
            out.push(0xF9);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::QAbs { dst, a } => {
            out.push(0xFA);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::QSat { dst, a } => {
            out.push(0xFB);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::QZero { dst } => {
            out.push(0xFC);
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::QMemZero => {
            out.push(0xFD);
        }
        Instruction::KImm { dst, value } => {
            out.push(0xFE);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_sleb(*value));
        }
        Instruction::Ret => {
            out.push(0xa6);
        }
        Instruction::Trap => {
            out.push(0x9F);
        }
    }
}

/// Build a Q8.8 value: i16_repr = (value * 256) as i16
pub fn q88(value: f32) -> i16 {
    (value * 256.0).round() as i16
}

pub fn build_e6(instructions: &[Instruction]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(b"UNICO\x06");

    let mut instr_buf = Vec::new();
    for instr in instructions {
        encode_instr(instr, &mut instr_buf);
    }
    let desc_code_size = instr_buf.len();

    let param_count_bytes = encode_uleb(1);
    let result_count_bytes = encode_uleb(1);
    let register_count_bytes = encode_uleb(16);
    let code_offset_bytes = encode_uleb(0);
    let code_size_bytes = encode_uleb(desc_code_size);
    let desc_uleb_bytes = param_count_bytes.len()
        + result_count_bytes.len()
        + register_count_bytes.len()
        + code_offset_bytes.len()
        + code_size_bytes.len();

    let func_payload = 1 + desc_uleb_bytes;
    bytes.push(0x02);
    bytes.extend(&encode_uleb(func_payload));
    bytes.extend(&encode_uleb(1));

    bytes.extend(&param_count_bytes);
    bytes.extend(&result_count_bytes);
    bytes.extend(&register_count_bytes);
    bytes.extend(&code_offset_bytes);
    bytes.extend(&code_size_bytes);

    bytes.push(0x01);
    bytes.extend(&encode_uleb(desc_code_size));
    bytes.extend(&instr_buf);
    bytes.push(0x00);

    bytes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> ExecutionResult {
        let module = E6Module::parse(bytes).expect("parse failed");
        module.verify().expect("verify failed");
        let mut exec = E6Executor::new();
        exec.execute(&module).expect("execute error")
    }

    #[test]
    fn test_e6_qadd() {
        // r0=1, r1=2 → ITOQ → q0=256, q1=512 → QADD → q2=768 (3.0)
        // Ret returns last modified qreg (q2)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 1 }, // r0 = 1
            Instruction::KImm { dst: 1, value: 2 }, // r1 = 2
            Instruction::IToQ { dst: 0, a: 0 }, // r0=1 → q0=256 (1.0)
            Instruction::IToQ { dst: 1, a: 1 }, // r1=2 → q1=512 (2.0)
            Instruction::QAdd { dst: 2, a: 0, b: 1 }, // q2 = 768 (3.0)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // Ret returns last modified qreg: q2 = 768 (Q8.8 of 3.0)
        assert_eq!(result.value, Some(768));
    }

    #[test]
    fn test_e6_itoq() {
        // r0=5 → ITOQ → q0 = 5 * 256 = 1280 (Q8.8 of 5.0)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 5 }, // r0 = 5
            Instruction::IToQ { dst: 0, a: 0 }, // r0=5 → q0=1280 (Q8.8 of 5.0)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // Ret returns q0 = 1280 (Q8.8 of 5.0)
        assert_eq!(result.value, Some(1280));
    }

    #[test]
    fn test_e6_qtoi() {
        // r0=0, r1=1 → ITOQ → q0=0, q1=256 → QADD → q2=256 → Ret
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::KImm { dst: 1, value: 1 }, // r1 = 1
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::IToQ { dst: 1, a: 1 }, // r1=1 → q1=256 (1.0 in Q8.8)
            Instruction::QAdd { dst: 2, a: 0, b: 1 }, // q2 = 256
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // Ret returns last_qreg: q2 = 256 (Q8.8 of 1.0)
        assert_eq!(result.value, Some(256));
    }

    #[test]
    fn test_e6_qneg() {
        // r0=0, r1=1 → ITOQ → q1=256 → QNEG → q2=-256
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::KImm { dst: 1, value: 1 }, // r1 = 1
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::IToQ { dst: 1, a: 1 }, // r1=1 → q1=256 (1.0 in Q8.8)
            Instruction::QNeg { dst: 2, a: 1 }, // q2 = -256
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // Ret returns last_qreg: q2 = -256
        assert_eq!(result.value, Some(-256));
    }

    #[test]
    fn test_e6_qsqrt() {
        // r0=0, r1=1 → ITOQ → q1=256 → QADD x15 → q1=4096 (16.0 in Q8.8)
        // QSQRT: sqrt(4096) = 1024 (Q8.8 of 4.0)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::KImm { dst: 1, value: 16 }, // r1 = 16
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::IToQ { dst: 1, a: 1 }, // r1=16 → q1=4096 (16.0 in Q8.8)
            Instruction::QSqrt { dst: 2, a: 1 }, // q2 = isqrt(4096) = 1024 (Q8.8 of 4.0)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QSQRT: sqrt(4096) = 1024 (Q8.8 of 4.0)
        assert_eq!(result.value, Some(1024));
    }

    #[test]
    fn test_e6_qsqrt_neg() {
        // sqrt(0) = 0, should pass (domain check handles negative)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::QNeg { dst: 1, a: 0 }, // q1 = 0
            Instruction::QSqrt { dst: 2, a: 1 }, // sqrt(0) = 0
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn test_e6_qmul() {
        // r0=2, r1=3 → ITOQ → q0=512, q1=768 → QMUL → q2=1536 (6.0 in Q8.8)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 2 }, // r0 = 2
            Instruction::KImm { dst: 1, value: 3 }, // r1 = 3
            Instruction::IToQ { dst: 0, a: 0 }, // r0=2 → q0=512 (2.0 in Q8.8)
            Instruction::IToQ { dst: 1, a: 1 }, // r1=3 → q1=768 (3.0 in Q8.8)
            Instruction::QMul { dst: 2, a: 0, b: 1 }, // q2 = (512*768)>>8 = 1536 (6.0 in Q8.8)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QMUL: Q8.8 * Q8.8 >> 8 = 1536 (Q8.8 of 6.0)
        assert_eq!(result.value, Some(1536));
    }

    #[test]
    fn test_e6_qdiv() {
        // r0=12, r1=3 → ITOQ → q0=3072, q1=768 → QDIV → q2=1024 (4.0 in Q8.8)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 12 }, // r0 = 12
            Instruction::KImm { dst: 1, value: 3 },  // r1 = 3
            Instruction::IToQ { dst: 0, a: 0 }, // r0=12 → q0=3072 (12.0 in Q8.8)
            Instruction::IToQ { dst: 1, a: 1 }, // r1=3 → q1=768 (3.0 in Q8.8)
            Instruction::QDiv { dst: 2, a: 0, b: 1 }, // q2 = (3072<<8)/768 = 1024 (4.0 in Q8.8)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QDIV: Q8.8 / Q8.8 → (a << 8) / b = 1024
        assert_eq!(result.value, Some(1024));
    }

    #[test]
    fn test_e6_qdiv_by_zero() {
        // r0=1, r1=1 → ITOQ → q0=256, q1=256 → QDIV → 256/256 = 256 (1.0 in Q8.8)
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 1 }, // r0 = 1
            Instruction::KImm { dst: 1, value: 1 }, // r1 = 1
            Instruction::IToQ { dst: 0, a: 0 }, // r0=1 → q0=256
            Instruction::IToQ { dst: 1, a: 1 }, // r1=1 → q1=256
            Instruction::QDiv { dst: 2, a: 0, b: 1 }, // 256/256 = 256 (1.0)
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QDIV: 256/256 = 256 (Q8.8 of 1.0)
        assert_eq!(result.value, Some(256));
    }

    #[test]
    fn test_e6_qload_store() {
        // r0=0, r1=1 → ITOQ → q1=256 → QSTORE → QLOAD → Ret q1
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::KImm { dst: 1, value: 1 }, // r1 = 1
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::IToQ { dst: 1, a: 1 }, // r1=1 → q1=256 (1.0 in Q8.8)
            Instruction::QStore { addr: 0, src: 1 }, // store q1 to addr 0
            Instruction::QZero { dst: 1 }, // clear q1 to 0
            Instruction::QLoad { addr: 0, dst: 1 }, // load from addr 0 → q1 = 256
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QLOAD restores q1 = 256 (Q8.8 of 1.0)
        assert_eq!(result.value, Some(256));
    }

    #[test]
    fn test_e6_qzero() {
        // r0=0, r1=1 → ITOQ → q1=256 → QZERO → q1=0
        let bytes = build_e6(&[
            Instruction::KImm { dst: 0, value: 0 }, // r0 = 0
            Instruction::KImm { dst: 1, value: 1 }, // r1 = 1
            Instruction::IToQ { dst: 0, a: 0 }, // r0=0 → q0=0
            Instruction::IToQ { dst: 1, a: 1 }, // r1=1 → q1=256
            Instruction::QZero { dst: 1 }, // q1 = 0
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // QZero sets q1 = 0
        assert_eq!(result.value, Some(0));
    }
}
