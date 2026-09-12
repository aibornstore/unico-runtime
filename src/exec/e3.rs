//! E3 Executor
//!
//! Multi-page memory + extended arithmetic profile:
//! - E2: LOAD.I64 (0x91), STORE.I64 (0x92), 4096-byte single page
//! - E3: 1-page memory (4096 bytes), extended arithmetic, i32/u32/u64 load-store
//!
//! E3 opcodes:
//!   0x10 => SUB.I64   0x11 => MUL.I64   0x12 => DIV.I64
//!   0x93 => LOAD.I32  0x94 => STORE.I32
//!   0x95 => LOAD.U64  0x96 => STORE.U64
//!   0x97 => LOAD.U32  0x98 => STORE.U32
//!   0x99 => MEM.SIZE

use crate::error::Result;
use crate::leb128::encode_uleb;
use crate::types::{ExecutionResult, Provenance, Status};
use std::time::Instant;

// ---------------------------------------------------------------------------
// E3 types
// ---------------------------------------------------------------------------

/// E3 memory: 1 page × 4096 bytes = 4096 bytes total
pub const E3_PAGE_COUNT: usize = 1;
pub const E3_PAGE_SIZE: usize = 4096;
pub const E3_MEMORY_SIZE: usize = E3_PAGE_COUNT * E3_PAGE_SIZE; // 4096

/// E3 instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    KImm { dst: u32, value: i64 },
    Add  { dst: u32, a: u32, b: u32 },
    Ret,
    Trap,
    Cmp  { pred: u8, dst: u32, a: u32, b: u32 },
    Br   { target: u32 },
    BrIf { cond: u32, target: u32 },
    Call { callee: usize },
    // E2
    LoadI64  { dst: u32, addr: u32 },
    StoreI64 { addr: u32, src: u32 },
    // E3 arithmetic
    SubI64 { dst: u32, a: u32, b: u32 },
    MulI64 { dst: u32, a: u32, b: u32 },
    DivI64 { dst: u32, a: u32, b: u32 },
    // E3 memory
    LoadI32  { dst: u32, addr: u32 },
    StoreI32 { addr: u32, src: u32 },
    LoadU64  { dst: u32, addr: u32 },
    StoreU64 { addr: u32, src: u32 },
    LoadU32  { dst: u32, addr: u32 },
    StoreU32 { addr: u32, src: u32 },
    MemSize,
}

/// E3 function definition
#[derive(Debug, Clone)]
pub struct E3FunctionDef {
    pub param_count: usize,
    pub result_count: usize,
    pub register_count: usize,
    pub code: Vec<Instruction>,
}

/// E3 module
#[derive(Debug)]
pub struct E3Module {
    pub functions: Vec<E3FunctionDef>,
    pub memory: Vec<u8>, // 524,288 bytes, zeroed
}

impl Clone for E3Module {
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
        0x00 => { // K.I64
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

             // skip terminator only for multi-byte ULEB
             // skip continuation bytes
            // Skip multi-byte ULEB terminator landing at second operand position

            let (imm_val, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

             // skip terminator only for multi-byte ULEB
             // skip continuation bytes
            Instruction::KImm { dst: dst.try_into().unwrap(), value: imm_val.try_into().unwrap() }
        }
        0x0b => { // ADD
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::Add { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xa6 => Instruction::Ret, // RET — single byte, no operands
        0x9F => Instruction::Trap, // TRAP
        0x8c => { // CMP
            let pred = bytes[pos]; pos += 1;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::Cmp { pred: pred.try_into().unwrap(), dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0x8d => { // BR
            let (target, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::Br { target: target.try_into().unwrap() }
        }
        0x8e => { // BR.IF
            let (cond, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (target, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::BrIf { cond: cond.try_into().unwrap(), target: target.try_into().unwrap() }
        }
        0x8f => { // CALL
            let (callee, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::Call { callee: callee.try_into().unwrap() }
        }
        0x91 => { // LOAD.I64
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::LoadI64 { dst: dst.try_into().unwrap(), addr: addr.try_into().unwrap() }
        }
        0x92 => { // STORE.I64
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::StoreI64 { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0x10 => { // SUB.I64
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::SubI64 { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0x11 => { // MUL.I64
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::MulI64 { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0x12 => { // DIV.I64
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::DivI64 { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0x93 => { // LOAD.I32
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::LoadI32 { dst: dst.try_into().unwrap(), addr: addr.try_into().unwrap() }
        }
        0x94 => { // STORE.I32
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::StoreI32 { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0x95 => { // LOAD.U64
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::LoadU64 { dst: dst.try_into().unwrap(), addr: addr.try_into().unwrap() }
        }
        0x96 => { // STORE.U64
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::StoreU64 { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0x97 => { // LOAD.U32
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::LoadU32 { dst: dst.try_into().unwrap(), addr: addr.try_into().unwrap() }
        }
        0x98 => { // STORE.U32
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;

            Instruction::StoreU32 { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0x99 => { // MEM.SIZE — single byte, no operands, writes to r0
            Instruction::MemSize
        }
        _ => return Err(crate::error::Error::Format(format!("unknown opcode: {opcode:#x}"))),
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
// E3Module parse
// ---------------------------------------------------------------------------

impl E3Module {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 || &bytes[0..6] != b"UNICO\x03" {
            return Err(crate::error::Error::Format("bad magic".into()));
        }
        let mut pos = 6;

        // FUNC section: tag(0x02), size, count, then 5 ULEB fields per function
        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(crate::error::Error::Format("missing FUNC section".into()));
        }
        pos += 1; // skip FUNC tag
        let (func_payload_len, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        let func_payload_end = pos + func_payload_len;
        if func_payload_end > bytes.len() {
            return Err(crate::error::Error::Format("truncated FUNC payload".into()));
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
            functions.push(E3FunctionDef { param_count, result_count, register_count, code: Vec::new() });
        }

        if pos != func_payload_end {
            return Err(crate::error::Error::Format("FUNC payload has trailing bytes".into()));
        }

        // CODE section: tag(0x01), size, code_bytes
        if pos >= bytes.len() || bytes[pos] != 0x01 {
            return Err(crate::error::Error::Format("missing CODE section".into()));
        }
        pos += 1; // skip CODE tag
        let (code_size, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        // NOTE: code_size from CODE section = desc_code_size from FUNC descriptor (both = instr_buf.len(), excl. END)
        let code_start = pos;
        let code_end = code_start + code_size;
        if code_end > bytes.len() {
            return Err(crate::error::Error::Format("code section overflow".into()));
        }

        // Decode all instructions (decode loop stops at pos >= bytes.len())
        let all_instrs = decode_all(&bytes[code_start..code_end])?;

        // Slice per function. For E3 single-function modules, give all decoded instructions to function 0.
        // For multi-function modules, distribute evenly (remainder to last function).
        let total_instrs = all_instrs.len();
        let base_instrs = if func_count > 0 { total_instrs / func_count } else { 0 };
        let remainder = if func_count > 0 { total_instrs % func_count } else { 0 };
        let mut instr_pos = 0;
        for i in 0..func_count {
            let extra = if i < remainder { 1 } else { 0 };
            let func_end = (instr_pos + base_instrs + extra).min(all_instrs.len());
            let func_instrs: Vec<_> = all_instrs[instr_pos..func_end].to_vec();
            functions[i].code = func_instrs;
            instr_pos = func_end;
        }

        // END tag — at code_end (since code_end = code_start + code_code_size = instr_buf.len())
        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(crate::error::Error::Format("missing final END byte".into()));
        }

        // E3: 1 page × 4096 bytes = 4096 bytes, zeroed
        let memory = vec![0u8; E3_MEMORY_SIZE];
        Ok(E3Module { functions, memory })
    }

    pub fn verify(&self) -> Result<()> {
        for func in &self.functions {
            if let Some(last) = func.code.last() {
                match last {
                    Instruction::Ret | Instruction::Trap => {}
                    _ => return Err(crate::error::Error::Verification("missing RET/TRAP".into())),
                }
            } else {
                return Err(crate::error::Error::Verification("empty function".into()));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// E3Executor
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Frame {
    func_idx: usize,
    pc: usize,
    regs: Vec<i64>,
    result_reg: Option<u32>,
}

pub struct E3Executor {
    functions: Vec<E3FunctionDef>,
    frames: Vec<Frame>,
    memory: Vec<u8>,
    fuel: u64,
    start: Instant,
}

impl E3Executor {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            frames: Vec::new(),
            memory: vec![0u8; E3_MEMORY_SIZE],
            fuel: 100_000,
            start: Instant::now(),
        }
    }

    pub fn execute(&mut self, module: &E3Module) -> Result<ExecutionResult> {
        self.functions = module.functions.clone();
        self.frames.clear();
        self.memory = module.memory.clone();
        self.fuel = 100_000;
        self.start = Instant::now();

        if self.functions.is_empty() {
            return Ok(ExecutionResult::fail("no functions".into(), self.provenance()));
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

    fn run_function(&mut self, func_idx: usize, result_reg: Option<u32>) -> Result<ExecutionResult> {
        if func_idx >= self.functions.len() {
            return Ok(ExecutionResult::fail(format!("E3: bad function index {func_idx}"), self.provenance()));
        }
        let func = &self.functions[func_idx];
        let regs = vec![0i64; func.register_count.max(4)];
        self.frames.push(Frame { func_idx, pc: 0, regs, result_reg });
        let mut frame_idx = self.frames.len() - 1;

        loop {
            if self.fuel == 0 {
                self.frames.pop();
                return Ok(ExecutionResult::fail("E3: fuel exhausted".into(), self.provenance()));
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
                Instruction::Add { dst, a, b } => {
                    let av = self.frames[frame_idx].regs[*a as usize];
                    let bv = self.frames[frame_idx].regs[*b as usize];
                    self.frames[frame_idx].regs[*dst as usize] = av.wrapping_add(bv);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::SubI64 { dst, a, b } => {
                    let av = self.frames[frame_idx].regs[*a as usize];
                    let bv = self.frames[frame_idx].regs[*b as usize];
                    self.frames[frame_idx].regs[*dst as usize] = av.wrapping_sub(bv);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::MulI64 { dst, a, b } => {
                    let av = self.frames[frame_idx].regs[*a as usize];
                    let bv = self.frames[frame_idx].regs[*b as usize];
                    self.frames[frame_idx].regs[*dst as usize] = av.wrapping_mul(bv);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::DivI64 { dst, a, b } => {
                    let av = self.frames[frame_idx].regs[*a as usize];
                    let bv = self.frames[frame_idx].regs[*b as usize];
                    if bv == 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: div by zero".into(), self.provenance()));
                    }
                    self.frames[frame_idx].regs[*dst as usize] = av.wrapping_div(bv);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Ret => {
                    let val = self.frames[frame_idx].regs[0];
                    self.frames.pop();
                    if self.frames.is_empty() {
                        return Ok(ExecutionResult::pass(val, self.provenance()));
                    }
                    frame_idx = self.frames.len() - 1;
                    if let Some(dst) = self.frames[frame_idx].result_reg {
                        self.frames[frame_idx].regs[dst as usize] = val;
                    }
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Trap => {
                    self.frames.pop();
                    return Ok(ExecutionResult::fail("E3: explicit trap".into(), self.provenance()));
                }
                Instruction::Cmp { pred, dst, a, b } => {
                    let av = self.frames[frame_idx].regs[*a as usize];
                    let bv = self.frames[frame_idx].regs[*b as usize];
                    let r = match pred {
                        0 => (av == bv) as i64,
                        1 => (av < bv) as i64,
                        _ => 0,
                    };
                    self.frames[frame_idx].regs[*dst as usize] = r;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Br { target } => {
                    self.frames[frame_idx].pc = *target as usize;
                }
                Instruction::BrIf { cond, target } => {
                    if self.frames[frame_idx].regs[*cond as usize] != 0 {
                        self.frames[frame_idx].pc = *target as usize;
                    } else {
                        self.frames[frame_idx].pc += 1;
                    }
                }
                Instruction::Call { callee } => {
                    let val = self.run_function(*callee, Some(0))?;
                    match val.status {
                        Status::Pass => {
                            self.frames[frame_idx].regs[0] = val.value.unwrap_or(0);
                            self.frames[frame_idx].pc += 1;
                        }
                        Status::Fail => { return Ok(val); }
                    }
                }
                Instruction::LoadI64 { dst, addr } => {
                    let addr = *addr as usize;
                    if addr + 8 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: LOAD.I64 OOB".into(), self.provenance()));
                    }
                    let v = i64::from_le_bytes([
                        self.memory[addr], self.memory[addr+1], self.memory[addr+2], self.memory[addr+3],
                        self.memory[addr+4], self.memory[addr+5], self.memory[addr+6], self.memory[addr+7],
                    ]);
                    self.frames[frame_idx].regs[*dst as usize] = v;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::StoreI64 { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 8 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: STORE.I64 OOB".into(), self.provenance()));
                    }
                    let v = self.frames[frame_idx].regs[*src as usize];
                    let bytes = (v as u64).to_le_bytes();
                    self.memory[addr..][..8].copy_from_slice(&bytes);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::LoadI32 { dst, addr } => {
                    let addr = *addr as usize;
                    if addr + 4 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: LOAD.I32 OOB".into(), self.provenance()));
                    }
                    let v = i32::from_le_bytes([self.memory[addr], self.memory[addr+1], self.memory[addr+2], self.memory[addr+3]]);
                    self.frames[frame_idx].regs[*dst as usize] = v as i64;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::StoreI32 { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 4 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: STORE.I32 OOB".into(), self.provenance()));
                    }
                    let v = self.frames[frame_idx].regs[*src as usize] as u32;
                    let bytes = v.to_le_bytes();
                    self.memory[addr..][..4].copy_from_slice(&bytes);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::LoadU64 { dst, addr } => {
                    let addr = *addr as usize;
                    if addr + 8 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: LOAD.U64 OOB".into(), self.provenance()));
                    }
                    let v = u64::from_le_bytes([
                        self.memory[addr], self.memory[addr+1], self.memory[addr+2], self.memory[addr+3],
                        self.memory[addr+4], self.memory[addr+5], self.memory[addr+6], self.memory[addr+7],
                    ]);
                    self.frames[frame_idx].regs[*dst as usize] = v as i64;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::StoreU64 { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 8 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: STORE.U64 OOB".into(), self.provenance()));
                    }
                    let v = self.frames[frame_idx].regs[*src as usize] as u64;
                    let bytes = v.to_le_bytes();
                    self.memory[addr..][..8].copy_from_slice(&bytes);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::LoadU32 { dst, addr } => {
                    let addr = *addr as usize;
                    if addr + 4 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: LOAD.U32 OOB".into(), self.provenance()));
                    }
                    let v = u32::from_le_bytes([self.memory[addr], self.memory[addr+1], self.memory[addr+2], self.memory[addr+3]]);
                    self.frames[frame_idx].regs[*dst as usize] = v as i64;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::StoreU32 { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 4 > E3_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E3: STORE.U32 OOB".into(), self.provenance()));
                    }
                    let v = self.frames[frame_idx].regs[*src as usize] as u32;
                    let bytes = v.to_le_bytes();
                    self.memory[addr..][..4].copy_from_slice(&bytes);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::MemSize => {
                    self.frames[frame_idx].regs[0] = E3_MEMORY_SIZE as i64;
                    self.frames[frame_idx].pc += 1;
                }
            }
        }
    }
}

impl Default for E3Executor {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Bytecode builder
// ---------------------------------------------------------------------------

pub fn build_e3(instructions: &[Instruction]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(b"UNICO\x03");

    // Encode instructions first
    let mut instr_buf = Vec::new();
    for instr in instructions {
        encode_instr(instr, &mut instr_buf);
    }
    // instr_buf contains all instructions (excl. END tag which is appended separately)
    // descriptor.code_size = instr_buf.len() (instruction bytes only, END is separate)
    // CODE section size = instr_buf.len() (instruction bytes only, END is separate)
    let desc_code_size = instr_buf.len(); // instruction bytes only (END is separate)

    // Build descriptor fields and compute total ULEB bytes
    let param_count_bytes = encode_uleb(1);
    let result_count_bytes = encode_uleb(1);
    let register_count_bytes = encode_uleb(4);
    let code_offset_bytes = encode_uleb(0);
    let code_size_bytes = encode_uleb(desc_code_size);
    // desc_uleb_bytes = sum of all descriptor field ULEB byte lengths
    let desc_uleb_bytes = param_count_bytes.len() + result_count_bytes.len()
        + register_count_bytes.len() + code_offset_bytes.len() + code_size_bytes.len();

    // FUNC section: tag(1) + size(1) + func_count(1) + descriptor_uleb_bytes
    // func_payload = func_count(1) + all descriptor ULEB bytes
    let func_payload = 1 + desc_uleb_bytes;
    bytes.push(0x02); // FUNC tag
    bytes.extend(&encode_uleb(func_payload));
    bytes.extend(&encode_uleb(1)); // func_count = 1

    // FUNC record: 5 ULEB fields
    bytes.extend(&param_count_bytes);
    bytes.extend(&result_count_bytes);
    bytes.extend(&register_count_bytes);
    bytes.extend(&code_offset_bytes);
    bytes.extend(&code_size_bytes);

    // CODE section: tag(1) + size(1) + code_bytes
    bytes.push(0x01); // CODE tag
    bytes.extend(&encode_uleb(desc_code_size)); // = instr_buf.len()
    bytes.extend(&instr_buf);

    // END tag
    bytes.push(0x00); // END tag
    bytes
}

fn encode_instr(instr: &Instruction, out: &mut Vec<u8>) {
    match instr {
        Instruction::KImm { dst, value } => {
            out.push(0x00);
            out.extend(&encode_uleb(*dst as usize));
            // ULEB-encoded 64-bit immediate
            let imm_usize = *value as usize;
            out.extend(&encode_uleb(imm_usize));
        }
        Instruction::Add { dst, a, b } => {
            out.push(0x0b);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::SubI64 { dst, a, b } => {
            out.push(0x10);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::MulI64 { dst, a, b } => {
            out.push(0x11);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::DivI64 { dst, a, b } => {
            out.push(0x12);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::Ret => { out.push(0xa6); } // single byte, no operands
        Instruction::Trap => { out.push(0x9F); }
        Instruction::Cmp { pred, dst, a, b } => {
            out.push(0x8c);
            out.push(*pred);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::Br { target } => {
            out.push(0x8d);
            out.extend(&encode_uleb(*target as usize));
        }
        Instruction::BrIf { cond, target } => {
            out.push(0x8e);
            out.extend(&encode_uleb(*cond as usize));
            out.extend(&encode_uleb(*target as usize));
        }
        Instruction::Call { callee } => {
            out.push(0x8f);
            out.extend(&encode_uleb(*callee));
        }
        Instruction::LoadI64 { dst, addr } => {
            out.push(0x91);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::StoreI64 { addr, src } => {
            out.push(0x92);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::LoadI32 { dst, addr } => {
            out.push(0x93);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::StoreI32 { addr, src } => {
            out.push(0x94);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::LoadU64 { dst, addr } => {
            out.push(0x95);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::StoreU64 { addr, src } => {
            out.push(0x96);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::LoadU32 { dst, addr } => {
            out.push(0x97);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::StoreU32 { addr, src } => {
            out.push(0x98);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::MemSize { .. } => {
            out.push(0x99); // single byte, no operands
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> ExecutionResult {
        let module = E3Module::parse(bytes).expect("parse failed");
        module.verify().expect("verify failed");
        let mut exec = E3Executor::new();
        exec.execute(&module).expect("execute error")
    }

    #[test]
    fn test_e3_return_constant() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 99 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(99));
    }

    #[test]
    fn test_e3_add() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 10 },
            Instruction::KImm { dst: 1, value: 32 },
            Instruction::Add { dst: 0, a: 0, b: 1 }, // r0 = 10 + 32 = 42
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_e3_sub() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 100 },
            Instruction::KImm { dst: 1, value: 38 },
            Instruction::SubI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(62));
    }

    #[test]
    fn test_e3_mul() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 6 },
            Instruction::KImm { dst: 1, value: 7 },
            Instruction::MulI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_e3_div() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 100 },
            Instruction::KImm { dst: 1, value: 7 },
            Instruction::DivI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(14));
    }

    #[test]
    fn test_e3_div_by_zero() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 10 },
            Instruction::KImm { dst: 1, value: 0 },
            Instruction::DivI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("div by zero")));
    }

    #[test]
    fn test_e3_mul_overflow() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: i64::MAX },
            Instruction::KImm { dst: 1, value: 2 },
            Instruction::MulI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(-2)); // wrapping
    }

    #[test]
    fn test_e3_store_load_i64() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 999 },
            Instruction::StoreI64 { addr: 0, src: 0 },
            Instruction::LoadI64 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(999));
    }

    #[test]
    fn test_e3_i32_unaligned() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 42 },
            Instruction::StoreI32 { addr: 3, src: 0 },
            Instruction::LoadI32 { dst: 0, addr: 3 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_e3_u64_at_boundary() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 12345678901234 },
            Instruction::StoreU64 { addr: 1000, src: 0 },
            Instruction::LoadU64 { dst: 0, addr: 1000 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(12345678901234));
    }

    #[test]
    fn test_e3_mem_size() {
        let bytes = build_e3(&[
            Instruction::MemSize,
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(4096));
    }

    #[test]
    fn test_e3_large_page() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 7777 },
            Instruction::StoreI64 { addr: 2000, src: 0 },
            Instruction::LoadI64 { dst: 0, addr: 2000 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(7777));
    }

    #[test]
    fn test_e3_oob() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::StoreI64 { addr: 4096, src: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_cmp() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 5 },
            Instruction::KImm { dst: 1, value: 5 },
            Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e3_br() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::Br { target: 3 },
            Instruction::KImm { dst: 0, value: 99 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e3_trap() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 42 },
            Instruction::Trap,
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("trap")));
    }
}
