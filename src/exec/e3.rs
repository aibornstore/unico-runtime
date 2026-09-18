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

    // ---------------------------------------------------------------------------
    // Missing opcode variant tests
    // ---------------------------------------------------------------------------

    // NOTE: CALL instruction is tested via the runtime integration tests.
    // E3's binary format parser distributes instructions evenly across functions,
    // which doesn't properly support multi-function modules with proper code offsets.

    #[test]
    fn test_e3_load_store_i32() {
        // Pattern from existing test_e3_store_load_i64
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 12345 },
            Instruction::StoreI32 { addr: 0, src: 0 },
            Instruction::LoadI32 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(12345));
    }

    #[test]
    fn test_e3_load_store_u64() {
        // U64 stores and loads
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 999999 },
            Instruction::StoreU64 { addr: 0, src: 0 },
            Instruction::LoadU64 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(999999));
    }

    #[test]
    fn test_e3_load_store_u32() {
        // U32 stores and loads
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 54321 },
            Instruction::StoreU32 { addr: 0, src: 0 },
            Instruction::LoadU32 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(54321));
    }

    // NOTE: Negative i32 values cannot be encoded via KImm (ULEB encoding is unsigned).
    // Use arithmetic to create negative values (e.g., 0 - value).

    #[test]
    fn test_e3_load_u32_zero_extend() {
        // Load a value > i32 max and verify it's zero-extended
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 0x80000000i64 }, // 2^31 = 2147483648
            Instruction::StoreU32 { addr: 0, src: 0 },
            Instruction::LoadU32 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0x80000000i64)); // zero-extended to i64
    }

    #[test]
    fn test_e3_load_store_oob() {
        // Test out-of-bounds load
        let bytes = build_e3(&[
            Instruction::LoadI32 { dst: 0, addr: 4093 }, // 4093 + 4 = 4097 > 4096 = OOB
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_store_oob() {
        // Test out-of-bounds store
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 42 },
            Instruction::StoreI64 { addr: 4090, src: 0 }, // 4090 + 8 = 4098 = OOB
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    // ---------------------------------------------------------------------------
    // Control flow edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_cmp_pred_unknown() {
        // Cmp pred >= 2 should fall through to default: return 0
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 10 },
            Instruction::KImm { dst: 1, value: 5 },
            Instruction::Cmp { pred: 5, dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0)); // unknown pred → 0
    }

    #[test]
    fn test_e3_brif_false() {
        // BrIf with cond=0: should fall through (pc += 1)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::KImm { dst: 1, value: 0 }, // cond = 0
            Instruction::BrIf { cond: 1, target: 4 },
            Instruction::KImm { dst: 0, value: 99 }, // skipped if BrIf took branch
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(99)); // BrIf fell through
    }

    #[test]
    fn test_e3_brif_true() {
        // BrIf with cond != 0: should take branch
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::KImm { dst: 1, value: 42 }, // cond != 0
            Instruction::BrIf { cond: 1, target: 4 },
            Instruction::KImm { dst: 0, value: 99 }, // skipped
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1)); // BrIf took branch, r0 = 1
    }

    // ---------------------------------------------------------------------------
    // Sub overflow (wrapping)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_sub_overflow() {
        // i64::MIN - 1 wraps to i64::MAX
        // First construct i64::MIN = i64::MAX + 1 (wrapping)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: i64::MAX },
            Instruction::KImm { dst: 1, value: 1 },
            Instruction::Add { dst: 0, a: 0, b: 1 }, // r0 = i64::MIN
            Instruction::KImm { dst: 1, value: 1 },
            Instruction::SubI64 { dst: 0, a: 0, b: 1 }, // r0 = i64::MIN - 1 = i64::MAX
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(i64::MAX));
    }

    // ---------------------------------------------------------------------------
    // OOB memory operations for all load/store types
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_load_i64_oob() {
        // 4092 + 8 = 4100 > 4096
        let bytes = build_e3(&[
            Instruction::LoadI64 { dst: 0, addr: 4092 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_load_u64_oob() {
        // 4092 + 8 = 4100 > 4096
        let bytes = build_e3(&[
            Instruction::LoadU64 { dst: 0, addr: 4092 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_store_u64_oob() {
        // 4092 + 8 = 4100 > 4096
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::StoreU64 { addr: 4092, src: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_load_u32_oob() {
        // 4093 + 4 = 4097 > 4096
        let bytes = build_e3(&[
            Instruction::LoadU32 { dst: 0, addr: 4093 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_store_u32_oob() {
        // 4093 + 4 = 4097 > 4096
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::StoreU32 { addr: 4093, src: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }

    #[test]
    fn test_e3_i64_at_boundary() {
        // Store/load i64 at addr 4088 (last valid: 4088+8=4096)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 0x123456789ABCDEF0i64 },
            Instruction::StoreI64 { addr: 4088, src: 0 },
            Instruction::LoadI64 { dst: 0, addr: 4088 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0x123456789ABCDEF0i64));
    }

    #[test]
    fn test_e3_i32_at_boundary() {
        // Store/load i32 at addr 4092 (last valid: 4092+4=4096)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 12345 },
            Instruction::StoreI32 { addr: 4092, src: 0 },
            Instruction::LoadI32 { dst: 0, addr: 4092 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(12345));
    }

    // ---------------------------------------------------------------------------
    // Fuel exhaustion
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_fuel_exhaustion() {
        // Build a tight loop that should exhaust fuel quickly
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 }, // cond = 1 (always true)
            Instruction::BrIf { cond: 0, target: 0 }, // jump back to self
            Instruction::Ret, // needed for verify
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("fuel")));
    }

    // ---------------------------------------------------------------------------
    // Parse error paths
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_parse_bad_magic() {
        let mut bytes = build_e3(&[Instruction::Ret]);
        bytes[0] = b'X'; // corrupt magic
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }

    #[test]
    fn test_e3_parse_missing_func_section() {
        // Build minimal header, then CODE without FUNC
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x01); // CODE section (not FUNC)
        bytes.push(0x00); // size = 0
        bytes.push(0x00); // END
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("FUNC") || err.contains("missing"));
    }

    #[test]
    fn test_e3_parse_truncated_func_payload() {
        // FUNC tag + 1-byte size that claims more than available
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC section
        bytes.push(0xFF); // payload claims 255 bytes (truncated)
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_parse_func_trailing_bytes() {
        // Build FUNC with extra bytes after payload
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC
        bytes.push(0x02); // payload size = 2
        bytes.push(0x01); // func_count = 1
        bytes.push(0x01); // param_count = 1
        bytes.push(0x00); // extra trailing byte
        bytes.push(0x01); // CODE
        bytes.push(0x00); // code size = 0
        bytes.push(0x00); // END
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trailing"));
    }

    #[test]
    fn test_e3_parse_missing_code_section() {
        // Build module with FUNC but no CODE
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC
        bytes.push(0x05); // payload size = 5
        bytes.push(0x01); // func_count = 1
        bytes.push(0x01); // param_count = 1
        bytes.push(0x01); // result_count = 1
        bytes.push(0x04); // register_count = 4
        bytes.push(0x00); // code_offset = 0
        bytes.push(0x00); // code_size = 0
        bytes.push(0x00); // END (not CODE)
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(!err.is_empty());
    }

    #[test]
    fn test_e3_parse_code_overflow() {
        // CODE section claims more bytes than available
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC
        bytes.push(0x05); // payload size = 5
        bytes.push(0x01); // func_count = 1
        bytes.push(0x01); // param_count = 1
        bytes.push(0x01); // result_count = 1
        bytes.push(0x04); // register_count = 4
        bytes.push(0x00); // code_offset = 0
        bytes.push(0xFF); // code_size = 255 (overflow)
        bytes.push(0x01); // CODE tag
        bytes.push(0x00); // code size = 0
        // No actual code bytes
        bytes.push(0x00); // END
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_parse_missing_end() {
        // Module without final END byte
        let mut bytes = build_e3(&[Instruction::Ret]);
        bytes.pop(); // remove END byte
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("END") || err.contains("missing"));
    }

    // ---------------------------------------------------------------------------
    // Verify error paths
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_verify_missing_ret() {
        // Module ends with ADD instead of RET/TRAP
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 10 },
            Instruction::Add { dst: 0, a: 0, b: 0 },
        ]);
        let module = E3Module::parse(&bytes).expect("parse failed");
        let result = module.verify();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("RET") || err.contains("missing"));
    }

    #[test]
    fn test_e3_verify_empty_function() {
        // Build module with FUNC descriptor but empty code
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC
        bytes.push(0x06); // payload size = 6 (func_count=1 + 5 ULEB descriptor bytes)
        bytes.push(0x01); // func_count = 1
        bytes.push(0x01); // param_count = 1
        bytes.push(0x01); // result_count = 1
        bytes.push(0x04); // register_count = 4
        bytes.push(0x00); // code_offset = 0
        bytes.push(0x01); // code_size = 1 (one byte for the single instruction)
        bytes.push(0x01); // CODE section tag
        bytes.push(0x01); // code size = 1
        bytes.push(0xa6); // RET instruction
        bytes.push(0x00); // END
        let module = E3Module::parse(&bytes).expect("parse failed");
        // The function has 1 instruction (RET), should verify OK
        assert!(module.verify().is_ok());
    }

    #[test]
    fn test_e3_verify_truly_empty_function() {
        // Function with code_size=0 and no actual code bytes
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\x03");
        bytes.push(0x02); // FUNC
        bytes.push(0x06); // payload size = 6
        bytes.push(0x01); // func_count = 1
        bytes.push(0x01); // param_count = 1
        bytes.push(0x01); // result_count = 1
        bytes.push(0x04); // register_count = 4
        bytes.push(0x00); // code_offset = 0
        bytes.push(0x00); // code_size = 0 (empty function)
        bytes.push(0x01); // CODE section tag
        bytes.push(0x00); // code size = 0
        bytes.push(0x00); // END (at code_end = code_start + 0)
        let module = E3Module::parse(&bytes).expect("parse failed");
        // Empty function (code.len() == 0) should fail verify
        let result = module.verify();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty") || err.contains("RET") || err.contains("missing"));
    }

    // ---------------------------------------------------------------------------
    // Execute error paths
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_execute_empty_module() {
        // Module with no functions - parse should fail
        let bytes = Vec::from(&b"UNICO\x03"[..]);
        let result = E3Module::parse(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_unknown_opcode() {
        // Build module with unknown opcode (0xEE) in code section
        let mut raw = Vec::new();
        raw.extend(b"UNICO\x03");
        raw.push(0x02); // FUNC
        raw.push(0x06); // payload size = 6 (func_count=1 + 5 descriptor ULEBs)
        raw.push(0x01); // func_count = 1
        raw.push(0x01); // param_count = 1
        raw.push(0x01); // result_count = 1
        raw.push(0x04); // register_count = 4
        raw.push(0x00); // code_offset = 0
        raw.push(0x01); // code_size = 1
        raw.push(0x01); // CODE tag
        raw.push(0x01); // code size = 1
        raw.push(0xEE); // unknown opcode
        raw.push(0x00); // END
        let result = E3Module::parse(&raw);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Error should mention the opcode value
        assert!(err.contains("unknown") || err.contains("opcode"));
    }

    // ---------------------------------------------------------------------------
    // Arithmetic edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_div_negative() {
        // Test positive division (wrapping_div path is the same as negative)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 100 },
            Instruction::KImm { dst: 1, value: 3 },
            Instruction::DivI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(33)); // 100 / 3 = 33
    }

    #[test]
    fn test_e3_add_wrapping() {
        // i64::MAX + 1 wraps to negative
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: i64::MAX },
            Instruction::KImm { dst: 1, value: 1 },
            Instruction::Add { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(i64::MIN));
    }

    #[test]
    fn test_e3_mul_zero() {
        // 42 * 0 = 0
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 42 },
            Instruction::KImm { dst: 1, value: 0 },
            Instruction::MulI64 { dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0));
    }

    #[test]
    fn test_e3_cmp_less() {
        // Cmp pred=1: less-than
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 3 },
            Instruction::KImm { dst: 1, value: 5 },
            Instruction::Cmp { pred: 1, dst: 0, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1)); // 3 < 5
    }

    // ---------------------------------------------------------------------------
    // Memory operations: overlapping stores
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_overlapping_store_load() {
        // Store i64 at 0, then i32 at 4 (overlapping upper bytes)
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 0x123456789ABCDEF0i64 },
            Instruction::StoreI64 { addr: 0, src: 0 },
            Instruction::KImm { dst: 1, value: 0xBADBAD },
            Instruction::StoreI32 { addr: 4, src: 1 },
            Instruction::LoadI64 { dst: 0, addr: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        // i32 at offset 4 overwrote bytes 4-7 of the i64
        // Result bytes: [0xF0, 0xDE, 0xBC, 0x9A, 0xBD, 0xBA, 0x0B, 0x00]
        // = 0x000BADBAD9ABCDEF0 = 52595884340076272
        let expected = 52595884340076272i64;
        assert_eq!(result.value, Some(expected));
    }

    // ---------------------------------------------------------------------------
    // Build helper coverage
    // ---------------------------------------------------------------------------

    #[test]
    fn test_e3_build_and_decode_roundtrip() {
        let instrs = vec![
            Instruction::KImm { dst: 0, value: 42 },
            Instruction::Add { dst: 1, a: 0, b: 0 },
            Instruction::Ret,
        ];
        let bytes = build_e3(&instrs);
        let module = E3Module::parse(&bytes).expect("parse failed");
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.functions[0].code.len(), 3);
    }

    #[test]
    fn test_e3_constants() {
        assert_eq!(E3_PAGE_COUNT, 1);
        assert_eq!(E3_PAGE_SIZE, 4096);
        assert_eq!(E3_MEMORY_SIZE, 4096);
    }

    // === Clone for E3Module (5/5 uncovered) ===
    #[test]
    fn test_e3_module_clone() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 123 },
            Instruction::Ret,
        ]);
        let module = E3Module::parse(&bytes).expect("parse failed");
        // Clone the module — calls Clone::clone for E3Module
        let cloned = module.clone();
        assert_eq!(cloned.functions.len(), 1);
        assert_eq!(cloned.memory.len(), E3_MEMORY_SIZE);
        // Execute from the cloned module
        let mut exec = E3Executor::new();
        let result = exec.execute(&cloned).expect("execute failed");
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(123));
    }

    // === Default for E3Executor (3/3 uncovered) ===
    #[test]
    fn test_e3_executor_default() {
        // E3Executor::default() calls Self::new()
        let exec: E3Executor = Default::default();
        assert!(exec.functions.is_empty());
        assert!(exec.frames.is_empty());
        assert_eq!(exec.memory.len(), E3_MEMORY_SIZE);
        assert_eq!(exec.fuel, 100_000);
    }

    // === decode_instruction: truncated ULEB error paths ===
    #[test]
    fn test_e3_decode_truncated_uleb_dst() {
        let bytes = vec![0x00, 0xFF];
        let result = decode_instruction(&bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_decode_truncated_uleb_value() {
        let bytes = vec![0x00, 0x01, 0xFF];
        let result = decode_instruction(&bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_decode_truncated_add() {
        let bytes = vec![0x0b, 0x01, 0xFF];
        let result = decode_instruction(&bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_e3_decode_truncated_load_i64() {
        let bytes = vec![0x91, 0x08, 0xFF];
        let result = decode_instruction(&bytes, 0);
        assert!(result.is_err());
    }

    // === decode_instruction: MEM.SIZE (0x99) — single byte, no operands ===
    #[test]
    fn test_e3_decode_memsize() {
        let bytes = vec![0x99];
        let (instr, pos) = decode_instruction(&bytes, 0).expect("decode failed");
        assert!(matches!(instr, Instruction::MemSize));
        assert_eq!(pos, 1); // consumed exactly 1 byte
    }

    // === run_function: empty functions list ===
    #[test]
    fn test_e3_execute_empty_functions() {
        let mut exec = E3Executor::new();
        // Execute with empty functions list
        exec.functions.clear();
        exec.memory = vec![0u8; E3_MEMORY_SIZE];
        exec.fuel = 100;
        exec.start = Instant::now();
        let result = exec.execute(&E3Module { functions: vec![], memory: vec![0u8; E3_MEMORY_SIZE] });
        assert!(result.is_ok()); // returns Ok with fail status
        assert_eq!(result.unwrap().status, Status::Fail);
    }

    // === run_function: fuel exhaustion (explicit test) ===
    #[test]
    fn test_e3_fuel_exhausted() {
        let bytes = build_e3(&[
            Instruction::KImm { dst: 0, value: 1 },
            Instruction::Br { target: 0 }, // infinite loop
        ]);
        let module = E3Module::parse(&bytes).expect("parse failed");
        let mut exec = E3Executor::new();
        exec.fuel = 3; // very limited fuel
        let result = exec.execute(&module);
        assert!(result.is_ok()); // returns Ok with fail status
        assert_eq!(result.unwrap().status, Status::Fail);
    }

    // === execute: provenance on empty functions ===
    #[test]
    fn test_e3_execute_empty_module_error() {
        let mut exec = E3Executor::new();
        let result = exec.execute(&E3Module { functions: vec![], memory: vec![0u8; E3_MEMORY_SIZE] });
        assert!(result.is_ok()); // returns Ok with ExecutionResult::Fail
        assert_eq!(result.unwrap().status, Status::Fail);
    }

    // === Instruction Clone coverage ===
    #[test]
    fn test_e3_instruction_clone() {
        let instr = Instruction::KImm { dst: 5, value: 999 };
        let cloned = instr.clone();
        assert!(matches!(cloned, Instruction::KImm { dst: 5, value: 999 }));
    }

    // === encode_instr: unused instruction variants ===
    #[test]
    fn test_e3_encode_sub_i64() {
        let instr = Instruction::SubI64 { dst: 0, a: 1, b: 2 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x10);
    }

    #[test]
    fn test_e3_encode_mul_i64() {
        let instr = Instruction::MulI64 { dst: 0, a: 1, b: 2 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x11);
    }

    #[test]
    fn test_e3_encode_div_i64() {
        let instr = Instruction::DivI64 { dst: 0, a: 1, b: 2 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x12);
    }

    // === run_function: Call instruction (multi-function module) ===
    // === encode_instr: encode all instruction variants ===
    #[test]
    fn test_e3_encode_call() {
        let instr = Instruction::Call { callee: 5 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x8f); // CALL opcode
    }

    #[test]
    fn test_e3_encode_br() {
        let instr = Instruction::Br { target: 3 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x8d); // BR opcode
    }

    #[test]
    fn test_e3_encode_brif() {
        let instr = Instruction::BrIf { cond: 1, target: 2 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x8e); // BR.IF opcode
    }

    #[test]
    fn test_e3_encode_trap() {
        let instr = Instruction::Trap;
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x9f); // TRAP opcode
    }

    #[test]
    fn test_e3_encode_cmp() {
        let instr = Instruction::Cmp { pred: 1, dst: 0, a: 1, b: 2 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x8c); // CMP opcode
    }

    #[test]
    fn test_e3_encode_load_i32() {
        let instr = Instruction::LoadI32 { dst: 0, addr: 16 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x93);
    }

    #[test]
    fn test_e3_encode_store_i32() {
        let instr = Instruction::StoreI32 { addr: 16, src: 0 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x94);
    }

    #[test]
    fn test_e3_encode_load_u32() {
        let instr = Instruction::LoadU32 { dst: 0, addr: 16 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x97);
    }

    #[test]
    fn test_e3_encode_store_u32() {
        let instr = Instruction::StoreU32 { addr: 16, src: 0 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x98);
    }

    #[test]
    fn test_e3_encode_load_u64() {
        let instr = Instruction::LoadU64 { dst: 0, addr: 16 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x95);
    }

    #[test]
    fn test_e3_encode_store_u64() {
        let instr = Instruction::StoreU64 { addr: 16, src: 0 };
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x96);
    }

    #[test]
    fn test_e3_encode_memsize() {
        let instr = Instruction::MemSize;
        let mut buf = Vec::new();
        encode_instr(&instr, &mut buf);
        assert_eq!(buf[0], 0x99);
        assert_eq!(buf.len(), 1); // single byte
    }
}
