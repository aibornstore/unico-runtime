//! E5 Executor — SIMD Profile
//!
//! 128-bit SIMD (4×f32 lanes):
//! - VADD, VMUL, VSUB, VDIV, VSQRT, VMIN, VMAX
//! - VIMM (f32 immediate → all 4 lanes)
//! - VLOAD (16 bytes), VSTORE (16 bytes)
//! - Memory: 1 page × 4096 bytes
//!
//! E5 opcodes:
//!   0xE0 => VADD    0xE1 => VMUL    0xE2 => VSUB    0xE3 => VDIV
//!   0xE4 => VSQRT   0xE5 => VMIN    0xE6 => VMAX    0xE7 => VIMM
//!   0xE8 => VLOAD   0xE9 => VSTORE  0xEA => VMOV    0xEB => VSETIMM
//!   0xEC => VCPY    0xED => VZERO   0xEE => VONE    0xEF => VMEMZERO

use crate::error::Result;
use crate::leb128::encode_uleb;
#[allow(unused_imports)]
use crate::types::{ExecutionResult, Provenance, Status};
use std::time::Instant;

// ---------------------------------------------------------------------------
// E5 types
// ---------------------------------------------------------------------------

/// E5 instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    // Vector binary ops: dst, a, b (all V-reg indices)
    VAdd   { dst: u8, a: u8, b: u8 },
    VMul   { dst: u8, a: u8, b: u8 },
    VSub   { dst: u8, a: u8, b: u8 },
    VDiv   { dst: u8, a: u8, b: u8 },
    VMin   { dst: u8, a: u8, b: u8 },
    VMax   { dst: u8, a: u8, b: u8 },
    // Unary vector op
    VSqrt  { dst: u8, a: u8 },
    // Immediate: dst, f32_value (4 bytes little-endian)
    VImm   { dst: u8, imm: f32 },
    // Memory: addr (ULEB), vreg (ULEB) — 16-byte aligned
    VLoad  { addr: u32, dst: u8 },
    VStore { addr: u32, src: u8 },
    // Vector move/copy
    VMov   { dst: u8, src: u8 },
    // Set all lanes to constant f32
    VSetImm { dst: u8, imm: f32 },
    // Copy scalar to all lanes
    VCpy   { dst: u8, src: u8 }, // dst_lane[i] = src[0] for all i
    // Specials
    VZero  { dst: u8 }, // set all lanes to 0.0
    VOne   { dst: u8 }, // set all lanes to 1.0
    VMemZero,            // zero all memory
    // Control
    Ret,
    Trap,
}

/// E5 function definition
#[derive(Debug, Clone)]
pub struct E5FunctionDef {
    pub param_count: usize,
    pub result_count: usize,
    pub register_count: usize,
    pub code: Vec<Instruction>,
}

/// E5 module
#[derive(Debug)]
pub struct E5Module {
    pub functions: Vec<E5FunctionDef>,
    pub memory: Vec<u8>, // 4096 bytes, zeroed
}

impl Clone for E5Module {
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
        0xE0 => {
            // VADD dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VAdd { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE1 => {
            // VMUL dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VMul { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE2 => {
            // VSUB dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VSub { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE3 => {
            // VDIV dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VDiv { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE4 => {
            // VSQRT dst a
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VSqrt { dst: dst.try_into().unwrap(), a: a.try_into().unwrap() }
        }
        0xE5 => {
            // VMIN dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VMin { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE6 => {
            // VMAX dst a b
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (a, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (b, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VMax { dst: dst.try_into().unwrap(), a: a.try_into().unwrap(), b: b.try_into().unwrap() }
        }
        0xE7 => {
            // VIMM dst (f32 immediate, 4 bytes LE)
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            if pos + 4 > bytes.len() {
                return Err(crate::error::Error::Format("VIMM: truncated f32 immediate".into()));
            }
            let imm = f32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            Instruction::VImm { dst: dst.try_into().unwrap(), imm: imm.try_into().unwrap() }
        }
        0xE8 => {
            // VLOAD addr dst
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VLoad { addr: addr.try_into().unwrap(), dst: dst.try_into().unwrap() }
        }
        0xE9 => {
            // VSTORE addr src
            let (addr, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VStore { addr: addr.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0xEA => {
            // VMOV dst src
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VMov { dst: dst.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0xEB => {
            // VSETIMM dst (f32 immediate, 4 bytes LE)
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            if pos + 4 > bytes.len() {
                return Err(crate::error::Error::Format("VSETIMM: truncated f32 immediate".into()));
            }
            let imm = f32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            Instruction::VSetImm { dst: dst.try_into().unwrap(), imm: imm.try_into().unwrap() }
        }
        0xEC => {
            // VCPY dst src (broadcast lane 0 of src to all lanes of dst)
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            let (src, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VCpy { dst: dst.try_into().unwrap(), src: src.try_into().unwrap() }
        }
        0xED => {
            // VZERO dst
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VZero { dst: dst.try_into().unwrap() }
        }
        0xEE => {
            // VONE dst
            let (dst, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
            Instruction::VOne { dst: dst.try_into().unwrap() }
        }
        0xEF => Instruction::VMemZero,
        0xa6 => Instruction::Ret,
        0x9F => Instruction::Trap,
        _ => return Err(crate::error::Error::Format(format!("E5: unknown opcode: {opcode:#x}"))),
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
// E5Module parse
// ---------------------------------------------------------------------------

impl E5Module {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 || &bytes[0..6] != b"UNICO\x05" {
            return Err(crate::error::Error::Format("E5: bad magic".into()));
        }
        let mut pos = 6;

        // FUNC section: tag(0x02), size, count, then 5 ULEB fields per function
        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(crate::error::Error::Format("E5: missing FUNC section".into()));
        }
        pos += 1;
        let (func_payload_len, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        let func_payload_end = pos + func_payload_len;
        if func_payload_end > bytes.len() {
            return Err(crate::error::Error::Format("E5: truncated FUNC payload".into()));
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
            functions.push(E5FunctionDef {
                param_count,
                result_count,
                register_count,
                code: Vec::new(),
            });
        }

        if pos != func_payload_end {
            return Err(crate::error::Error::Format("E5: FUNC payload trailing bytes".into()));
        }

        // CODE section: tag(0x01), size, code_bytes
        if pos >= bytes.len() || bytes[pos] != 0x01 {
            return Err(crate::error::Error::Format("E5: missing CODE section".into()));
        }
        pos += 1;
        let (code_size, _uleb_len) = crate::leb128::decode_uleb(&bytes[pos..])?;

            pos += _uleb_len;
        let code_start = pos;
        let code_end = code_start + code_size;
        if code_end > bytes.len() {
            return Err(crate::error::Error::Format("E5: code section overflow".into()));
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

        // END tag
        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(crate::error::Error::Format("E5: missing END byte".into()));
        }

        // E5: 1 page × 4096 bytes
        let memory = vec![0u8; E5_MEMORY_SIZE];
        Ok(E5Module { functions, memory })
    }

    pub fn verify(&self) -> Result<()> {
        for func in &self.functions {
            if let Some(last) = func.code.last() {
                match last {
                    Instruction::Ret | Instruction::Trap => {}
                    _ => {
                        return Err(crate::error::Error::Verification(
                            "E5: missing RET/TRAP".into(),
                        ))
                    }
                }
            } else {
                return Err(crate::error::Error::Verification("E5: empty function".into()));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// E5Executor
// ---------------------------------------------------------------------------

/// 128-bit SIMD register: 4 f32 lanes
#[derive(Debug, Clone, Copy)]
pub struct VReg(pub [f32; 4]);

impl Default for VReg {
    fn default() -> Self {
        VReg([0.0; 4])
    }
}

struct Frame {
    func_idx: usize,
    pc: usize,
    regs: Vec<i64>,
    vregs: Vec<VReg>,
    result_reg: Option<u32>,
    last_vreg: Option<u8>,
}

pub struct E5Executor {
    functions: Vec<E5FunctionDef>,
    frames: Vec<Frame>,
    memory: Vec<u8>,
    fuel: u64,
    start: Instant,
}

impl E5Executor {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            frames: Vec::new(),
            memory: vec![0u8; E5_MEMORY_SIZE],
            fuel: 100_000,
            start: Instant::now(),
        }
    }

    pub fn execute(&mut self, module: &E5Module) -> Result<ExecutionResult> {
        self.functions = module.functions.clone();
        self.frames.clear();
        self.memory = module.memory.clone();
        self.fuel = 100_000;
        self.start = Instant::now();

        if self.functions.is_empty() {
            return Ok(ExecutionResult::fail("E5: no functions".into(), self.provenance()));
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
                format!("E5: bad function index {func_idx}"),
                self.provenance(),
            ));
        }
        let func = &self.functions[func_idx];
        let regs = vec![0i64; func.register_count.max(4).max(16)];
        let vregs = vec![VReg::default(); 16];
        self.frames.push(Frame {
            func_idx,
            pc: 0,
            regs,
            vregs,
            result_reg,
            last_vreg: None,
        });
        let mut frame_idx = self.frames.len() - 1;

        loop {
            if self.fuel == 0 {
                self.frames.pop();
                return Ok(ExecutionResult::fail("E5: fuel exhausted".into(), self.provenance()));
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
                Instruction::VAdd { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = va.0[i] + vb.0[i];
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VMul { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = va.0[i] * vb.0[i];
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VSub { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = va.0[i] - vb.0[i];
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VDiv { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        if vb.0[i] == 0.0 {
                            self.frames.pop();
                            return Ok(ExecutionResult::fail(
                                "E5: SIMD div-by-zero".into(),
                                self.provenance(),
                            ));
                        }
                        r.0[i] = va.0[i] / vb.0[i];
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VSqrt { dst, a } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        if va.0[i] < 0.0 {
                            self.frames.pop();
                            return Ok(ExecutionResult::fail(
                                "E5: sqrt domain error".into(),
                                self.provenance(),
                            ));
                        }
                        r.0[i] = va.0[i].sqrt();
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VMin { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = va.0[i].min(vb.0[i]);
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VMax { dst, a, b } => {
                    let va = self.frames[frame_idx].vregs[*a as usize];
                    let vb = self.frames[frame_idx].vregs[*b as usize];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = va.0[i].max(vb.0[i]);
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VImm { dst, imm } => {
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = *imm;
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VSetImm { dst, imm } => {
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = *imm;
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VLoad { addr, dst } => {
                    let addr = *addr as usize;
                    if addr + 16 > E5_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E5: VLOAD OOB".into(), self.provenance()));
                    }
                    if addr % 16 != 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail(
                            "E5: VLOAD unaligned".into(),
                            self.provenance(),
                        ));
                    }
                    let mut r = VReg::default();
                    for i in 0..4 {
                        let bytes =
                            &self.memory[addr + i * 4..][..4];
                        r.0[i] = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VStore { addr, src } => {
                    let addr = *addr as usize;
                    if addr + 16 > E5_MEMORY_SIZE {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail("E5: VSTORE OOB".into(), self.provenance()));
                    }
                    if addr % 16 != 0 {
                        self.frames.pop();
                        return Ok(ExecutionResult::fail(
                            "E5: VSTORE unaligned".into(),
                            self.provenance(),
                        ));
                    }
                    let r = self.frames[frame_idx].vregs[*src as usize];
                    for i in 0..4 {
                        let bytes = r.0[i].to_le_bytes();
                        self.memory[addr + i * 4..addr + i * 4 + 4]
                            .copy_from_slice(&bytes);
                    }
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VMov { dst, src } => {
                    self.frames[frame_idx].vregs[*dst as usize] =
                        self.frames[frame_idx].vregs[*src as usize];
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VCpy { dst, src } => {
                    let val = self.frames[frame_idx].vregs[*src as usize].0[0];
                    let mut r = VReg::default();
                    for i in 0..4 {
                        r.0[i] = val;
                    }
                    self.frames[frame_idx].vregs[*dst as usize] = r;
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VZero { dst } => {
                    self.frames[frame_idx].vregs[*dst as usize] = VReg([0.0; 4]);
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VOne { dst } => {
                    self.frames[frame_idx].vregs[*dst as usize] = VReg([1.0; 4]);
                    self.frames[frame_idx].last_vreg = Some(*dst);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::VMemZero => {
                    self.memory.fill(0);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Ret => {
                    // Return the last modified vreg's lane 0
                    let result = if let Some(idx) = self.frames[frame_idx].last_vreg {
                        self.frames[frame_idx].vregs[idx as usize].0[0] as i64
                    } else {
                        self.frames[frame_idx].vregs[0].0[0] as i64
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
                    return Ok(ExecutionResult::fail("E5: explicit trap".into(), self.provenance()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bytecode builder
// ---------------------------------------------------------------------------

pub const E5_PAGE_COUNT: usize = 1;
pub const E5_PAGE_SIZE: usize = 4096;
pub const E5_MEMORY_SIZE: usize = E5_PAGE_COUNT * E5_PAGE_SIZE;

fn encode_instr(instr: &Instruction, out: &mut Vec<u8>) {
    match instr {
        Instruction::VAdd { dst, a, b } => {
            out.push(0xE0);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VMul { dst, a, b } => {
            out.push(0xE1);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VSub { dst, a, b } => {
            out.push(0xE2);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VDiv { dst, a, b } => {
            out.push(0xE3);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VSqrt { dst, a } => {
            out.push(0xE4);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
        }
        Instruction::VMin { dst, a, b } => {
            out.push(0xE5);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VMax { dst, a, b } => {
            out.push(0xE6);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*a as usize));
            out.extend(&encode_uleb(*b as usize));
        }
        Instruction::VImm { dst, imm } => {
            out.push(0xE7);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&imm.to_le_bytes());
        }
        Instruction::VSetImm { dst, imm } => {
            out.push(0xEB);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&imm.to_le_bytes());
        }
        Instruction::VLoad { addr, dst } => {
            out.push(0xE8);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::VStore { addr, src } => {
            out.push(0xE9);
            out.extend(&encode_uleb(*addr as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::VMov { dst, src } => {
            out.push(0xEA);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::VCpy { dst, src } => {
            out.push(0xEC);
            out.extend(&encode_uleb(*dst as usize));
            out.extend(&encode_uleb(*src as usize));
        }
        Instruction::VZero { dst } => {
            out.push(0xED);
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::VOne { dst } => {
            out.push(0xEE);
            out.extend(&encode_uleb(*dst as usize));
        }
        Instruction::VMemZero => {
            out.push(0xEF);
        }
        Instruction::Ret => {
            out.push(0xa6);
        }
        Instruction::Trap => {
            out.push(0x9F);
        }
    }
}

pub fn build_e5(instructions: &[Instruction]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(b"UNICO\x05");

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
        let module = E5Module::parse(bytes).expect("parse failed");
        module.verify().expect("verify failed");
        let mut exec = E5Executor::new();
        exec.execute(&module).expect("execute error")
    }

    #[test]
    fn test_e5_vadd() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 1.0 },
            Instruction::VImm { dst: 1, imm: 2.0 },
            Instruction::VAdd { dst: 2, a: 0, b: 1 }, // v2 = v0 + v1 = [3,3,3,3]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(3));
    }

    #[test]
    fn test_e5_vmul() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 2.0 },
            Instruction::VImm { dst: 1, imm: 3.0 },
            Instruction::VMul { dst: 2, a: 0, b: 1 }, // v2 = v0 * v1 = [6,6,6,6]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(6));
    }

    #[test]
    fn test_e5_vsub() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 10.0 },
            Instruction::VImm { dst: 1, imm: 4.0 },
            Instruction::VSub { dst: 2, a: 0, b: 1 }, // v2 = v0 - v1 = [6,6,6,6]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(6));
    }

    #[test]
    fn test_e5_vdiv() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 20.0 },
            Instruction::VImm { dst: 1, imm: 4.0 },
            Instruction::VDiv { dst: 2, a: 0, b: 1 }, // v2 = v0 / v1 = [5,5,5,5]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(5));
    }

    #[test]
    fn test_e5_vsqrt() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 16.0 },
            Instruction::VSqrt { dst: 1, a: 0 }, // v1 = sqrt(v0) = [4,4,4,4]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(4));
    }

    #[test]
    fn test_e5_vsqrt_neg() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: -1.0 },
            Instruction::VSqrt { dst: 1, a: 0 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("domain")));
    }

    #[test]
    fn test_e5_vmin_vmax() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 1.0 },
            Instruction::VImm { dst: 1, imm: 5.0 },
            Instruction::VMin { dst: 2, a: 0, b: 1 }, // [1,1,1,1]
            Instruction::VMax { dst: 3, a: 0, b: 1 }, // [5,5,5,5]
            Instruction::VAdd { dst: 4, a: 2, b: 3 }, // [6,6,6,6]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(6));
    }

    #[test]
    fn test_e5_vload_store() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 42.0 },
            Instruction::VStore { addr: 0, src: 0 }, // store v0 to addr 0
            Instruction::VZero { dst: 0 }, // clear v0
            Instruction::VLoad { addr: 0, dst: 0 }, // load from addr 0
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_e5_vmov() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 7.0 },
            Instruction::VMov { dst: 1, src: 0 }, // copy v0 → v1
            Instruction::VAdd { dst: 2, a: 0, b: 1 }, // [14,14,14,14]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(14));
    }

    #[test]
    fn test_e5_vzero_vone() {
        let bytes = build_e5(&[
            Instruction::VZero { dst: 0 },
            Instruction::VOne { dst: 1 },
            Instruction::VAdd { dst: 2, a: 0, b: 1 }, // [1,1,1,1]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e5_vcpy() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 3.0 },
            Instruction::VImm { dst: 1, imm: 99.0 },
            Instruction::VCpy { dst: 1, src: 0 }, // broadcast lane 0 of v0 → all lanes of v1
            Instruction::VAdd { dst: 2, a: 0, b: 1 }, // [6,6,6,6]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(6));
    }

    #[test]
    fn test_e5_vsetimm() {
        let bytes = build_e5(&[
            Instruction::VSetImm { dst: 0, imm: 8.0 },
            Instruction::VMov { dst: 1, src: 0 },
            Instruction::VAdd { dst: 2, a: 0, b: 1 }, // [16,16,16,16]
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(16));
    }

    #[test]
    fn test_e5_vdiv_by_zero() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 1.0 },
            Instruction::VImm { dst: 1, imm: 0.0 },
            Instruction::VDiv { dst: 2, a: 0, b: 1 },
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("div")));
    }

    #[test]
    fn test_e5_vmemzero() {
        let bytes = build_e5(&[
            Instruction::VImm { dst: 0, imm: 7.0 },
            Instruction::VStore { addr: 0, src: 0 }, // addr 0 is 16-byte aligned
            Instruction::VMemZero, // zero all memory
            Instruction::VLoad { addr: 0, dst: 0 }, // should be zeros
            Instruction::Ret,
        ]);
        let result = run(&bytes);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0));
    }
}
