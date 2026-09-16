//! E2 Executor
//! 
//! Linear-memory profile: adds LOAD.I64 and STORE.I64 to E1
//! - Memory: 4096 bytes, zero-initialized, module-global
//! - LOAD.I64: read 8 bytes little-endian
//! - STORE.I64: write 8 bytes little-endian
//! - Bounds: address ≤ 4088, alignment address % 8 == 0

use crate::error::{Error, Result};
use crate::leb128::{decode_uleb, decode_sleb};
use crate::types::{Profile, Provenance, ExecutionResult, I64};

/// E2 Instructions (E1 + memory ops)
#[derive(Debug, Clone)]
pub enum Instruction {
    // E0 inherited
    Trap,
    KImm { dst: u32, imm: I64 },
    Add { dst: u32, lhs: u32, rhs: u32 },
    Ret { result: u32 },
    // E1 inherited
    Cmp { pred: u32, dst: u32, lhs: u32, rhs: u32 },
    Br { target: u32 },
    BrIf { cond: u32, target: u32 },
    Call { callee: u32, argc: u32, args: Vec<u32>, result_reg: u32 },
    // E2 new
    Load { dst: u32, address: u32 },
    Store { address: u32, src: u32 },
}

/// E2 Module
#[derive(Debug, Clone)]
pub struct Module {
    pub profile: Profile,
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub param_count: u32,
    pub result_count: u32,
    pub register_count: u32,
    pub code_offset: u32,
    pub code_size: u32,
    pub instructions: Vec<Instruction>,
}

/// E2 Executor with call stack and linear memory
pub struct E2Executor {
    frames: Vec<Frame>,
    memory: Vec<u8>,
    fuel: u64,
    returning: bool,
}

#[derive(Debug, Clone)]
struct Frame {
    func_idx: u32,
    pc: usize,
    registers: Vec<I64>,
    result_dst: Option<u32>,
}

impl E2Executor {
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(8),
            memory: vec![0u8; 4096],
            fuel: 100_000,
            returning: false,
        }
    }
    
    pub fn execute(&mut self, module: &Module) -> Result<ExecutionResult> {
        let start = std::time::Instant::now();
        self.fuel = 100_000;
        self.frames.clear();
        self.memory = vec![0u8; 4096];
        self.returning = false;
        
        if module.functions.is_empty() {
            return Err(Error::Format("No functions".into()));
        }
        
        let entry = &module.functions[0];
        if entry.param_count != 0 {
            return Err(Error::Verification("Entry function must have 0 parameters".into()));
        }
        let regs = vec![0i64; entry.register_count as usize];
        self.frames.push(Frame { func_idx: 0, pc: 0, registers: regs, result_dst: None });
        
        loop {
            if self.fuel == 0 {
                return Ok(ExecutionResult::fail(
                    "E2T002: Fuel exhausted".into(),
                    self.provenance(start),
                ));
            }
            self.fuel -= 1;
            
            let depth = self.frames.len();
            if depth > 8 {
                return Err(Error::Verification("call stack overflow (>8)".into()));
            }
            
            let frame_idx = self.frames.len() - 1;
            let func_idx = self.frames[frame_idx].func_idx;
            let func = &module.functions[func_idx as usize];
            
            let pc = self.frames[frame_idx].pc;
            if pc >= func.instructions.len() {
                return Err(Error::Verification(format!("fell off end of f{}", func_idx)));
            }
            
            let instr = func.instructions[pc].clone();
            
            match instr {
                Instruction::KImm { dst, imm } => {
                    self.frames[frame_idx].registers[dst as usize] = imm;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Add { dst, lhs, rhs } => {
                    let a = self.frames[frame_idx].registers[lhs as usize];
                    let b = self.frames[frame_idx].registers[rhs as usize];
                    self.frames[frame_idx].registers[dst as usize] = a.wrapping_add(b);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Cmp { pred, dst, lhs, rhs } => {
                    let a = self.frames[frame_idx].registers[lhs as usize];
                    let b = self.frames[frame_idx].registers[rhs as usize];
                    let result: I64 = match pred {
                        0 => if a == b { 1 } else { 0 },
                        1 => if a < b { 1 } else { 0 },
                        _ => return Err(Error::Verification(format!("invalid CMP pred: {}", pred))),
                    };
                    self.frames[frame_idx].registers[dst as usize] = result;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Br { target } => {
                    self.frames[frame_idx].pc = target as usize;
                }
                Instruction::BrIf { cond, target } => {
                    let cond_val = self.frames[frame_idx].registers[cond as usize];
                    if cond_val != 0 {
                        self.frames[frame_idx].pc = target as usize;
                    } else {
                        self.frames[frame_idx].pc += 1;
                    }
                }
                Instruction::Call { callee, argc, args, result_reg } => {
                    if callee as usize >= module.functions.len() {
                        return Err(Error::Verification(format!("invalid callee f{}", callee)));
                    }
                    let callee_func = &module.functions[callee as usize];
                    if argc != callee_func.param_count {
                        return Err(Error::Verification(format!(
                            "argc {} != param_count {}", argc, callee_func.param_count
                        )));
                    }
                    let mut new_regs = vec![0i64; callee_func.register_count as usize];
                    for (i, &arg_reg) in args.iter().enumerate() {
                        new_regs[i] = self.frames[frame_idx].registers[arg_reg as usize];
                    }
                    self.frames.push(Frame {
                        func_idx: callee,
                        pc: 0,
                        registers: new_regs,
                        result_dst: Some(result_reg),
                    });
                }
                Instruction::Ret { result } => {
                    let ret_value = self.frames[frame_idx].registers[result as usize];
                    let result_dst = self.frames[frame_idx].result_dst;
                    self.frames.pop();
                    
                    if self.frames.is_empty() {
                        return Ok(ExecutionResult::pass(ret_value, self.provenance(start)));
                    }
                    
                    let caller_idx = self.frames.len() - 1;
                    if let Some(dst) = result_dst {
                        self.frames[caller_idx].registers[dst as usize] = ret_value;
                    }
                    self.frames[caller_idx].pc += 1;
                }
                Instruction::Load { dst, address } => {
                    let addr = self.frames[frame_idx].registers[address as usize] as u64;
                    
                    // Bounds check: addr > 4088
                    if addr > 4088 {
                        return Ok(ExecutionResult::fail(
                            "E2T003: Memory OOB".into(),
                            self.provenance(start),
                        ));
                    }
                    // Alignment check: addr % 8 != 0
                    if addr % 8 != 0 {
                        return Ok(ExecutionResult::fail(
                            "E2T004: Memory alignment error".into(),
                            self.provenance(start),
                        ));
                    }
                    
                    // Read 8 bytes little-endian
                    let addr_usize = addr as usize;
                    let value = i64::from_le_bytes([
                        self.memory[addr_usize],
                        self.memory[addr_usize + 1],
                        self.memory[addr_usize + 2],
                        self.memory[addr_usize + 3],
                        self.memory[addr_usize + 4],
                        self.memory[addr_usize + 5],
                        self.memory[addr_usize + 6],
                        self.memory[addr_usize + 7],
                    ]);
                    self.frames[frame_idx].registers[dst as usize] = value;
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Store { address, src } => {
                    let addr = self.frames[frame_idx].registers[address as usize] as u64;
                    let value = self.frames[frame_idx].registers[src as usize];
                    
                    // Bounds check
                    if addr > 4088 {
                        return Ok(ExecutionResult::fail(
                            "E2T003: Memory OOB".into(),
                            self.provenance(start),
                        ));
                    }
                    // Alignment check
                    if addr % 8 != 0 {
                        return Ok(ExecutionResult::fail(
                            "E2T004: Memory alignment error".into(),
                            self.provenance(start),
                        ));
                    }
                    
                    // Write 8 bytes little-endian
                    let bytes = value.to_le_bytes();
                    let addr_usize = addr as usize;
                    self.memory[addr_usize..addr_usize + 8].copy_from_slice(&bytes);
                    self.frames[frame_idx].pc += 1;
                }
                Instruction::Trap => {
                    return Ok(ExecutionResult::fail(
                        "E2T001: Explicit TRAP".into(),
                        self.provenance(start),
                    ));
                }
            }
        }
    }
    
    fn provenance(&self, start: std::time::Instant) -> Provenance {
        Provenance {
            instructions: 100_000 - self.fuel,
            fuel_remaining: self.fuel,
            host_calls: 0,
            duration_us: start.elapsed().as_micros() as u64,
            deterministic: true,
        }
    }
}

impl Default for E2Executor {
    fn default() -> Self { Self::new() }
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 6 || &bytes[0..6] != b"UNICO\xe2" {
            return Err(Error::Format("Invalid E2 magic".into()));
        }
        
        let mut pos = 6;
        
        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(Error::Format("Missing FUNC section".into()));
        }
        pos += 1;
        let (func_section_len, n) = decode_uleb(&bytes[pos..])?; pos += n;
        let func_section_len = func_section_len as usize;
        
        let func_section_end = pos + func_section_len;
        let (func_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
        let func_count = func_count as u32;
        
        let mut functions = Vec::new();
        
        for _ in 0..func_count {
            let (param_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (result_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (register_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (code_offset, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (code_size, n) = decode_uleb(&bytes[pos..])?; pos += n;
            
            functions.push(Function {
                param_count: param_count as u32,
                result_count: result_count as u32,
                register_count: register_count as u32,
                code_offset: code_offset as u32,
                code_size: code_size as u32,
                instructions: Vec::new(),
            });
        }
        
        if pos != func_section_end {
            return Err(Error::Format("FUNC section size mismatch".into()));
        }
        
        if pos >= bytes.len() || bytes[pos] != 0x03 {
            return Err(Error::Format("Missing CODE section".into()));
        }
        pos += 1;
        let (code_section_len, n) = decode_uleb(&bytes[pos..])?; pos += n;
        let code_section_len = code_section_len as usize;
        
        let code_start = pos;
        let code_end = pos + code_section_len;
        
        for (i, func) in functions.iter_mut().enumerate() {
            let start = code_start + func.code_offset as usize;
            let end = start + func.code_size as usize;
            if end > code_end {
                return Err(Error::Format(format!("Function {} code out of bounds", i)));
            }
            func.instructions = decode_instructions(&bytes[start..end])?;
        }
        
        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(Error::Format("Missing END section".into()));
        }
        
        Ok(Self { profile: Profile::E2, functions })
    }
    
    pub fn verify(&self) -> Result<()> {
        if self.functions.is_empty() {
            return Err(Error::Verification("No functions".into()));
        }
        let entry = &self.functions[0];
        if entry.param_count != 0 {
            return Err(Error::Verification("Entry must have 0 params".into()));
        }
        for (i, func) in self.functions.iter().enumerate() {
            if func.result_count != 1 {
                return Err(Error::Verification(format!("f{} must have exactly 1 result", i)));
            }
            if func.register_count < func.param_count {
                return Err(Error::Verification(format!("f{} registers < params", i)));
            }
            if let Some(last) = func.instructions.last() {
                match last {
                    Instruction::Ret { .. } | Instruction::Trap => {},
                    _ => return Err(Error::Verification(format!("f{} must end with RET or TRAP", i))),
                }
            } else {
                return Err(Error::Verification(format!("f{} empty body", i)));
            }
        }
        Ok(())
    }
}

fn decode_instructions(bytes: &[u8]) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut pos = 0;
    
    while pos < bytes.len() {
        let opcode = bytes[pos];
        pos += 1;
        match opcode {
            0x00 => instructions.push(Instruction::Trap),
            0x0b => {
                let (dst, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (imm, n) = decode_sleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::KImm { dst: dst as u32, imm });
            }
            0x13 => {
                let (dst, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (lhs, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (rhs, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Add { dst: dst as u32, lhs: lhs as u32, rhs: rhs as u32 });
            }
            0x8c => {
                let (pred, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (dst, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (lhs, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (rhs, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Cmp { pred: pred as u32, dst: dst as u32, lhs: lhs as u32, rhs: rhs as u32 });
            }
            0x8d => {
                let (target, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Br { target: target as u32 });
            }
            0x8e => {
                let (cond, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (target, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::BrIf { cond: cond as u32, target: target as u32 });
            }
            0x8f => {
                let (callee, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (argc, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let mut args = Vec::with_capacity(argc as usize);
                for _ in 0..argc as usize {
                    let (arg, n) = decode_uleb(&bytes[pos..])?; pos += n;
                    args.push(arg as u32);
                }
                // result_count (ULEB, must be 1) — read and advance
                let (_, n) = decode_uleb(&bytes[pos..])?; pos += n;
                // result register (ULEB)
                let (result_reg, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Call { callee: callee as u32, argc: argc as u32, args, result_reg: result_reg as u32 });
            }
            0xa6 => {
                // result_count (ULEB, must be 1) — read and advance
                let (_, n) = decode_uleb(&bytes[pos..])?; pos += n;
                // result register (ULEB)
                let (result, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Ret { result: result as u32 });
            }
            0x91 => {
                let (dst, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (address, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Load { dst: dst as u32, address: address as u32 });
            }
            0x92 => {
                let (address, n) = decode_uleb(&bytes[pos..])?; pos += n;
                let (src, n) = decode_uleb(&bytes[pos..])?; pos += n;
                instructions.push(Instruction::Store { address: address as u32, src: src as u32 });
            }
            _ => return Err(Error::Format(format!("Unknown E2 opcode: 0x{:02x}", opcode))),
        }
    }
    
    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leb128::encode_uleb;
    use crate::types::Status;

    fn build_e2(functions: Vec<(Vec<u8>, u32, u32)>) -> Vec<u8> {
        let mut func_payload = encode_uleb(functions.len());
        let mut code_sections = Vec::new();
        let mut offset = 0u32;
        
        for (code, param_count, register_count) in &functions {
            func_payload.extend(encode_uleb(*param_count as usize));
            func_payload.extend(encode_uleb(1)); // result_count = 1
            func_payload.extend(encode_uleb(*register_count as usize));
            func_payload.extend(encode_uleb(offset as usize));
            func_payload.extend(encode_uleb(code.len()));
            code_sections.push(code.clone());
            offset += code.len() as u32;
        }
        
        let combined_code: Vec<u8> = code_sections.into_iter().flatten().collect();
        
        let mut module = Vec::new();
        module.extend(b"UNICO\xe2");
        module.push(0x02);
        module.extend(encode_uleb(func_payload.len()));
        module.extend(func_payload);
        module.push(0x03);
        module.extend(encode_uleb(combined_code.len()));
        module.extend(combined_code);
        module.push(0x00);
        module
    }
    
    #[test]
    fn test_store_load() {
        // Store 42 at addr 0, load it back, return 42
        // K r0=0, K r1=42, STORE [r0]=r1, LOAD r2=[r0], RET r2
        // K.I64: opcode(1) + dst ULEB(1) + imm SLEB(1) = 3 bytes each
        // STORE: opcode(1) + addr ULEB(1) + src ULEB(1) = 3 bytes
        // LOAD: opcode(1) + dst ULEB(1) + addr ULEB(1) = 3 bytes
        // RET: opcode(1) + result_count(1) + result(1) = 3 bytes
        // Total: 3+3+3+3+3 = 15 bytes
        let code = vec![
            0x0b, 0x00, 0x00,       // K.I64 r0=0 (address)           [0,1,2]
            0x0b, 0x01, 0x2a,       // K.I64 r1=42                     [3,4,5]
            0x92, 0x00, 0x01,       // STORE addr=r0 src=r1            [6,7,8]
            0x91, 0x02, 0x00,       // LOAD dst=r2 address=r0           [9,10,11]
            0xa6, 0x01, 0x02,       // RET r2                           [12,13,14]
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }
    
    #[test]
    fn test_memory_oob() {
        // STORE at address 32768 (> 4088) should trap
        // 32768 = 2^15, 3-byte SLEB: 32768/128=256 rem 0, 256/128=2 rem 0, 2/128=0 rem 2
        // chunks=[0,0,2], bytes=[0x80,0x80,0x82] (all have bit 7=1 → sleb_len=3)
        // K.I64 r0=32768: opcode(1) + dst(1) + SLEB(3) = 5 bytes
        // K.I64 r1=1: opcode(1) + dst(1) + SLEB(1) = 3 bytes
        // STORE: 3 bytes, RET: 3 bytes. Total: 5+3+3+3 = 14 bytes
        let code = vec![
            0x0b, 0x00, 0x80, 0x80, 0x82, 0x0b, // K.I64 r0=32768 (5 bytes) [0-6]
            0x0b, 0x01, 0x01,       // K.I64 r1=1                        [7,8,9]
            0x92, 0x00, 0x01,       // STORE addr=r0 src=r1              [10,11,12]
            0xa6, 0x01, 0x01,       // RET r1                            [13,14,15]
        ];
        let module_bytes = build_e2(vec![(code, 0, 2)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("OOB")));
    }
    
    #[test]
    fn test_memory_unaligned() {
        // STORE at address 1 (misaligned: 1 % 8 != 0)
        // K.I64: 3+3=6 bytes, STORE: 3 bytes, RET: 3 bytes = 12 bytes
        let code = vec![
            0x0b, 0x00, 0x01,       // K.I64 r0=1 (misaligned)
            0x0b, 0x01, 0x42,       // K.I64 r1=66
            0x92, 0x00, 0x01,       // STORE addr=r0 src=r1
            0xa6, 0x01, 0x01,       // RET r1
        ];
        let module_bytes = build_e2(vec![(code, 0, 2)]);
        let module = Module::parse(&module_bytes).unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("alignment")));
    }

    // ── Add ─────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_add() {
        // K r0=5, K r1=3, Add r2=r0+r1, RET r2 → 8
        let code = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x03,       // K.I64 r1=3
            0x13, 0x02, 0x00, 0x01, // Add r2=r0+r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(8));
    }

    #[test]
    fn test_e2_add_overflow() {
        // K r0=I64::MAX, K r1=1, Add r2=r0+r1 (wrapping) → I64::MIN
        // I64::MAX SLEB: 0xff*9 + 0x00 (10 bytes)
        let code = vec![
            0x0b, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, // K.I64 r0=I64::MAX
            0x0b, 0x01, 0x01,       // K.I64 r1=1
            0x13, 0x02, 0x00, 0x01, // Add r2=r0+r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(i64::MIN));
    }

    // ── Cmp ─────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_cmp_eq() {
        // K r0=5, K r1=5, Cmp pred=0 (eq) r2=r0,r1, RET r2 → 1
        let code = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x05,       // K.I64 r1=5
            0x8c, 0x00, 0x02, 0x00, 0x01, // Cmp pred=0 r2=r0,r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e2_cmp_lt() {
        // K r0=3, K r1=5, Cmp pred=1 (lt) r2=r0,r1, RET r2 → 1
        let code = vec![
            0x0b, 0x00, 0x03,       // K.I64 r0=3
            0x0b, 0x01, 0x05,       // K.I64 r1=5
            0x8c, 0x01, 0x02, 0x00, 0x01, // Cmp pred=1 r2=r0,r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e2_cmp_invalid_pred() {
        // Cmp with pred=2 → execute error (not a verify error)
        let code = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x03,       // K.I64 r1=3
            0x8c, 0x02, 0x02, 0x00, 0x01, // Cmp pred=2 (invalid)
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e2(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module);

        assert!(result.is_err());
        assert!(matches!(result, Err(e) if e.to_string().contains("CMP pred")));
    }

    // ── Br ──────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_br() {
        // K r0=42, Br 2 → jumps to RET at index 2, RET r0 → 42
        let code = vec![
            0x0b, 0x00, 0x2a,       // K.I64 r0=42
            0x8d, 0x02,               // Br target=2
            0xa6, 0x01, 0x00,       // RET r0
        ];
        let module_bytes = build_e2(vec![(code, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    // ── BrIf ────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_brif_taken() {
        // K r0=1, BrIf r0=1 target=2 (taken → skip K r1=100), RET r0 → 1
        let code = vec![
            0x0b, 0x00, 0x01,       // K.I64 r0=1
            0x8e, 0x00, 0x02,       // BrIf r0 target=2
            0x0b, 0x01, 0x64,       // K.I64 r1=100 (skipped)
            0xa6, 0x01, 0x00,       // RET r0
        ];
        let module_bytes = build_e2(vec![(code, 0, 2)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }

    #[test]
    fn test_e2_brif_not_taken() {
        // K r0=0, BrIf r0=0 target=2 (not taken), K r1=100, RET r1 → 100
        // 100 SLEB = 0xE4, 0x00 (2 bytes, since 100 has bit 6 set in 1-byte form)
        let code = vec![
            0x0b, 0x00, 0x00,       // K.I64 r0=0
            0x8e, 0x00, 0x02,       // BrIf r0 target=2 (not taken)
            0x0b, 0x01, 0xe4, 0x00, // K.I64 r1=100 (2-byte SLEB)
            0xa6, 0x01, 0x01,       // RET r1
        ];
        let module_bytes = build_e2(vec![(code, 0, 2)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(100));
    }

    // ── Call ────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_call() {
        // f0: K r0=7, Call f1 args=[r0] result_reg=1, RET r1 → 14 (7+7)
        // f1: Add r0=r0+r0, RET r0
        let f1_code = vec![
            0x13, 0x00, 0x00, 0x00, // Add r0=r0+r0 (arg passed in r0)
            0xa6, 0x01, 0x00,       // RET r0
        ];
        let f0_code = vec![
            0x0b, 0x00, 0x07,       // K.I64 r0=7
            0x8f, 0x01, 0x01, 0x00, 0x01, 0x01, // Call f1 argc=1 args=[r0] result_reg=1
            0xa6, 0x01, 0x01,       // RET r1
        ];
        let module_bytes = build_e2(vec![(f0_code, 0, 2), (f1_code, 1, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(14));
    }

    #[test]
    fn test_e2_call_invalid_callee() {
        // Call callee=99 (non-existent) → execution error
        let f0_code = vec![
            0x8f, 0x63, 0x01, 0x00, 0x01, 0x01, // Call callee=99 argc=1 args=[r0] result_reg=1
            0xa6, 0x01, 0x01,       // RET r1
        ];
        let module_bytes = build_e2(vec![(f0_code, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module);

        assert!(result.is_err());
        assert!(matches!(result, Err(e) if e.to_string().contains("invalid callee")));
    }

    // ── Trap ────────────────────────────────────────────────────────────

    #[test]
    fn test_e2_trap() {
        let code = vec![0x00]; // Trap
        let module_bytes = build_e2(vec![(code, 0, 0)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();

        let mut exec = E2Executor::new();
        let result = exec.execute(&module).unwrap();

        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("TRAP")));
    }

    // ── Verify errors ───────────────────────────────────────────────────

    #[test]
    fn test_e2_verify_entry_params() {
        let code = vec![0xa6, 0x01, 0x00]; // RET r0
        let module_bytes = build_e2(vec![(code, 1, 1)]); // param_count=1 (entry must have 0)
        let module = Module::parse(&module_bytes).unwrap();

        assert!(module.verify().is_err());
    }

    #[test]
    fn test_e2_verify_result_count() {
        // Manually build module with result_count=2 (invalid)
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\xe2");
        bytes.push(0x02); // FUNC section marker
        let mut func_payload = encode_uleb(1); // 1 function
        func_payload.extend(encode_uleb(0)); // param_count=0
        func_payload.extend(encode_uleb(2)); // result_count=2 (invalid)
        func_payload.extend(encode_uleb(1)); // register_count=1
        func_payload.extend(encode_uleb(0)); // code_offset=0
        func_payload.extend(encode_uleb(3)); // code_size=3
        let code = vec![0xa6, 0x01, 0x00]; // RET r0
        func_payload.extend(code.clone());
        bytes.extend(encode_uleb(func_payload.len()));
        bytes.extend(func_payload);
        bytes.push(0x03); // CODE section
        bytes.extend(encode_uleb(3)); // code_section_len=3
        bytes.extend(code);
        bytes.push(0x00); // END
        let module = Module::parse(&bytes);
        assert!(module.is_err());
    }

    #[test]
    fn test_e2_verify_no_ret() {
        // Function body without RET or TRAP at end
        let code = vec![0x0b, 0x00, 0x05]; // K.I64 r0=5 (no RET)
        let module_bytes = build_e2(vec![(code, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        assert!(module.verify().is_err());
    }

    #[test]
    fn test_e2_verify_empty_body() {
        // Function with no instructions
        let code = vec![];
        let module_bytes = build_e2(vec![(code, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        assert!(module.verify().is_err());
    }

    // ── Parse errors ────────────────────────────────────────────────────

    #[test]
    fn test_e2_parse_bad_magic() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(Module::parse(&bytes).is_err());
    }

    #[test]
    fn test_e2_parse_missing_func() {
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\xe2");
        // No FUNC section marker (0x02)
        bytes.push(0x00); // Just END marker without proper structure
        assert!(Module::parse(&bytes).is_err());
    }

    #[test]
    fn test_e2_parse_missing_code() {
        // Has FUNC but no CODE section
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\xe2");
        bytes.push(0x02); // FUNC section marker
        bytes.extend(encode_uleb(0)); // func_section_len=0
        bytes.push(0x03); // CODE section marker
        bytes.extend(encode_uleb(0)); // code_section_len=0
        // Missing END marker
        assert!(Module::parse(&bytes).is_err());
    }

    #[test]
    fn test_e2_parse_missing_end() {
        let code = vec![0xa6, 0x01, 0x00];
        let module_bytes = build_e2(vec![(code, 0, 1)]);
        let mut truncated = module_bytes.clone();
        truncated.pop(); // Remove END byte
        assert!(Module::parse(&truncated).is_err());
    }

    #[test]
    fn test_e2_parse_truncated_uleb() {
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\xe2");
        bytes.push(0x02); // FUNC section marker
        bytes.push(0x01); // func_section_len=1
        bytes.push(0x01); // only 1 byte of what should be more
        assert!(Module::parse(&bytes).is_err());
    }

    #[test]
    fn test_e2_parse_unknown_opcode() {
        // Unknown opcode 0xFF in code section → parse error in decode_instructions
        let code = vec![0xff];
        let module_bytes = build_e2(vec![(code, 0, 0)]);
        assert!(Module::parse(&module_bytes).is_err());
    }

    #[test]
    fn test_e2_parse_code_out_of_bounds() {
        // Function code_offset points beyond code section
        let mut bytes = Vec::new();
        bytes.extend(b"UNICO\xe2");
        bytes.push(0x02);
        let mut func_payload = encode_uleb(1); // 1 function
        func_payload.extend(encode_uleb(0)); // param_count=0
        func_payload.extend(encode_uleb(1)); // result_count=1
        func_payload.extend(encode_uleb(1)); // register_count=1
        func_payload.extend(encode_uleb(255)); // code_offset=255 (way out of bounds)
        func_payload.extend(encode_uleb(1)); // code_size=1
        let code = vec![0x0b, 0x00, 0x00]; // actual code (3 bytes)
        func_payload.extend(code.clone());
        bytes.extend(encode_uleb(func_payload.len()));
        bytes.extend(func_payload);
        bytes.push(0x03);
        bytes.extend(encode_uleb(3)); // code_section_len=3
        bytes.extend(code);
        bytes.push(0x00); // END
        let module = Module::parse(&bytes);
        assert!(module.is_err());
    }
}
