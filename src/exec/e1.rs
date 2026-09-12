//! E1 Executor
//! 
//! Control-flow profile: adds CMP, BR, BR.IF, CALL
//! - CMP.I64: pred(0=EQ,1=LT.S) dst lhs rhs → BOOL
//! - BR: unconditional jump to target
//! - BR.IF: conditional jump if cond=true
//! - CALL: direct local call (depth ≤8)
//! - RET: return from function

use crate::error::{Error, Result};
use crate::types::{Profile, Provenance, ExecutionResult, I64};

/// E1 Instructions
#[derive(Debug, Clone)]
pub enum Instruction {
    // E0 inherited
    Trap,
    KImm { dst: u32, imm: I64 },
    Add { dst: u32, lhs: u32, rhs: u32 },
    Ret { result: u32 },
    // E1 new
    Cmp { pred: u32, dst: u32, lhs: u32, rhs: u32 },
    Br { target: u32 },
    BrIf { cond: u32, target: u32 },
    Call { callee: u32, argc: u32, args: Vec<u32>, result_reg: u32 },
}

/// E1 Module
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

/// E1 Executor with call stack
pub struct E1Executor {
    frames: Vec<Frame>,
    fuel: u64,
}

#[derive(Debug, Clone)]
struct Frame {
    func_idx: u32,
    pc: usize,
    registers: Vec<I64>,
    /// Register in parent frame that receives the return value
    result_dst: Option<u32>,
}

impl E1Executor {
    pub fn new() -> Self {
        Self { frames: Vec::with_capacity(8), fuel: 100_000 }
    }
    
    /// Execute E1 module
    pub fn execute(&mut self, module: &Module) -> Result<ExecutionResult> {
        let start = std::time::Instant::now();
        self.fuel = 100_000;
        self.frames.clear();
        
        if module.functions.is_empty() {
            return Err(Error::Format("No functions".into()));
        }
        
        // Initialize entry frame (f0)
        let entry = &module.functions[0];
        if entry.param_count != 0 {
            return Err(Error::Verification("Entry function must have 0 parameters".into()));
        }
        let regs = vec![0i64; entry.register_count as usize];
        self.frames.push(Frame { func_idx: 0, pc: 0, registers: regs, result_dst: None });
        
        loop {
            if self.fuel == 0 {
                return Ok(ExecutionResult::fail(
                    "E1T002: Fuel exhausted".into(),
                    self.provenance(start),
                ));
            }
            self.fuel -= 1;
            
            // Check depth BEFORE borrowing frames mutably
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
            
            // Clone the instruction to avoid borrow conflicts
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
                        0 => if a == b { 1 } else { 0 }, // EQ
                        1 => if a < b { 1 } else { 0 }, // LT.S (signed)
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
                    
                    // Copy args to new frame registers (params first)
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
                        // Entry frame returning - this is the final result
                        return Ok(ExecutionResult::pass(ret_value, self.provenance(start)));
                    }
                    
                    // Write return value to caller's result register
                    let caller_idx = self.frames.len() - 1;
                    if let Some(dst) = result_dst {
                        self.frames[caller_idx].registers[dst as usize] = ret_value;
                    }
                    
                    // Advance caller's PC past the CALL instruction
                    self.frames[caller_idx].pc += 1;
                }
                Instruction::Trap => {
                    return Ok(ExecutionResult::fail(
                        "E1T001: Explicit TRAP".into(),
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

impl Default for E1Executor {
    fn default() -> Self { Self::new() }
}

impl Module {
    /// Parse E1 module from bytes
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 6 || &bytes[0..6] != b"UNICO\xe1" {
            return Err(Error::Format("Invalid E1 magic".into()));
        }
        
        let mut pos = 6;
        
        // Parse FUNC section
        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(Error::Format("Missing FUNC section".into()));
        }
        pos += 1;
        let func_section_len = {
            let len = uleb_len(bytes[pos]);
            let v = read_uleb(&bytes[pos..]) as usize; pos += len; v
        };
        
        let func_section_end = pos + func_section_len;
        let func_count = {
            let len = uleb_len(bytes[pos]);
            let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
        };
        
        let mut functions = Vec::new();
        let mut code_offsets = Vec::new();
        
        for _ in 0..func_count {
            let param_count = {
                let len = uleb_len(bytes[pos]);
                let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
            };
            let result_count = {
                let len = uleb_len(bytes[pos]);
                let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
            };
            let register_count = {
                let len = uleb_len(bytes[pos]);
                let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
            };
            let code_offset = {
                let len = uleb_len(bytes[pos]);
                let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
            };
            let code_size = {
                let len = uleb_len(bytes[pos]);
                let v = read_uleb(&bytes[pos..]) as u32; pos += len; v
            };
            
            code_offsets.push(code_offset);
            functions.push(Function {
                param_count, result_count, register_count, code_offset, code_size,
                instructions: Vec::new(),
            });
        }
        
        if pos != func_section_end {
            return Err(Error::Format("FUNC section size mismatch".into()));
        }
        
        // Parse CODE section
        if pos >= bytes.len() || bytes[pos] != 0x03 {
            return Err(Error::Format("Missing CODE section".into()));
        }
        pos += 1;
        let code_section_len = {
            let len = uleb_len(bytes[pos]);
            let v = read_uleb(&bytes[pos..]) as usize; pos += len; v
        };
        
        let code_start = pos;
        let code_end = pos + code_section_len;
        
        // Decode each function's code
        for (i, func) in functions.iter_mut().enumerate() {
            let start = code_start + func.code_offset as usize;
            let end = start + func.code_size as usize;
            if end > code_end {
                return Err(Error::Format(format!("Function {} code out of bounds", i)));
            }
            func.instructions = decode_instructions(&bytes[start..end], func.register_count)?;
        }
        
        // Check END
        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(Error::Format("Missing END section".into()));
        }
        
        Ok(Self { profile: Profile::E1, functions })
    }
    
    /// Verify module statically
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

fn decode_instructions(bytes: &[u8], _register_count: u32) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut pos = 0;
    
    while pos < bytes.len() {
        let opcode = bytes[pos];
        pos += 1;
        
        match opcode {
            0x00 => instructions.push(Instruction::Trap),
            0x0b => {
                let dst_len = uleb_len(bytes[pos]);
                let dst = read_uleb(&bytes[pos..]) as u32; pos += dst_len;
                let imm_len = sleb_len(&bytes[pos..]);
                let imm = read_sleb(&bytes[pos..]) as i64; pos += imm_len;
                instructions.push(Instruction::KImm { dst, imm });
            }
            0x13 => {
                let dst_len = uleb_len(bytes[pos]);
                let dst = read_uleb(&bytes[pos..]) as u32; pos += dst_len;
                let lhs_len = uleb_len(bytes[pos]);
                let lhs = read_uleb(&bytes[pos..]) as u32; pos += lhs_len;
                let rhs_len = uleb_len(bytes[pos]);
                let rhs = read_uleb(&bytes[pos..]) as u32; pos += rhs_len;
                instructions.push(Instruction::Add { dst, lhs, rhs });
            }
            0x8c => {
                let pred_len = uleb_len(bytes[pos]);
                let pred = read_uleb(&bytes[pos..]) as u32; pos += pred_len;
                let dst_len = uleb_len(bytes[pos]);
                let dst = read_uleb(&bytes[pos..]) as u32; pos += dst_len;
                let lhs_len = uleb_len(bytes[pos]);
                let lhs = read_uleb(&bytes[pos..]) as u32; pos += lhs_len;
                let rhs_len = uleb_len(bytes[pos]);
                let rhs = read_uleb(&bytes[pos..]) as u32; pos += rhs_len;
                instructions.push(Instruction::Cmp { pred, dst, lhs, rhs });
            }
            0x8d => {
                let target_len = uleb_len(bytes[pos]);
                let target = read_uleb(&bytes[pos..]) as u32; pos += target_len;
                instructions.push(Instruction::Br { target });
            }
            0x8e => {
                let cond_len = uleb_len(bytes[pos]);
                let cond = read_uleb(&bytes[pos..]) as u32; pos += cond_len;
                let target_len = uleb_len(bytes[pos]);
                let target = read_uleb(&bytes[pos..]) as u32; pos += target_len;
                instructions.push(Instruction::BrIf { cond, target });
            }
            0x8f => {
                let callee_len = uleb_len(bytes[pos]);
                let callee = read_uleb(&bytes[pos..]) as u32; pos += callee_len;
                let argc_len = uleb_len(bytes[pos]);
                let argc = read_uleb(&bytes[pos..]) as u32; pos += argc_len;
                let mut args = Vec::with_capacity(argc as usize);
                for _ in 0..argc {
                    let arg_len = uleb_len(bytes[pos]);
                    let arg = read_uleb(&bytes[pos..]) as u32; pos += arg_len;
                    args.push(arg);
                }
                // result_count (ULEB, must be 1) — read and advance
                let _ = read_uleb(&bytes[pos..]); pos += uleb_len(bytes[pos]);
                // result register (ULEB)
                let result_len = uleb_len(bytes[pos]);
                let result_reg = read_uleb(&bytes[pos..]) as u32; pos += result_len;
                instructions.push(Instruction::Call { callee, argc, args, result_reg });
            }
            0xa6 => {
                // result_count (ULEB, must be 1) — read and advance
                let _ = read_uleb(&bytes[pos..]); pos += uleb_len(bytes[pos]);
                // result register (ULEB)
                let result_len = uleb_len(bytes[pos]);
                let result = read_uleb(&bytes[pos..]) as u32; pos += result_len;
                instructions.push(Instruction::Ret { result });
            }
            _ => return Err(Error::Format(format!("Unknown E1 opcode: 0x{:02x}", opcode))),
        }
    }
    
    Ok(instructions)
}

fn read_uleb(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 8 { break; }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 { break; }
        shift += 7;
    }
    result
}

fn read_sleb(bytes: &[u8]) -> i64 {
    let mut result = 0i64;
    let mut shift = 0;
    for i in 0..8 {
        if i >= bytes.len() { break; }
        let b = bytes[i] as i64;
        result |= (b & 0x7f) << shift;
        if b & 0x80 == 0 { break; } // Bit 7 = 0 means last byte
        shift += 7;
    }
    // Sign extend: check if highest received byte has sign bit set
    if shift > 0 && (result >> (shift - 1)) & 1 != 0 {
        result |= -(1i64 << shift);
    }
    result
}

fn uleb_len(first: u8) -> usize {
    let mut len = 1;
    let mut b = first;
    while b & 0x80 != 0 && len < 10 {
        len += 1;
        b >>= 7;
    }
    len
}

fn sleb_len(bytes: &[u8]) -> usize {
    // Count SLEB128 total bytes: count bytes where bit 7 = 1, then add 1 for final byte.
    let mut len = 0;
    for &byte in bytes.iter() {
        if byte & 0x80 == 0 { break; }
        len += 1;
        if len >= 10 { break; }
    }
    len + 1 // Add 1 for the final byte (bit 7 = 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Status;
    
    fn uleb(v: usize) -> u8 {
        if v < 128 { v as u8 } else { (v & 0x7f) as u8 | 0x80 }
    }
    
    fn build_e1(functions: Vec<(Vec<u8>, u32, u32)>) -> Vec<u8> {
        // functions: Vec<(code, param_count, register_count)>
        // Returns: full E1 module bytes
        let func_count = functions.len() as u32;
        
        // Build FUNC payload
        let mut func_payload = vec![uleb(func_count as usize) as u8];
        let mut code_sections = Vec::new();
        let mut offset = 0u32;
        
        for (code, param_count, register_count) in &functions {
            func_payload.push(uleb(*param_count as usize) as u8);
            func_payload.push(1u8); // result_count=1
            func_payload.push(uleb(*register_count as usize) as u8);
            func_payload.push(uleb(offset as usize) as u8);
            func_payload.push(uleb(code.len()) as u8);
            code_sections.push(code.clone());
            offset += code.len() as u32;
        }
        
        // Combine code sections
        let combined_code: Vec<u8> = code_sections.into_iter().flatten().collect();
        
        vec![
            b"UNICO".to_vec(),
            vec![0xe1],
            vec![0x02], // FUNC tag
            vec![uleb(func_payload.len()) as u8],
            func_payload,
            vec![0x03], // CODE tag
            vec![uleb(combined_code.len()) as u8],
            combined_code,
            vec![0x00], // END
        ].concat()
    }
    
    #[test]
    fn test_cmp_eq() {
        // f0: K r0=10, K r1=10, CMP EQ r2 r0 r1, RET r2
        // Expected: r2=1 (10 == 10)
        let code = vec![
            0x0b, 0x00, 0x0a,       // K.I64 r0=10
            0x0b, 0x01, 0x0a,       // K.I64 r1=10
            0x8c, 0x00, 0x02, 0x00, 0x01, // CMP.I64 pred=0(EQ) dst=r2 lhs=r0 rhs=r1
            0xa6, 0x01, 0x02,       // RET r2 (result_count=1, result=2)
        ];
        let module_bytes = build_e1(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }
    
    #[test]
    fn test_cmp_lt() {
        // f0: K r0=5, K r1=10, CMP LT.S r2 r0 r1, RET r2
        // Expected: r2=1 (5 < 10)
        let code = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x0a,       // K.I64 r1=10
            0x8c, 0x01, 0x02, 0x00, 0x01, // CMP.I64 pred=1(LT.S) dst=r2 lhs=r0 rhs=r1
            0xa6, 0x01, 0x02,       // RET r2 (result_count=1, result=2)
        ];
        let module_bytes = build_e1(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }
    
    #[test]
    fn test_br() {
        // f0: K r0=1, BR skip, K r0=2, skip: RET r0
        // Instructions: [KImm, BR, KImm, RET] → ordinals [0, 1, 2, 3]
        // BR target=3 (skip KImm at ordinal 2, jump to RET at ordinal 3)
        // K.I64: 3+3=6, BR: 2, RET: 3 = 11 bytes
        let code = vec![
            0x0b, 0x00, 0x01,       // K.I64 r0=1  (ordinal 0)
            0x8d, 0x03,             // BR target=3   (ordinal 1)
            0x0b, 0x00, 0x02,       // K.I64 r0=2  (ordinal 2, skipped)
            0xa6, 0x01, 0x00,       // RET r0 (ordinal 3, result_count=1, result=0)
        ];
        let module_bytes = build_e1(vec![(code, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }
    
    #[test]
    fn test_br_if_taken() {
        // f0: K r0=1, K r1=1, CMP EQ r2 r1 r1, BR.IF r2 skip, K r0=99, skip: RET r0
        // Instructions: [KImm, KImm, CMP, BR.IF, KImm, RET] → ordinals [0,1,2,3,4,5]
        // r2=1 (1==1), BR.IF taken, target=5 (skip KImm at ordinal 4, jump to RET at ordinal 5)
        // K.I64: 3+3+3=9, CMP: 5, BR.IF: 3, RET: 3 = 20 bytes
        let code = vec![
            0x0b, 0x00, 0x01,       // K.I64 r0=1       (ordinal 0)
            0x0b, 0x01, 0x01,       // K.I64 r1=1       (ordinal 1)
            0x8c, 0x00, 0x02, 0x01, 0x01, // CMP EQ r2 r1 r1 (ordinal 2)
            0x8e, 0x02, 0x05,       // BR.IF r2 target=5 (ordinal 3) → ordinal 5 is RET
            0x0b, 0x00, 0x63,       // K.I64 r0=99     (ordinal 4, skipped)
            0xa6, 0x01, 0x00,       // RET r0 (ordinal 5, result_count=1, result=0)
        ];
        let module_bytes = build_e1(vec![(code, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(1));
    }
    
    #[test]
    fn test_call() {
        // Multi-function module: f0 (entry) calls f1 (leaf)
        // f0: K r0=5, CALL f1(r0) → r1, RET r1
        // f1: K r0=99, RET r0
        // Expected: f0 returns 99
        // f0: K.I64: 3, CALL: 6, RET: 3 = 12 bytes
        // f1: K.I64: 3, RET: 3 = 6 bytes
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5                [0,1,2]
            // CALL: opcode(1)+callee(1)+argc(1)+arg(1)+result_count(1)+result(1) = 6
            0x8f, 0x01, 0x01, 0x00, 0x01, 0x01, // [3-8]
            0xa6, 0x01, 0x01,       // RET r1                          [9,10,11]
        ];
        let f1 = vec![
            0x0b, 0x00, 0x63,       // K.I64 r0=99                 [0,1,2]
            0xa6, 0x01, 0x00,       // RET r0                         [3,4,5]
        ];
        let module_bytes = build_e1(vec![(f0, 0, 2), (f1, 1, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(99));
    }
}
