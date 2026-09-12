//! E0 Executor
//! 
//! Basic i64 operations executor for UNICO E0 profile
//! 
//! Grammar: (K.I64 | ADD.I64)* (RET | TRAP)

use crate::error::{Error, Result};
use crate::types::{Profile, Provenance, ExecutionResult};

/// E0 Opcodes
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Opcode {
    Trap = 0x00,
    KI64 = 0x0b,
    AddI64 = 0x13,
    Ret = 0xa6,
}

/// E0 Instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    KImm { dst: u32, imm: i64 },
    Add { dst: u32, lhs: u32, rhs: u32 },
    Ret { result: u32 },
    Trap,
}

/// E0 Function
#[derive(Debug, Clone)]
pub struct Function {
    pub param_count: u32,
    pub result_count: u32,
    pub register_count: u32,
    pub code_offset: u32,
    pub code_size: u32,
    pub instructions: Vec<Instruction>,
}

/// E0 Module
#[derive(Debug, Clone)]
pub struct Module {
    pub profile: Profile,
    pub functions: Vec<Function>,
}

impl Module {
    /// Parse E0 module from bytes
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // Check magic
        if bytes.len() < 6 || &bytes[0..6] != b"UNICO\xe0" {
            return Err(Error::Format("Invalid E0 magic".into()));
        }
        
        // E0: FUNC section (tag 0x02) + CODE section (tag 0x03) + END (tag 0x00)
        let mut pos = 6;
        
        // Parse FUNC section
        if pos >= bytes.len() || bytes[pos] != 0x02 {
            return Err(Error::Format("Missing FUNC section".into()));
        }
        pos += 1;
        let func_len = {
            let len = func_len_len(&bytes[pos]);
            let v = read_uleb(&bytes[pos..]) as usize; pos += len; v
        };
        let _ = func_len; // silence unused warning
        
        // Function: param_count, result_count, register_count, code_offset, code_size
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
        
        // Parse CODE section
        if pos >= bytes.len() || bytes[pos] != 0x03 {
            return Err(Error::Format("Missing CODE section".into()));
        }
        pos += 1;
        let code_len = {
            let len = code_len_len(&bytes[pos]);
            let v = read_uleb(&bytes[pos..]) as usize; pos += len; v
        };
        
        // Decode instructions
        let code_start = pos;
        let code_end = pos + code_len;
        let instructions = decode_instructions(&bytes[code_start..code_end], register_count)?;
        
        // Check END section
        if code_end >= bytes.len() || bytes[code_end] != 0x00 {
            return Err(Error::Format("Missing END section".into()));
        }
        
        Ok(Self {
            profile: Profile::E0,
            functions: vec![Function {
                param_count,
                result_count,
                register_count,
                code_offset,
                code_size,
                instructions,
            }],
        })
    }
    
    /// Verify module statically
    pub fn verify(&self) -> Result<()> {
        if self.functions.is_empty() {
            return Err(Error::Verification("No functions".into()));
        }
        
        let func = &self.functions[0];
        
        // Must have exactly 1 result
        if func.result_count != 1 {
            return Err(Error::Verification("Must have exactly 1 result".into()));
        }
        
        // Registers must be >= params
        if func.register_count < func.param_count {
            return Err(Error::Verification("Registers < params".into()));
        }
        
        // Must end with RET or TRAP
        if let Some(last) = func.instructions.last() {
            match last {
                Instruction::Ret { .. } | Instruction::Trap => {},
                _ => return Err(Error::Verification("Must end with RET or TRAP".into())),
            }
        } else {
            return Err(Error::Verification("Empty function".into()));
        }
        
        Ok(())
    }
}

/// E0 Executor
pub struct E0Executor {
    registers: Vec<i64>,
    pc: usize,
    fuel: u64,
}

impl E0Executor {
    pub fn new() -> Self {
        Self {
            registers: Vec::with_capacity(64),
            pc: 0,
            fuel: 100_000,
        }
    }
    
    /// Execute E0 module
    pub fn execute(&mut self, module: &Module) -> Result<ExecutionResult> {
        let start = std::time::Instant::now();
        
        // Reset state
        self.registers.clear();
        self.pc = 0;
        self.fuel = 100_000;
        
        let func = &module.functions[0];
        self.registers.resize(func.register_count as usize, 0);
        
        // Execute instructions
        while self.pc < func.instructions.len() {
            self.fuel -= 1;
            if self.fuel == 0 {
                return Ok(ExecutionResult::fail(
                    "E0T002: Fuel exhausted".into(),
                    self.provenance(start),
                ));
            }
            
            match &func.instructions[self.pc] {
                Instruction::KImm { dst, imm } => {
                    self.registers[*dst as usize] = *imm;
                    self.pc += 1;
                }
                Instruction::Add { dst, lhs, rhs } => {
                    let a = self.registers[*lhs as usize];
                    let b = self.registers[*rhs as usize];
                    self.registers[*dst as usize] = a.wrapping_add(b);
                    self.pc += 1;
                }
                Instruction::Ret { result } => {
                    let value = self.registers[*result as usize];
                    return Ok(ExecutionResult::pass(value, self.provenance(start)));
                }
                Instruction::Trap => {
                    return Ok(ExecutionResult::fail(
                        "E0T001: Explicit TRAP".into(),
                        self.provenance(start),
                    ));
                }
            }
        }
        
        Err(Error::Verification("fell off end".into()))
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

impl Default for E0Executor {
    fn default() -> Self {
        Self::new()
    }
}

// LEB128 helpers
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

fn uleb_len(first: u8) -> usize {
    let mut len = 1;
    let mut b = first;
    while b & 0x80 != 0 && len < 10 {
        len += 1;
        b >>= 7;
    }
    len
}

fn func_len_len(first_byte: &u8) -> usize {
    uleb_len(*first_byte)
}

fn code_len_len(first_byte: &u8) -> usize {
    uleb_len(*first_byte)
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
                // K.I64 dst imm
                let dst_len = uleb_len(bytes[pos]);
                let dst = read_uleb(&bytes[pos..]) as u32; pos += dst_len;
                let imm_len = sleb_len(&bytes[pos..]);
                let imm = read_sleb(&bytes[pos..]) as i64; pos += imm_len;
                instructions.push(Instruction::KImm { dst, imm });
            }
            0x13 => {
                // ADD.I64 dst lhs rhs
                let dst_len = uleb_len(bytes[pos]);
                let dst = read_uleb(&bytes[pos..]) as u32; pos += dst_len;
                let lhs_len = uleb_len(bytes[pos]);
                let lhs = read_uleb(&bytes[pos..]) as u32; pos += lhs_len;
                let rhs_len = uleb_len(bytes[pos]);
                let rhs = read_uleb(&bytes[pos..]) as u32; pos += rhs_len;
                instructions.push(Instruction::Add { dst, lhs, rhs });
            }
            0xa6 => {
                // RET count result (count=1)
                let count_len = uleb_len(bytes[pos]);
                let count = read_uleb(&bytes[pos..]) as u32; pos += count_len;
                let result_len = uleb_len(bytes[pos]);
                let result = read_uleb(&bytes[pos..]) as u32; pos += result_len;
                if count != 1 {
                    return Err(Error::Verification("RET count != 1".into()));
                }
                instructions.push(Instruction::Ret { result });
            }
            _ => return Err(Error::Format(format!("Unknown opcode: 0x{:02x}", opcode))),
        }
    }
    
    Ok(instructions)
}

fn read_sleb(bytes: &[u8]) -> i64 {
    let mut result = 0i64;
    let mut shift = 0;
    let mut b;
    for i in 0..8 {
        b = bytes[i] as i64;
        result |= (b & 0x7f) << shift;
        if b & 0x40 == 0 { break; }
        shift += 7;
    }
    result
}

fn sleb_len(bytes: &[u8]) -> usize {
    let mut len = 0;
    let mut b;
    for &byte in bytes.iter() {
        len += 1;
        b = byte as i64;
        if b & 0x40 == 0 { break; }
        if len >= 10 { break; }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Status;
    
    fn uleb(v: usize) -> u8 {
        if v < 128 { v as u8 } else { (v & 0x7f) as u8 | 0x80 }
    }
    
    fn build_module(code: Vec<u8>, result_count: u8, register_count: u8) -> Vec<u8> {
        let func_desc = vec![0u8, result_count, register_count, 0u8, code.len() as u8];
        let func_section = {
            let mut s = vec![uleb(func_desc.len())];
            s.extend_from_slice(&func_desc);
            s
        };
        vec![
            b"UNICO".to_vec(),
            vec![0xe0],
            vec![0x02],
            func_section,
            vec![0x03],
            vec![uleb(code.len())],
            code,
            vec![0x00],
        ].concat()
    }
    
    #[test]
    fn test_parse_return42() {
        // E0 module: return 42
        // magic(6) + FUNC(tag=0x02, func_len, params, results, regs, offset, size) + CODE(tag=0x03, code_len, code) + END(0x00)
        // K.I64 r0=42: 0x0b 00 2a  (opcode, dst=0 uleb, imm=42 sleb)
        // RET: 0xa6 01 00 (opcode, count=1, result_reg=0)
        let bytes = hex::decode("554e49434fe00205000101000603060b002aa6010000").unwrap();
        let module = Module::parse(&bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E0Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }
    
    #[test]
    fn test_add_i64() {
        // r2 = r0 + r1 where r0=10, r1=32 => r2=42
        // K.I64 r0=10 (0x0b, 0x00, 0x0a), K.I64 r1=32 (0x0b, 0x01, 0x20)
        // ADD r2 r0 r1 (0x13, 0x02, 0x00, 0x01), RET r2 (0xa6, 0x01, 0x02)
        let code = vec![0x0b, 0x00, 0x0a, 0x0b, 0x01, 0x20, 0x13, 0x02, 0x00, 0x01, 0xa6, 0x01, 0x02];
        let module_bytes = build_module(code, 1, 3);
        
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E0Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }
    
    #[test]
    fn test_trap() {
        // K.I64 r0=1, TRAP
        let code = vec![0x0b, 0x00, 0x01, 0x00];
        let module_bytes = build_module(code, 0, 1);
        
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E0Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.as_ref().is_some_and(|e| e.contains("TRAP")));
    }
}
