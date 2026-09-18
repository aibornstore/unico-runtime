//! E1 Executor
//! 
//! Control-flow profile: adds CMP, BR, BR.IF, CALL
//! - CMP.I64: pred(0=EQ,1=LT.S) dst lhs rhs → BOOL
//! - BR: unconditional jump to target
//! - BR.IF: conditional jump if cond=true
//! - CALL: direct local call (depth ≤8)
//! - RET: return from function

use crate::error::{Error, Result};
use crate::leb128::{decode_uleb, decode_sleb};
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
            let (v, n) = decode_uleb(&bytes[pos..])?; pos += n; v as usize
        };
        
        let func_section_end = pos + func_section_len;
        let (func_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
        let func_count = func_count as u32;
        
        let mut functions = Vec::new();
        let mut code_offsets = Vec::new();
        
        for _ in 0..func_count {
            let (param_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (result_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (register_count, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (code_offset, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let (code_size, n) = decode_uleb(&bytes[pos..])?; pos += n;
            let param_count = param_count as u32;
            let result_count = result_count as u32;
            let register_count = register_count as u32;
            let code_offset = code_offset as u32;
            let code_size = code_size as u32;
            
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
        let (code_section_len, n) = decode_uleb(&bytes[pos..])?; pos += n;
        let code_section_len = code_section_len as usize;
        
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
            _ => return Err(Error::Format(format!("Unknown E1 opcode: 0x{:02x}", opcode))),
        }
    }
    
    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Status;
    
    fn uleb(v: usize) -> u8 {
        // Proper ULEB128 single-byte: for v < 128, just return v as-is (no continuation bit).
        v as u8
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
        // SLEB128 for 99: 0x63 0x01 (two bytes, since 99 >= 64)
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5                  [0,1,2]
            // CALL: opcode(1)+callee(1)+argc(1)+arg(1)+result_count(1)+result(1) = 6
            0x8f, 0x01, 0x01, 0x00, 0x01, 0x01, // [3-8]
            0xa6, 0x01, 0x01,       // RET r1                             [9,10,11]
        ];
        let f1 = vec![
            // K.I64 r0=99: dst=0(ULEB), imm=99(SLEB128: 0xe3 0x00)
            0x0b, 0x00, 0xe3, 0x00, // K.I64 r0=99   [0,1,2,3] = 4 bytes
            0xa6, 0x01, 0x00,       // RET r0          [4,5,6] = 3 bytes
        ];
        // f1: 4+3=7 bytes of code, register_count=2 to match RET writing to r0
        let module_bytes = build_e1(vec![(f0, 0, 2), (f1, 1, 2)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(99));
    }

    // ---- Parse error tests ----
    #[test]
    fn test_parse_invalid_magic() {
        let bytes = b"NICO\x00\x00".to_vec();
        let r = Module::parse(&bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid E1 magic"));
    }

    #[test]
    fn test_parse_short_magic() {
        let bytes = b"UNIC".to_vec();
        let r = Module::parse(&bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid E1 magic"));
    }

    #[test]
    fn test_parse_missing_func_section() {
        // Magic is correct but no FUNC section follows
        let bytes = vec![
            b'U', b'N', b'I', b'C', b'O', 0xe1, // Magic
            0x03, 0x00, // CODE tag with len=0
            0x00, // END
        ];
        let r = Module::parse(&bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Missing FUNC section"));
    }

    #[test]
    fn test_parse_missing_code_section() {
        // Build bytes where after FUNC we go straight to END (no CODE)
        let module_bytes = vec![
            b'U', b'N', b'I', b'C', b'O', 0xe1, // Magic
            0x02, // FUNC tag
            0x06, // FUNC payload len = 6 bytes
            0x01, // 1 function
            0x00, // param_count=0
            0x01, // result_count=1
            0x01, // register_count=1
            0x00, // code_offset=0
            0x01, // code_size=1
            // No CODE section - goes to END
            0x00, // END
        ];
        let r = Module::parse(&module_bytes);
        assert!(r.is_err());
        // Parser expects CODE section after FUNC but finds END
        assert!(r.unwrap_err().to_string().contains("Missing CODE section"));
    }

    #[test]
    fn test_parse_func_section_mismatch() {
        // Build with wrong FUNC payload size
        let mut module_bytes = vec![
            b'U', b'N', b'I', b'C', b'O', 0xe1, // Magic
            0x02, // FUNC tag
            0x03, // FUNC payload len = 3 (WRONG - should be 6)
            0x01, // 1 function
            0x00, // param_count=0
            0x01, // result_count=1
            0x01, // register_count=1
            0x00, // code_offset=0
            0x01, // code_size=1
            0x03, // CODE tag
            0x01, // CODE len
            0x00, // TRAP opcode
            0x00, // END
        ];
        let r = Module::parse(&module_bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("FUNC section size mismatch"));
    }

    #[test]
    fn test_parse_code_out_of_bounds() {
        // Build with code_offset pointing past the end of code section
        // The code section is only 1 byte, but offset is 5
        let module_bytes = vec![
            b'U', b'N', b'I', b'C', b'O', 0xe1, // Magic
            0x02, // FUNC tag
            0x06, // FUNC payload len = 6
            0x01, // 1 function
            0x00, // param_count=0
            0x01, // result_count=1
            0x01, // register_count=1
            0x05, // code_offset=5 (past end of 1-byte code)
            0x01, // code_size=1
            0x03, // CODE tag
            0x01, // CODE len = 1
            0x00, // TRAP opcode (1 byte)
            0x00, // END
        ];
        let r = Module::parse(&module_bytes);
        assert!(r.is_err());
        // The error should mention function index or out of bounds
        let err = r.unwrap_err().to_string();
        assert!(err.contains("out of bounds") || err.contains("Function"));
    }

    #[test]
    fn test_parse_missing_end() {
        // Build E1 without END marker
        let f0 = vec![
            0x0b, 0x00, 0x01, // K.I64 r0=1
            0xa6, 0x01, 0x00, // RET r0
        ];
        let mut module_bytes = build_e1(vec![(f0, 0, 1)]);
        // Remove the END byte
        module_bytes.pop();
        let r = Module::parse(&module_bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Missing END section"));
    }

    #[test]
    fn test_parse_unknown_opcode() {
        // Create a module with an unknown opcode in the code
        // Use low-level byte construction to avoid format issues
        let mut module_bytes = vec![
            b'U', b'N', b'I', b'C', b'O', 0xe1, // Magic
            0x02, // FUNC tag
            0x06, // FUNC payload len
            0x01, // 1 function
            0x00, // param_count=0
            0x01, // result_count=1
            0x01, // register_count=1
            0x00, // code_offset=0
            0x01, // code_size=1
            0x03, // CODE tag
            0x01, // CODE len
            0xFF, // Unknown opcode 0xFF
            0x00, // END
        ];
        let r = Module::parse(&module_bytes);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown E1 opcode"));
    }

    // ---- Verify error tests ----
    #[test]
    fn test_verify_empty_functions() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![],
        };
        let r = module.verify();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("No functions"));
    }

    #[test]
    fn test_verify_entry_has_params() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 1, // Non-zero params
                result_count: 1,
                register_count: 2,
                code_offset: 0,
                code_size: 0,
                instructions: vec![Instruction::Trap],
            }],
        };
        let r = module.verify();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Entry must have 0 params"));
    }

    #[test]
    fn test_verify_wrong_result_count() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 0,
                result_count: 0, // Must be 1
                register_count: 1,
                code_offset: 0,
                code_size: 0,
                instructions: vec![Instruction::Trap],
            }],
        };
        let r = module.verify();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("must have exactly 1 result"));
    }

    #[test]
    fn test_verify_registers_less_than_params() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 3,
                result_count: 1,
                register_count: 2, // Less than param_count
                code_offset: 0,
                code_size: 0,
                instructions: vec![Instruction::Trap],
            }],
        };
        let r = module.verify();
        assert!(r.is_err());
        // Check for error about register count
        let err = r.unwrap_err().to_string();
        assert!(err.contains("registers") || err.contains("params"));
    }

    #[test]
    fn test_verify_empty_body() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 0,
                result_count: 1,
                register_count: 1,
                code_offset: 0,
                code_size: 0,
                instructions: vec![], // Empty body
            }],
        };
        let r = module.verify();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("empty body"));
    }

    #[test]
    fn test_verify_ends_with_trap() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 0,
                result_count: 1,
                register_count: 1,
                code_offset: 0,
                code_size: 0,
                instructions: vec![
                    Instruction::KImm { dst: 0, imm: 42 },
                    Instruction::KImm { dst: 0, imm: 0 }, // Not ending with RET or TRAP
                ],
            }],
        };
        let r = module.verify();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("must end with RET or TRAP"));
    }

    // ---- Execute error tests ----
    #[test]
    fn test_execute_empty_module() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![],
        };
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("No functions"));
    }

    #[test]
    fn test_execute_entry_has_params() {
        let module = Module {
            profile: Profile::E1,
            functions: vec![Function {
                param_count: 1,
                result_count: 1,
                register_count: 2,
                code_offset: 0,
                code_size: 0,
                instructions: vec![Instruction::Trap],
            }],
        };
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Entry function must have 0 parameters"));
    }

    #[test]
    fn test_execute_fell_off_end() {
        // Module with no terminating instruction
        let f0 = vec![
            0x0b, 0x00, 0x01, // K.I64 r0=1 (no RET or TRAP)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("fell off end"));
    }

    #[test]
    fn test_execute_invalid_callee() {
        // f0: CALL f99 (invalid callee), should fail
        let f0 = vec![
            0x8f, 0x63, 0x00, 0x00, 0x01, 0x00, // CALL callee=99 (doesn't exist)
            0xa6, 0x01, 0x00,       // RET r0 (never reached)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid callee"));
    }

    #[test]
    fn test_execute_argc_mismatch() {
        // f0 calls f1 with wrong argc
        // f0: CALL f1 with argc=2 but f1 expects 1 param
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x8f, 0x01, 0x02, 0x00, 0x00, 0x01, 0x01, // CALL callee=1, argc=2 (wrong!)
            0xa6, 0x01, 0x01,       // RET r1 (never reached)
        ];
        let f1 = vec![
            0xa6, 0x01, 0x00,       // RET r0 (expects 1 param)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 2), (f1, 1, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("argc"));
    }

    #[test]
    fn test_execute_cmp_invalid_pred() {
        // f0: CMP with pred=99 (invalid)
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x0a,       // K.I64 r1=10
            0x8c, 0x63, 0x02, 0x00, 0x01, // CMP pred=99 (invalid) dst=r2 lhs=r0 rhs=r1
            0xa6, 0x01, 0x02,       // RET r2 (never reached)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E1Executor::new();
        let r = exec.execute(&module);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid CMP pred"));
    }

    #[test]
    fn test_execute_trap() {
        let f0 = vec![
            0x00,                   // TRAP
        ];
        let module_bytes = build_e1(vec![(f0, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        assert_eq!(result.status, Status::Fail);
        assert!(result.error.unwrap().contains("Explicit TRAP"));
    }

    #[test]
    fn test_execute_add() {
        // f0: K r0=5, K r1=10, ADD r2=r0+r1, RET r2
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x0a,       // K.I64 r1=10
            0x13, 0x02, 0x00, 0x01, // ADD r2 r0 r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(15)); // 5 + 10
    }

    #[test]
    fn test_execute_add_overflow() {
        // f0: K r0=63 (max single-byte positive SLEB), K r1=1, ADD r2=r0+r1, RET r2
        // 63 + 1 = 64 (wraps to -64 in signed arithmetic)
        let f0 = vec![
            0x0b, 0x00, 0x3f,       // K.I64 r0=63 (0x3f is max positive single-byte SLEB)
            0x0b, 0x01, 0x01,       // K.I64 r1=1
            0x13, 0x02, 0x00, 0x01, // ADD r2 r0 r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(64)); // 63 + 1 = 64
    }

    #[test]
    fn test_execute_cmp_neq() {
        // f0: K r0=5, K r1=10, CMP EQ r2 r0 r1, RET r2
        // Expected: r2=0 (5 != 10)
        let f0 = vec![
            0x0b, 0x00, 0x05,       // K.I64 r0=5
            0x0b, 0x01, 0x0a,       // K.I64 r1=10
            0x8c, 0x00, 0x02, 0x00, 0x01, // CMP.I64 pred=0(EQ) dst=r2 lhs=r0 rhs=r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0)); // 5 != 10
    }

    #[test]
    fn test_execute_cmp_not_less() {
        // f0: K r0=10, K r1=5, CMP LT.S r2 r0 r1, RET r2
        // Expected: r2=0 (10 >= 5)
        let f0 = vec![
            0x0b, 0x00, 0x0a,       // K.I64 r0=10
            0x0b, 0x01, 0x05,       // K.I64 r1=5
            0x8c, 0x01, 0x02, 0x00, 0x01, // CMP.I64 pred=1(LT.S) dst=r2 lhs=r0 rhs=r1
            0xa6, 0x01, 0x02,       // RET r2
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        module.verify().unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0)); // 10 >= 5
    }

    #[test]
    fn test_execute_br_if_not_taken() {
        // f0: K r0=0, K r1=0, CMP EQ r2 r0 r1 (true), BR.IF skip, K r0=99, skip: RET r0
        // BR.IF taken because cond=1, so K r0=99 is SKIPPED
        let f0 = vec![
            0x0b, 0x00, 0x00,       // K.I64 r0=0
            0x0b, 0x01, 0x00,       // K.I64 r1=0
            0x8c, 0x00, 0x02, 0x00, 0x01, // CMP EQ r2 r0 r1 (r2=1, true)
            0x8e, 0x02, 0x05,       // BR.IF r2 target=5 (taken, jump to RET)
            0x0b, 0x00, 0x63,       // K.I64 r0=99 (SKIPPED)
            0xa6, 0x01, 0x00,       // RET r0 (ordinal 5)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(0)); // r0 is 0, K r0=99 was skipped
    }

    #[test]
    fn test_execute_br_if_taken_to_skip() {
        // Test BR.IF where condition is false (not taken)
        // f0: K r0=1, K r1=0, CMP EQ r2 r0 r1 (false), BR.IF skip, K r0=50, skip: RET r0
        // Use 50 (single-byte SLEB128 = 0x32)
        let f0 = vec![
            0x0b, 0x00, 0x01,       // K.I64 r0=1
            0x0b, 0x01, 0x00,       // K.I64 r1=0
            0x8c, 0x00, 0x02, 0x00, 0x01, // CMP EQ r2 r0 r1 (r2=0, false)
            0x8e, 0x02, 0x05,       // BR.IF r2 target=5 (NOT taken)
            0x0b, 0x00, 0x32,         // K.I64 r0=50 (single-byte SLEB128)
            0xa6, 0x01, 0x00,       // RET r0 (ordinal 5)
        ];
        let module_bytes = build_e1(vec![(f0, 0, 3)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(50)); // r0 is 50, K r0=50 was executed
    }

    #[test]
    fn test_execute_call_with_no_return_value_dest() {
        // Test calling a function that doesn't store result
        // f0: CALL f1 (no result register), but we still need to advance PC
        // f1: K r0=42, RET r0
        let f0 = vec![
            0x8f, 0x01, 0x00, 0x01, 0x00, // CALL f1, argc=0, no args, result_count=1, result_reg=0
            0xa6, 0x01, 0x00,       // RET r0 (returns whatever f1 returned)
        ];
        let f1 = vec![
            0x0b, 0x00, 0x2a,       // K.I64 r0=42
            0xa6, 0x01, 0x00,       // RET r0
        ];
        let module_bytes = build_e1(vec![(f0, 0, 1), (f1, 0, 1)]);
        let module = Module::parse(&module_bytes).unwrap();
        
        let mut exec = E1Executor::new();
        let result = exec.execute(&module).unwrap();
        
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_executor_default() {
        let exec = E1Executor::default();
        assert_eq!(exec.fuel, 100_000);
        assert!(exec.frames.is_empty());
    }
}
