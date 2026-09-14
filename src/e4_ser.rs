//! E4 Binary Serialization
//!
//! Binary format for E4Module:
//! - Header: magic "E4XX" + version (1 byte)
//! - Memory: size (u32) + bytes
//! - Functions: count + each function's def + code
//!
//! Instruction opcodes (variant index in Instruction enum):
//!   0x00 Br       0x01 BrIf     0x02 Ret        0x03 Trap
//!   0x04 Cmp      0x05 LoadI64  0x06 StoreI64   0x07 FAdd
//!   0x08 FSub     0x09 FMul     0x0A FDiv       0x0B FSqrt
//!   0x0C FNeg     0x0D FAbs     0x0E FRound     0x0F FCmp
//!   0x10 I2F      0x11 F2I      0x12 U2F        0x13 F2U
//!   0x14 Mov      0x15 FImm     0x16 HostCall

use crate::error::{Error, Result};
use crate::exec::e4::{E4FunctionDef, E4Module, Instruction};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Write};

const MAGIC: &[u8] = b"E4XX";
const VERSION: u8 = 1;

/// Estimate encoded binary size of an E4Module for pre-allocation.
pub fn encoded_size(module: &E4Module) -> usize {
    let mut size = 0;
    // Header: magic (4) + version (1)
    size += 5;
    // Memory: size u32 + bytes
    size += 4 + module.memory.len();
    // Functions count
    size += 4;
    for f in &module.functions {
        size += instruction_size_fn(f);
    }
    size
}

fn instruction_size_fn(f: &E4FunctionDef) -> usize {
    let mut size = 0;
    size += 4 + 4 + 4 + 4; // param_count + result_count + register_count + code_len
    for instr in &f.code {
        size += instruction_size(instr);
    }
    size
}

fn instruction_size(instr: &Instruction) -> usize {
    match instr {
        Instruction::Trap => 1,
        Instruction::Br { .. } | Instruction::Ret { .. } => 5,
        Instruction::BrIf { .. } | Instruction::LoadI64 { .. } | Instruction::StoreI64 { .. }
        | Instruction::FSqrt { .. } | Instruction::FNeg { .. } | Instruction::FAbs { .. }
        | Instruction::FRound { .. } | Instruction::I2F { .. } | Instruction::F2I { .. }
        | Instruction::U2F { .. } | Instruction::F2U { .. } | Instruction::Mov { .. }
        | Instruction::FSqrtF64 { .. } | Instruction::FNegF64 { .. } | Instruction::FAbsF64 { .. }
        | Instruction::FRoundF64 { .. } | Instruction::I2F64 { .. } | Instruction::F642I { .. }
        | Instruction::U2F64 { .. } | Instruction::F642U { .. } => 9,
        Instruction::FAdd { .. } | Instruction::FSub { .. } | Instruction::FMul { .. }
        | Instruction::FDiv { .. }
        | Instruction::FAddF64 { .. } | Instruction::FSubF64 { .. } | Instruction::FMulF64 { .. }
        | Instruction::FDivF64 { .. } => 13,
        Instruction::Cmp { .. } | Instruction::FCmp { .. } | Instruction::FCmpF64 { .. } => 14,
        Instruction::FImm { .. } | Instruction::FImmF64 { .. } => 9,
        Instruction::HostCall { args, results, .. } => {
            13 + (args.len() + results.len()) * 4
        }
    }
}

/// Encode an E4Module to binary format.
pub fn encode_e4(module: &E4Module) -> Vec<u8> {
    let capacity = encoded_size(module);
    let mut buf = Vec::with_capacity(capacity);

    // Header
    buf.write_all(MAGIC).unwrap();
    buf.push(VERSION);

    // Memory
    write_u32(&mut buf, module.memory.len() as u32);
    buf.extend_from_slice(&module.memory);

    // Functions
    write_u32(&mut buf, module.functions.len() as u32);
    for f in &module.functions {
        encode_function(&mut buf, f);
    }

    buf
}

fn encode_function(buf: &mut Vec<u8>, f: &E4FunctionDef) {
    write_u32(buf, f.param_count as u32);
    write_u32(buf, f.result_count as u32);
    write_u32(buf, f.register_count as u32);
    write_u32(buf, f.code.len() as u32);
    for instr in &f.code {
        encode_instruction(buf, instr);
    }
}

fn encode_instruction(buf: &mut Vec<u8>, instr: &Instruction) {
    match instr {
        Instruction::Br { target } => {
            buf.push(0x00);
            write_u32(buf, *target);
        }
        Instruction::BrIf { cond, target } => {
            buf.push(0x01);
            write_u32(buf, *cond);
            write_u32(buf, *target);
        }
        Instruction::Ret { dst } => {
            buf.push(0x02);
            write_u32(buf, *dst);
        }
        Instruction::Trap => {
            buf.push(0x03);
        }
        Instruction::Cmp { pred, dst, a, b } => {
            buf.push(0x04);
            buf.push(*pred);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::LoadI64 { dst, addr } => {
            buf.push(0x05);
            write_u32(buf, *dst);
            write_u32(buf, *addr);
        }
        Instruction::StoreI64 { addr, src } => {
            buf.push(0x06);
            write_u32(buf, *addr);
            write_u32(buf, *src);
        }
        Instruction::FAdd { dst, a, b } => {
            buf.push(0x07);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::FSub { dst, a, b } => {
            buf.push(0x08);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::FMul { dst, a, b } => {
            buf.push(0x09);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::FDiv { dst, a, b } => {
            buf.push(0x0A);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::FSqrt { dst, a } => {
            buf.push(0x0B);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::FNeg { dst, a } => {
            buf.push(0x0C);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::FAbs { dst, a } => {
            buf.push(0x0D);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::FRound { dst, a } => {
            buf.push(0x0E);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::FCmp { pred, dst, a, b } => {
            buf.push(0x0F);
            buf.push(*pred);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        Instruction::I2F { dst, a } => {
            buf.push(0x10);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::F2I { dst, a } => {
            buf.push(0x11);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::U2F { dst, a } => {
            buf.push(0x12);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::F2U { dst, a } => {
            buf.push(0x13);
            write_u32(buf, *dst);
            write_u32(buf, *a);
        }
        Instruction::Mov { dst, src } => {
            buf.push(0x14);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        Instruction::FImm { dst, imm } => {
            buf.push(0x15);
            write_u32(buf, *dst);
            buf.extend_from_slice(&imm.to_bits().to_le_bytes());
        }
        Instruction::FAddF64 { dst, a, b } => { buf.push(0x17); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::FSubF64 { dst, a, b } => { buf.push(0x18); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::FMulF64 { dst, a, b } => { buf.push(0x19); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::FDivF64 { dst, a, b } => { buf.push(0x1A); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::FSqrtF64 { dst, a } => { buf.push(0x1B); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::FNegF64 { dst, a } => { buf.push(0x1C); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::FAbsF64 { dst, a } => { buf.push(0x1D); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::FRoundF64 { dst, a } => { buf.push(0x1E); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::FCmpF64 { pred, dst, a, b } => { buf.push(0x1F); buf.push(*pred); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::I2F64 { dst, a } => { buf.push(0x20); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::F642I { dst, a } => { buf.push(0x21); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::U2F64 { dst, a } => { buf.push(0x22); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::F642U { dst, a } => { buf.push(0x23); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::FImmF64 { dst, imm } => { buf.push(0x24); write_u32(buf, *dst); buf.extend_from_slice(&imm.to_bits().to_le_bytes()); }
        Instruction::HostCall { id, args, results } => {
            buf.push(0x16);
            write_u32(buf, *id);
            write_u32(buf, args.len() as u32);
            for &a in args {
                write_u32(buf, a);
            }
            write_u32(buf, results.len() as u32);
            for &r in results {
                write_u32(buf, r);
            }
        }
    }
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Decode an E4Module from binary format.
pub fn decode_e4(buf: &[u8]) -> Result<E4Module> {
    // Fast path: use byteorder Cursor for bulk reads
    let mut cursor = std::io::Cursor::new(buf);

    // Header: check magic
    {
        let mut magic_buf = [0u8; 4];
        cursor.read_exact(&mut magic_buf).map_err(|_| {
            Error::Generic("E4: truncated header".into())
        })?;
        if &magic_buf != MAGIC {
            return Err(Error::Generic("E4: bad magic".into()));
        }
    }

    let version = cursor.read_u8().map_err(|_| {
        Error::Generic("E4: truncated header".into())
    })?;
    if version != VERSION {
        return Err(Error::Generic(format!("E4: unsupported version {}", version)));
    }

    // Memory
    let mem_size = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let mut memory = vec![0u8; mem_size];
    cursor.read_exact(&mut memory).map_err(|_| {
        Error::Generic("E4: truncated memory data".into())
    })?;

    // Functions
    let fn_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let mut functions = Vec::with_capacity(fn_count);
    for _ in 0..fn_count {
        functions.push(decode_function_from_cursor(&mut cursor)?);
    }

    Ok(E4Module { functions, memory })
}

fn decode_function_from_cursor<R: Read>(cursor: &mut R) -> Result<E4FunctionDef> {
    let param_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let result_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let register_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let instr_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;

    let mut code = Vec::with_capacity(instr_count);
    for _ in 0..instr_count {
        code.push(decode_instruction_from_cursor(cursor)?);
    }

    Ok(E4FunctionDef {
        param_count,
        result_count,
        register_count,
        code,
    })
}

fn decode_instruction_from_cursor<R: Read>(cursor: &mut R) -> Result<Instruction> {
    let opcode = cursor.read_u8().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })?;
    match opcode {
        0x00 => {
            let target = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::Br { target })
        }
        0x01 => {
            let cond = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let target = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::BrIf { cond, target })
        }
        0x02 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::Ret { dst })
        }
        0x03 => Ok(Instruction::Trap),
        0x04 => {
            let pred = cursor.read_u8().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::Cmp { pred, dst, a, b })
        }
        0x05 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let addr = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::LoadI64 { dst, addr })
        }
        0x06 => {
            let addr = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let src = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::StoreI64 { addr, src })
        }
        0x07 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FAdd { dst, a, b })
        }
        0x08 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FSub { dst, a, b })
        }
        0x09 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FMul { dst, a, b })
        }
        0x0A => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FDiv { dst, a, b })
        }
        0x0B => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FSqrt { dst, a })
        }
        0x0C => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FNeg { dst, a })
        }
        0x0D => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FAbs { dst, a })
        }
        0x0E => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FRound { dst, a })
        }
        0x0F => {
            let pred = cursor.read_u8().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let b = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FCmp { pred, dst, a, b })
        }
        0x10 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::I2F { dst, a })
        }
        0x11 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::F2I { dst, a })
        }
        0x12 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::U2F { dst, a })
        }
        0x13 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let a = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::F2U { dst, a })
        }
        0x14 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let src = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::Mov { dst, src })
        }
        0x15 => {
            let dst = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let imm = cursor.read_f32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            Ok(Instruction::FImm { dst, imm })
        }
        0x16 => {
            let id = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            let arg_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })? as usize;
            let mut args = Vec::with_capacity(arg_count);
            for _ in 0..arg_count {
                args.push(cursor.read_u32::<LittleEndian>().map_err(|_| {
                    Error::Generic("E4: truncated data".into())
                })?);
            }
            let result_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })? as usize;
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                results.push(cursor.read_u32::<LittleEndian>().map_err(|_| {
                    Error::Generic("E4: truncated data".into())
                })?);
            }
            Ok(Instruction::HostCall { id, args, results })
        }
        0x17 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FAddF64 { dst, a, b }) }
        0x18 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FSubF64 { dst, a, b }) }
        0x19 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FMulF64 { dst, a, b }) }
        0x1A => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FDivF64 { dst, a, b }) }
        0x1B => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FSqrtF64 { dst, a }) }
        0x1C => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FNegF64 { dst, a }) }
        0x1D => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FAbsF64 { dst, a }) }
        0x1E => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FRoundF64 { dst, a }) }
        0x1F => { let pred = cursor.read_u8().map_err(|e| e)?; let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FCmpF64 { pred, dst, a, b }) }
        0x20 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::I2F64 { dst, a }) }
        0x21 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::F642I { dst, a }) }
        0x22 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::U2F64 { dst, a }) }
        0x23 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::F642U { dst, a }) }
        0x24 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let imm = cursor.read_f64::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::FImmF64 { dst, imm }) }
        _ => Err(Error::Generic(format!("E4: unknown opcode {:#04x}", opcode))),
    }
}

// ---------------------------------------------------------------------------
// Roundtrip tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::e4::{E4Executor, E4Module, E4Value};

    fn roundtrip(module: &E4Module) -> E4Module {
        let bytes = encode_e4(module);
        decode_e4(&bytes).unwrap()
    }

    #[test]
    fn test_e4_encode_decode_fadd() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.5 },
                    Instruction::FImm { dst: 1, imm: 2.5 },
                    Instruction::FAdd { dst: 2, a: 0, b: 1 },
                    Instruction::Mov { dst: 0, src: 2 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 256],
        };
        let decoded = roundtrip(&module);
        assert_eq!(decoded.functions.len(), 1);
        assert_eq!(decoded.functions[0].code.len(), 5);
        assert_eq!(decoded.memory.len(), 256);

        // Execute the decoded module
        let mut exec = E4Executor::default();
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        let bits = result.value.unwrap() as u32;
        let f = f32::from_bits(bits);
        assert!((f - 4.0).abs() < 0.001, "expected 4.0, got {f}");
    }

    #[test]
    fn test_e4_encode_decode_all_ops() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 10.0 },
                    Instruction::FImm { dst: 1, imm: 3.0 },
                    Instruction::FSub { dst: 2, a: 0, b: 1 }, // 7.0
                    Instruction::FMul { dst: 3, a: 2, b: 2 }, // 49.0
                    Instruction::FNeg { dst: 4, a: 3 },       // -49.0
                    Instruction::FAbs { dst: 5, a: 4 },       // 49.0
                    Instruction::FSqrt { dst: 6, a: 5 },      // 7.0
                    Instruction::FRound { dst: 7, a: 6 },      // 7.0
                    Instruction::FCmp { pred: 4, dst: 0, a: 6, b: 7 }, // eq
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 64],
        };
        let decoded = roundtrip(&module);
        let mut exec = E4Executor::default();
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 1); // sqrt(49) == round(7.0)
    }

    #[test]
    fn test_e4_encode_decode_hostcall() {
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(123));
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::HostCall { id: 0, args: vec![], results: vec![0] },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 64],
        };
        let decoded = roundtrip(&module);
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 123);
    }

    #[test]
    fn test_e4_decode_bad_magic() {
        let result = decode_e4(b"XXXX" as &[u8]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }

    #[test]
    fn test_e4_decode_truncated() {
        let result = decode_e4(b"E4XX");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn test_e4_decode_unknown_opcode() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E4XX");
        bytes.push(1); // version
        bytes.extend_from_slice(&4u32.to_le_bytes()); // memory size
        bytes.extend_from_slice(&vec![0u8; 4]); // memory
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 function
        bytes.extend_from_slice(&0u32.to_le_bytes()); // param_count
        bytes.extend_from_slice(&1u32.to_le_bytes()); // result_count
        bytes.extend_from_slice(&4u32.to_le_bytes()); // register_count
        bytes.extend_from_slice(&1u32.to_le_bytes()); // code len = 1
        bytes.push(0xFF); // unknown opcode
        let result = decode_e4(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown opcode"));
    }

    #[test]
    fn test_e4_encode_decode_memory_and_multi_function() {
        let module = E4Module {
            functions: vec![
                E4FunctionDef {
                    param_count: 1,
                    result_count: 1,
                    register_count: 4,
                    code: vec![
                        Instruction::Ret { dst: 0 },
                    ],
                },
                E4FunctionDef {
                    param_count: 0,
                    result_count: 0,
                    register_count: 2,
                    code: vec![Instruction::Trap],
                },
            ],
            memory: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let decoded = roundtrip(&module);
        assert_eq!(decoded.functions.len(), 2);
        assert_eq!(decoded.functions[0].param_count, 1);
        assert_eq!(decoded.functions[1].param_count, 0);
        assert_eq!(decoded.memory, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // -------------------------------------------------------------------------
    // T30: Additional serialization edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_e4_encode_decode_empty_memory() {
        // Zero-sized memory should roundtrip
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 2,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.0 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![],
        };
        let decoded = roundtrip(&module);
        assert!(decoded.memory.is_empty());
    }

    #[test]
    fn test_e4_encode_decode_large_immediate() {
        // FImm with large f32 value: 1e30 = 0x72A11E2E
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 2,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1e30_f32 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 64],
        };
        let decoded = roundtrip(&module);
        let mut exec = E4Executor::default();
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        let bits = result.value.unwrap() as u32;
        assert_eq!(bits, 1e30_f32.to_bits());
    }

    #[test]
    fn test_e4_encode_decode_special_floats() {
        // Encode/decode NaN and -0.0. NaN != anything (pred=5), -0.0 == -0.0 (pred=4)
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 3,
                code: vec![
                    Instruction::FImm { dst: 0, imm: f32::NAN },
                    Instruction::FImm { dst: 1, imm: -0.0_f32 },
                    Instruction::FCmp { pred: 5, dst: 2, a: 0, b: 1 }, // NaN != -0.0
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 64],
        };
        let decoded = roundtrip(&module);
        let mut exec = E4Executor::default();
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 1); // NaN != -0.0
    }

    #[test]
    fn test_e4_encode_decode_hostcall_with_args_and_results() {
        // HostCall with multiple args: host extracts f32 bits, returns first arg's bits
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|args| {
            let first_bits = match &args[0] {
                E4Value::F32(f) => f.to_bits() as i64,
                E4Value::F64(f) => f.to_bits() as i64,
                E4Value::I32(i) => *i as i64,
            };
            E4Value::I32(first_bits as i32)
        });
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 10.0 }, // bits = 0x41200000
                    Instruction::FImm { dst: 1, imm: 20.0 }, // bits = 0x41A00000
                    Instruction::HostCall {
                        id: 0,
                        args: vec![0, 1],
                        results: vec![2, 3],
                    },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 64],
        };
        let decoded = roundtrip(&module);
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 0x41200000_i64); // 10.0 bits
    }

    #[test]
    fn test_encoded_size_estimate() {
        // encoded_size should be >= actual encoded size
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.5 },
                    Instruction::FImm { dst: 1, imm: 2.5 },
                    Instruction::FAdd { dst: 2, a: 0, b: 1 },
                    Instruction::Mov { dst: 0, src: 2 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 256],
        };
        let encoded = encode_e4(&module);
        let estimate = encoded_size(&module);
        assert!(estimate >= encoded.len(), "estimate {} >= actual {}", estimate, encoded.len());
    }

    #[test]
    fn test_e4_encode_decode_f64_instructions() {
        // F64 instruction roundtrip
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 3.14159265358979 }, // pi
                    Instruction::FImmF64 { dst: 1, imm: 2.718281828459045 }, // e
                    Instruction::FAddF64 { dst: 2, a: 0, b: 1 },
                    Instruction::FMulF64 { dst: 3, a: 0, b: 1 },
                    Instruction::FDivF64 { dst: 4, a: 0, b: 1 },
                    Instruction::FSqrtF64 { dst: 5, a: 0 },
                    Instruction::FNegF64 { dst: 6, a: 0 },
                    Instruction::FAbsF64 { dst: 7, a: 1 },
                    Instruction::FRoundF64 { dst: 0, a: 1 },
                    Instruction::FCmpF64 { pred: 0, dst: 1, a: 0, b: 1 },
                    Instruction::I2F64 { dst: 2, a: 0 },
                    Instruction::F642I { dst: 3, a: 0 },
                    Instruction::U2F64 { dst: 4, a: 0 },
                    Instruction::F642U { dst: 5, a: 0 },
                    Instruction::Ret { dst: 5 },
                ],
            }],
            memory: vec![0u8; 256],
        };
        let encoded = encode_e4(&module);
        let decoded = decode_e4(&encoded).unwrap();
        assert_eq!(decoded.functions.len(), 1);
        assert_eq!(decoded.functions[0].code.len(), 15);
        // Check first instruction
        if let Instruction::FImmF64 { dst, imm } = decoded.functions[0].code[0] {
            assert_eq!(dst, 0);
            assert!((imm - 3.14159265358979).abs() < 1e-10);
        } else {
            panic!("expected FImmF64");
        }
    }

    #[test]
    fn test_e4_roundtrip_all_instruction_types() {
        // Property: encode -> decode preserves all instruction types
        let all_instructions = vec![
            Instruction::Trap,
            Instruction::Ret { dst: 0 },
            Instruction::Br { target: 1 },
            Instruction::BrIf { cond: 0, target: 2 },
            Instruction::Mov { dst: 1, src: 0 },
            Instruction::Cmp { pred: 0, dst: 6, a: 0, b: 1 },
            Instruction::LoadI64 { dst: 2, addr: 0 },
            Instruction::StoreI64 { addr: 0, src: 1 },
            Instruction::FImm { dst: 0, imm: 1.5 },
            Instruction::FAdd { dst: 1, a: 0, b: 1 },
            Instruction::FSub { dst: 2, a: 0, b: 1 },
            Instruction::FMul { dst: 3, a: 0, b: 1 },
            Instruction::FDiv { dst: 4, a: 0, b: 1 },
            Instruction::FSqrt { dst: 5, a: 0 },
            Instruction::FNeg { dst: 6, a: 0 },
            Instruction::FAbs { dst: 7, a: 0 },
            Instruction::FRound { dst: 0, a: 1 },
            Instruction::FCmp { pred: 0, dst: 10, a: 0, b: 1 },
            Instruction::I2F { dst: 2, a: 0 },
            Instruction::F2I { dst: 3, a: 0 },
            Instruction::U2F { dst: 4, a: 0 },
            Instruction::F2U { dst: 5, a: 0 },
            Instruction::FImmF64 { dst: 0, imm: 2.71828 },
            Instruction::FAddF64 { dst: 1, a: 0, b: 1 },
            Instruction::FMulF64 { dst: 2, a: 0, b: 1 },
            Instruction::FDivF64 { dst: 3, a: 0, b: 1 },
            Instruction::FSqrtF64 { dst: 4, a: 0 },
            Instruction::FNegF64 { dst: 5, a: 0 },
            Instruction::FAbsF64 { dst: 6, a: 0 },
            Instruction::FRoundF64 { dst: 7, a: 0 },
            Instruction::FCmpF64 { pred: 1, dst: 0, a: 1, b: 2 },
            Instruction::I2F64 { dst: 1, a: 0 },
            Instruction::F642I { dst: 2, a: 0 },
            Instruction::U2F64 { dst: 3, a: 0 },
            Instruction::F642U { dst: 4, a: 0 },
            Instruction::HostCall { id: 0, args: vec![0, 1], results: vec![2] },
        ];
        for instr in all_instructions {
            let module = E4Module {
                functions: vec![E4FunctionDef {
                    param_count: 0,
                    result_count: 0,
                    register_count: 8,
                    code: vec![instr.clone(), Instruction::Trap],
                }],
                memory: vec![0u8; 256],
            };
            let encoded = encode_e4(&module);
            let decoded = decode_e4(&encoded).unwrap();
            assert_eq!(decoded.functions[0].code[0], instr, "roundtrip failed for {:?}", instr);
        }
    }

    #[test]
    fn test_e4_encode_preserves_module_equality() {
        // Property: encoding two equal modules produces equal bytes
        let module1 = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 1,
                result_count: 2,
                register_count: 16,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 3.14 },
                    Instruction::FImm { dst: 1, imm: 2.71 },
                    Instruction::FMul { dst: 2, a: 0, b: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 4096],
        };
        let module2 = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 1,
                result_count: 2,
                register_count: 16,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 3.14 },
                    Instruction::FImm { dst: 1, imm: 2.71 },
                    Instruction::FMul { dst: 2, a: 0, b: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 4096],
        };
        let bytes1 = encode_e4(&module1);
        let bytes2 = encode_e4(&module2);
        assert_eq!(bytes1, bytes2, "equal modules encode to equal bytes");
    }

    #[test]
    fn test_e4_encode_different_instructions_different_sizes() {
        // Property: different instructions encode to different sizes
        let trap_module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Trap],
            }],
            memory: vec![0u8; 256],
        };
        let ret_module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Ret { dst: 0 }],
            }],
            memory: vec![0u8; 256],
        };
        let fimm_module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FImm { dst: 0, imm: 1.0 }],
            }],
            memory: vec![0u8; 256],
        };
        let bytes_trap = encode_e4(&trap_module);
        let bytes_ret = encode_e4(&ret_module);
        let bytes_fimm = encode_e4(&fimm_module);
        // Trap=1 opcode, Ret=5 bytes, FImm=9 bytes
        assert_eq!(bytes_trap.len(), bytes_ret.len() - 4, "Trap should be 4 bytes shorter than Ret");
        assert_eq!(bytes_fimm.len(), bytes_ret.len() + 4, "FImm should be 4 bytes longer than Ret");
    }
}
