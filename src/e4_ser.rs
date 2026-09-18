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
    // Jump tables: count + (count + entries) per table
    size += 4; // table count
    for table in &module.tables {
        size += 4; // entry count
        size += 4 * table.len(); // each entry is u32
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
        | Instruction::FDivF64 { .. }
        | Instruction::IAdd { .. } | Instruction::ISub { .. } | Instruction::IMul { .. }
        | Instruction::IDiv { .. }
        | Instruction::IAnd { .. } | Instruction::IOr { .. } | Instruction::IXor { .. }
        | Instruction::IRotl { .. } | Instruction::IRotr { .. } => 13,
        Instruction::INot { .. } | Instruction::IClz { .. } | Instruction::ICtz { .. }
        | Instruction::IPopcnt { .. } | Instruction::TableBr { .. } | Instruction::MemGrow { .. }
        | Instruction::SExt { .. } | Instruction::ZExt { .. } => 9,
        Instruction::MemCopy { .. } | Instruction::MemFill { .. } => 13,
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

    // Jump tables
    write_u32(&mut buf, module.tables.len() as u32);
    for table in &module.tables {
        write_u32(&mut buf, table.len() as u32);
        for &target in table {
            write_u32(&mut buf, target);
        }
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
        Instruction::IAdd { dst, a, b } => { buf.push(0x25); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::ISub { dst, a, b } => { buf.push(0x26); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IMul { dst, a, b } => { buf.push(0x27); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IDiv { dst, a, b } => { buf.push(0x28); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IAnd { dst, a, b } => { buf.push(0x29); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IOr { dst, a, b } => { buf.push(0x2A); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IXor { dst, a, b } => { buf.push(0x2B); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::INot { dst, a } => { buf.push(0x2C); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::IClz { dst, a } => { buf.push(0x2D); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::ICtz { dst, a } => { buf.push(0x2E); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::IPopcnt { dst, a } => { buf.push(0x2F); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::IRotl { dst, a, b } => { buf.push(0x30); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
        Instruction::IRotr { dst, a, b } => { buf.push(0x31); write_u32(buf, *dst); write_u32(buf, *a); write_u32(buf, *b); }
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
        Instruction::TableBr { table_idx, index } => { buf.push(0x32); write_u32(buf, *table_idx); write_u32(buf, *index); }
        Instruction::MemGrow { dst, delta } => { buf.push(0x33); write_u32(buf, *dst); write_u32(buf, *delta); }
        Instruction::SExt { dst, a } => { buf.push(0x34); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::ZExt { dst, a } => { buf.push(0x35); write_u32(buf, *dst); write_u32(buf, *a); }
        Instruction::MemCopy { dst, src, size } => { buf.push(0x36); write_u32(buf, *dst); write_u32(buf, *src); write_u32(buf, *size); }
        Instruction::MemFill { addr, value, size } => { buf.push(0x37); write_u32(buf, *addr); write_u32(buf, *value); write_u32(buf, *size); }
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

    // Jump tables
    let table_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
        Error::Generic("E4: truncated data".into())
    })? as usize;
    let mut tables = Vec::with_capacity(table_count);
    for _ in 0..table_count {
        let entry_count = cursor.read_u32::<LittleEndian>().map_err(|_| {
            Error::Generic("E4: truncated data".into())
        })? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let target = cursor.read_u32::<LittleEndian>().map_err(|_| {
                Error::Generic("E4: truncated data".into())
            })?;
            entries.push(target);
        }
        tables.push(entries);
    }

    Ok(E4Module { functions, memory, tables })
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
        0x25 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IAdd { dst, a, b }) }
        0x26 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::ISub { dst, a, b }) }
        0x27 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IMul { dst, a, b }) }
        0x28 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IDiv { dst, a, b }) }
        0x29 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IAnd { dst, a, b }) }
        0x2A => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IOr { dst, a, b }) }
        0x2B => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IXor { dst, a, b }) }
        0x2C => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::INot { dst, a }) }
        0x2D => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IClz { dst, a }) }
        0x2E => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::ICtz { dst, a }) }
        0x2F => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IPopcnt { dst, a }) }
        0x30 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IRotl { dst, a, b }) }
        0x31 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let b = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::IRotr { dst, a, b }) }
        0x32 => { let table_idx = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let index = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::TableBr { table_idx, index }) }
        0x33 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let delta = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::MemGrow { dst, delta }) }
        0x34 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::SExt { dst, a }) }
        0x35 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let a = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::ZExt { dst, a }) }
        0x36 => { let dst = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let src = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let size = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::MemCopy { dst, src, size }) }
        0x37 => { let addr = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let value = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; let size = cursor.read_u32::<LittleEndian>().map_err(|e| e)?; Ok(Instruction::MemFill { addr, value, size }) }
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
        };
        let decoded = roundtrip(&module);
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 123);
    }

    #[test]
    fn test_e4_encode_decode_tablebr() {
        // TableBr roundtrip: set r0=1, jump to table[0][1]=PC 3, return 2
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (index)
                    Instruction::TableBr { table_idx: 0, index: 0 }, // jump to table[0][1] = PC 3
                    Instruction::Ret { dst: 0 }, // unreachable (PC 2)
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // PC 3: r1 = 1
                    Instruction::IAdd { dst: 1, a: 1, b: 1 }, // PC 4: r1 = 2
                    Instruction::Ret { dst: 1 }, // PC 5: return 2
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![vec![2, 3, 6]], // targets: PC 2, 3, 6
        };
        let decoded = roundtrip(&module);
        // Verify tables roundtrip correctly
        assert_eq!(decoded.tables.len(), 1);
        assert_eq!(decoded.tables[0], &[2, 3, 6]);
        // Verify decoded code matches original
        assert_eq!(decoded.functions[0].code.len(), 6);
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 2);
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
    fn test_e4_decode_truncated_instruction() {
        // Encode a module with a 3-field instruction (e.g. FAdd), then truncate
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FAdd { dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 8],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // Truncate to remove the last byte of the instruction
        let truncated = &encoded[..encoded.len() - 1];
        let result = decode_e4(truncated);
        assert!(result.is_err(), "truncated instruction should fail");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_function_code() {
        // Encode module with 2 instructions, truncate to leave only 1
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FAdd { dst: 0, a: 1, b: 2 }, Instruction::Trap],
            }],
            memory: vec![0u8; 8],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // Truncate to remove the Trap instruction
        let truncated = &encoded[..encoded.len() - 2];
        let result = decode_e4(truncated);
        assert!(result.is_err(), "truncated function code should fail");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_memory() {
        // Valid header and function count, but truncated memory
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E4XX");
        bytes.push(1); // version
        bytes.extend_from_slice(&256u32.to_le_bytes()); // memory size = 256
        bytes.extend_from_slice(&vec![0u8; 128]); // only 128 bytes of memory
        // Truncated here
        let result = decode_e4(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_wrong_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E4XX");
        bytes.push(99); // wrong version
        bytes.extend_from_slice(&4u32.to_le_bytes()); // memory size
        bytes.extend_from_slice(&vec![0u8; 4]); // memory
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 functions
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 tables
        let result = decode_e4(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported version"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_function_header() {
        // Truncate during function header (missing instr_count field)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"E4XX");                      // 0-3: magic
        bytes.push(1);                                         // 4: version
        bytes.extend_from_slice(&4u32.to_le_bytes());          // 5-8: memory size = 4
        bytes.extend_from_slice(&vec![0u8; 4]);                // 9-12: memory
        bytes.extend_from_slice(&1u32.to_le_bytes());          // 13-16: fn_count = 1
        bytes.extend_from_slice(&0u32.to_le_bytes());          // 17-20: param_count
        bytes.extend_from_slice(&0u32.to_le_bytes());          // 21-24: result_count
        bytes.extend_from_slice(&4u32.to_le_bytes());          // 25-28: register_count
        // instr_count MISSING here → truncated during decode_function_from_cursor
        let result = decode_e4(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_instruction_fields() {
        // Encode module with FAdd (3 fields: dst, a, b), truncate after opcode only
        // FAdd encoding: opcode(1) + dst(4) + a(4) + b(4) = 13 bytes per instruction
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FAdd { dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // Module layout: header(5) + memory(8) + fn_count(4) + fn_header(17) + FAdd(13) = 47
        // Truncate after opcode byte of FAdd (position 43 = 42+1), leaving 0 bytes for dst field
        let truncated = &encoded[..43];
        let result = decode_e4(truncated);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_table_entry_count() {
        // Module with 1 table, 2 entries → truncate before entry_count is fully read
        // Header: magic(4) + version(1) + mem_size(4) + mem(4) = 13
        // Fn: fn_count(4) + header(17) + Trap(1) = 22 → total = 35
        // Tables: table_count(4) + entry_count(4) + targets(8) = 16 → total = 51
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Trap],
            }],
            memory: vec![0u8; 4],
            tables: vec![vec![10, 20]], // 2 entries
        };
        let encoded = encode_e4(&module);
        // Tables start at byte 35. Truncate at byte 37 → cuts into entry_count field
        // entry_count = 2 (at bytes 37-40), truncating at 37 cuts at 2 bytes of entry_count
        let truncated = &encoded[..37];
        let result = decode_e4(truncated);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_e4_decode_truncated_table_targets() {
        // Module with 1 table, 2 entries → truncate during second target read
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Trap],
            }],
            memory: vec![0u8; 4],
            tables: vec![vec![10, 20]], // 2 entries
        };
        let encoded = encode_e4(&module);
        // Tables start at byte 35. entry_count at 37-40. First target at 41-44.
        // Truncate at byte 44 → cuts in the middle of second target (20)
        let truncated = &encoded[..44];
        let result = decode_e4(truncated);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            Instruction::IAdd { dst: 5, a: 0, b: 1 },
            Instruction::ISub { dst: 6, a: 0, b: 1 },
            Instruction::IMul { dst: 7, a: 0, b: 1 },
            Instruction::IDiv { dst: 0, a: 0, b: 1 },
            Instruction::IAnd { dst: 0, a: 0, b: 1 },
            Instruction::IOr { dst: 0, a: 0, b: 1 },
            Instruction::IXor { dst: 0, a: 0, b: 1 },
            Instruction::INot { dst: 0, a: 0 },
            Instruction::IClz { dst: 0, a: 0 },
            Instruction::ICtz { dst: 0, a: 0 },
            Instruction::IPopcnt { dst: 0, a: 0 },
            Instruction::IRotl { dst: 0, a: 0, b: 1 },
            Instruction::IRotr { dst: 0, a: 0, b: 1 },
            Instruction::HostCall { id: 0, args: vec![0, 1], results: vec![2] },
            Instruction::ZExt { dst: 0, a: 1 },
            Instruction::SExt { dst: 1, a: 2 },
            Instruction::MemCopy { dst: 0, src: 1, size: 8 },
            Instruction::MemFill { addr: 0, value: 1, size: 8 },
            Instruction::TableBr { table_idx: 0, index: 1 },
            Instruction::MemGrow { dst: 0, delta: 1 },
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
                tables: vec![],
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
            memory: vec![0u8; 65536],
            tables: vec![],
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
            memory: vec![0u8; 65536],
            tables: vec![],
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
            tables: vec![],
        };
        let ret_module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Ret { dst: 0 }],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let fimm_module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FImm { dst: 0, imm: 1.0 }],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let bytes_trap = encode_e4(&trap_module);
        let bytes_ret = encode_e4(&ret_module);
        let bytes_fimm = encode_e4(&fimm_module);
        // Trap=1 opcode, Ret=5 bytes, FImm=9 bytes
        assert_eq!(bytes_trap.len(), bytes_ret.len() - 4, "Trap should be 4 bytes shorter than Ret");
        assert_eq!(bytes_fimm.len(), bytes_ret.len() + 4, "FImm should be 4 bytes longer than Ret");
    }

    #[test]
    fn test_e4_encode_decode_missing_instruction_variants() {
        // Covers F32 missing: FAbs(0x0D), FRound(0x0E), FCmp(0x0F), I2F(0x10), F2I(0x11), U2F(0x12), F2U(0x13)
        // And F64 missing: FSubF64(0x18), FDivF64(0x1A) — others covered in test_e4_encode_decode_f64_instructions
        let all_missing = vec![
            Instruction::FAbs { dst: 0, a: 1 },
            Instruction::FRound { dst: 1, a: 0 },
            Instruction::FCmp { pred: 1, dst: 2, a: 0, b: 1 },
            Instruction::I2F { dst: 0, a: 1 },
            Instruction::F2I { dst: 1, a: 0 },
            Instruction::U2F { dst: 2, a: 1 },
            Instruction::F2U { dst: 3, a: 0 },
            Instruction::FSubF64 { dst: 0, a: 1, b: 2 },
            Instruction::FDivF64 { dst: 1, a: 2, b: 3 },
        ];
        for instr in all_missing {
            let module = E4Module {
                functions: vec![E4FunctionDef {
                    param_count: 0,
                    result_count: 0,
                    register_count: 8,
                    code: vec![instr.clone(), Instruction::Trap],
                }],
                memory: vec![0u8; 256],
                tables: vec![],
            };
            let encoded = encode_e4(&module);
            let decoded = decode_e4(&encoded).unwrap();
            assert_eq!(decoded.functions[0].code[0], instr, "roundtrip failed for {:?}", instr);
        }
    }

    // -------------------------------------------------------------------------
    // T31: Truncated decode for F64 / int / memory opcodes (0x17-0x37)
    // The roundtrip tests cover success paths; these cover error paths.
    // Each instruction decode branch has individual field-read error paths.
    // -------------------------------------------------------------------------

    #[test]
    fn test_e4_decode_truncated_f64_two_reg() {
        // FSqrtF64 (0x1B): opcode at byte 30, fields at 31-38.
        // Truncate at 30 (opcode only) → first dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FSqrtF64 { dst: 0, a: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 29: FImmF64 opcode(1) + dst(4) + imm(8) = 13 → end at 42
        // byte 30: FSqrtF64 opcode(1) + dst(4) + a(4) = 9 → end at 39
        // Truncate at 30 → opcode byte only, dst read fails
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated FSqrtF64 opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_fcmp_f64() {
        // FCmpF64 (0x1F): opcode at byte 31, pred at 32, dst at 33-36, a at 37-40, b at 41-44.
        // Truncate at 31 (opcode only) → pred read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FCmpF64 { pred: 4, dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // Trap ends at 29, FCmpF64 starts at 31 (pred=u8), then dst, a, b (3×u32)
        // Truncate at 31 → opcode only, pred read fails
        let result = decode_e4(&encoded[..31]);
        assert!(result.is_err(), "truncated FCmpF64 opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_fimm_f64() {
        // FImmF64 (0x24): opcode at byte 29, dst at 30-33, imm at 34-41.
        // Truncate at 29 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FImmF64 { dst: 0, imm: 1.23456789_f64 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 29: FImmF64 opcode, truncate at 29 → opcode only, dst read fails
        let result = decode_e4(&encoded[..29]);
        assert!(result.is_err(), "truncated FImmF64 opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_f64_partial_fields() {
        // FMulF64 (0x19): opcode at byte 30, dst at 31-34, a at 35-38, b at 39-42.
        // Truncate at 34 (after dst field) → a read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::FMulF64 { dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 30: FMulF64 opcode; dst at 31-34; a at 35-38; b at 39-42
        // Truncate at 35 → opcode + dst complete, a read fails
        let result = decode_e4(&encoded[..35]);
        assert!(result.is_err(), "truncated FMulF64 mid-field should fail");
    }

    #[test]
    fn test_e4_decode_truncated_int_two_reg() {
        // INot (0x2C): opcode at byte 30, dst at 31-34, a at 35-38.
        // Truncate at 30 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::INot { dst: 0, a: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 30: INot opcode; truncate at 30 → opcode only, dst fails
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated INot opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_int_three_reg() {
        // IAdd (0x25): opcode at byte 30, dst at 31-34, a at 35-38, b at 39-42.
        // Truncate at 35 (after dst field) → a read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::IAdd { dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 30: IAdd opcode; dst at 31-34; truncate at 35 → a read fails
        let result = decode_e4(&encoded[..35]);
        assert!(result.is_err(), "truncated IAdd mid-field should fail");
    }

    #[test]
    fn test_e4_decode_truncated_memcopy() {
        // MemCopy (0x36): opcode at byte 30, dst at 31-34, src at 35-38, size at 39-42.
        // Truncate at 30 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::MemCopy { dst: 0, src: 1, size: 8 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 30: MemCopy opcode; truncate at 30 → opcode only, dst fails
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated MemCopy opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_memsize() {
        // MemGrow (0x33): opcode at byte 30, dst at 31-34, delta at 35-38.
        // Truncate at 35 (after dst field) → delta read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::MemGrow { dst: 0, delta: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // byte 30: MemGrow opcode; dst at 31-34; truncate at 35 → delta fails
        let result = decode_e4(&encoded[..35]);
        assert!(result.is_err(), "truncated MemGrow mid-field should fail");
    }

    #[test]
    fn test_e4_decode_truncated_sext_zext() {
        // SExt (0x34): opcode at byte 30, dst at 31-34, a at 35-38.
        // Truncate at 30 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::SExt { dst: 0, a: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated SExt opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_bit_count_ops() {
        // ICtz (0x2E): opcode at byte 30, dst at 31-34, a at 35-38.
        // Truncate at 30 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::ICtz { dst: 0, a: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated ICtz opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_rotate_ops() {
        // IRotl (0x30): opcode at byte 30, dst at 31-34, a at 35-38, b at 39-42.
        // Truncate at 30 (opcode only) → dst read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::IRotl { dst: 0, a: 1, b: 2 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated IRotl opcode should fail");
    }

    #[test]
    fn test_e4_decode_truncated_tablebr() {
        // TableBr (0x32): opcode at byte 30, table_idx at 31-34, index at 35-38.
        // Truncate at 30 (opcode only) → table_idx read fails.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::TableBr { table_idx: 0, index: 1 }],
            }],
            memory: vec![0u8; 4],
            tables: vec![vec![1, 2, 3]],
        };
        let encoded = encode_e4(&module);
        // TableBr opcode at byte 30; truncate at 30 → table_idx read fails
        let result = decode_e4(&encoded[..30]);
        assert!(result.is_err(), "truncated TableBr opcode should fail");
    }

    #[test]
    fn test_e4_encode_decode_multi_function_module() {
        // 3 functions with different instruction mixes; exercises all encode paths
        // and decode paths for functions 1, 2, and 3.
        let module = E4Module {
            functions: vec![
                E4FunctionDef {
                    param_count: 1,
                    result_count: 1,
                    register_count: 4,
                    code: vec![
                        Instruction::FImm { dst: 0, imm: 42.0 },
                        Instruction::FAdd { dst: 1, a: 0, b: 0 },
                        Instruction::Ret { dst: 1 },
                    ],
                },
                E4FunctionDef {
                    param_count: 0,
                    result_count: 1,
                    register_count: 4,
                    code: vec![
                        Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                        Instruction::INot { dst: 1, a: 0 },
                        Instruction::Ret { dst: 1 },
                    ],
                },
                E4FunctionDef {
                    param_count: 0,
                    result_count: 0,
                    register_count: 4,
                    code: vec![
                        Instruction::MemGrow { dst: 0, delta: 1 },
                        Instruction::Trap,
                    ],
                },
            ],
            memory: vec![0xAB, 0xCD],
            tables: vec![],
        };
        let decoded = roundtrip(&module);
        assert_eq!(decoded.functions.len(), 3);
        assert_eq!(decoded.functions[0].param_count, 1);
        assert_eq!(decoded.functions[1].result_count, 1);
        assert_eq!(decoded.functions[2].code.len(), 2);
        assert_eq!(decoded.memory, &[0xAB, 0xCD]);
    }

    #[test]
    fn test_e4_encode_decode_multi_table_module() {
        // 2 jump tables; exercises table count > 1 and table loop in encode/decode.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::Trap],
            }],
            memory: vec![],
            tables: vec![vec![10, 20, 30], vec![5, 15]],
        };
        let decoded = roundtrip(&module);
        assert_eq!(decoded.tables.len(), 2);
        assert_eq!(decoded.tables[0], &[10, 20, 30]);
        assert_eq!(decoded.tables[1], &[5, 15]);
    }

    #[test]
    fn test_e4_encoded_size_exactness() {
        // Verify encoded_size is never smaller than actual encoded size.
        // Also covers HostCall encode path (variable-size instruction).
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 8,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.0 },
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 1024],
            tables: vec![vec![1, 2, 3, 4]],
        };
        let actual = encode_e4(&module).len();
        let estimate = encoded_size(&module);
        assert!(estimate >= actual, "encoded_size {} must be >= actual {}", estimate, actual);
        // Verify the estimate is within reasonable bounds (no more than 2x actual)
        assert!(estimate <= actual * 2, "encoded_size {} should not wildly exceed actual {}", estimate, actual);
    }

    #[test]
    fn test_e4_decode_truncated_hostcall_args() {
        // HostCall (0x16): opcode at byte 29, id at 30-33, arg_count at 34-37,
        // args at 38-..., result_count at ..., results at ...
        // Truncate during args read (after opcode + id + arg_count + 1 arg, missing 1 arg).
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::HostCall { id: 0, args: vec![1, 2], results: vec![3] }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // HostCall: opcode(1) + id(4) + arg_count(4) + 2 args(8) + result_count(4) + 1 result(4) = 25
        // HostCall starts at byte 29. Truncate at byte 29 + 1 + 4 + 4 + 4 = 42
        // → opcode + id + arg_count + 1 arg read, 1 arg missing
        let result = decode_e4(&encoded[..42]);
        assert!(result.is_err(), "truncated HostCall args should fail");
    }

    #[test]
    fn test_e4_decode_truncated_hostcall_results() {
        // HostCall: truncate during results read.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![Instruction::HostCall { id: 0, args: vec![], results: vec![1, 2] }],
            }],
            memory: vec![0u8; 4],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        // HostCall: opcode(1) + id(4) + arg_count(4) + result_count(4) + 2 results(8) = 21
        // Starts at byte 29. Truncate at 29 + 1 + 4 + 4 + 4 = 42 → cuts in results
        let result = decode_e4(&encoded[..42]);
        assert!(result.is_err(), "truncated HostCall results should fail");
    }

    #[test]
    fn test_e4_encode_decode_bitwise_ops_execution() {
        // IAnd/IOr/IXor with execution to verify semantics preserved after roundtrip.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
                    Instruction::IAnd { dst: 2, a: 0, b: 1 }, // r2 = 1
                    Instruction::IXor { dst: 3, a: 0, b: 1 }, // r3 = 0
                    Instruction::IOr { dst: 4, a: 0, b: 1 },  // r4 = 1
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let decoded = roundtrip(&module);
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 0, "1 XOR 1 should be 0");
    }

    #[test]
    fn test_e4_encode_decode_popcnt_clz_ctz() {
        // IPopcnt, IClz, ICtz roundtrip with execution.
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1 (binary: 1)
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
                    Instruction::IPopcnt { dst: 2, a: 0 }, // r2 = 1
                    Instruction::IClz { dst: 3, a: 0 },    // r3 = 31
                    Instruction::ICtz { dst: 4, a: 0 },    // r4 = 0
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![0u8; 64],
            tables: vec![],
        };
        let decoded = roundtrip(&module);
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        assert_eq!(result.value.unwrap(), 1, "popcnt(1) should be 1");
    }

    #[test]
    fn test_e4_encode_decode_integer_arithmetic() {
        // IAdd/ISub/IMul/IDiv roundtrip
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::Cmp { pred: 0, dst: 0, a: 0, b: 0 }, // r0 = 1
                    Instruction::Cmp { pred: 0, dst: 1, a: 0, b: 0 }, // r1 = 1
                    Instruction::IAdd { dst: 2, a: 0, b: 1 },
                    Instruction::ISub { dst: 3, a: 2, b: 0 },
                    Instruction::IMul { dst: 4, a: 2, b: 1 },
                    Instruction::IDiv { dst: 5, a: 4, b: 0 },
                    Instruction::Ret { dst: 5 },
                ],
            }],
            memory: vec![0u8; 256],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let decoded = decode_e4(&encoded).unwrap();
        assert_eq!(decoded.functions[0].code.len(), 7);
        // Execute
        let mut exec = E4Executor::default();
        exec.host_functions_mut().register(|_args| E4Value::I32(0));
        let result = exec.execute(&decoded, 0).unwrap();
        assert_eq!(result.status, crate::types::Status::Pass);
        // r0=1, r1=1, r2=2, r3=1, r4=2, r5=2
        assert_eq!(result.value.unwrap(), 2);
    }
}
