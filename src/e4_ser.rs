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
use crate::exec::e4::{E4FunctionDef, E4Module, E4Value, Instruction};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Write};

const MAGIC: &[u8] = b"E4XX";
const VERSION: u8 = 1;

/// Encode an E4Module to binary format.
pub fn encode_e4(module: &E4Module) -> Vec<u8> {
    let mut buf = Vec::new();

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
        _ => Err(Error::Generic(format!("E4: unknown opcode {:#04x}", opcode))),
    }
}

// ---------------------------------------------------------------------------
// Roundtrip tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::e4::{E4Executor, E4Module};

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
}
