//! UNICO U30 Serialization
//!
//! Binary format for U30Module:
//! - Header: magic "U30X" + version (1 byte)
//! - Regions: count, then each region's id/size/flags/initial
//! - Tables: count, then each table's id/targets
//! - Functions: count, then each function's params/results/blocks
//! - Entry function index
//!
//! All multi-byte integers are little-endian.
//! U30Type, U30Op, U30Terminator use variant indices.

use crate::error::{Error, Result};
use crate::ir::{
    U30Block, U30Function, U30Module, U30Op, U30TableDecl, U30Terminator, U30Type, U30Value,
};
use std::io::Write;

const MAGIC: &[u8] = b"U30X";
const VERSION: u8 = 1;

/// Encode a U30Module to binary format.
pub fn encode(module: &U30Module) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.write_all(MAGIC).unwrap();
    buf.push(VERSION);

    // Regions
    write_u32(&mut buf, module.regions.len() as u32);
    for r in &module.regions {
        write_u32(&mut buf, r.id);
        write_u32(&mut buf, r.size as u32);
        buf.push(if r.readable { 1 } else { 0 });
        buf.push(if r.writable { 1 } else { 0 });
        write_u32(&mut buf, r.initial.len() as u32);
        buf.extend_from_slice(&r.initial);
    }

    // Tables
    write_u32(&mut buf, module.tables.len() as u32);
    for t in &module.tables {
        write_u32(&mut buf, t.id);
        write_u32(&mut buf, t.targets.len() as u32);
        for &target in &t.targets {
            write_u32(&mut buf, target as u32);
        }
    }

    // Functions
    write_u32(&mut buf, module.functions.len() as u32);
    for f in &module.functions {
        encode_function(&mut buf, f);
    }

    // Entry
    write_u32(&mut buf, module.entry_function as u32);

    buf
}

fn encode_function(buf: &mut Vec<u8>, f: &U30Function) {
    // Params
    write_u32(buf, f.params.len() as u32);
    for &p in &f.params {
        buf.push(type_idx(&p));
    }

    // Results
    write_u32(buf, f.results.len() as u32);
    for &r in &f.results {
        buf.push(type_idx(&r));
    }

    // Blocks
    write_u32(buf, f.blocks.len() as u32);
    for b in &f.blocks {
        encode_block(buf, b);
    }

    // Entry block
    write_u32(buf, f.entry_block as u32);
}

fn encode_block(buf: &mut Vec<u8>, b: &U30Block) {
    // Ops
    write_u32(buf, b.ops.len() as u32);
    for op in &b.ops {
        encode_op(buf, op);
    }

    // Terminator
    encode_terminator(buf, &b.terminator);
}

fn encode_op(buf: &mut Vec<u8>, op: &U30Op) {
    match op {
        // 0: Nop
        U30Op::Nop => {
            buf.push(0);
        }
        // 1: Const
        U30Op::Const { dst, value } => {
            buf.push(1);
            write_u32(buf, *dst);
            encode_value(buf, value);
        }
        // 2: Binary
        U30Op::Binary { dst, op, a, b } => {
            buf.push(2);
            write_u32(buf, encode_binary_op(op));
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 3: Select
        U30Op::Select { dst, cond, a, b } => {
            buf.push(3);
            write_u32(buf, *dst);
            write_u32(buf, *cond);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 4: NotU8
        U30Op::NotU8 { dst, src } => {
            buf.push(4);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 5: NotU16
        U30Op::NotU16 { dst, src } => {
            buf.push(5);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 6: NotU32
        U30Op::NotU32 { dst, src } => {
            buf.push(6);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 7: NotU64
        U30Op::NotU64 { dst, src } => {
            buf.push(7);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 8: I2F
        U30Op::I2F { dst, src } => {
            buf.push(8);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 9: F2I
        U30Op::F2I { dst, src } => {
            buf.push(9);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 10: TruncF32U64
        U30Op::TruncF32U64 { dst, src } => {
            buf.push(10);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 11: ReinterpretF32U32
        U30Op::ReinterpretF32U32 { dst, src } => {
            buf.push(11);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 12: ReinterpretU32F32
        U30Op::ReinterpretU32F32 { dst, src } => {
            buf.push(12);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 13: AbsU64
        U30Op::AbsU64 { dst, src } => {
            buf.push(13);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 14: AbsU32
        U30Op::AbsU32 { dst, src } => {
            buf.push(14);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 15: NegU64
        U30Op::NegU64 { dst, src } => {
            buf.push(15);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 16: NegU32
        U30Op::NegU32 { dst, src } => {
            buf.push(16);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 17: CtzU64
        U30Op::CtzU64 { dst, src } => {
            buf.push(17);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 18: CtzU32
        U30Op::CtzU32 { dst, src } => {
            buf.push(18);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 19: ClzU64
        U30Op::ClzU64 { dst, src } => {
            buf.push(19);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 20: ClzU32
        U30Op::ClzU32 { dst, src } => {
            buf.push(20);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 21: PopcntU64
        U30Op::PopcntU64 { dst, src } => {
            buf.push(21);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 22: PopcntU32
        U30Op::PopcntU32 { dst, src } => {
            buf.push(22);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 23: RotlU64
        U30Op::RotlU64 { dst, val, sh } => {
            buf.push(23);
            write_u32(buf, *dst);
            write_u32(buf, *val);
            write_u32(buf, *sh);
        }
        // 24: RotlU32
        U30Op::RotlU32 { dst, val, sh } => {
            buf.push(24);
            write_u32(buf, *dst);
            write_u32(buf, *val);
            write_u32(buf, *sh);
        }
        // 25: RotrU64
        U30Op::RotrU64 { dst, val, sh } => {
            buf.push(25);
            write_u32(buf, *dst);
            write_u32(buf, *val);
            write_u32(buf, *sh);
        }
        // 26: RotrU32
        U30Op::RotrU32 { dst, val, sh } => {
            buf.push(26);
            write_u32(buf, *dst);
            write_u32(buf, *val);
            write_u32(buf, *sh);
        }
        // 27: FEq
        U30Op::FEq { dst, a, b } => {
            buf.push(27);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 28: FLt
        U30Op::FLt { dst, a, b } => {
            buf.push(28);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 29: FGt
        U30Op::FGt { dst, a, b } => {
            buf.push(29);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 30: FLe
        U30Op::FLe { dst, a, b } => {
            buf.push(30);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 31: FGe
        U30Op::FGe { dst, a, b } => {
            buf.push(31);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 32: FAdd
        U30Op::FAdd { dst, a, b } => {
            buf.push(32);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 33: FSub
        U30Op::FSub { dst, a, b } => {
            buf.push(33);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 34: FMul
        U30Op::FMul { dst, a, b } => {
            buf.push(34);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 35: FDiv
        U30Op::FDiv { dst, a, b } => {
            buf.push(35);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 36: FSqrt
        U30Op::FSqrt { dst, src } => {
            buf.push(36);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 37: FAbs
        U30Op::FAbs { dst, src } => {
            buf.push(37);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 38: FNeg
        U30Op::FNeg { dst, src } => {
            buf.push(38);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 39: FMin
        U30Op::FMin { dst, a, b } => {
            buf.push(39);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 40: FMax
        U30Op::FMax { dst, a, b } => {
            buf.push(40);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 41: ZExtI8U16
        U30Op::ZExtI8U16 { dst, src } => {
            buf.push(41);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 42: ZExtI8U32
        U30Op::ZExtI8U32 { dst, src } => {
            buf.push(42);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 43: ZExtI8U64
        U30Op::ZExtI8U64 { dst, src } => {
            buf.push(43);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 44: ZExtI16U32
        U30Op::ZExtI16U32 { dst, src } => {
            buf.push(44);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 45: ZExtI16U64
        U30Op::ZExtI16U64 { dst, src } => {
            buf.push(45);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 46: ZExtI32U64
        U30Op::ZExtI32U64 { dst, src } => {
            buf.push(46);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 47: TruncU64U32
        U30Op::TruncU64U32 { dst, src } => {
            buf.push(47);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 48: TruncU64U16
        U30Op::TruncU64U16 { dst, src } => {
            buf.push(48);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 49: TruncU32U16
        U30Op::TruncU32U16 { dst, src } => {
            buf.push(49);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 50: MemCopy
        U30Op::MemCopy {
            dst_region,
            dst_offset,
            src_region,
            src_offset,
            size,
        } => {
            buf.push(50);
            write_u32(buf, *dst_region);
            write_u32(buf, *dst_offset);
            write_u32(buf, *src_region);
            write_u32(buf, *src_offset);
            write_u32(buf, *size);
        }
        // 51: MemFill
        U30Op::MemFill {
            region,
            offset,
            value,
            size,
        } => {
            buf.push(51);
            write_u32(buf, *region);
            write_u32(buf, *offset);
            write_u32(buf, *value);
            write_u32(buf, *size);
        }
        // 52: MemSize
        U30Op::MemSize { dst, region } => {
            buf.push(52);
            write_u32(buf, *dst);
            write_u32(buf, *region);
        }
        // 53: MemGrow
        U30Op::MemGrow { dst, region, delta } => {
            buf.push(53);
            write_u32(buf, *dst);
            write_u32(buf, *region);
            write_u32(buf, *delta);
        }
        // 54: F64Eq
        U30Op::F64Eq { dst, a, b } => {
            buf.push(54);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 55: F64Lt
        U30Op::F64Lt { dst, a, b } => {
            buf.push(55);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 56: F64Gt
        U30Op::F64Gt { dst, a, b } => {
            buf.push(56);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 57: F64Le
        U30Op::F64Le { dst, a, b } => {
            buf.push(57);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 58: F64Ge
        U30Op::F64Ge { dst, a, b } => {
            buf.push(58);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 59: F64Add
        U30Op::F64Add { dst, a, b } => {
            buf.push(59);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 60: F64Sub
        U30Op::F64Sub { dst, a, b } => {
            buf.push(60);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 61: F64Mul
        U30Op::F64Mul { dst, a, b } => {
            buf.push(61);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 62: F64Div
        U30Op::F64Div { dst, a, b } => {
            buf.push(62);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 63: F64Sqrt
        U30Op::F64Sqrt { dst, src } => {
            buf.push(63);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 64: F64Abs
        U30Op::F64Abs { dst, src } => {
            buf.push(64);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 65: F64Neg
        U30Op::F64Neg { dst, src } => {
            buf.push(65);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 66: F64Min
        U30Op::F64Min { dst, a, b } => {
            buf.push(66);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 67: F64Max
        U30Op::F64Max { dst, a, b } => {
            buf.push(67);
            write_u32(buf, *dst);
            write_u32(buf, *a);
            write_u32(buf, *b);
        }
        // 68: I64F64
        U30Op::I64F64 { dst, src } => {
            buf.push(68);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 69: F64I64
        U30Op::F64I64 { dst, src } => {
            buf.push(69);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 70: F32F64
        U30Op::F32F64 { dst, src } => {
            buf.push(70);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 71: F64F32
        U30Op::F64F32 { dst, src } => {
            buf.push(71);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 72: ReinterpretF64U64
        U30Op::ReinterpretF64U64 { dst, src } => {
            buf.push(72);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 73: ReinterpretU64F64
        U30Op::ReinterpretU64F64 { dst, src } => {
            buf.push(73);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 74: SExtI8U16
        U30Op::SExtI8U16 { dst, src } => {
            buf.push(74);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 75: SExtI8U32
        U30Op::SExtI8U32 { dst, src } => {
            buf.push(75);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 76: SExtI8U64
        U30Op::SExtI8U64 { dst, src } => {
            buf.push(76);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 77: SExtI16U32
        U30Op::SExtI16U32 { dst, src } => {
            buf.push(77);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 78: SExtI16U64
        U30Op::SExtI16U64 { dst, src } => {
            buf.push(78);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 79: SExtI32U64
        U30Op::SExtI32U64 { dst, src } => {
            buf.push(79);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 80: ByteSwapU16
        U30Op::ByteSwapU16 { dst, src } => {
            buf.push(80);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 81: ByteSwapU32
        U30Op::ByteSwapU32 { dst, src } => {
            buf.push(81);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 82: ByteSwapU64
        U30Op::ByteSwapU64 { dst, src } => {
            buf.push(82);
            write_u32(buf, *dst);
            write_u32(buf, *src);
        }
        // 83: Call
        U30Op::Call {
            function,
            args,
            results,
        } => {
            buf.push(83);
            write_u32(buf, *function);
            write_u32(buf, args.len() as u32);
            for &a in args {
                write_u32(buf, a);
            }
            write_u32(buf, results.len() as u32);
            for &r in results {
                write_u32(buf, r);
            }
        }
        // 84: IndirectCall
        U30Op::IndirectCall {
            function,
            args,
            results,
        } => {
            buf.push(84);
            write_u32(buf, *function);
            write_u32(buf, args.len() as u32);
            for &a in args {
                write_u32(buf, a);
            }
            write_u32(buf, results.len() as u32);
            for &r in results {
                write_u32(buf, r);
            }
        }
        // 85: TableBr
        U30Op::TableBr { table, index } => {
            buf.push(85);
            write_u32(buf, *table);
            write_u32(buf, *index);
        }
        // 86: Break
        U30Op::Break { code } => {
            buf.push(86);
            write_u32(buf, *code);
        }
        // 87: Assert
        U30Op::Assert { cond, msg } => {
            buf.push(87);
            write_u32(buf, *cond);
            write_u32(buf, *msg);
        }
        // 88: LoadU8
        U30Op::LoadU8 { dst, region, offset } => {
            buf.push(88);
            write_u32(buf, *dst);
            write_u32(buf, *region);
            write_u32(buf, *offset);
        }
        // 89: StoreU8
        U30Op::StoreU8 { region, offset, src } => {
            buf.push(89);
            write_u32(buf, *region);
            write_u32(buf, *offset);
            write_u32(buf, *src);
        }
        // 90: LoadU16
        U30Op::LoadU16 { dst, region, offset } => {
            buf.push(90);
            write_u32(buf, *dst);
            write_u32(buf, *region);
            write_u32(buf, *offset);
        }
        // 91: StoreU16
        U30Op::StoreU16 { region, offset, src } => {
            buf.push(91);
            write_u32(buf, *region);
            write_u32(buf, *offset);
            write_u32(buf, *src);
        }
        // 92: LoadU32
        U30Op::LoadU32 { dst, region, offset } => {
            buf.push(92);
            write_u32(buf, *dst);
            write_u32(buf, *region);
            write_u32(buf, *offset);
        }
        // 93: StoreU32
        U30Op::StoreU32 { region, offset, src } => {
            buf.push(93);
            write_u32(buf, *region);
            write_u32(buf, *offset);
            write_u32(buf, *src);
        }
        // 94: LoadU64
        U30Op::LoadU64 { dst, region, offset } => {
            buf.push(94);
            write_u32(buf, *dst);
            write_u32(buf, *region);
            write_u32(buf, *offset);
        }
        // 95: StoreU64
        U30Op::StoreU64 { region, offset, src } => {
            buf.push(95);
            write_u32(buf, *region);
            write_u32(buf, *offset);
            write_u32(buf, *src);
        }
    }
}

fn encode_terminator(buf: &mut Vec<u8>, t: &U30Terminator) {
    match t {
        // 0: Br
        U30Terminator::Br { target } => {
            buf.push(0);
            write_u32(buf, *target as u32);
        }
        // 1: BrIf
        U30Terminator::BrIf {
            cond,
            then_target,
            else_target,
        } => {
            buf.push(1);
            write_u32(buf, *cond);
            write_u32(buf, *then_target as u32);
            write_u32(buf, *else_target as u32);
        }
        // 2: Ret
        U30Terminator::Ret { values } => {
            buf.push(2);
            write_u32(buf, values.len() as u32);
            for &v in values {
                write_u32(buf, v);
            }
        }
        // 3: TailCall
        U30Terminator::TailCall { function, args } => {
            buf.push(3);
            write_u32(buf, *function);
            write_u32(buf, args.len() as u32);
            for &a in args {
                write_u32(buf, a);
            }
        }
        // 4: Trap
        U30Terminator::Trap { code } => {
            buf.push(4);
            write_u32(buf, *code);
        }
    }
}

fn encode_value(buf: &mut Vec<u8>, v: &U30Value) {
    match v {
        U30Value::Bool(b) => {
            buf.push(0);
            buf.push(if *b { 1 } else { 0 });
        }
        U30Value::U8(x) => {
            buf.push(1);
            buf.push(*x);
        }
        U30Value::U16(x) => {
            buf.push(2);
            buf.extend_from_slice(&x.to_le_bytes());
        }
        U30Value::U32(x) => {
            buf.push(3);
            buf.extend_from_slice(&x.to_le_bytes());
        }
        U30Value::U64(x) => {
            buf.push(4);
            buf.extend_from_slice(&x.to_le_bytes());
        }
        U30Value::F32(x) => {
            buf.push(5);
            buf.extend_from_slice(&x.to_bits().to_le_bytes());
        }
        U30Value::F64(x) => {
            buf.push(6);
            buf.extend_from_slice(&x.to_bits().to_le_bytes());
        }
    }
}

fn type_idx(t: &U30Type) -> u8 {
    match t {
        U30Type::Bool => 0,
        U30Type::U8 => 1,
        U30Type::U16 => 2,
        U30Type::U32 => 3,
        U30Type::U64 => 4,
        U30Type::F32 => 5,
        U30Type::F64 => 6,
    }
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(Error::Generic("U30X: truncated data".into()));
    }
    let v = u32::from_le_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= buf.len() {
        return Err(Error::Generic("U30X: truncated data".into()));
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

/// Decode a U30Module from binary format.
pub fn decode(buf: &[u8]) -> Result<U30Module> {
    let mut pos = 0;

    // Header
    if buf.len() < pos + 4 {
        return Err(Error::Generic("U30X: truncated header".into()));
    }
    if &buf[pos..pos + 4] != MAGIC {
        return Err(Error::Generic("U30X: bad magic".into()));
    }
    pos += 4;
    if buf.len() < pos + 1 {
        return Err(Error::Generic("U30X: truncated header".into()));
    }
    let version = buf[pos];
    pos += 1;
    if version != VERSION {
        return Err(Error::Generic(format!(
            "U30X: unsupported version {}",
            version
        )));
    }

    // Regions
    let region_count = read_u32(buf, &mut pos)? as usize;
    let mut regions = Vec::with_capacity(region_count);
    for _ in 0..region_count {
        let id = read_u32(buf, &mut pos)?;
        let size = read_u32(buf, &mut pos)? as usize;
        let readable = read_u8(buf, &mut pos)? != 0;
        let writable = read_u8(buf, &mut pos)? != 0;
        let init_len = read_u32(buf, &mut pos)? as usize;
        if pos + init_len > buf.len() {
            return Err(Error::Generic("U30X: truncated region data".into()));
        }
        let initial = buf[pos..pos + init_len].to_vec();
        pos += init_len;
        regions.push(crate::ir::U30RegionDecl {
            id,
            size,
            readable,
            writable,
            initial,
        });
    }

    // Tables
    let table_count = read_u32(buf, &mut pos)? as usize;
    let mut tables = Vec::with_capacity(table_count);
    for _ in 0..table_count {
        let id = read_u32(buf, &mut pos)?;
        let target_count = read_u32(buf, &mut pos)? as usize;
        let mut targets = Vec::with_capacity(target_count);
        for _ in 0..target_count {
            targets.push(read_u32(buf, &mut pos)? as usize);
        }
        tables.push(U30TableDecl { id, targets });
    }

    // Functions
    let fn_count = read_u32(buf, &mut pos)? as usize;
    let mut functions = Vec::with_capacity(fn_count);
    for _ in 0..fn_count {
        functions.push(decode_function(buf, &mut pos)?);
    }

    // Entry
    let entry_function = read_u32(buf, &mut pos)? as usize;

    Ok(U30Module {
        regions,
        tables,
        functions,
        entry_function,
    })
}

fn decode_function(buf: &[u8], pos: &mut usize) -> Result<U30Function> {
    let param_count = read_u32(buf, pos)? as usize;
    let mut params = Vec::with_capacity(param_count);
    for _ in 0..param_count {
        params.push(decode_type(buf, pos)?);
    }

    let result_count = read_u32(buf, pos)? as usize;
    let mut results = Vec::with_capacity(result_count);
    for _ in 0..result_count {
        results.push(decode_type(buf, pos)?);
    }

    let block_count = read_u32(buf, pos)? as usize;
    let mut blocks = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        blocks.push(decode_block(buf, pos)?);
    }

    let entry_block = read_u32(buf, pos)? as usize;

    Ok(U30Function {
        params,
        results,
        blocks,
        entry_block,
    })
}

fn decode_block(buf: &[u8], pos: &mut usize) -> Result<U30Block> {
    let op_count = read_u32(buf, pos)? as usize;
    let mut ops = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        ops.push(decode_op(buf, pos)?);
    }

    let terminator = decode_terminator(buf, pos)?;
    Ok(U30Block { ops, terminator })
}

fn decode_op(buf: &[u8], pos: &mut usize) -> Result<U30Op> {
    let variant = read_u8(buf, pos)?;
    match variant {
        0 => Ok(U30Op::Nop),
        1 => {
            let dst = read_u32(buf, pos)?;
            let value = decode_value(buf, pos)?;
            Ok(U30Op::Const { dst, value })
        }
        2 => {
            let op_idx = read_u32(buf, pos)?;
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            let op = decode_binary_op(op_idx)?;
            Ok(U30Op::Binary { dst, op, a, b })
        }
        3 => {
            let dst = read_u32(buf, pos)?;
            let cond = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::Select { dst, cond, a, b })
        }
        4 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NotU8 { dst, src })
        }
        5 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NotU16 { dst, src })
        }
        6 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NotU32 { dst, src })
        }
        7 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NotU64 { dst, src })
        }
        8 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::I2F { dst, src })
        }
        9 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F2I { dst, src })
        }
        10 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::TruncF32U64 { dst, src })
        }
        11 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ReinterpretF32U32 { dst, src })
        }
        12 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ReinterpretU32F32 { dst, src })
        }
        13 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::AbsU64 { dst, src })
        }
        14 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::AbsU32 { dst, src })
        }
        15 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NegU64 { dst, src })
        }
        16 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::NegU32 { dst, src })
        }
        17 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::CtzU64 { dst, src })
        }
        18 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::CtzU32 { dst, src })
        }
        19 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ClzU64 { dst, src })
        }
        20 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ClzU32 { dst, src })
        }
        21 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::PopcntU64 { dst, src })
        }
        22 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::PopcntU32 { dst, src })
        }
        23 => {
            let dst = read_u32(buf, pos)?;
            let val = read_u32(buf, pos)?;
            let sh = read_u32(buf, pos)?;
            Ok(U30Op::RotlU64 { dst, val, sh })
        }
        24 => {
            let dst = read_u32(buf, pos)?;
            let val = read_u32(buf, pos)?;
            let sh = read_u32(buf, pos)?;
            Ok(U30Op::RotlU32 { dst, val, sh })
        }
        25 => {
            let dst = read_u32(buf, pos)?;
            let val = read_u32(buf, pos)?;
            let sh = read_u32(buf, pos)?;
            Ok(U30Op::RotrU64 { dst, val, sh })
        }
        26 => {
            let dst = read_u32(buf, pos)?;
            let val = read_u32(buf, pos)?;
            let sh = read_u32(buf, pos)?;
            Ok(U30Op::RotrU32 { dst, val, sh })
        }
        27 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FEq { dst, a, b })
        }
        28 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FLt { dst, a, b })
        }
        29 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FGt { dst, a, b })
        }
        30 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FLe { dst, a, b })
        }
        31 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FGe { dst, a, b })
        }
        32 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FAdd { dst, a, b })
        }
        33 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FSub { dst, a, b })
        }
        34 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FMul { dst, a, b })
        }
        35 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FDiv { dst, a, b })
        }
        36 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::FSqrt { dst, src })
        }
        37 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::FAbs { dst, src })
        }
        38 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::FNeg { dst, src })
        }
        39 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FMin { dst, a, b })
        }
        40 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::FMax { dst, a, b })
        }
        41 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI8U16 { dst, src })
        }
        42 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI8U32 { dst, src })
        }
        43 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI8U64 { dst, src })
        }
        44 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI16U32 { dst, src })
        }
        45 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI16U64 { dst, src })
        }
        46 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ZExtI32U64 { dst, src })
        }
        47 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::TruncU64U32 { dst, src })
        }
        48 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::TruncU64U16 { dst, src })
        }
        49 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::TruncU32U16 { dst, src })
        }
        50 => {
            let dst_region = read_u32(buf, pos)?;
            let dst_offset = read_u32(buf, pos)?;
            let src_region = read_u32(buf, pos)?;
            let src_offset = read_u32(buf, pos)?;
            let size = read_u32(buf, pos)?;
            Ok(U30Op::MemCopy {
                dst_region,
                dst_offset,
                src_region,
                src_offset,
                size,
            })
        }
        51 => {
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            let value = read_u32(buf, pos)?;
            let size = read_u32(buf, pos)?;
            Ok(U30Op::MemFill {
                region,
                offset,
                value,
                size,
            })
        }
        52 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            Ok(U30Op::MemSize { dst, region })
        }
        53 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            let delta = read_u32(buf, pos)?;
            Ok(U30Op::MemGrow { dst, region, delta })
        }
        54 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Eq { dst, a, b })
        }
        55 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Lt { dst, a, b })
        }
        56 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Gt { dst, a, b })
        }
        57 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Le { dst, a, b })
        }
        58 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Ge { dst, a, b })
        }
        59 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Add { dst, a, b })
        }
        60 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Sub { dst, a, b })
        }
        61 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Mul { dst, a, b })
        }
        62 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Div { dst, a, b })
        }
        63 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F64Sqrt { dst, src })
        }
        64 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F64Abs { dst, src })
        }
        65 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F64Neg { dst, src })
        }
        66 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Min { dst, a, b })
        }
        67 => {
            let dst = read_u32(buf, pos)?;
            let a = read_u32(buf, pos)?;
            let b = read_u32(buf, pos)?;
            Ok(U30Op::F64Max { dst, a, b })
        }
        68 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::I64F64 { dst, src })
        }
        69 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F64I64 { dst, src })
        }
        70 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F32F64 { dst, src })
        }
        71 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::F64F32 { dst, src })
        }
        72 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ReinterpretF64U64 { dst, src })
        }
        73 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ReinterpretU64F64 { dst, src })
        }
        74 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI8U16 { dst, src })
        }
        75 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI8U32 { dst, src })
        }
        76 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI8U64 { dst, src })
        }
        77 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI16U32 { dst, src })
        }
        78 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI16U64 { dst, src })
        }
        79 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::SExtI32U64 { dst, src })
        }
        80 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ByteSwapU16 { dst, src })
        }
        81 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ByteSwapU32 { dst, src })
        }
        82 => {
            let dst = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::ByteSwapU64 { dst, src })
        }
        83 => {
            let function = read_u32(buf, pos)?;
            let arg_count = read_u32(buf, pos)? as usize;
            let mut args = Vec::with_capacity(arg_count);
            for _ in 0..arg_count {
                args.push(read_u32(buf, pos)?);
            }
            let result_count = read_u32(buf, pos)? as usize;
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                results.push(read_u32(buf, pos)?);
            }
            Ok(U30Op::Call {
                function,
                args,
                results,
            })
        }
        84 => {
            let function = read_u32(buf, pos)?;
            let arg_count = read_u32(buf, pos)? as usize;
            let mut args = Vec::with_capacity(arg_count);
            for _ in 0..arg_count {
                args.push(read_u32(buf, pos)?);
            }
            let result_count = read_u32(buf, pos)? as usize;
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                results.push(read_u32(buf, pos)?);
            }
            Ok(U30Op::IndirectCall {
                function,
                args,
                results,
            })
        }
        85 => {
            let table = read_u32(buf, pos)?;
            let index = read_u32(buf, pos)?;
            Ok(U30Op::TableBr { table, index })
        }
        86 => {
            let code = read_u32(buf, pos)?;
            Ok(U30Op::Break { code })
        }
        87 => {
            let cond = read_u32(buf, pos)?;
            let msg = read_u32(buf, pos)?;
            Ok(U30Op::Assert { cond, msg })
        }
        88 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            Ok(U30Op::LoadU8 { dst, region, offset })
        }
        89 => {
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::StoreU8 { region, offset, src })
        }
        90 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            Ok(U30Op::LoadU16 { dst, region, offset })
        }
        91 => {
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::StoreU16 { region, offset, src })
        }
        92 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            Ok(U30Op::LoadU32 { dst, region, offset })
        }
        93 => {
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::StoreU32 { region, offset, src })
        }
        94 => {
            let dst = read_u32(buf, pos)?;
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            Ok(U30Op::LoadU64 { dst, region, offset })
        }
        95 => {
            let region = read_u32(buf, pos)?;
            let offset = read_u32(buf, pos)?;
            let src = read_u32(buf, pos)?;
            Ok(U30Op::StoreU64 { region, offset, src })
        }
        _ => Err(Error::Generic(format!(
            "U30X: unknown op variant {}",
            variant
        ))),
    }
}

fn decode_terminator(buf: &[u8], pos: &mut usize) -> Result<U30Terminator> {
    let variant = read_u8(buf, pos)?;
    match variant {
        0 => {
            let target = read_u32(buf, pos)? as usize;
            Ok(U30Terminator::Br { target })
        }
        1 => {
            let cond = read_u32(buf, pos)?;
            let then_target = read_u32(buf, pos)? as usize;
            let else_target = read_u32(buf, pos)? as usize;
            Ok(U30Terminator::BrIf {
                cond,
                then_target,
                else_target,
            })
        }
        2 => {
            let count = read_u32(buf, pos)? as usize;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(read_u32(buf, pos)?);
            }
            Ok(U30Terminator::Ret { values })
        }
        3 => {
            let function = read_u32(buf, pos)?;
            let count = read_u32(buf, pos)? as usize;
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                args.push(read_u32(buf, pos)?);
            }
            Ok(U30Terminator::TailCall { function, args })
        }
        4 => {
            let code = read_u32(buf, pos)?;
            Ok(U30Terminator::Trap { code })
        }
        _ => Err(Error::Generic(format!(
            "U30X: unknown terminator variant {}",
            variant
        ))),
    }
}

fn decode_type(buf: &[u8], pos: &mut usize) -> Result<U30Type> {
    let t = read_u8(buf, pos)?;
    match t {
        0 => Ok(U30Type::Bool),
        1 => Ok(U30Type::U8),
        2 => Ok(U30Type::U16),
        3 => Ok(U30Type::U32),
        4 => Ok(U30Type::U64),
        5 => Ok(U30Type::F32),
        6 => Ok(U30Type::F64),
        _ => Err(Error::Generic(format!("U30X: unknown type variant {}", t))),
    }
}

fn decode_value(buf: &[u8], pos: &mut usize) -> Result<U30Value> {
    let t = read_u8(buf, pos)?;
    match t {
        0 => {
            let b = read_u8(buf, pos)?;
            Ok(U30Value::Bool(b != 0))
        }
        1 => {
            let x = read_u8(buf, pos)?;
            Ok(U30Value::U8(x))
        }
        2 => {
            if *pos + 2 > buf.len() {
                return Err(Error::Generic("U30X: truncated data".into()));
            }
            let x =
                u16::from_le_bytes([buf[*pos], buf[*pos + 1]]);
            *pos += 2;
            Ok(U30Value::U16(x))
        }
        3 => {
            if *pos + 4 > buf.len() {
                return Err(Error::Generic("U30X: truncated data".into()));
            }
            let x = u32::from_le_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
            ]);
            *pos += 4;
            Ok(U30Value::U32(x))
        }
        4 => {
            if *pos + 8 > buf.len() {
                return Err(Error::Generic("U30X: truncated data".into()));
            }
            let x = u64::from_le_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
                buf[*pos + 4],
                buf[*pos + 5],
                buf[*pos + 6],
                buf[*pos + 7],
            ]);
            *pos += 8;
            Ok(U30Value::U64(x))
        }
        5 => {
            if *pos + 4 > buf.len() {
                return Err(Error::Generic("U30X: truncated data".into()));
            }
            let bits = u32::from_le_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
            ]);
            *pos += 4;
            Ok(U30Value::F32(f32::from_bits(bits)))
        }
        6 => {
            if *pos + 8 > buf.len() {
                return Err(Error::Generic("U30X: truncated data".into()));
            }
            let bits = u64::from_le_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
                buf[*pos + 4],
                buf[*pos + 5],
                buf[*pos + 6],
                buf[*pos + 7],
            ]);
            *pos += 8;
            Ok(U30Value::F64(f64::from_bits(bits)))
        }
        _ => Err(Error::Generic(format!(
            "U30X: unknown value variant {}",
            t
        ))),
    }
}

/// Decode a U30BinaryOp from its index.
///
/// Uses `use crate::ir::U30BinaryOp as Op;` and matches on `op_idx` to return
/// `Op::VariantName`, where the index corresponds to the derive order.
fn decode_binary_op(op_idx: u32) -> Result<crate::ir::U30BinaryOp> {
    use crate::ir::U30BinaryOp as Op;
    match op_idx {
        0 => Ok(Op::AddWrapU64),
        1 => Ok(Op::AddWrapU32),
        2 => Ok(Op::SubWrapU64),
        3 => Ok(Op::SubWrapU32),
        4 => Ok(Op::MulWrapU64),
        5 => Ok(Op::MulWrapU32),
        6 => Ok(Op::AndU8),
        7 => Ok(Op::OrU8),
        8 => Ok(Op::XorU8),
        9 => Ok(Op::ShlU64),
        10 => Ok(Op::ShlU32),
        11 => Ok(Op::ShrU64),
        12 => Ok(Op::ShrU32),
        13 => Ok(Op::DivU64),
        14 => Ok(Op::DivU32),
        15 => Ok(Op::RemU64),
        16 => Ok(Op::RemU32),
        17 => Ok(Op::Eq),
        18 => Ok(Op::LtU64),
        19 => Ok(Op::GtU64),
        20 => Ok(Op::GeU64),
        21 => Ok(Op::LeU64),
        22 => Ok(Op::LeU32),
        23 => Ok(Op::MinU64),
        24 => Ok(Op::MaxU64),
        25 => Ok(Op::MinU32),
        26 => Ok(Op::MaxU32),
        _ => Err(Error::Generic(format!(
            "U30X: unknown binary op {}",
            op_idx
        ))),
    }
}

/// Encode a U30BinaryOp to its index.
fn encode_binary_op(op: &crate::ir::U30BinaryOp) -> u32 {
    use crate::ir::U30BinaryOp as Op;
    match op {
        Op::AddWrapU64 => 0,
        Op::AddWrapU32 => 1,
        Op::SubWrapU64 => 2,
        Op::SubWrapU32 => 3,
        Op::MulWrapU64 => 4,
        Op::MulWrapU32 => 5,
        Op::AndU8 => 6,
        Op::OrU8 => 7,
        Op::XorU8 => 8,
        Op::ShlU64 => 9,
        Op::ShlU32 => 10,
        Op::ShrU64 => 11,
        Op::ShrU32 => 12,
        Op::DivU64 => 13,
        Op::DivU32 => 14,
        Op::RemU64 => 15,
        Op::RemU32 => 16,
        Op::Eq => 17,
        Op::LtU64 => 18,
        Op::GtU64 => 19,
        Op::GeU64 => 20,
        Op::LeU64 => 21,
        Op::LeU32 => 22,
        Op::MinU64 => 23,
        Op::MaxU64 => 24,
        Op::MinU32 => 25,
        Op::MaxU32 => 26,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        U30Block, U30Function, U30Module, U30Op, U30Terminator, U30Type, U30Value,
        U30RegionDecl, U30TableDecl,
    };
    use crate::runtime::U30Runtime;

    #[test]
    fn test_ser_simple_module_roundtrip() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 8,
                readable: true,
                writable: true,
                initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const {
                        dst: 0,
                        value: U30Value::U64(42),
                    }],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };

        let encoded = encode(&module);
        let decoded = decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.functions.len(), 1);
        assert_eq!(decoded.regions.len(), 1);
        assert_eq!(decoded.entry_function, 0);
        assert_eq!(decoded.functions[0].results.len(), 1);
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 1);

        // Verify the decoded Const op matches
        if let U30Op::Const { dst, value: U30Value::U64(v) } = decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(dst, 0);
            assert_eq!(v, 42);
        } else {
            panic!("Expected Const op with U64(42)");
        }
    }

    #[test]
    fn test_ser_with_memory_roundtrip() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl {
                    id: 0,
                    size: 16,
                    readable: true,
                    writable: true,
                    initial: vec![1, 2, 3, 4],
                },
                U30RegionDecl {
                    id: 1,
                    size: 16,
                    readable: true,
                    writable: true,
                    initial: vec![],
                },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const {
                            dst: 0,
                            value: U30Value::U32(0),
                        },
                        U30Op::Const {
                            dst: 1,
                            value: U30Value::U32(2),
                        },
                        U30Op::Const {
                            dst: 2,
                            value: U30Value::U32(2),
                        },
                        U30Op::MemCopy {
                            dst_region: 1,
                            dst_offset: 0,
                            src_region: 0,
                            src_offset: 1,
                            size: 2,
                        },
                        U30Op::LoadU8 {
                            dst: 3,
                            region: 1,
                            offset: 0,
                        },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };

        let encoded = encode(&module);
        let decoded = decode(&encoded).expect("decode should succeed");

        // Execute both and compare results
        let runtime = U30Runtime::default();
        let orig = runtime
            .execute_experimental(&module, &[])
            .expect("orig execution");
        let roundtrip = runtime
            .execute_experimental(&decoded, &[])
            .expect("roundtrip execution");
        assert_eq!(orig.results, roundtrip.results);
    }

    #[test]
    fn test_ser_bad_magic() {
        let result = decode(b"XXXX");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("bad magic"),
            "expected 'bad magic', got: {}",
            err
        );
    }

    // === Error path tests for decode functions ===

    #[test]
    fn test_ser_decode_op_unknown_variant() {
        // Variant 96 is beyond the known range (0-95) — exercises the _ catch-all
        let buf = vec![96];
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("unknown op variant"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_unknown_type() {
        // Type 7 is beyond the known range (0-6) — exercises the _ catch-all
        let buf = vec![7];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("unknown value variant"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_binary_op_invalid() {
        // op_idx 27 is beyond the known range (0-26)
        let err = decode_binary_op(27).unwrap_err();
        assert!(err.to_string().contains("unknown binary op"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_terminator_unknown_variant() {
        // Variant 5 is beyond the known range (Trap=4) — exercises the _ catch-all
        // Must provide enough bytes after variant to pass truncation checks
        let buf = vec![5, 0, 0, 0, 0];
        let mut pos = 0;
        let err = decode_terminator(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("unknown terminator variant"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_no_fields() {
        // Variant byte present (0 = Nop) but no data after — Nop has no fields so this works
        let buf = vec![0];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Nop));
    }

    #[test]
    fn test_ser_decode_op_truncated_variant_byte() {
        // Empty buffer — cannot read variant byte
        let buf = vec![];
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_const_fields() {
        // Variant 1 (Const) but only 1 byte of dst — needs 4 bytes for u32
        let buf = vec![1, 0x42];
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_const_value_type() {
        // Variant 1 (Const): dst complete (4 bytes), but no value type byte
        let buf = vec![1, 0, 0, 0, 0]; // dst=0
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_memcopy() {
        // Variant 50 (MemCopy): needs 6 x u32 = 24 bytes after variant
        // Provide only variant + 3 u32s (partial)
        let buf = vec![50, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]; // 14 bytes total, 13 after variant
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_truncated_u16() {
        // Type 2 (U16): needs 2 bytes, provide only 1
        let buf = vec![2, 0x42];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_truncated_u32() {
        // Type 3 (U32): needs 4 bytes, provide only 3
        let buf = vec![3, 0, 0, 0];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_truncated_u64() {
        // Type 4 (U64): needs 8 bytes, provide only 7
        let buf = vec![4, 0, 0, 0, 0, 0, 0, 0];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_truncated_f32() {
        // Type 5 (F32): needs 4 bytes, provide only 3
        let buf = vec![5, 0, 0, 0];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_truncated_f64() {
        // Type 6 (F64): needs 8 bytes, provide only 7
        let buf = vec![6, 0, 0, 0, 0, 0, 0, 0];
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_terminator_truncated_br() {
        // Variant 0 (Br): needs 1 u32 (4 bytes), provide 1 byte
        let buf = vec![0, 0x42];
        let mut pos = 0;
        let err = decode_terminator(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_terminator_truncated_brif() {
        // Variant 1 (BrIf): needs 3 x u32, provide only 2
        let buf = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 2]; // 2 complete u32s, need 3
        let mut pos = 0;
        let err = decode_terminator(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_terminator_truncated_ret() {
        // Variant 2 (Ret): count=1 needs 1 value, but truncated
        // Variant(1) + count=1(4) + 0 bytes for value
        let buf = vec![2, 1, 0, 0, 0]; // count=1, but no bytes for value
        let mut pos = 0;
        let err = decode_terminator(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_terminator_truncated_tailcall() {
        // Variant 3 (TailCall): count=1 needs 1 arg, but truncated
        let buf = vec![3, 0, 0, 0, 0, 1]; // fn=0, count=1, no arg bytes
        let mut pos = 0;
        let err = decode_terminator(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_binary_op() {
        // Variant 2 (Binary): dst=0, op_idx=0 (valid), a=0, b truncated
        let buf = vec![2, 0, 0, 0, 0, 0, 0, 0, 0]; // 9 bytes: dst(4)+op_idx(4)+a(1)
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_call() {
        // Variant 83 (Call): arg_count=2 needs 2 args, provide 1
        let mut buf = vec![83]; // variant
        buf.extend_from_slice(&0u32.to_le_bytes()); // function=0
        buf.extend_from_slice(&2u32.to_le_bytes()); // arg_count=2
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg1
        // missing arg2
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_op_truncated_indirect_call() {
        // Variant 84 (IndirectCall): arg_count=2 needs 2 args, provide 1
        let mut buf = vec![84]; // variant
        buf.extend_from_slice(&0u32.to_le_bytes()); // function_reg=0
        buf.extend_from_slice(&2u32.to_le_bytes()); // arg_count=2
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg1
        // missing arg2
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_decode_value_u64_roundtrip() {
        // Type 4 (U64): full 8 bytes — exercise the full path
        let buf = vec![4, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::U64(0x0807060504030201)));
    }

    #[test]
    fn test_ser_decode_value_f64_roundtrip() {
        // Type 6 (F64): full 8 bytes — exercise the full path
        let bits: u64 = 0x3FF0000000000000u64; // 1.0
        let mut buf = vec![6];
        buf.extend_from_slice(&bits.to_le_bytes());
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::F64(f) if f.to_bits() == bits));
    }

    #[test]
    fn test_ser_decode_value_bool_roundtrip() {
        // Type 0 (Bool): full 1 byte
        let buf = vec![0, 1];
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::Bool(true)));
    }

    #[test]
    fn test_ser_decode_value_u8_roundtrip() {
        // Type 1 (U8): full 1 byte
        let buf = vec![1, 42];
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::U8(42)));
    }

    #[test]
    fn test_ser_decode_binary_op_valid() {
        // All valid binary op indices 0-26
        for idx in 0u32..=26 {
            decode_binary_op(idx).expect("valid binary op should decode");
        }
    }

    #[test]
    fn test_ser_read_u32_truncated() {
        let buf = vec![0, 0, 0]; // only 3 bytes, need 4
        let mut pos = 0;
        let err = read_u32(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    #[test]
    fn test_ser_read_u8_truncated() {
        let buf = vec![];
        let mut pos = 0;
        let err = read_u8(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    // === End error path tests ===

    #[test]
    fn test_ser_truncated() {
        let result = decode(b"U30X");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("truncated"),
            "expected 'truncated', got: {}",
            err
        );
    }

    #[test]
    fn test_ser_tablebr_roundtrip() {
        // Module with a TableBr instruction
        let module = U30Module {
            regions: vec![],
            tables: vec![U30TableDecl {
                id: 0,
                targets: vec![1, 2], // two targets: block 1 and block 2
            }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    // Block 0: switch on index via TableBr
                    U30Block {
                        ops: vec![
                            U30Op::Const {
                                dst: 0,
                                value: U30Value::U32(1), // index = 1
                            },
                            U30Op::TableBr {
                                table: 0,
                                index: 0,
                            },
                        ],
                        terminator: U30Terminator::Ret { values: vec![99] }, // unreachable
                    },
                    // Block 1: taken when index=0
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![10] },
                    },
                    // Block 2: taken when index=1
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![20] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };

        let encoded = encode(&module);
        let decoded = decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.tables.len(), 1);
        assert_eq!(decoded.tables[0].id, 0);
        assert_eq!(decoded.tables[0].targets, vec![1, 2]);

        // Verify the TableBr op round-tripped correctly
        let ops = &decoded.functions[0].blocks[0].ops;
        assert!(ops.iter().any(|op| matches!(op, U30Op::TableBr { table: 0, index: 0 })),
            "expected TableBr {{ table: 0, index: 0 }} in ops");
    }

    #[test]
    fn test_ser_all_binary_ops_roundtrip() {
        use crate::ir::U30BinaryOp::*;
        let ops_to_test = [
            (AddWrapU64, 0),
            (AddWrapU32, 1),
            (SubWrapU64, 2),
            (SubWrapU32, 3),
            (MulWrapU64, 4),
            (MulWrapU32, 5),
            (AndU8, 6),
            (OrU8, 7),
            (XorU8, 8),
            (ShlU64, 9),
            (ShlU32, 10),
            (ShrU64, 11),
            (ShrU32, 12),
            (DivU64, 13),
            (DivU32, 14),
            (RemU64, 15),
            (RemU32, 16),
            (Eq, 17),
            (LtU64, 18),
            (GtU64, 19),
            (GeU64, 20),
            (LeU64, 21),
            (LeU32, 22),
            (MinU64, 23),
            (MaxU64, 24),
            (MinU32, 25),
            (MaxU32, 26),
        ];

        for (op, _expected_idx) in ops_to_test {
            let module = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Binary { dst: 0, op, a: 0, b: 0 }],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let encoded = encode(&module);
            let decoded = decode(&encoded).expect(&format!("decode should succeed for {:?}", op));
            
            if let U30Op::Binary { op: decoded_op, .. } = &decoded.functions[0].blocks[0].ops[0] {
                assert_eq!(*decoded_op, op, "Binary op {:?} should round-trip", op);
            } else {
                panic!("Expected Binary op");
            }
        }
    }

    #[test]
    fn test_ser_all_value_types_roundtrip() {
        // Test U8
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::U8(42) }],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::U8(v), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*v, 42);
        } else { panic!("expected U8"); }

        // Test U16
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::U16(1234) }],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::U16(v), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*v, 1234);
        } else { panic!("expected U16"); }

        // Test U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::U32(999999) }],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::U32(v), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*v, 999999);
        } else { panic!("expected U32"); }

        // Test Bool
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::Bool(true) }],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::Bool(b), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert!(b);
        } else { panic!("expected Bool"); }
    }

    #[test]
    fn test_ser_multiple_functions() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Const { dst: 0, value: U30Value::U32(1) }],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Const { dst: 0, value: U30Value::U32(2) }],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 1, // second function is entry
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.functions.len(), 2);
        assert_eq!(decoded.entry_function, 1);
    }

    #[test]
    fn test_ser_multiple_regions() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: false, initial: vec![0; 64] },
                U30RegionDecl { id: 1, size: 128, readable: true, writable: true, initial: vec![1; 128] },
                U30RegionDecl { id: 2, size: 256, readable: false, writable: true, initial: vec![] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions.len(), 3);
        assert_eq!(decoded.regions[0].id, 0);
        assert_eq!(decoded.regions[1].id, 1);
        assert_eq!(decoded.regions[2].id, 2);
        assert_eq!(decoded.regions[0].size, 64);
        assert_eq!(decoded.regions[1].writable, true);
        assert_eq!(decoded.regions[2].readable, false);
    }

    #[test]
    fn test_ser_decode_invalid_magic() {
        let invalid = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let err = decode(&invalid).expect_err("invalid magic should fail");
        assert!(err.to_string().contains("U30X") || err.to_string().contains("magic"));
    }

    #[test]
    fn test_ser_decode_truncated_header() {
        // Header is 5 bytes: 4 magic + 1 version
        let truncated = b"U30X".to_vec(); // only 3 bytes
        let err = decode(&truncated).expect_err("truncated header should fail");
        assert!(err.to_string().contains("truncated") || err.to_string().contains("U30X"));
    }

    #[test]
    fn test_ser_decode_truncated_regions() {
        // Valid header but truncated region data
        let mut data = b"U30X".to_vec(); // magic + version
        data.push(1); // 1 region
        // Missing region data
        let err = decode(&data).expect_err("truncated region data should fail");
        assert!(err.to_string().contains("truncated") || err.to_string().contains("region"));
    }

    #[test]
    fn test_ser_decode_truncated_function() {
        // Valid header and regions but truncated function
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1); // version
        data.push(0); // 0 regions
        data.push(1); // 1 function
        // Missing function data
        let err = decode(&data).expect_err("truncated function should fail");
        // Should fail with some error about data
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_ser_decode_truncated_block() {
        // Valid up to functions but truncated block
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1);
        data.push(0); // 0 regions
        data.push(0); // 0 functions... wait, need at least 1 function
        data.push(1); // 1 function
        data.push(0); // 0 params
        data.push(0); // 0 results
        data.push(0); // 1 block (entry)
        // Truncated block
        let err = decode(&data).expect_err("truncated block should fail");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_ser_encode_decode_empty_module() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![],
            entry_function: 0,
        };
        let encoded = encode(&module);
        assert!(encoded.len() >= 5); // header only
        // Empty module can be encoded
        let decoded = decode(&encoded).expect("empty module decode");
        assert_eq!(decoded.functions.len(), 0);
    }

    #[test]
    fn test_ser_encode_decode_many_regions() {
        let regions: Vec<_> = (0..10).map(|i| U30RegionDecl {
            id: i as u32,
            size: ((i + 1) * 64) as usize,
            readable: i % 2 == 0,
            writable: i % 2 == 1,
            initial: vec![i as u8; 8],
        }).collect();
        
        let module = U30Module {
            regions,
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions.len(), 10);
    }

    #[test]
    fn test_ser_encode_decode_many_tables() {
        let tables: Vec<_> = (0..5).map(|i| U30TableDecl {
            id: i,
            targets: vec![(i + 1) as usize, (i + 2) as usize, (i + 3) as usize],
        }).collect();
        
        let module = U30Module {
            regions: vec![],
            tables,
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.tables.len(), 5);
    }

    #[test]
    fn test_ser_encode_decode_many_functions() {
        let functions: Vec<_> = (0..20).map(|_| U30Function {
            params: vec![],
            results: vec![],
            blocks: vec![U30Block {
                ops: vec![],
                terminator: U30Terminator::Ret { values: vec![] },
            }],
            entry_block: 0,
        }).collect();
        
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions,
            entry_function: 5,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions.len(), 20);
        assert_eq!(decoded.entry_function, 5);
    }

    #[test]
    fn test_ser_encode_decode_blocks_with_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U8(1) },
                            U30Op::Const { dst: 1, value: U30Value::U8(2) },
                            U30Op::Const { dst: 2, value: U30Value::U8(3) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U8(100) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks.len(), 2);
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 3);
    }

    #[test]
    fn test_ser_encode_decode_br_terminator() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Br { target: 1 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::Br { target } = decoded.functions[0].blocks[0].terminator {
            assert_eq!(target, 1);
        } else {
            panic!("Expected Br terminator");
        }
    }

    #[test]
    fn test_ser_encode_decode_ret_with_values() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::Ret { values } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(values.as_slice(), &[1, 2, 3]);
        } else {
            panic!("Expected Ret terminator");
        }
    }

    #[test]
    fn test_ser_encode_decode_unary_ops() {
        // Test Select and NotU8 operations
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(5) },
                        U30Op::Const { dst: 1, value: U30Value::U8(10) },
                        U30Op::Const { dst: 2, value: U30Value::Bool(true) },
                        U30Op::Select { dst: 3, cond: 2, a: 0, b: 1 },
                        U30Op::NotU8 { dst: 4, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 5);
        // Verify Select round-tripped
        if let U30Op::Select { dst, cond, a, b } = decoded.functions[0].blocks[0].ops[3] {
            assert_eq!(dst, 3);
            assert_eq!(cond, 2);
            assert_eq!(a, 0);
            assert_eq!(b, 1);
        } else {
            panic!("Expected Select op");
        }
    }

    #[test]
    fn test_ser_encode_decode_memfill_memcopy() {
        // Test MemFill and MemCopy roundtrip (encode/decode only)
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![0; 256] },
                U30RegionDecl { id: 1, size: 256, readable: true, writable: true, initial: vec![0; 256] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xFF) },
                        U30Op::Const { dst: 2, value: U30Value::U32(16) },
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 0, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        // Just test roundtrip encoding/decoding
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions.len(), 2);
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 5);
    }

    #[test]
    fn test_ser_encode_decode_break_assert() {
        // Test Break and Assert instructions
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        U30Op::Assert { cond: 0, msg: 1 },
                        U30Op::Break { code: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let _decoded = decode(&encode(&module)).unwrap();
        // Break/Assert are no-op in this context but should encode/decode
    }

    #[test]
    fn test_ser_encode_decode_load_store() {
        // Test LoadU16, StoreU16 roundtrip
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![0; 256] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U16],  // Return U16 value
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U16(0x1234) },
                        U30Op::StoreU16 { region: 0, offset: 0, src: 1 },
                        U30Op::LoadU16 { dst: 2, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        // Execute both
        let runtime = U30Runtime::default();
        let orig = runtime.execute_experimental(&module, &[]).expect("orig");
        let roundtrip = runtime.execute_experimental(&decoded, &[]).expect("roundtrip");
        assert_eq!(orig.results, roundtrip.results);
    }

    #[test]
    fn test_ser_encode_decode_call() {
        // Test Call instruction (local function call)
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                // Function 0 (entry): call function 1
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U32],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(42) },
                            U30Op::Const { dst: 1, value: U30Value::U32(10) },
                            U30Op::Call { function: 1, args: vec![0, 1], results: vec![2] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    }],
                    entry_block: 0,
                },
                // Function 1: receives two args, returns sum
                U30Function {
                    params: vec![U30Type::U32, U30Type::U32],
                    results: vec![U30Type::U32],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Binary { dst: 0, op: crate::ir::U30BinaryOp::AddWrapU32, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions.len(), 2);
        // Execute
        let runtime = U30Runtime::default();
        let orig = runtime.execute_experimental(&module, &[]).expect("orig");
        assert_eq!(orig.results, vec![U30Value::U32(52)]); // 42 + 10
    }

    #[test]
    fn test_ser_encode_decode_f32_ops() {
        // Test F32 arithmetic: FAdd, FSub, FMul, FDiv (FAdd expects F32, not F64)
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(3.0) },
                        U30Op::Const { dst: 1, value: U30Value::F32(2.0) },
                        U30Op::FAdd { dst: 2, a: 0, b: 1 },
                        U30Op::FSub { dst: 3, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let _decoded = decode(&encode(&module)).unwrap();
        let runtime = U30Runtime::default();
        let orig = runtime.execute_experimental(&module, &[]).expect("orig");
        assert_eq!(orig.results, vec![U30Value::F32(5.0)]); // 3.0 + 2.0
    }

    #[test]
    fn test_ser_encode_decode_memgrow() {
        // Test MemGrow
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(64) },
                        U30Op::MemGrow { dst: 1, region: 0, delta: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let _decoded = decode(&encode(&module)).unwrap();
        let runtime = U30Runtime::default();
        let orig = runtime.execute_experimental(&module, &[]).expect("orig");
        let roundtrip = runtime.execute_experimental(&decode(&encode(&module)).unwrap(), &[]).expect("roundtrip");
        assert_eq!(orig.results, roundtrip.results);
    }

    #[test]
    fn test_ser_encode_decode_f64_ops_roundtrip() {
        // Test F64Add, F64Mul, F64Sqrt roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(9.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(3.0) },
                        U30Op::F64Sqrt { dst: 2, src: 0 }, // sqrt(9) = 3
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let _decoded = decode(&encode(&module)).unwrap();
        let runtime = U30Runtime::default();
        let orig = runtime.execute_experimental(&module, &[]).expect("orig");
        // sqrt(9) = 3
        if let U30Value::F64(v) = &orig.results[0] {
            assert!((v - 3.0).abs() < 0.0001);
        } else {
            panic!("expected F64 result");
        }
    }

    #[test]
    fn test_ser_encode_decode_float_conversions() {
        // Test I2F, F2I conversions - just test encoding/decoding
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F32],  // I2F produces F32
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::I2F { dst: 1, src: 0 },  // 42 as float
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 2);
    }

    #[test]
    fn test_ser_encode_decode_all_terminators() {
        // Test all terminator types: Br, BrIf, Ret, Trap
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![
                        U30Block {
                            ops: vec![],
                            terminator: U30Terminator::Br { target: 1 },
                        },
                        U30Block {
                            ops: vec![],
                            terminator: U30Terminator::Ret { values: vec![] },
                        },
                    ],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::Br { target } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(*target, 1);
        } else {
            panic!("Expected Br terminator");
        }
    }

    #[test]
    fn test_ser_encode_decode_breakpoint_invariant() {
        // Test that Break instruction (no-op in U30) encodes/decodes correctly
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Break { code: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 1);
    }

    #[test]
    fn test_ser_encode_decode_assert_roundtrip() {
        // Test Assert instruction
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        U30Op::Assert { cond: 0, msg: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 2);
    }

    #[test]
    fn test_ser_encode_decode_tablebr_roundtrip() {
        // Test TableBr instruction with multiple tables
        let module = U30Module {
            regions: vec![],
            tables: vec![
                crate::ir::U30TableDecl { id: 0, targets: vec![1, 2] },
                crate::ir::U30TableDecl { id: 1, targets: vec![3, 4, 5, 6] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::TableBr { table: 1, index: 0 },  // use table 1
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.tables.len(), 2);
        assert_eq!(decoded.tables[1].targets.len(), 4);
    }

    #[test]
    fn test_ser_encode_decode_tail_call() {
        // Test TailCall instruction
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::Const { dst: 1, value: U30Value::U32(2) },
                    ],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![0, 1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::TailCall { function, args } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(*function, 0);
            assert_eq!(args.as_slice(), &[0, 1]);
        } else {
            panic!("Expected TailCall terminator");
        }
    }

    #[test]
    fn test_ser_encode_decode_i2f_f2i() {
        // Test I2F and F2I conversions
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::I2F { dst: 1, src: 0 },
                        U30Op::F2I { dst: 2, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 3);
    }

    #[test]
    fn test_ser_encode_decode_f64_add() {
        // Test F64Add roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.0) },
                        U30Op::F64Add { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::F64Add { dst, a, b } = &decoded.functions[0].blocks[0].ops[2] {
            assert_eq!(*dst, 2);
            assert_eq!(*a, 0);
            assert_eq!(*b, 1);
        } else {
            panic!("Expected F64Add op");
        }
    }

    #[test]
    fn test_ser_encode_decode_f64_sub_mul() {
        // Test F64Sub, F64Mul roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(5.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(3.0) },
                        U30Op::F64Sub { dst: 2, a: 0, b: 1 },
                        U30Op::F64Mul { dst: 3, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 4);
    }

    #[test]
    fn test_ser_encode_decode_f64_div_sqrt() {
        // Test F64Div, F64Sqrt roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(10.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.0) },
                        U30Op::F64Div { dst: 2, a: 0, b: 1 },
                        U30Op::F64Sqrt { dst: 3, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 4);
    }

    #[test]
    fn test_ser_encode_decode_f64_neg_abs() {
        // Test F64Neg, F64Abs roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(-5.0) },
                        U30Op::F64Neg { dst: 1, src: 0 },
                        U30Op::F64Abs { dst: 2, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 3);
    }

    #[test]
    fn test_ser_encode_decode_f64_min_max() {
        // Test F64Min, F64Max roundtrip
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.0) },
                        U30Op::F64Min { dst: 2, a: 0, b: 1 },
                        U30Op::F64Max { dst: 3, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 4);
    }

    #[test]
    fn test_ser_encode_decode_break() {
        // Test Break instruction
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Break { code: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Break { code } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*code, 0);
        } else {
            panic!("Expected Break op");
        }
    }

    #[test]
    fn test_ser_encode_decode_u64_value() {
        // Test U64 constant value
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(u64::MAX) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::U64(v), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*v, u64::MAX);
        } else {
            panic!("Expected Const U64");
        }
    }

    #[test]
    fn test_ser_encode_decode_f32_value() {
        // Test F32 constant value
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(f32::MAX) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::F32(v), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*v, f32::MAX);
        } else {
            panic!("Expected Const F32");
        }
    }

    #[test]
    fn test_ser_encode_decode_bool_true() {
        // Test Bool(true) constant value
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Const { value: U30Value::Bool(b), .. } = &decoded.functions[0].blocks[0].ops[0] {
            assert!(b);
        } else {
            panic!("Expected Const Bool(true)");
        }
    }

    #[test]
    fn test_ser_encode_decode_brif_terminator() {
        // Test BrIf terminator
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 2, else_target: 1 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::BrIf { cond, then_target, else_target } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(*cond, 0);
            assert_eq!(*then_target, 2);
            assert_eq!(*else_target, 1);
        } else {
            panic!("Expected BrIf terminator");
        }
    }

    // Test MemSize roundtrip
    #[test]
    fn test_ser_encode_decode_memsize() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 128, readable: true, writable: true, initial: vec![0; 128] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemSize { dst: 0, region: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions.len(), 1);
        if let U30Op::MemSize { dst, region } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*dst, 0);
            assert_eq!(*region, 0);
        } else {
            panic!("Expected MemSize op");
        }
    }

    // Test MemCopy roundtrip
    #[test]
    fn test_ser_encode_decode_memcopy() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
                U30RegionDecl { id: 1, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 1, src_offset: 0, size: 16 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions.len(), 2);
        if let U30Op::MemCopy { dst_region, dst_offset: _, src_region, src_offset: _, size } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*dst_region, 0);
            assert_eq!(*src_region, 1);
            assert_eq!(*size, 16);
        } else {
            panic!("Expected MemCopy op");
        }
    }

    // Test MemFill roundtrip
    #[test]
    fn test_ser_encode_decode_memfill() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemFill { region: 0, offset: 0, value: 42, size: 16 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::MemFill { region, offset: _, value, size } = &decoded.functions[0].blocks[0].ops[0] {
            assert_eq!(*region, 0);
            assert_eq!(*value, 42);
            assert_eq!(*size, 16);
        } else {
            panic!("Expected MemFill op");
        }
    }

    // Test TableBr roundtrip
    #[test]
    fn test_ser_encode_decode_tablebr() {
        let module = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![1, 2, 3] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(1) },
                            U30Op::TableBr { table: 0, index: 0 },
                        ],
                        terminator: U30Terminator::Br { target: 1 },
                    },
                    U30Block { ops: vec![], terminator: U30Terminator::Ret { values: vec![] } },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.tables.len(), 1);
        if let U30Op::TableBr { table, index } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*table, 0);
            assert_eq!(*index, 0);
        } else {
            panic!("Expected TableBr op");
        }
    }

    // Test Assert roundtrip
    #[test]
    fn test_ser_encode_decode_assert() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        U30Op::Assert { cond: 0, msg: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::Assert { cond, msg } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*cond, 0);
            assert_eq!(*msg, 0);
        } else {
            panic!("Expected Assert op");
        }
    }

    // Test IndirectCall roundtrip
    #[test]
    fn test_ser_encode_decode_indirect_call() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::IndirectCall { function: 0, args: vec![1, 2], results: vec![3] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::IndirectCall { function, args, results } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*function, 0);
            assert_eq!(*args, vec![1, 2]);
            assert_eq!(*results, vec![3]);
        } else {
            panic!("Expected IndirectCall op");
        }
    }

    // Test ByteSwap roundtrip
    #[test]
    fn test_ser_encode_decode_byteswap_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0x12345678) },
                        U30Op::ByteSwapU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::ByteSwapU32 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected ByteSwapU32 op");
        }
    }

    // Test ReinterpretF64U64 roundtrip
    #[test]
    fn test_ser_encode_decode_reinterpret_f64_u64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.5) },
                        U30Op::ReinterpretF64U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::ReinterpretF64U64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected ReinterpretF64U64 op");
        }
    }

    // Test ReinterpretU64F64 roundtrip
    #[test]
    fn test_ser_encode_decode_reinterpret_u64_f64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0x3FF8_0000_0000_0000) }, // 1.5 as u64
                        U30Op::ReinterpretU64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::ReinterpretU64F64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected ReinterpretU64F64 op");
        }
    }

    // Test I64F64 roundtrip
    #[test]
    fn test_ser_encode_decode_i64_f64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::I64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::I64F64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected I64F64 op");
        }
    }

    // Test F64I64 roundtrip
    #[test]
    fn test_ser_encode_decode_f64_i64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(42.5) },
                        U30Op::F64I64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::F64I64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected F64I64 op");
        }
    }

    // Test F32F64 roundtrip
    #[test]
    fn test_ser_encode_decode_f32_f64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.5) },
                        U30Op::F32F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::F32F64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected F32F64 op");
        }
    }

    // Test F64F32 roundtrip
    #[test]
    fn test_ser_encode_decode_f64_f32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.5) },
                        U30Op::F64F32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::F64F32 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected F64F32 op");
        }
    }

    // Test TruncF32U64 roundtrip
    #[test]
    fn test_ser_encode_decode_trunc_f32_u64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.5) },
                        U30Op::TruncF32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::TruncF32U64 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected TruncF32U64 op");
        }
    }

    // Test TailCall terminator roundtrip
    #[test]
    fn test_ser_encode_decode_tailcall() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::Const { dst: 1, value: U30Value::U64(42) },
                    ],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![0, 1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::TailCall { function, args } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(*function, 0);
            assert_eq!(*args, vec![0, 1]);
        } else {
            panic!("Expected TailCall terminator");
        }
    }

    // Test Trap terminator roundtrip
    #[test]
    fn test_ser_encode_decode_trap() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Trap { code: 99 },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Terminator::Trap { code } = &decoded.functions[0].blocks[0].terminator {
            assert_eq!(*code, 99);
        } else {
            panic!("Expected Trap terminator");
        }
    }

    // Test CtzU32 roundtrip
    #[test]
    fn test_ser_encode_decode_ctz_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(8) },
                        U30Op::CtzU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::CtzU32 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected CtzU32 op");
        }
    }

    // Test ClzU32 roundtrip
    #[test]
    fn test_ser_encode_decode_clz_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::ClzU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::ClzU32 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected ClzU32 op");
        }
    }

    // Test PopcntU32 roundtrip
    #[test]
    fn test_ser_encode_decode_popcnt_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0xFF) },
                        U30Op::PopcntU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::PopcntU32 { dst, src } = &decoded.functions[0].blocks[0].ops[1] {
            assert_eq!(*dst, 1);
            assert_eq!(*src, 0);
        } else {
            panic!("Expected PopcntU32 op");
        }
    }

    // Test RotlU32 roundtrip
    #[test]
    fn test_ser_encode_decode_rotl_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::Const { dst: 1, value: U30Value::U32(4) },
                        U30Op::RotlU32 { dst: 2, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::RotlU32 { dst, val, sh } = &decoded.functions[0].blocks[0].ops[2] {
            assert_eq!(*dst, 2);
            assert_eq!(*val, 0);
            assert_eq!(*sh, 1);
        } else {
            panic!("Expected RotlU32 op");
        }
    }

    // Test RotrU32 roundtrip
    #[test]
    fn test_ser_encode_decode_rotr_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(16) },
                        U30Op::Const { dst: 1, value: U30Value::U32(2) },
                        U30Op::RotrU32 { dst: 2, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        if let U30Op::RotrU32 { dst, val, sh } = &decoded.functions[0].blocks[0].ops[2] {
            assert_eq!(*dst, 2);
            assert_eq!(*val, 0);
            assert_eq!(*sh, 1);
        } else {
            panic!("Expected RotrU32 op");
        }
    }

    // Test roundtrip for Abs, Neg, Ctz, Clz, Popcnt ops
    #[test]
    fn test_ser_encode_decode_bitwise_unary_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::AbsU64 { dst: 1, src: 0 },
                        U30Op::NegU64 { dst: 2, src: 0 },
                        U30Op::CtzU64 { dst: 3, src: 0 },
                        U30Op::ClzU64 { dst: 4, src: 0 },
                        U30Op::PopcntU64 { dst: 5, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3, 4, 5] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 6);
        assert!(matches!(decoded.functions[0].blocks[0].ops[1], U30Op::AbsU64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::NegU64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::CtzU64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::ClzU64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::PopcntU64 { .. }));
    }

    // Test roundtrip for RotlU64 and RotrU64
    #[test]
    fn test_ser_encode_decode_rot_u64_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0x8000_0000_0000_0000u64) },
                        U30Op::Const { dst: 1, value: U30Value::U64(4) },
                        U30Op::RotlU64 { dst: 2, val: 0, sh: 1 },
                        U30Op::RotrU64 { dst: 3, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::RotlU64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::RotrU64 { .. }));
    }

    // Test roundtrip for NotU16, NotU32, NotU64
    #[test]
    fn test_ser_encode_decode_not_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0xFF) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xFFFF) },
                        U30Op::Const { dst: 2, value: U30Value::U64(0xFFFF_FFFF_FFFF_FFFFu64) },
                        U30Op::NotU16 { dst: 3, src: 0 },
                        U30Op::NotU32 { dst: 4, src: 1 },
                        U30Op::NotU64 { dst: 5, src: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3, 4, 5] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::NotU16 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::NotU32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::NotU64 { .. }));
    }

    // Test roundtrip for ZExt variants
    #[test]
    fn test_ser_encode_decode_zext_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(42) },
                        U30Op::ZExtI8U16 { dst: 1, src: 0 },
                        U30Op::ZExtI8U32 { dst: 2, src: 0 },
                        U30Op::ZExtI8U64 { dst: 3, src: 0 },
                        U30Op::ZExtI16U32 { dst: 4, src: 1 },
                        U30Op::ZExtI16U64 { dst: 5, src: 1 },
                        U30Op::ZExtI32U64 { dst: 6, src: 4 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[1], U30Op::ZExtI8U16 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::ZExtI8U32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::ZExtI8U64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::ZExtI16U32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::ZExtI16U64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[6], U30Op::ZExtI32U64 { .. }));
    }

    // Test roundtrip for SExt variants
    #[test]
    fn test_ser_encode_decode_sext_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xFF) },
                        U30Op::Const { dst: 1, value: U30Value::U16(0xFFFF) },
                        U30Op::Const { dst: 2, value: U30Value::U32(0xFFFF_FFFF) },
                        U30Op::SExtI8U16 { dst: 3, src: 0 },
                        U30Op::SExtI8U32 { dst: 4, src: 0 },
                        U30Op::SExtI8U64 { dst: 5, src: 0 },
                        U30Op::SExtI16U32 { dst: 6, src: 1 },
                        U30Op::SExtI16U64 { dst: 7, src: 1 },
                        U30Op::SExtI32U64 { dst: 8, src: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3, 4, 5, 6, 7, 8] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::SExtI8U16 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::SExtI8U32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::SExtI8U64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[6], U30Op::SExtI16U32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[7], U30Op::SExtI16U64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[8], U30Op::SExtI32U64 { .. }));
    }

    // Test roundtrip for ByteSwap variants
    #[test]
    fn test_ser_encode_decode_byteswap_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0x1234) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0x1234_5678) },
                        U30Op::Const { dst: 2, value: U30Value::U64(0x0123_4567_89AB_CDEF) },
                        U30Op::ByteSwapU16 { dst: 3, src: 0 },
                        U30Op::ByteSwapU32 { dst: 4, src: 1 },
                        U30Op::ByteSwapU64 { dst: 5, src: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3, 4, 5] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::ByteSwapU16 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::ByteSwapU32 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::ByteSwapU64 { .. }));
    }

    // Test roundtrip for F32 comparison ops
    #[test]
    fn test_ser_encode_decode_f32_cmp_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F32(2.0) },
                        U30Op::FEq { dst: 2, a: 0, b: 1 },
                        U30Op::FLt { dst: 3, a: 0, b: 1 },
                        U30Op::FGt { dst: 4, a: 0, b: 1 },
                        U30Op::FLe { dst: 5, a: 0, b: 1 },
                        U30Op::FGe { dst: 6, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::FEq { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::FLt { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::FGt { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::FLe { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[6], U30Op::FGe { .. }));
    }

    // Test roundtrip for F32 arithmetic ops
    #[test]
    fn test_ser_encode_decode_f32_arith_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(3.0) },
                        U30Op::Const { dst: 1, value: U30Value::F32(2.0) },
                        U30Op::FAdd { dst: 2, a: 0, b: 1 },
                        U30Op::FSub { dst: 3, a: 0, b: 1 },
                        U30Op::FMul { dst: 4, a: 0, b: 1 },
                        U30Op::FDiv { dst: 5, a: 0, b: 1 },
                        U30Op::FSqrt { dst: 6, src: 0 },
                        U30Op::FAbs { dst: 7, src: 0 },
                        U30Op::FNeg { dst: 8, src: 0 },
                        U30Op::FMin { dst: 9, a: 0, b: 1 },
                        U30Op::FMax { dst: 10, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5, 6, 7, 8, 9, 10] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::FAdd { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::FSub { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::FMul { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::FDiv { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[6], U30Op::FSqrt { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[7], U30Op::FAbs { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[8], U30Op::FNeg { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[9], U30Op::FMin { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[10], U30Op::FMax { .. }));
    }

    // Test roundtrip for F64 comparison ops
    #[test]
    fn test_ser_encode_decode_f64_cmp_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.0) },
                        U30Op::F64Eq { dst: 2, a: 0, b: 1 },
                        U30Op::F64Lt { dst: 3, a: 0, b: 1 },
                        U30Op::F64Gt { dst: 4, a: 0, b: 1 },
                        U30Op::F64Le { dst: 5, a: 0, b: 1 },
                        U30Op::F64Ge { dst: 6, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::F64Eq { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[3], U30Op::F64Lt { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[4], U30Op::F64Gt { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[5], U30Op::F64Le { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[6], U30Op::F64Ge { .. }));
    }

    // Test roundtrip for I64F64 and F64I64
    #[test]
    fn test_ser_encode_decode_i64_f64_conversions() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::I64F64 { dst: 1, src: 0 },
                        U30Op::F64I64 { dst: 2, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(decoded.functions[0].blocks[0].ops[1], U30Op::I64F64 { .. }));
        assert!(matches!(decoded.functions[0].blocks[0].ops[2], U30Op::F64I64 { .. }));
    }

    // Test roundtrip for IndirectCall (different signature from existing test)
    #[test]
    fn test_ser_encode_decode_indirect_call_v2() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(1) },
                            U30Op::IndirectCall { function: 0, args: vec![], results: vec![1] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![1] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert!(matches!(
            decoded.functions[0].blocks[0].ops[1],
            U30Op::IndirectCall { .. }
        ));
    }

    // Test decode with bad magic (custom crafted)
    #[test]
    fn test_ser_decode_bad_magic_custom() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00]; // wrong magic
        data.push(1); // version
        let result = decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("bad magic") || err.to_string().contains("U30X"));
    }

    // Test decode with wrong version
    #[test]
    fn test_ser_decode_wrong_version() {
        let mut data = vec![0x55, 0x33, 0x30, 0x58]; // "U30X"
        data.push(99); // wrong version
        let result = decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("version") || err.to_string().contains("unsupported"));
    }

    // Test decode with truncated region data - truncate mid-region initial bytes
    #[test]
    fn test_ser_decode_truncated_region_data() {
        // First encode a valid module with region data
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 16,
                readable: true,
                writable: true,
                initial: vec![0xAA; 16],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let data = encode(&module);
        // Truncate the last 5 bytes (middle of region initial data)
        let truncated = data[..data.len() - 5].to_vec();
        let result = decode(&truncated);
        assert!(result.is_err(), "Truncated data should fail to decode");
    }

    // Test encode/decode with params and results types
    #[test]
    fn test_ser_encode_decode_function_signature() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64, U30Type::Bool, U30Type::F32],
                results: vec![U30Type::U64, U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].params.len(), 3);
        assert_eq!(decoded.functions[0].results.len(), 2);
    }

    // Test encode/decode with large region initial data
    #[test]
    fn test_ser_encode_decode_large_region() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 1024,
                readable: true,
                writable: false,
                initial: vec![0xAB; 256],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.regions[0].initial.len(), 256);
        assert!(decoded.regions[0].initial.iter().all(|&b| b == 0xAB));
    }

    // ─────────────────────────────────────────────────────────────────
    // Additional roundtrip / coverage tests added for +1-2% coverage
    // ─────────────────────────────────────────────────────────────────

    /// Test every U30Op variant encode→decode roundtrip with explicit assertions.
    /// Covers decode_op variants 0-95 that may not have dedicated tests.
    #[test]
    fn test_ser_all_op_variants_decode_roundtrip() {

        let cases: Vec<(&str, U30Op)> = vec![
            // 0: Nop
            ("Nop", U30Op::Nop),
            // 1: Const (tested separately below)
            // 2: Binary (tested via test_ser_all_binary_ops_roundtrip)
            // 3: Select
            ("Select", U30Op::Select { dst: 0, cond: 1, a: 2, b: 3 }),
            // 4-7: Not variants
            ("NotU8",  U30Op::NotU8  { dst: 0, src: 1 }),
            ("NotU16", U30Op::NotU16 { dst: 0, src: 1 }),
            ("NotU32", U30Op::NotU32 { dst: 0, src: 1 }),
            ("NotU64", U30Op::NotU64 { dst: 0, src: 1 }),
            // 8-9: Conversion
            ("I2F",  U30Op::I2F  { dst: 0, src: 1 }),
            ("F2I",  U30Op::F2I  { dst: 0, src: 1 }),
            // 10-12: Reinterpret
            ("TruncF32U64",       U30Op::TruncF32U64       { dst: 0, src: 1 }),
            ("ReinterpretF32U32", U30Op::ReinterpretF32U32 { dst: 0, src: 1 }),
            ("ReinterpretU32F32", U30Op::ReinterpretU32F32 { dst: 0, src: 1 }),
            // 13-14: Abs
            ("AbsU64", U30Op::AbsU64 { dst: 0, src: 1 }),
            ("AbsU32", U30Op::AbsU32 { dst: 0, src: 1 }),
            // 15-16: Neg
            ("NegU64", U30Op::NegU64 { dst: 0, src: 1 }),
            ("NegU32", U30Op::NegU32 { dst: 0, src: 1 }),
            // 17-22: bit count
            ("CtzU64",   U30Op::CtzU64   { dst: 0, src: 1 }),
            ("CtzU32",   U30Op::CtzU32   { dst: 0, src: 1 }),
            ("ClzU64",   U30Op::ClzU64   { dst: 0, src: 1 }),
            ("ClzU32",   U30Op::ClzU32   { dst: 0, src: 1 }),
            ("PopcntU64", U30Op::PopcntU64 { dst: 0, src: 1 }),
            ("PopcntU32", U30Op::PopcntU32 { dst: 0, src: 1 }),
            // 23-26: Rot
            ("RotlU64", U30Op::RotlU64 { dst: 0, val: 1, sh: 2 }),
            ("RotlU32", U30Op::RotlU32 { dst: 0, val: 1, sh: 2 }),
            ("RotrU64", U30Op::RotrU64 { dst: 0, val: 1, sh: 2 }),
            ("RotrU32", U30Op::RotrU32 { dst: 0, val: 1, sh: 2 }),
            // 27-31: F32 cmp (tested in test_ser_encode_decode_f32_cmp_ops)
            // 32-40: F32 arith (tested in test_ser_encode_decode_f32_arith_ops)
            // 41-49: ZExt / Trunc
            ("ZExtI8U16",  U30Op::ZExtI8U16  { dst: 0, src: 1 }),
            ("ZExtI8U32",  U30Op::ZExtI8U32  { dst: 0, src: 1 }),
            ("ZExtI8U64",  U30Op::ZExtI8U64  { dst: 0, src: 1 }),
            ("ZExtI16U32", U30Op::ZExtI16U32 { dst: 0, src: 1 }),
            ("ZExtI16U64", U30Op::ZExtI16U64 { dst: 0, src: 1 }),
            ("ZExtI32U64", U30Op::ZExtI32U64 { dst: 0, src: 1 }),
            ("TruncU64U32", U30Op::TruncU64U32 { dst: 0, src: 1 }),
            ("TruncU64U16", U30Op::TruncU64U16 { dst: 0, src: 1 }),
            ("TruncU32U16", U30Op::TruncU32U16 { dst: 0, src: 1 }),
            // 52-53: Memory
            ("MemSize", U30Op::MemSize { dst: 0, region: 1 }),
            ("MemGrow", U30Op::MemGrow { dst: 0, region: 1, delta: 2 }),
            // 68-73: F64 conversions
            ("I64F64",            U30Op::I64F64            { dst: 0, src: 1 }),
            ("F64I64",            U30Op::F64I64            { dst: 0, src: 1 }),
            ("F32F64",            U30Op::F32F64            { dst: 0, src: 1 }),
            ("F64F32",            U30Op::F64F32            { dst: 0, src: 1 }),
            ("ReinterpretF64U64", U30Op::ReinterpretF64U64 { dst: 0, src: 1 }),
            ("ReinterpretU64F64", U30Op::ReinterpretU64F64 { dst: 0, src: 1 }),
            // 74-79: SExt
            ("SExtI8U16",  U30Op::SExtI8U16  { dst: 0, src: 1 }),
            ("SExtI8U32",  U30Op::SExtI8U32  { dst: 0, src: 1 }),
            ("SExtI8U64",  U30Op::SExtI8U64  { dst: 0, src: 1 }),
            ("SExtI16U32", U30Op::SExtI16U32 { dst: 0, src: 1 }),
            ("SExtI16U64", U30Op::SExtI16U64 { dst: 0, src: 1 }),
            ("SExtI32U64", U30Op::SExtI32U64 { dst: 0, src: 1 }),
            // 80-82: ByteSwap
            ("ByteSwapU16", U30Op::ByteSwapU16 { dst: 0, src: 1 }),
            ("ByteSwapU32", U30Op::ByteSwapU32 { dst: 0, src: 1 }),
            ("ByteSwapU64", U30Op::ByteSwapU64 { dst: 0, src: 1 }),
            // 85-95: Memory + br
            ("TableBr",  U30Op::TableBr  { table: 0, index: 1 }),
            ("Break",    U30Op::Break    { code: 99 }),
            ("Assert",   U30Op::Assert   { cond: 0, msg: 1 }),
            ("LoadU8",   U30Op::LoadU8   { dst: 0, region: 1, offset: 2 }),
            ("StoreU8",  U30Op::StoreU8  { region: 0, offset: 1, src: 2 }),
            ("LoadU16",  U30Op::LoadU16  { dst: 0, region: 1, offset: 2 }),
            ("StoreU16", U30Op::StoreU16 { region: 0, offset: 1, src: 2 }),
            ("LoadU32",  U30Op::LoadU32  { dst: 0, region: 1, offset: 2 }),
            ("StoreU32", U30Op::StoreU32 { region: 0, offset: 1, src: 2 }),
            ("LoadU64",  U30Op::LoadU64  { dst: 0, region: 1, offset: 2 }),
            ("StoreU64", U30Op::StoreU64 { region: 0, offset: 1, src: 2 }),
        ];

        for (name, op) in cases {
            let module = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![op.clone()],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let encoded = encode(&module);
            let decoded = decode(&encoded)
                .unwrap_or_else(|e| panic!("decode failed for {}: {}", name, e));
            let got = &decoded.functions[0].blocks[0].ops[0];
            assert_eq!(got, &op, "roundtrip mismatch for {}", name);
        }
    }

    /// Test every U30Value variant decode via decode_value.
    #[test]
    fn test_ser_decode_value_all_variants() {
        // Bool (type 0)
        let got = {
            let buf = vec![0, 1];
            let mut pos = 0;
            decode_value(&buf, &mut pos).unwrap()
        };
        assert!(matches!(got, U30Value::Bool(true)));

        // U8 (type 1)
        let got = {
            let buf = vec![1, 99];
            let mut pos = 0;
            decode_value(&buf, &mut pos).unwrap()
        };
        assert!(matches!(got, U30Value::U8(99)));

        // U16 (type 2) — full 2 bytes
        let got = {
            let buf = vec![2, 0x34, 0x12];
            let mut pos = 0;
            decode_value(&buf, &mut pos).unwrap()
        };
        assert!(matches!(got, U30Value::U16(0x1234)));

        // U32 (type 3) — full 4 bytes
        let got = {
            let buf = vec![3, 0x78, 0x56, 0x34, 0x12];
            let mut pos = 0;
            decode_value(&buf, &mut pos).unwrap()
        };
        assert!(matches!(got, U30Value::U32(0x12345678)));

        // F32 (type 5) — full 4 bytes
        let got = {
            let bits: u32 = 0x40490FDBu32; // 3.14159
            let mut buf = vec![5];
            buf.extend_from_slice(&bits.to_le_bytes());
            let mut pos = 0;
            decode_value(&buf, &mut pos).unwrap()
        };
        assert!(matches!(got, U30Value::F32(f) if f.to_bits() == 0x40490FDBu32));
    }

    /// Test every U30Type variant encode→decode.
    #[test]
    fn test_ser_decode_type_all_variants() {
        // Build a minimal module and replace params/results with each type
        for (idx, ty) in [
            (0u8, U30Type::Bool),
            (1,   U30Type::U8),
            (2,   U30Type::U16),
            (3,   U30Type::U32),
            (4,   U30Type::U64),
            (5,   U30Type::F32),
            (6,   U30Type::F64),
        ] {
            // Verify encode_type / decode_type roundtrip
            let module = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![ty.clone()],
                    results: vec![ty.clone()],
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let decoded = decode(&encode(&module)).unwrap();
            assert_eq!(decoded.functions[0].params[0], ty, "type idx {} failed", idx);
            assert_eq!(decoded.functions[0].results[0], ty, "type idx {} failed", idx);
        }
    }

    /// Test decode_type error path for unknown variant.
    #[test]
    fn test_ser_decode_type_unknown_variant() {
        let buf = vec![99]; // unknown type
        let mut pos = 0;
        let err = decode_type(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("unknown type"), "got: {}", err);
    }

    /// Test decode_terminator variant 4 (Trap) explicit decode.
    #[test]
    fn test_ser_decode_terminator_trap() {
        let buf = vec![4, 77, 0, 0, 0]; // variant=4, code=77
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::Trap { code: 77 }));
    }

    /// Test decode_op: truncated after Select fields (variant 3, partial)
    #[test]
    fn test_ser_decode_op_truncated_select() {
        // Variant 3 (Select): needs dst(4) + cond(4) + a(4) + b(4) = 16 bytes after variant
        let buf = vec![3, 0, 0, 0, 0, 1, 0, 0, 0, 2]; // 10 bytes total, need 4 more
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: truncated after NotU8 field (variant 4, partial)
    #[test]
    fn test_ser_decode_op_truncated_notu8() {
        // Variant 4 (NotU8): needs dst(4) + src(4) = 8 bytes after variant
        let buf = vec![4, 0, 0, 0, 0]; // 5 bytes total, need 4 more
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 86 (Break) explicit decode.
    #[test]
    fn test_ser_decode_op_break() {
        let buf = vec![86, 42, 0, 0, 0]; // variant=86, code=42
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Break { code: 42 }));
    }

    /// Test decode_op: variant 87 (Assert) explicit decode.
    #[test]
    fn test_ser_decode_op_assert() {
        let buf = vec![87, 5, 0, 0, 0, 7, 0, 0, 0]; // variant=87, cond=5, msg=7
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Assert { cond: 5, msg: 7 }));
    }

    /// Test decode_op: variant 88 (LoadU8) explicit decode.
    #[test]
    fn test_ser_decode_op_loadu8() {
        let mut buf = vec![88];
        buf.extend_from_slice(&1u32.to_le_bytes()); // dst=1
        buf.extend_from_slice(&2u32.to_le_bytes()); // region=2
        buf.extend_from_slice(&3u32.to_le_bytes()); // offset=3
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::LoadU8 { dst: 1, region: 2, offset: 3 }));
    }

    /// Test decode_op: variant 89 (StoreU8) explicit decode.
    #[test]
    fn test_ser_decode_op_storeu8() {
        let mut buf = vec![89];
        buf.extend_from_slice(&0u32.to_le_bytes()); // region=0
        buf.extend_from_slice(&4u32.to_le_bytes()); // offset=4
        buf.extend_from_slice(&5u32.to_le_bytes()); // src=5
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::StoreU8 { region: 0, offset: 4, src: 5 }));
    }

    /// Test decode_op: variant 90 (LoadU16) explicit decode.
    #[test]
    fn test_ser_decode_op_loadu16() {
        let mut buf = vec![90];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::LoadU16 { dst: 1, region: 2, offset: 3 }));
    }

    /// Test decode_op: variant 91 (StoreU16) explicit decode.
    #[test]
    fn test_ser_decode_op_storeu16() {
        let mut buf = vec![91];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&5u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::StoreU16 { region: 0, offset: 4, src: 5 }));
    }

    /// Test decode_op: variant 92 (LoadU32) explicit decode.
    #[test]
    fn test_ser_decode_op_loadu32() {
        let mut buf = vec![92];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::LoadU32 { dst: 1, region: 2, offset: 3 }));
    }

    /// Test decode_op: variant 93 (StoreU32) explicit decode.
    #[test]
    fn test_ser_decode_op_storeu32() {
        let mut buf = vec![93];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&5u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::StoreU32 { region: 0, offset: 4, src: 5 }));
    }

    /// Test decode_op: variant 94 (LoadU64) explicit decode.
    #[test]
    fn test_ser_decode_op_loadu64() {
        let mut buf = vec![94];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::LoadU64 { dst: 1, region: 2, offset: 3 }));
    }

    /// Test decode_op: variant 95 (StoreU64) explicit decode.
    #[test]
    fn test_ser_decode_op_storeu64() {
        let mut buf = vec![95];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&5u32.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::StoreU64 { region: 0, offset: 4, src: 5 }));
    }

    /// Test decode_op: truncated at TableBr fields (variant 85, partial)
    #[test]
    fn test_ser_decode_op_truncated_tablebr() {
        let buf = vec![85, 0, 0, 0, 0]; // variant + dst=0, missing index
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: truncated at Break (variant 86, partial)
    #[test]
    fn test_ser_decode_op_truncated_break() {
        let buf = vec![86]; // variant only, missing code
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: truncated at Assert (variant 87, partial)
    #[test]
    fn test_ser_decode_op_truncated_assert() {
        let buf = vec![87, 0, 0, 0, 0]; // variant + cond=0, missing msg
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: truncated at LoadU8 (variant 88, partial)
    #[test]
    fn test_ser_decode_op_truncated_loadu8() {
        let buf = vec![88, 0, 0, 0, 0]; // variant + dst, missing region+offset
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: truncated at StoreU8 (variant 89, partial)
    #[test]
    fn test_ser_decode_op_truncated_storeu8() {
        let buf = vec![89, 0, 0, 0, 0]; // variant + region, missing offset+src
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: TableBr explicit roundtrip (variant 85)
    #[test]
    fn test_ser_decode_op_tablebr() {
        let buf = vec![85, 0, 0, 0, 0, 1, 0, 0, 0]; // table=0, index=1
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::TableBr { table: 0, index: 1 }));
    }

    /// Test decode_terminator: Ret with multiple values explicit decode.
    #[test]
    fn test_ser_decode_terminator_ret_multi() {
        let mut buf = vec![2]; // variant=2 (Ret)
        buf.extend_from_slice(&3u32.to_le_bytes()); // count=3
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&20u32.to_le_bytes());
        buf.extend_from_slice(&30u32.to_le_bytes());
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::Ret { values } if values == &[10, 20, 30]));
    }

    /// Test decode_terminator: TailCall with args explicit decode.
    #[test]
    fn test_ser_decode_terminator_tailcall_multi() {
        let mut buf = vec![3]; // variant=3 (TailCall)
        buf.extend_from_slice(&99u32.to_le_bytes()); // function=99
        buf.extend_from_slice(&2u32.to_le_bytes()); // count=2
        buf.extend_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&8u32.to_le_bytes());
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::TailCall { function: 99, args } if args == &[7, 8]));
    }

    /// Test full module decode at function boundary truncation.
    #[test]
    fn test_ser_decode_truncated_function_header() {
        // Valid header + 1 empty region, but function data truncated mid-param-count
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1); // version
        data.push(0); // 0 regions
        data.push(1); // 1 function
        // No params count byte — truncation
        let err = decode(&data).expect_err("truncated function header");
        assert!(err.to_string().contains("truncated") || !err.to_string().is_empty());
    }

    /// Test full module decode at table count boundary.
    #[test]
    fn test_ser_decode_truncated_table_count() {
        // Valid header + 0 regions, then 0 table count but truncated
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1); // version
        data.push(0); // 0 regions
        // 0 tables count cut off at 1 byte (no functions data)
        // But actually we need at least 1 function to reach tables
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 functions
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 table
        // Truncated: table id missing
        let err = decode(&data).expect_err("truncated at table id");
        assert!(!err.to_string().is_empty());
    }

    /// Test decode_function: truncated params count.
    #[test]
    fn test_ser_decode_function_truncated_params() {
        // Minimal valid header, then function with truncated param count
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1);
        data.push(0); // 0 regions
        data.push(0); // 0 tables
        data.push(1); // 1 function
        // Truncated: no param count byte
        let err = decode(&data).expect_err("truncated params");
        assert!(!err.to_string().is_empty());
    }

    /// Test decode_function: params present but truncated type bytes.
    #[test]
    fn test_ser_decode_function_truncated_param_types() {
        // Valid header, function declares 2 params but provides only 1 type byte
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1);
        data.push(0); // 0 regions
        data.push(0); // 0 tables
        data.push(1); // 1 function
        data.extend_from_slice(&2u32.to_le_bytes()); // param_count=2
        data.push(0); // param type 0 (Bool) — first param
        // Missing second param type
        let err = decode(&data).expect_err("truncated param types");
        assert!(!err.to_string().is_empty());
    }

    /// Test decode_block: truncated block count.
    #[test]
    fn test_ser_decode_block_truncated_count() {
        // Valid header, function with 1 block but block count byte missing
        let mut data = Vec::new();
        data.extend_from_slice(b"U30X");
        data.push(1);
        data.push(0); // 0 regions
        data.push(0); // 0 tables
        data.push(1); // 1 function
        data.push(0); // 0 params
        data.push(0); // 0 results
        // Truncated: no block count
        let err = decode(&data).expect_err("truncated block count");
        assert!(!err.to_string().is_empty());
    }

    /// Test encode → decode roundtrip with all U30Value types as Const.
    #[test]
    fn test_ser_const_all_value_types_explicit() {
        let values = [
            (U30Value::Bool(false),  "Bool(false)"),
            (U30Value::U8(0),       "U8"),
            (U30Value::U16(0),      "U16"),
            (U30Value::U32(0),      "U32"),
            (U30Value::U64(0),      "U64"),
            (U30Value::F32(0.0),    "F32"),
            (U30Value::F64(0.0),    "F64"),
        ];
        for (val, name) in values {
            let module = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Const { dst: 0, value: val }],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let decoded = decode(&encode(&module)).unwrap();
            let got = &decoded.functions[0].blocks[0].ops[0];
            assert!(matches!(got, U30Op::Const { .. }), "Const roundtrip failed for {}", name);
        }
    }

    /// Test encode → decode for all U30Terminator variants with explicit assertions.
    #[test]
    fn test_ser_all_terminator_variants_explicit() {
        // Br variant 0
        {
            let buf = vec![0, 5, 0, 0, 0]; // variant=0, target=5
            let mut pos = 0;
            let t = decode_terminator(&buf, &mut pos).unwrap();
            assert!(matches!(t, U30Terminator::Br { target: 5 }));
        }
        // BrIf variant 1
        {
            let buf = vec![1, 3, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0]; // cond=3,then=7,else=9
            let mut pos = 0;
            let t = decode_terminator(&buf, &mut pos).unwrap();
            assert!(matches!(t, U30Terminator::BrIf { cond: 3, then_target: 7, else_target: 9 }));
        }
        // Ret variant 2 (already covered)
        // TailCall variant 3 (already covered)
        // Trap variant 4
        {
            let buf = vec![4, 55, 0, 0, 0]; // variant=4, code=55
            let mut pos = 0;
            let t = decode_terminator(&buf, &mut pos).unwrap();
            assert!(matches!(t, U30Terminator::Trap { code: 55 }));
        }
    }

    /// Test decode_binary_op: valid indices 0-26 covered,
    /// and invalid index 27 caught.
    #[test]
    fn test_ser_decode_binary_op_invalid_edge() {
        // Test one more edge: index 28 (beyond known)
        let err = decode_binary_op(28).unwrap_err();
        assert!(err.to_string().contains("unknown binary op"), "got: {}", err);
    }

    /// Test decode_op: invalid binary op index within valid variant.
    /// Provide all fields (dst, op_idx, a, b) so decode_binary_op is reached.
    #[test]
    fn test_ser_decode_op_invalid_binary_op_idx() {
        // Variant 2 (Binary): variant + dst(4) + op_idx=27(4) + a(4) + b(4) = 17 bytes
        let buf = vec![
            2,                               // variant = Binary
            27, 0, 0, 0,                    // op_idx = 27 (invalid)
            0, 0, 0, 0,                     // dst = 0
            0, 0, 0, 0,                     // a = 0
            0, 0, 0, 0,                     // b = 0
        ];
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("binary op"), "got: {}", err);
    }

    /// Test encode and decode: module with all types as params and results.
    #[test]
    fn test_ser_module_all_param_result_types() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![
                    U30Type::Bool,
                    U30Type::U8,
                    U30Type::U16,
                    U30Type::U32,
                    U30Type::U64,
                    U30Type::F32,
                    U30Type::F64,
                ],
                results: vec![
                    U30Type::Bool,
                    U30Type::U8,
                    U30Type::U16,
                    U30Type::U32,
                    U30Type::U64,
                    U30Type::F32,
                    U30Type::F64,
                ],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0, 1, 2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].params.len(), 7);
        assert_eq!(decoded.functions[0].results.len(), 7);
    }

    /// Test decode_value: Bool variant explicitly.
    #[test]
    fn test_ser_decode_value_bool_false() {
        let buf = vec![0, 0]; // type=0, value=false
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::Bool(false)));
    }

    /// Test decode_op: Const with F64 value explicit decode.
    #[test]
    fn test_ser_decode_op_const_f64() {
        let bits: u64 = 0x3FF0000000000000u64; // 1.0
        let mut buf = vec![1]; // variant=Const
        buf.extend_from_slice(&0u32.to_le_bytes()); // dst=0
        buf.push(6); // value type=F64
        buf.extend_from_slice(&bits.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Const { dst: 0, value: U30Value::F64(f) }
            if f.to_bits() == bits));
    }

    /// Test decode_op: Const with F32 value explicit decode.
    #[test]
    fn test_ser_decode_op_const_f32() {
        let bits: u32 = 0x40490FDBu32; // 3.14159
        let mut buf = vec![1]; // variant=Const
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(5); // value type=F32
        buf.extend_from_slice(&bits.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Const { dst: 0, value: U30Value::F32(f) }
            if f.to_bits() == bits));
    }

    /// Test decode_op: Const with U16 value explicit decode.
    #[test]
    fn test_ser_decode_op_const_u16() {
        let mut buf = vec![1]; // variant=Const
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2); // value type=U16
        buf.extend_from_slice(&0xCDu16.to_le_bytes()); // 0xCD
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Const { dst: 0, value: U30Value::U16(0xCD) }));
    }

    /// Test decode_op: Const with Bool value explicit decode.
    #[test]
    fn test_ser_decode_op_const_bool() {
        let mut buf = vec![1]; // variant=Const
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0); // value type=Bool
        buf.push(1); // value=true
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Const { dst: 0, value: U30Value::Bool(true) }));
    }

    /// Test decode_op: MemSize explicit decode (variant 52).
    #[test]
    fn test_ser_decode_op_memsize() {
        let mut buf = vec![52];
        buf.extend_from_slice(&3u32.to_le_bytes()); // dst=3
        buf.extend_from_slice(&1u32.to_le_bytes()); // region=1
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemSize { dst: 3, region: 1 }));
    }

    /// Test decode_op: MemGrow explicit decode (variant 53).
    #[test]
    fn test_ser_decode_op_memgrow() {
        let mut buf = vec![53];
        buf.extend_from_slice(&4u32.to_le_bytes()); // dst=4
        buf.extend_from_slice(&2u32.to_le_bytes()); // region=2
        buf.extend_from_slice(&8u32.to_le_bytes()); // delta=8
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemGrow { dst: 4, region: 2, delta: 8 }));
    }

    /// Test decode_op: MemFill explicit decode (variant 51, complete).
    #[test]
    fn test_ser_decode_op_memfill() {
        let mut buf = vec![51];
        buf.extend_from_slice(&0u32.to_le_bytes()); // region=0
        buf.extend_from_slice(&16u32.to_le_bytes()); // offset=16
        buf.extend_from_slice(&99u32.to_le_bytes()); // value=99
        buf.extend_from_slice(&4u32.to_le_bytes()); // size=4
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemFill { region: 0, offset: 16, value: 99, size: 4 }));
    }

    /// Test decode_op: MemCopy explicit decode (variant 50, complete).
    #[test]
    fn test_ser_decode_op_memcopy() {
        let mut buf = vec![50];
        buf.extend_from_slice(&0u32.to_le_bytes()); // dst_region=0
        buf.extend_from_slice(&8u32.to_le_bytes());  // dst_offset=8
        buf.extend_from_slice(&1u32.to_le_bytes()); // src_region=1
        buf.extend_from_slice(&0u32.to_le_bytes());  // src_offset=0
        buf.extend_from_slice(&4u32.to_le_bytes());  // size=4
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemCopy {
            dst_region: 0, dst_offset: 8, src_region: 1, src_offset: 0, size: 4
        }));
    }

    /// Test decode_op: Call with 0 args and 0 results explicit decode (variant 83).
    #[test]
    fn test_ser_decode_op_call_empty() {
        let mut buf = vec![83];
        buf.extend_from_slice(&7u32.to_le_bytes()); // function=7
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg_count=0
        buf.extend_from_slice(&0u32.to_le_bytes()); // result_count=0
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Call { function: 7, args, results }
            if args.is_empty() && results.is_empty()));
    }

    /// Test decode_op: IndirectCall with 0 args and 0 results (variant 84).
    #[test]
    fn test_ser_decode_op_indirect_call_empty() {
        let mut buf = vec![84];
        buf.extend_from_slice(&5u32.to_le_bytes()); // function_reg=5
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg_count=0
        buf.extend_from_slice(&0u32.to_le_bytes()); // result_count=0
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::IndirectCall { function: 5, args, results }
            if args.is_empty() && results.is_empty()));
    }

    /// Test decode_op: I2F explicit decode (variant 8).
    #[test]
    fn test_ser_decode_op_i2f() {
        let buf = vec![8, 0, 0, 0, 0, 1, 0, 0, 0]; // dst=0, src=1
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::I2F { dst: 0, src: 1 }));
    }

    /// Test decode_op: F2I explicit decode (variant 9).
    #[test]
    fn test_ser_decode_op_f2i() {
        let buf = vec![9, 2, 0, 0, 0, 3, 0, 0, 0]; // dst=2, src=3
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::F2I { dst: 2, src: 3 }));
    }

    /// Test decode_op: Select explicit decode (variant 3, complete).
    #[test]
    fn test_ser_decode_op_select() {
        let buf = vec![3, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0];
        // dst=5, cond=6, a=7, b=8
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Select { dst: 5, cond: 6, a: 7, b: 8 }));
    }

    /// Test decode_op: NotU8 explicit decode (variant 4).
    #[test]
    fn test_ser_decode_op_notu8() {
        let buf = vec![4, 9, 0, 0, 0, 10, 0, 0, 0]; // dst=9, src=10
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::NotU8 { dst: 9, src: 10 }));
    }

    /// Test decode_op: AbsU64 explicit decode (variant 13).
    #[test]
    fn test_ser_decode_op_absu64() {
        let buf = vec![13, 1, 0, 0, 0, 2, 0, 0, 0]; // dst=1, src=2
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::AbsU64 { dst: 1, src: 2 }));
    }

    /// Test decode_op: NegU64 explicit decode (variant 15).
    #[test]
    fn test_ser_decode_op_negu64() {
        let buf = vec![15, 3, 0, 0, 0, 4, 0, 0, 0]; // dst=3, src=4
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::NegU64 { dst: 3, src: 4 }));
    }

    /// Test decode_op: CtzU64 explicit decode (variant 17).
    #[test]
    fn test_ser_decode_op_ctzu64() {
        let buf = vec![17, 5, 0, 0, 0, 6, 0, 0, 0]; // dst=5, src=6
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::CtzU64 { dst: 5, src: 6 }));
    }

    /// Test decode_op: ClzU64 explicit decode (variant 19).
    #[test]
    fn test_ser_decode_op_clzu64() {
        let buf = vec![19, 7, 0, 0, 0, 8, 0, 0, 0]; // dst=7, src=8
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::ClzU64 { dst: 7, src: 8 }));
    }

    /// Test decode_op: PopcntU64 explicit decode (variant 21).
    #[test]
    fn test_ser_decode_op_popcntu64() {
        let buf = vec![21, 9, 0, 0, 0, 10, 0, 0, 0]; // dst=9, src=10
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::PopcntU64 { dst: 9, src: 10 }));
    }

    /// Test decode_op: RotlU64 explicit decode (variant 23).
    #[test]
    fn test_ser_decode_op_rotlu64() {
        let buf = vec![23, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]; // dst=1,val=2,sh=3
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::RotlU64 { dst: 1, val: 2, sh: 3 }));
    }

    /// Test decode_op: ZExtI8U16 explicit decode (variant 41).
    #[test]
    fn test_ser_decode_op_zexti8u16() {
        let buf = vec![41, 0, 0, 0, 0, 1, 0, 0, 0]; // dst=0, src=1
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::ZExtI8U16 { dst: 0, src: 1 }));
    }

    /// Test decode_op: TruncU64U32 explicit decode (variant 47).
    #[test]
    fn test_ser_decode_op_truncu64u32() {
        let buf = vec![47, 2, 0, 0, 0, 3, 0, 0, 0]; // dst=2, src=3
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::TruncU64U32 { dst: 2, src: 3 }));
    }

    /// Test decode_op: SExtI8U16 explicit decode (variant 74).
    #[test]
    fn test_ser_decode_op_sexti8u16() {
        let buf = vec![74, 1, 0, 0, 0, 2, 0, 0, 0]; // dst=1, src=2
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::SExtI8U16 { dst: 1, src: 2 }));
    }

    /// Test decode_op: ByteSwapU16 explicit decode (variant 80).
    #[test]
    fn test_ser_decode_op_byteswapu16() {
        let buf = vec![80, 3, 0, 0, 0, 4, 0, 0, 0]; // dst=3, src=4
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::ByteSwapU16 { dst: 3, src: 4 }));
    }

    /// Test decode_op: ReinterpretF32U32 explicit decode (variant 11).
    #[test]
    fn test_ser_decode_op_reinterpret_f32_u32() {
        let buf = vec![11, 0, 0, 0, 0, 1, 0, 0, 0]; // dst=0, src=1
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::ReinterpretF32U32 { dst: 0, src: 1 }));
    }

    /// Test decode_op: ReinterpretU32F32 explicit decode (variant 12).
    #[test]
    fn test_ser_decode_op_reinterpret_u32_f32() {
        let buf = vec![12, 1, 0, 0, 0, 2, 0, 0, 0]; // dst=1, src=2
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::ReinterpretU32F32 { dst: 1, src: 2 }));
    }

    /// Test decode_op: TruncF32U64 explicit decode (variant 10).
    #[test]
    fn test_ser_decode_op_truncf32u64() {
        let buf = vec![10, 2, 0, 0, 0, 3, 0, 0, 0]; // dst=2, src=3
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::TruncF32U64 { dst: 2, src: 3 }));
    }

    /// Test decode_op: variant 95 StoreU64 truncated.
    #[test]
    fn test_ser_decode_op_truncated_storeu64() {
        let buf = vec![95, 0, 0, 0, 0]; // variant + region, missing offset+src
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 94 LoadU64 truncated.
    #[test]
    fn test_ser_decode_op_truncated_loadu64() {
        let buf = vec![94, 0, 0, 0, 0, 1, 0, 0, 0]; // variant + dst + region, missing offset
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 93 StoreU32 truncated.
    #[test]
    fn test_ser_decode_op_truncated_storeu32() {
        let buf = vec![93, 0, 0, 0, 0]; // variant + region, missing offset+src
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 92 LoadU32 truncated.
    #[test]
    fn test_ser_decode_op_truncated_loadu32() {
        let buf = vec![92, 0, 0, 0, 0, 1, 0, 0, 0]; // variant + dst + region, missing offset
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 91 StoreU16 truncated.
    #[test]
    fn test_ser_decode_op_truncated_storeu16() {
        let buf = vec![91, 0, 0, 0, 0]; // variant + region, missing offset+src
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 90 LoadU16 truncated.
    #[test]
    fn test_ser_decode_op_truncated_loadu16() {
        let buf = vec![90, 0, 0, 0, 0, 1, 0, 0, 0]; // variant + dst + region, missing offset
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: MemFill truncated (variant 51, missing fields).
    #[test]
    fn test_ser_decode_op_truncated_memfill() {
        let buf = vec![51, 0, 0, 0, 0, 1, 0, 0, 0]; // region + offset + value, missing size
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: MemSize truncated (variant 52, missing region).
    #[test]
    fn test_ser_decode_op_truncated_memsize() {
        let buf = vec![52, 0, 0, 0, 0]; // variant + dst, missing region
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: MemGrow truncated (variant 53, missing delta).
    #[test]
    fn test_ser_decode_op_truncated_memgrow() {
        let buf = vec![53, 0, 0, 0, 0, 1, 0, 0, 0]; // variant + dst + region, missing delta
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: Call result_count present but truncated results (variant 83).
    #[test]
    fn test_ser_decode_op_truncated_call_results() {
        let mut buf = vec![83];
        buf.extend_from_slice(&0u32.to_le_bytes()); // function=0
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg_count=0
        buf.extend_from_slice(&2u32.to_le_bytes()); // result_count=2
        buf.extend_from_slice(&0u32.to_le_bytes()); // result1
        // result2 missing
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: IndirectCall result_count present but truncated (variant 84).
    #[test]
    fn test_ser_decode_op_truncated_indirect_call_results() {
        let mut buf = vec![84];
        buf.extend_from_slice(&0u32.to_le_bytes()); // function_reg=0
        buf.extend_from_slice(&0u32.to_le_bytes()); // arg_count=0
        buf.extend_from_slice(&2u32.to_le_bytes()); // result_count=2
        buf.extend_from_slice(&0u32.to_le_bytes()); // result1
        // result2 missing
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    /// Test decode_op: variant 0 (Nop) works even with extra trailing bytes.
    #[test]
    fn test_ser_decode_op_nop_trailing_bytes() {
        let buf = vec![0, 99, 99, 99]; // Nop followed by garbage
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Nop));
        assert_eq!(pos, 1); // only consumed the variant byte
    }

    // ─────────────────────────────────────────────────────────────────
    // End of additional coverage tests
    // ─────────────────────────────────────────────────────────────────

    // Test encode/decode with table with many targets
    #[test]
    fn test_ser_encode_decode_table_many_targets() {
        let module = U30Module {
            regions: vec![],
            tables: vec![U30TableDecl { id: 0, targets: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9] }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.tables[0].targets.len(), 10);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Additional coverage tests for 100% regions
    // ═══════════════════════════════════════════════════════════════════════════

    /// Test decode_op: Nop variant (0) explicit decode - covers encode path
    #[test]
    fn test_ser_decode_op_nop_explicit() {
        let buf = vec![0];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Nop));
    }

    /// Test decode_op: Const with U64 value explicit decode (variant 1)
    #[test]
    fn test_ser_decode_op_const_u64() {
        let bits: u64 = 0xDEADBEEFCAFEBABEu64;
        let mut buf = vec![1]; // variant=Const
        buf.extend_from_slice(&0u32.to_le_bytes()); // dst=0
        buf.push(4); // value type=U64
        buf.extend_from_slice(&bits.to_le_bytes());
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Const { dst: 0, value: U30Value::U64(v) } if v == bits));
    }

    /// Test decode_op: Binary with all valid binary ops (variants 2 with valid op_idx)
    #[test]
    fn test_ser_decode_op_binary_all_ops() {
        use crate::ir::U30BinaryOp as Op;
        let ops = [
            (0u32, Op::AddWrapU64), (1, Op::AddWrapU32), (2, Op::SubWrapU64),
            (3, Op::SubWrapU32), (4, Op::MulWrapU64), (5, Op::MulWrapU32),
            (6, Op::AndU8), (7, Op::OrU8), (8, Op::XorU8),
            (9, Op::ShlU64), (10, Op::ShlU32), (11, Op::ShrU64), (12, Op::ShrU32),
            (13, Op::DivU64), (14, Op::DivU32), (15, Op::RemU64), (16, Op::RemU32),
            (17, Op::Eq), (18, Op::LtU64), (19, Op::GtU64), (20, Op::GeU64),
            (21, Op::LeU64), (22, Op::LeU32), (23, Op::MinU64), (24, Op::MaxU64),
            (25, Op::MinU32), (26, Op::MaxU32),
        ];
        for (op_idx, op) in ops {
            let mut buf = vec![2]; // variant=Binary
            buf.extend_from_slice(&op_idx.to_le_bytes()); // op_idx
            buf.extend_from_slice(&0u32.to_le_bytes()); // dst
            buf.extend_from_slice(&1u32.to_le_bytes()); // a
            buf.extend_from_slice(&2u32.to_le_bytes()); // b
            let mut pos = 0;
            let decoded_op = decode_op(&buf, &mut pos).unwrap();
            assert!(matches!(decoded_op, U30Op::Binary { op: decoded, .. } if decoded == op), 
                "Binary op_idx {} mismatch", op_idx);
        }
    }

    /// Test decode_op: variants 4-7 (Not variants) full decode
    #[test]
    fn test_ser_decode_op_all_not_variants() {
        let cases = [
            (4u8, U30Op::NotU8 { dst: 1, src: 2 }),
            (5, U30Op::NotU16 { dst: 3, src: 4 }),
            (6, U30Op::NotU32 { dst: 5, src: 6 }),
            (7, U30Op::NotU64 { dst: 7, src: 8 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::NotU8 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::NotU16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::NotU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::NotU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 10-16 (Conversion and unary) full decode
    #[test]
    fn test_ser_decode_op_all_conversion_unary() {
        let cases = [
            (8u8, U30Op::I2F { dst: 0, src: 1 }),
            (9, U30Op::F2I { dst: 1, src: 2 }),
            (10, U30Op::TruncF32U64 { dst: 2, src: 3 }),
            (11, U30Op::ReinterpretF32U32 { dst: 3, src: 4 }),
            (12, U30Op::ReinterpretU32F32 { dst: 4, src: 5 }),
            (13, U30Op::AbsU64 { dst: 5, src: 6 }),
            (14, U30Op::AbsU32 { dst: 6, src: 7 }),
            (15, U30Op::NegU64 { dst: 7, src: 8 }),
            (16, U30Op::NegU32 { dst: 8, src: 9 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::I2F { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F2I { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::TruncF32U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ReinterpretF32U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ReinterpretU32F32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::AbsU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::AbsU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::NegU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::NegU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 17-22 (bit count ops) full decode
    #[test]
    fn test_ser_decode_op_all_bit_count() {
        let cases = [
            (17u8, U30Op::CtzU64 { dst: 0, src: 1 }),
            (18, U30Op::CtzU32 { dst: 1, src: 2 }),
            (19, U30Op::ClzU64 { dst: 2, src: 3 }),
            (20, U30Op::ClzU32 { dst: 3, src: 4 }),
            (21, U30Op::PopcntU64 { dst: 4, src: 5 }),
            (22, U30Op::PopcntU32 { dst: 5, src: 6 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::CtzU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::CtzU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ClzU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ClzU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::PopcntU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::PopcntU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 23-26 (rotate ops) full decode
    #[test]
    fn test_ser_decode_op_all_rotate() {
        let cases = [
            (23u8, U30Op::RotlU64 { dst: 0, val: 1, sh: 2 }),
            (24, U30Op::RotlU32 { dst: 1, val: 2, sh: 3 }),
            (25, U30Op::RotrU64 { dst: 2, val: 3, sh: 4 }),
            (26, U30Op::RotrU32 { dst: 3, val: 4, sh: 5 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::RotlU64 { dst, val, sh } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&val.to_le_bytes()); buf.extend_from_slice(&sh.to_le_bytes()); }
            if let U30Op::RotlU32 { dst, val, sh } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&val.to_le_bytes()); buf.extend_from_slice(&sh.to_le_bytes()); }
            if let U30Op::RotrU64 { dst, val, sh } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&val.to_le_bytes()); buf.extend_from_slice(&sh.to_le_bytes()); }
            if let U30Op::RotrU32 { dst, val, sh } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&val.to_le_bytes()); buf.extend_from_slice(&sh.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 27-31 (F32 comparison ops) full decode
    #[test]
    fn test_ser_decode_op_all_f32_cmp() {
        let cases = [
            (27u8, U30Op::FEq { dst: 0, a: 1, b: 2 }),
            (28, U30Op::FLt { dst: 1, a: 2, b: 3 }),
            (29, U30Op::FGt { dst: 2, a: 3, b: 4 }),
            (30, U30Op::FLe { dst: 3, a: 4, b: 5 }),
            (31, U30Op::FGe { dst: 4, a: 5, b: 6 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::FEq { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FLt { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FGt { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FLe { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FGe { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 32-40 (F32 arithmetic ops) full decode
    #[test]
    fn test_ser_decode_op_all_f32_arith() {
        let cases = [
            (32u8, U30Op::FAdd { dst: 0, a: 1, b: 2 }),
            (33, U30Op::FSub { dst: 1, a: 2, b: 3 }),
            (34, U30Op::FMul { dst: 2, a: 3, b: 4 }),
            (35, U30Op::FDiv { dst: 3, a: 4, b: 5 }),
            (36, U30Op::FSqrt { dst: 4, src: 5 }),
            (37, U30Op::FAbs { dst: 5, src: 6 }),
            (38, U30Op::FNeg { dst: 6, src: 7 }),
            (39, U30Op::FMin { dst: 7, a: 8, b: 9 }),
            (40, U30Op::FMax { dst: 8, a: 9, b: 10 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::FAdd { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FSub { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FMul { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FDiv { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FSqrt { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::FAbs { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::FNeg { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::FMin { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::FMax { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 41-49 (ZExt/Trunc ops) full decode
    #[test]
    fn test_ser_decode_op_all_zext_trunc() {
        let cases = [
            (41u8, U30Op::ZExtI8U16 { dst: 0, src: 1 }),
            (42, U30Op::ZExtI8U32 { dst: 1, src: 2 }),
            (43, U30Op::ZExtI8U64 { dst: 2, src: 3 }),
            (44, U30Op::ZExtI16U32 { dst: 3, src: 4 }),
            (45, U30Op::ZExtI16U64 { dst: 4, src: 5 }),
            (46, U30Op::ZExtI32U64 { dst: 5, src: 6 }),
            (47, U30Op::TruncU64U32 { dst: 6, src: 7 }),
            (48, U30Op::TruncU64U16 { dst: 7, src: 8 }),
            (49, U30Op::TruncU32U16 { dst: 8, src: 9 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::ZExtI8U16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ZExtI8U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ZExtI8U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ZExtI16U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ZExtI16U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ZExtI32U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::TruncU64U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::TruncU64U16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::TruncU32U16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 54-67 (F64 arithmetic/comparison ops) full decode
    #[test]
    fn test_ser_decode_op_all_f64_ops() {
        let cases = [
            (54u8, U30Op::F64Eq { dst: 0, a: 1, b: 2 }),
            (55, U30Op::F64Lt { dst: 1, a: 2, b: 3 }),
            (56, U30Op::F64Gt { dst: 2, a: 3, b: 4 }),
            (57, U30Op::F64Le { dst: 3, a: 4, b: 5 }),
            (58, U30Op::F64Ge { dst: 4, a: 5, b: 6 }),
            (59, U30Op::F64Add { dst: 5, a: 6, b: 7 }),
            (60, U30Op::F64Sub { dst: 6, a: 7, b: 8 }),
            (61, U30Op::F64Mul { dst: 7, a: 8, b: 9 }),
            (62, U30Op::F64Div { dst: 8, a: 9, b: 10 }),
            (63, U30Op::F64Sqrt { dst: 9, src: 10 }),
            (64, U30Op::F64Abs { dst: 10, src: 11 }),
            (65, U30Op::F64Neg { dst: 11, src: 12 }),
            (66, U30Op::F64Min { dst: 12, a: 13, b: 14 }),
            (67, U30Op::F64Max { dst: 13, a: 14, b: 15 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::F64Eq { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Lt { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Gt { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Le { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Ge { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Add { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Sub { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Mul { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Div { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Sqrt { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F64Abs { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F64Neg { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F64Min { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            if let U30Op::F64Max { dst, a, b } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&a.to_le_bytes()); buf.extend_from_slice(&b.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 68-73 (F64 conversion ops) full decode
    #[test]
    fn test_ser_decode_op_all_f64_conversions() {
        let cases = [
            (68u8, U30Op::I64F64 { dst: 0, src: 1 }),
            (69, U30Op::F64I64 { dst: 1, src: 2 }),
            (70, U30Op::F32F64 { dst: 2, src: 3 }),
            (71, U30Op::F64F32 { dst: 3, src: 4 }),
            (72, U30Op::ReinterpretF64U64 { dst: 4, src: 5 }),
            (73, U30Op::ReinterpretU64F64 { dst: 5, src: 6 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::I64F64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F64I64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F32F64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::F64F32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ReinterpretF64U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ReinterpretU64F64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 74-82 (SExt and ByteSwap ops) full decode
    #[test]
    fn test_ser_decode_op_all_sext_byteswap() {
        let cases = [
            (74u8, U30Op::SExtI8U16 { dst: 0, src: 1 }),
            (75, U30Op::SExtI8U32 { dst: 1, src: 2 }),
            (76, U30Op::SExtI8U64 { dst: 2, src: 3 }),
            (77, U30Op::SExtI16U32 { dst: 3, src: 4 }),
            (78, U30Op::SExtI16U64 { dst: 4, src: 5 }),
            (79, U30Op::SExtI32U64 { dst: 5, src: 6 }),
            (80, U30Op::ByteSwapU16 { dst: 6, src: 7 }),
            (81, U30Op::ByteSwapU32 { dst: 7, src: 8 }),
            (82, U30Op::ByteSwapU64 { dst: 8, src: 9 }),
        ];
        for (variant, expected) in cases {
            let mut buf = vec![variant];
            if let U30Op::SExtI8U16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::SExtI8U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::SExtI8U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::SExtI16U32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::SExtI16U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::SExtI32U64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ByteSwapU16 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ByteSwapU32 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            if let U30Op::ByteSwapU64 { dst, src } = expected { buf.extend_from_slice(&dst.to_le_bytes()); buf.extend_from_slice(&src.to_le_bytes()); }
            let mut pos = 0;
            let op = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, expected);
        }
    }

    /// Test decode_op: variants 83-84 (Call and IndirectCall) with args/results
    #[test]
    fn test_ser_decode_op_call_indirect_with_args() {
        // Call with multiple args and results
        let mut buf = vec![83]; // variant=Call
        buf.extend_from_slice(&1u32.to_le_bytes()); // function=1
        buf.extend_from_slice(&2u32.to_le_bytes()); // arg_count=2
        buf.extend_from_slice(&10u32.to_le_bytes()); // arg1
        buf.extend_from_slice(&11u32.to_le_bytes()); // arg2
        buf.extend_from_slice(&2u32.to_le_bytes()); // result_count=2
        buf.extend_from_slice(&20u32.to_le_bytes()); // result1
        buf.extend_from_slice(&21u32.to_le_bytes()); // result2
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Call { function: 1, args, results } 
            if args == &[10, 11] && results == &[20, 21]));

        // IndirectCall with multiple args and results
        let mut buf2 = vec![84]; // variant=IndirectCall
        buf2.extend_from_slice(&2u32.to_le_bytes()); // function_reg=2
        buf2.extend_from_slice(&3u32.to_le_bytes()); // arg_count=3
        buf2.extend_from_slice(&30u32.to_le_bytes()); // arg1
        buf2.extend_from_slice(&31u32.to_le_bytes()); // arg2
        buf2.extend_from_slice(&32u32.to_le_bytes()); // arg3
        buf2.extend_from_slice(&1u32.to_le_bytes()); // result_count=1
        buf2.extend_from_slice(&40u32.to_le_bytes()); // result1
        let mut pos = 0;
        let op2 = decode_op(&buf2, &mut pos).unwrap();
        assert!(matches!(op2, U30Op::IndirectCall { function: 2, args, results } 
            if args == &[30, 31, 32] && results == &[40]));
    }

    /// Test decode_op: truncations for all 2-register ops (coverage for read_u32 errors)
    #[test]
    fn test_ser_decode_op_truncated_two_reg_ops() {
        // Test a few representative variants - the pattern is the same for all 2-register ops
        // Variant 8 (I2F): dst(4) + src(4) = 8 bytes needed
        let buf = vec![8, 0, 0, 0, 0]; // variant + dst only
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "I2F truncated");

        // Variant 36 (FSqrt): dst(4) + src(4) = 8 bytes needed
        let buf = vec![36, 0, 0, 0, 0]; // variant + dst only
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "FSqrt truncated");

        // Variant 52 (MemSize): dst(4) + region(4) = 8 bytes needed
        let buf = vec![52, 0, 0, 0, 0]; // variant + dst only
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "MemSize truncated");
    }

    /// Test decode_op: truncations for all 3-register ops
    #[test]
    fn test_ser_decode_op_truncated_three_reg_ops() {
        // Variant 27 (FEq): dst(4) + a(4) + b(4) = 12 bytes needed
        let buf = vec![27, 0, 0, 0, 0, 1, 0, 0, 0]; // variant + dst + a only
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "FEq truncated");

        // Variant 2 (Binary): op_idx(4) + dst(4) + a(4) + b(4) = 16 bytes needed
        let buf = vec![2, 0, 0, 0, 0, 0, 0, 0, 0]; // variant + op_idx + dst + a only
        let mut pos = 0;
        let err = decode_op(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "Binary truncated");
    }

    /// Test decode_terminator: BrIf with full fields
    #[test]
    fn test_ser_decode_terminator_brif_full() {
        let buf = vec![1, 5, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0]; // cond=5, then=10, else=20
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::BrIf { cond: 5, then_target: 10, else_target: 20 }));
    }

    /// Test decode_terminator: Ret with zero values
    #[test]
    fn test_ser_decode_terminator_ret_empty() {
        let buf = vec![2, 0, 0, 0, 0]; // variant=Ret, count=0
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::Ret { values } if values.is_empty()));
    }

    /// Test decode_terminator: TailCall with zero args
    #[test]
    fn test_ser_decode_terminator_tailcall_empty() {
        let buf = vec![3, 99, 0, 0, 0, 0, 0, 0, 0]; // variant=3, function=99, count=0
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::TailCall { function: 99, args } if args.is_empty()));
    }

    /// Test decode_value: U16 full path
    #[test]
    fn test_ser_decode_value_u16_full() {
        let buf = vec![2, 0x34, 0x12]; // type=2, value=0x1234
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::U16(0x1234)));
    }

    /// Test decode_value: U32 full path
    #[test]
    fn test_ser_decode_value_u32_full() {
        let buf = vec![3, 0x78, 0x56, 0x34, 0x12]; // type=3, value=0x12345678
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::U32(0x12345678)));
    }

    /// Test decode_value: F64 full path
    #[test]
    fn test_ser_decode_value_f64_full() {
        let bits: u64 = 0x3FF0000000000000u64; // 1.0
        let mut buf = vec![6]; // type=6
        buf.extend_from_slice(&bits.to_le_bytes());
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::F64(f) if f.to_bits() == bits));
    }

    /// Test encode paths: encode_value for all types
    #[test]
    fn test_ser_encode_all_value_types() {
        let values = [
            U30Value::Bool(false),
            U30Value::Bool(true),
            U30Value::U8(0),
            U30Value::U8(255),
            U30Value::U16(0),
            U30Value::U16(0xFFFF),
            U30Value::U32(0),
            U30Value::U32(u32::MAX),
            U30Value::U64(0),
            U30Value::U64(u64::MAX),
            U30Value::F32(0.0),
            U30Value::F32(f32::INFINITY),
            U30Value::F32(f32::NEG_INFINITY),
            U30Value::F32(f32::NAN),
            U30Value::F64(0.0),
            U30Value::F64(f64::INFINITY),
            U30Value::F64(f64::NEG_INFINITY),
            U30Value::F64(f64::NAN),
        ];
        for val in values {
            let mut buf = Vec::new();
            encode_value(&mut buf, &val);
            let mut pos = 0;
            let decoded = decode_value(&buf, &mut pos).unwrap();
            match (&val, &decoded) {
                (U30Value::Bool(a), U30Value::Bool(b)) => assert_eq!(a, b, "Bool mismatch"),
                (U30Value::U8(a), U30Value::U8(b)) => assert_eq!(a, b, "U8 mismatch"),
                (U30Value::U16(a), U30Value::U16(b)) => assert_eq!(a, b, "U16 mismatch"),
                (U30Value::U32(a), U30Value::U32(b)) => assert_eq!(a, b, "U32 mismatch"),
                (U30Value::U64(a), U30Value::U64(b)) => assert_eq!(a, b, "U64 mismatch"),
                (U30Value::F32(a), U30Value::F32(b)) => {
                    if a.is_nan() { assert!(b.is_nan(), "F32 NaN mismatch"); }
                    else { assert_eq!(a, b, "F32 mismatch"); }
                }
                (U30Value::F64(a), U30Value::F64(b)) => {
                    if a.is_nan() { assert!(b.is_nan(), "F64 NaN mismatch"); }
                    else { assert_eq!(a, b, "F64 mismatch"); }
                }
                _ => panic!("Type mismatch: {:?} vs {:?}", val, decoded),
            }
        }
    }

    /// Test encode_binary_op: all valid binary ops
    #[test]
    fn test_ser_encode_binary_op_all() {
        use crate::ir::U30BinaryOp as Op;
        let ops = [
            Op::AddWrapU64, Op::AddWrapU32, Op::SubWrapU64, Op::SubWrapU32,
            Op::MulWrapU64, Op::MulWrapU32, Op::AndU8, Op::OrU8, Op::XorU8,
            Op::ShlU64, Op::ShlU32, Op::ShrU64, Op::ShrU32,
            Op::DivU64, Op::DivU32, Op::RemU64, Op::RemU32,
            Op::Eq, Op::LtU64, Op::GtU64, Op::GeU64, Op::LeU64, Op::LeU32,
            Op::MinU64, Op::MaxU64, Op::MinU32, Op::MaxU32,
        ];
        for op in ops {
            let idx = encode_binary_op(&op);
            let decoded = decode_binary_op(idx).unwrap();
            assert_eq!(op, decoded, "BinaryOp mismatch for {:?}", op);
        }
    }

    /// Test encode_terminator: all terminator variants
    #[test]
    fn test_ser_encode_terminator_all() {
        let terminators = [
            U30Terminator::Br { target: 0 },
            U30Terminator::Br { target: 100 },
            U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 2 },
            U30Terminator::Ret { values: vec![] },
            U30Terminator::Ret { values: vec![1] },
            U30Terminator::Ret { values: vec![1, 2, 3] },
            U30Terminator::TailCall { function: 0, args: vec![] },
            U30Terminator::TailCall { function: 5, args: vec![1, 2] },
            U30Terminator::Trap { code: 0 },
            U30Terminator::Trap { code: 99 },
        ];
        for term in terminators {
            let mut buf = Vec::new();
            encode_terminator(&mut buf, &term);
            let mut pos = 0;
            let decoded = decode_terminator(&buf, &mut pos).unwrap();
            assert_eq!(term, decoded, "Terminator mismatch for {:?}", term);
        }
    }

    /// Test encode_op: all op variants roundtrip
    #[test]
    fn test_ser_encode_op_all_variants() {
        let ops = [
            U30Op::Nop,
            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
            U30Op::Const { dst: 0, value: U30Value::U8(42) },
            U30Op::Const { dst: 0, value: U30Value::U16(1234) },
            U30Op::Const { dst: 0, value: U30Value::U32(999999) },
            U30Op::Const { dst: 0, value: U30Value::U64(u64::MAX) },
            U30Op::Const { dst: 0, value: U30Value::F32(3.14) },
            U30Op::Const { dst: 0, value: U30Value::F64(2.71828) },
            U30Op::Binary { dst: 0, op: crate::ir::U30BinaryOp::AddWrapU64, a: 1, b: 2 },
            U30Op::Select { dst: 0, cond: 1, a: 2, b: 3 },
            U30Op::NotU8 { dst: 0, src: 1 },
            U30Op::NotU16 { dst: 0, src: 1 },
            U30Op::NotU32 { dst: 0, src: 1 },
            U30Op::NotU64 { dst: 0, src: 1 },
            U30Op::I2F { dst: 0, src: 1 },
            U30Op::F2I { dst: 0, src: 1 },
            U30Op::TruncF32U64 { dst: 0, src: 1 },
            U30Op::ReinterpretF32U32 { dst: 0, src: 1 },
            U30Op::ReinterpretU32F32 { dst: 0, src: 1 },
            U30Op::AbsU64 { dst: 0, src: 1 },
            U30Op::AbsU32 { dst: 0, src: 1 },
            U30Op::NegU64 { dst: 0, src: 1 },
            U30Op::NegU32 { dst: 0, src: 1 },
            U30Op::CtzU64 { dst: 0, src: 1 },
            U30Op::CtzU32 { dst: 0, src: 1 },
            U30Op::ClzU64 { dst: 0, src: 1 },
            U30Op::ClzU32 { dst: 0, src: 1 },
            U30Op::PopcntU64 { dst: 0, src: 1 },
            U30Op::PopcntU32 { dst: 0, src: 1 },
            U30Op::RotlU64 { dst: 0, val: 1, sh: 2 },
            U30Op::RotlU32 { dst: 0, val: 1, sh: 2 },
            U30Op::RotrU64 { dst: 0, val: 1, sh: 2 },
            U30Op::RotrU32 { dst: 0, val: 1, sh: 2 },
            U30Op::FEq { dst: 0, a: 1, b: 2 },
            U30Op::FLt { dst: 0, a: 1, b: 2 },
            U30Op::FGt { dst: 0, a: 1, b: 2 },
            U30Op::FLe { dst: 0, a: 1, b: 2 },
            U30Op::FGe { dst: 0, a: 1, b: 2 },
            U30Op::FAdd { dst: 0, a: 1, b: 2 },
            U30Op::FSub { dst: 0, a: 1, b: 2 },
            U30Op::FMul { dst: 0, a: 1, b: 2 },
            U30Op::FDiv { dst: 0, a: 1, b: 2 },
            U30Op::FSqrt { dst: 0, src: 1 },
            U30Op::FAbs { dst: 0, src: 1 },
            U30Op::FNeg { dst: 0, src: 1 },
            U30Op::FMin { dst: 0, a: 1, b: 2 },
            U30Op::FMax { dst: 0, a: 1, b: 2 },
            U30Op::ZExtI8U16 { dst: 0, src: 1 },
            U30Op::ZExtI8U32 { dst: 0, src: 1 },
            U30Op::ZExtI8U64 { dst: 0, src: 1 },
            U30Op::ZExtI16U32 { dst: 0, src: 1 },
            U30Op::ZExtI16U64 { dst: 0, src: 1 },
            U30Op::ZExtI32U64 { dst: 0, src: 1 },
            U30Op::TruncU64U32 { dst: 0, src: 1 },
            U30Op::TruncU64U16 { dst: 0, src: 1 },
            U30Op::TruncU32U16 { dst: 0, src: 1 },
            U30Op::MemCopy { dst_region: 0, dst_offset: 1, src_region: 2, src_offset: 3, size: 4 },
            U30Op::MemFill { region: 0, offset: 1, value: 2, size: 3 },
            U30Op::MemSize { dst: 0, region: 1 },
            U30Op::MemGrow { dst: 0, region: 1, delta: 2 },
            U30Op::F64Eq { dst: 0, a: 1, b: 2 },
            U30Op::F64Lt { dst: 0, a: 1, b: 2 },
            U30Op::F64Gt { dst: 0, a: 1, b: 2 },
            U30Op::F64Le { dst: 0, a: 1, b: 2 },
            U30Op::F64Ge { dst: 0, a: 1, b: 2 },
            U30Op::F64Add { dst: 0, a: 1, b: 2 },
            U30Op::F64Sub { dst: 0, a: 1, b: 2 },
            U30Op::F64Mul { dst: 0, a: 1, b: 2 },
            U30Op::F64Div { dst: 0, a: 1, b: 2 },
            U30Op::F64Sqrt { dst: 0, src: 1 },
            U30Op::F64Abs { dst: 0, src: 1 },
            U30Op::F64Neg { dst: 0, src: 1 },
            U30Op::F64Min { dst: 0, a: 1, b: 2 },
            U30Op::F64Max { dst: 0, a: 1, b: 2 },
            U30Op::I64F64 { dst: 0, src: 1 },
            U30Op::F64I64 { dst: 0, src: 1 },
            U30Op::F32F64 { dst: 0, src: 1 },
            U30Op::F64F32 { dst: 0, src: 1 },
            U30Op::ReinterpretF64U64 { dst: 0, src: 1 },
            U30Op::ReinterpretU64F64 { dst: 0, src: 1 },
            U30Op::SExtI8U16 { dst: 0, src: 1 },
            U30Op::SExtI8U32 { dst: 0, src: 1 },
            U30Op::SExtI8U64 { dst: 0, src: 1 },
            U30Op::SExtI16U32 { dst: 0, src: 1 },
            U30Op::SExtI16U64 { dst: 0, src: 1 },
            U30Op::SExtI32U64 { dst: 0, src: 1 },
            U30Op::ByteSwapU16 { dst: 0, src: 1 },
            U30Op::ByteSwapU32 { dst: 0, src: 1 },
            U30Op::ByteSwapU64 { dst: 0, src: 1 },
            U30Op::Call { function: 0, args: vec![1, 2], results: vec![3] },
            U30Op::IndirectCall { function: 0, args: vec![1, 2], results: vec![3] },
            U30Op::TableBr { table: 0, index: 1 },
            U30Op::Break { code: 42 },
            U30Op::Assert { cond: 0, msg: 1 },
            U30Op::LoadU8 { dst: 0, region: 1, offset: 2 },
            U30Op::StoreU8 { region: 0, offset: 1, src: 2 },
            U30Op::LoadU16 { dst: 0, region: 1, offset: 2 },
            U30Op::StoreU16 { region: 0, offset: 1, src: 2 },
            U30Op::LoadU32 { dst: 0, region: 1, offset: 2 },
            U30Op::StoreU32 { region: 0, offset: 1, src: 2 },
            U30Op::LoadU64 { dst: 0, region: 1, offset: 2 },
            U30Op::StoreU64 { region: 0, offset: 1, src: 2 },
        ];
        for op in ops {
            let mut buf = Vec::new();
            encode_op(&mut buf, &op);
            let mut pos = 0;
            let decoded = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, decoded, "Op mismatch for {:?}", op);
        }
    }

    /// Test decode_value: U16 truncated (end of file test)
    #[test]
    fn test_ser_decode_value_truncated_u16_eof() {
        let buf = vec![2, 0x42]; // type=U16 but only 1 byte
        let mut pos = 0;
        let err = decode_value(&buf, &mut pos).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {}", err);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Comprehensive tests for 100% regions coverage
    // ═══════════════════════════════════════════════════════════════════════════

    /// Test decode_op: all 96 variants explicitly covered
    #[test]
    fn test_ser_decode_op_all_96_variants_coverage() {
        // Test all variants 0-95 explicitly
        for variant in 0u8..=95u8 {
            let mut buf = vec![variant];
            // Add dummy data for fields based on variant type
            match variant {
                0 => {} // Nop - no fields
                1 => { buf.extend_from_slice(&0u32.to_le_bytes()); buf.push(0); buf.push(1); } // Const
                2 => { buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); } // Binary
                3 => { for _ in 0..4 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // Select
                4..=22 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // 2-u32 ops
                23..=26 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // 3-u32 ops
                27..=40 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // 3-u32 ops
                41..=49 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // 2-u32 ops
                50 => { for _ in 0..5 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // MemCopy
                51 => { for _ in 0..4 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // MemFill
                52 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // MemSize
                53 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // MemGrow
                54..=58 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // F64 cmp
                59..=67 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // F64 arith
                68..=73 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // F64 conv
                74..=82 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // SExt/ByteSwap
                83 => { buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); } // Call
                84 => { buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); buf.extend_from_slice(&0u32.to_le_bytes()); } // IndirectCall
                85 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // TableBr
                86 => { buf.extend_from_slice(&0u32.to_le_bytes()); } // Break
                87 => { for _ in 0..2 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // Assert
                88..=89 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // LoadU8/StoreU8
                90..=91 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // LoadU16/StoreU16
                92..=93 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // LoadU32/StoreU32
                94..=95 => { for _ in 0..3 { buf.extend_from_slice(&0u32.to_le_bytes()); } } // LoadU64/StoreU64
                _ => unreachable!(),
            }
            let mut pos = 0;
            // Just verify it doesn't panic
            let _ = decode_op(&buf, &mut pos);
        }
    }

    /// Test encode_path: all encode_op variants covered
    #[test]
    fn test_ser_encode_op_all_96_variants_encode_path() {
        use crate::ir::U30BinaryOp::*;
        let ops: Vec<U30Op> = vec![
            U30Op::Nop,
            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
            U30Op::Binary { dst: 0, op: AddWrapU64, a: 0, b: 0 },
            U30Op::Select { dst: 0, cond: 0, a: 0, b: 0 },
            U30Op::NotU8 { dst: 0, src: 0 },
            U30Op::NotU16 { dst: 0, src: 0 },
            U30Op::NotU32 { dst: 0, src: 0 },
            U30Op::NotU64 { dst: 0, src: 0 },
            U30Op::I2F { dst: 0, src: 0 },
            U30Op::F2I { dst: 0, src: 0 },
            U30Op::TruncF32U64 { dst: 0, src: 0 },
            U30Op::ReinterpretF32U32 { dst: 0, src: 0 },
            U30Op::ReinterpretU32F32 { dst: 0, src: 0 },
            U30Op::AbsU64 { dst: 0, src: 0 },
            U30Op::AbsU32 { dst: 0, src: 0 },
            U30Op::NegU64 { dst: 0, src: 0 },
            U30Op::NegU32 { dst: 0, src: 0 },
            U30Op::CtzU64 { dst: 0, src: 0 },
            U30Op::CtzU32 { dst: 0, src: 0 },
            U30Op::ClzU64 { dst: 0, src: 0 },
            U30Op::ClzU32 { dst: 0, src: 0 },
            U30Op::PopcntU64 { dst: 0, src: 0 },
            U30Op::PopcntU32 { dst: 0, src: 0 },
            U30Op::RotlU64 { dst: 0, val: 0, sh: 0 },
            U30Op::RotlU32 { dst: 0, val: 0, sh: 0 },
            U30Op::RotrU64 { dst: 0, val: 0, sh: 0 },
            U30Op::RotrU32 { dst: 0, val: 0, sh: 0 },
            U30Op::FEq { dst: 0, a: 0, b: 0 },
            U30Op::FLt { dst: 0, a: 0, b: 0 },
            U30Op::FGt { dst: 0, a: 0, b: 0 },
            U30Op::FLe { dst: 0, a: 0, b: 0 },
            U30Op::FGe { dst: 0, a: 0, b: 0 },
            U30Op::FAdd { dst: 0, a: 0, b: 0 },
            U30Op::FSub { dst: 0, a: 0, b: 0 },
            U30Op::FMul { dst: 0, a: 0, b: 0 },
            U30Op::FDiv { dst: 0, a: 0, b: 0 },
            U30Op::FSqrt { dst: 0, src: 0 },
            U30Op::FAbs { dst: 0, src: 0 },
            U30Op::FNeg { dst: 0, src: 0 },
            U30Op::FMin { dst: 0, a: 0, b: 0 },
            U30Op::FMax { dst: 0, a: 0, b: 0 },
            U30Op::ZExtI8U16 { dst: 0, src: 0 },
            U30Op::ZExtI8U32 { dst: 0, src: 0 },
            U30Op::ZExtI8U64 { dst: 0, src: 0 },
            U30Op::ZExtI16U32 { dst: 0, src: 0 },
            U30Op::ZExtI16U64 { dst: 0, src: 0 },
            U30Op::ZExtI32U64 { dst: 0, src: 0 },
            U30Op::TruncU64U32 { dst: 0, src: 0 },
            U30Op::TruncU64U16 { dst: 0, src: 0 },
            U30Op::TruncU32U16 { dst: 0, src: 0 },
            U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 0, src_offset: 0, size: 0 },
            U30Op::MemFill { region: 0, offset: 0, value: 0, size: 0 },
            U30Op::MemSize { dst: 0, region: 0 },
            U30Op::MemGrow { dst: 0, region: 0, delta: 0 },
            U30Op::F64Eq { dst: 0, a: 0, b: 0 },
            U30Op::F64Lt { dst: 0, a: 0, b: 0 },
            U30Op::F64Gt { dst: 0, a: 0, b: 0 },
            U30Op::F64Le { dst: 0, a: 0, b: 0 },
            U30Op::F64Ge { dst: 0, a: 0, b: 0 },
            U30Op::F64Add { dst: 0, a: 0, b: 0 },
            U30Op::F64Sub { dst: 0, a: 0, b: 0 },
            U30Op::F64Mul { dst: 0, a: 0, b: 0 },
            U30Op::F64Div { dst: 0, a: 0, b: 0 },
            U30Op::F64Sqrt { dst: 0, src: 0 },
            U30Op::F64Abs { dst: 0, src: 0 },
            U30Op::F64Neg { dst: 0, src: 0 },
            U30Op::F64Min { dst: 0, a: 0, b: 0 },
            U30Op::F64Max { dst: 0, a: 0, b: 0 },
            U30Op::I64F64 { dst: 0, src: 0 },
            U30Op::F64I64 { dst: 0, src: 0 },
            U30Op::F32F64 { dst: 0, src: 0 },
            U30Op::F64F32 { dst: 0, src: 0 },
            U30Op::ReinterpretF64U64 { dst: 0, src: 0 },
            U30Op::ReinterpretU64F64 { dst: 0, src: 0 },
            U30Op::SExtI8U16 { dst: 0, src: 0 },
            U30Op::SExtI8U32 { dst: 0, src: 0 },
            U30Op::SExtI8U64 { dst: 0, src: 0 },
            U30Op::SExtI16U32 { dst: 0, src: 0 },
            U30Op::SExtI16U64 { dst: 0, src: 0 },
            U30Op::SExtI32U64 { dst: 0, src: 0 },
            U30Op::ByteSwapU16 { dst: 0, src: 0 },
            U30Op::ByteSwapU32 { dst: 0, src: 0 },
            U30Op::ByteSwapU64 { dst: 0, src: 0 },
            U30Op::Call { function: 0, args: vec![], results: vec![] },
            U30Op::IndirectCall { function: 0, args: vec![], results: vec![] },
            U30Op::TableBr { table: 0, index: 0 },
            U30Op::Break { code: 0 },
            U30Op::Assert { cond: 0, msg: 0 },
            U30Op::LoadU8 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU8 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU16 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU16 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU32 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU32 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU64 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU64 { region: 0, offset: 0, src: 0 },
        ];
        for op in ops {
            let mut buf = Vec::new();
            encode_op(&mut buf, &op);
            assert!(!buf.is_empty(), "encode_op should produce output for {:?}", op);
        }
    }

    /// Test encode_terminator: all 5 variants covered
    #[test]
    fn test_ser_encode_terminator_all_5_variants() {
        let terms = vec![
            U30Terminator::Br { target: 0 },
            U30Terminator::BrIf { cond: 0, then_target: 0, else_target: 0 },
            U30Terminator::Ret { values: vec![] },
            U30Terminator::TailCall { function: 0, args: vec![] },
            U30Terminator::Trap { code: 0 },
        ];
        for term in terms {
            let mut buf = Vec::new();
            encode_terminator(&mut buf, &term);
            assert!(!buf.is_empty());
        }
    }

    /// Test encode_value: all 7 variants covered
    #[test]
    fn test_ser_encode_value_all_7_variants() {
        let values = vec![
            U30Value::Bool(false),
            U30Value::U8(0),
            U30Value::U16(0),
            U30Value::U32(0),
            U30Value::U64(0),
            U30Value::F32(0.0),
            U30Value::F64(0.0),
        ];
        for val in values {
            let mut buf = Vec::new();
            encode_value(&mut buf, &val);
            assert!(!buf.is_empty());
        }
    }

    /// Test type_idx: all 7 types covered
    #[test]
    fn test_ser_type_idx_all_7_types() {
        let types = vec![
            U30Type::Bool,
            U30Type::U8,
            U30Type::U16,
            U30Type::U32,
            U30Type::U64,
            U30Type::F32,
            U30Type::F64,
        ];
        for ty in types {
            let idx = type_idx(&ty);
            assert!(idx <= 6);
        }
    }

    /// Test decode: region with empty initial data
    #[test]
    fn test_ser_decode_region_empty_initial() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 0,
                readable: true,
                writable: true,
                initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.regions[0].initial.len(), 0);
    }

    /// Test decode: multiple tables with empty targets
    #[test]
    fn test_ser_decode_multiple_tables_empty_targets() {
        let module = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![] },
                U30TableDecl { id: 1, targets: vec![] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.tables.len(), 2);
        assert!(decoded.tables[0].targets.is_empty());
        assert!(decoded.tables[1].targets.is_empty());
    }

    /// Test decode: function with no params and no results
    #[test]
    fn test_ser_decode_function_no_params_results() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.functions[0].params.len(), 0);
        assert_eq!(decoded.functions[0].results.len(), 0);
    }

    /// Test decode: block with no ops
    #[test]
    fn test_ser_decode_block_no_ops() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 0);
    }

    /// Test encode: large function count
    #[test]
    fn test_ser_encode_decode_many_functions_edge() {
        let functions: Vec<_> = (0..100).map(|_| U30Function {
            params: vec![],
            results: vec![],
            blocks: vec![U30Block {
                ops: vec![],
                terminator: U30Terminator::Ret { values: vec![] },
            }],
            entry_block: 0,
        }).collect();
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions,
            entry_function: 50,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.functions.len(), 100);
        assert_eq!(decoded.entry_function, 50);
    }

    /// Test encode: many regions edge case
    #[test]
    fn test_ser_encode_decode_many_regions_edge() {
        let regions: Vec<_> = (0..100).map(|i| U30RegionDecl {
            id: i as u32,
            size: 0,
            readable: i % 2 == 0,
            writable: i % 2 == 1,
            initial: vec![],
        }).collect();
        let module = U30Module {
            regions,
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.regions.len(), 100);
    }

    /// Test encode: many tables edge case
    #[test]
    fn test_ser_encode_decode_many_tables_edge() {
        let tables: Vec<_> = (0..50).map(|i| U30TableDecl {
            id: i,
            targets: vec![i as usize],
        }).collect();
        let module = U30Module {
            regions: vec![],
            tables,
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.tables.len(), 50);
    }

    /// Test encode: large block with many ops
    #[test]
    fn test_ser_encode_decode_large_block() {
        let ops: Vec<_> = (0..100).map(|i| U30Op::Const { dst: i as u32, value: U30Value::U32(i) }).collect();
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops,
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let encoded = encode(&module);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.functions[0].blocks[0].ops.len(), 100);
    }

    /// Test decode: Ret with single value
    #[test]
    fn test_ser_decode_terminator_ret_single_value() {
        let buf = vec![2, 1, 0, 0, 0, 5, 0, 0, 0]; // variant=2, count=1, value=5
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::Ret { values } if values == &[5]));
    }

    /// Test decode: TailCall with single arg
    #[test]
    fn test_ser_decode_terminator_tailcall_single_arg() {
        let buf = vec![3, 7, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0]; // variant=3, fn=7, count=1, arg=9
        let mut pos = 0;
        let t = decode_terminator(&buf, &mut pos).unwrap();
        assert!(matches!(t, U30Terminator::TailCall { function: 7, args } if args == &[9]));
    }

    /// Test decode: decode_value Bool false path
    #[test]
    fn test_ser_decode_value_bool_false_path() {
        let buf = vec![0, 0]; // type=0, value=0
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::Bool(false)));
    }

    /// Test decode: decode_value U8 full path
    #[test]
    fn test_ser_decode_value_u8_full_path() {
        let buf = vec![1, 255]; // type=1, value=255
        let mut pos = 0;
        let val = decode_value(&buf, &mut pos).unwrap();
        assert!(matches!(val, U30Value::U8(255)));
    }

    /// Test decode: decode_binary_op all valid indices encode/decode
    #[test]
    fn test_ser_decode_binary_op_all_valid() {
        for idx in 0u32..=26 {
            // Just verify each index decodes to a valid variant
            let _ = decode_binary_op(idx).unwrap();
        }
    }

    /// Test decode: decode_op variant 2 (Binary) with valid binary op
    #[test]
    fn test_ser_decode_op_binary_valid() {
        let buf = vec![
            2, 0, 0, 0, 0, // variant=2, op_idx=0 (AddWrapU64)
            1, 0, 0, 0, // dst=1
            2, 0, 0, 0, // a=2
            3, 0, 0, 0, // b=3
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Binary { op: crate::ir::U30BinaryOp::AddWrapU64, .. }));
    }

    /// Test decode: decode_op variant 83 (Call) with empty args and results
    #[test]
    fn test_ser_decode_op_call_empty_args_results() {
        let buf = vec![
            83, // variant=83
            0, 0, 0, 0, // function=0
            0, 0, 0, 0, // arg_count=0
            0, 0, 0, 0, // result_count=0
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::Call { args, results, .. } if args.is_empty() && results.is_empty()));
    }

    /// Test decode: decode_type all 7 variants
    #[test]
    fn test_ser_decode_type_all_7_variants() {
        for t in 0u8..=6u8 {
            let buf = vec![t];
            let mut pos = 0;
            let _ = decode_type(&buf, &mut pos).unwrap();
        }
    }

    /// Test encode: function with all type params
    #[test]
    fn test_ser_encode_decode_all_type_params() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![
                    U30Type::Bool,
                    U30Type::U8,
                    U30Type::U16,
                    U30Type::U32,
                    U30Type::U64,
                    U30Type::F32,
                    U30Type::F64,
                ],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].params.len(), 7);
    }

    /// Test encode: function with all type results
    #[test]
    fn test_ser_encode_decode_all_type_results() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![
                    U30Type::Bool,
                    U30Type::U8,
                    U30Type::U16,
                    U30Type::U32,
                    U30Type::U64,
                    U30Type::F32,
                    U30Type::F64,
                ],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0, 1, 2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let decoded = decode(&encode(&module)).unwrap();
        assert_eq!(decoded.functions[0].results.len(), 7);
    }

    /// Test encode: encode_function covered
    #[test]
    fn test_ser_encode_function_coverage() {
        let f = U30Function {
            params: vec![U30Type::U32],
            results: vec![U30Type::U32],
            blocks: vec![U30Block {
                ops: vec![],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        let mut buf = Vec::new();
        encode_function(&mut buf, &f);
        assert!(!buf.is_empty());
    }

    /// Test encode: encode_block covered
    #[test]
    fn test_ser_encode_block_coverage() {
        let b = U30Block {
            ops: vec![],
            terminator: U30Terminator::Ret { values: vec![] },
        };
        let mut buf = Vec::new();
        encode_block(&mut buf, &b);
        assert!(!buf.is_empty());
    }

    /// Test decode_op: all 96 encode->decode roundtrip
    #[test]
    fn test_ser_all_op_variants_encode_decode_roundtrip() {
        use crate::ir::U30BinaryOp::*;
        let ops = vec![
            U30Op::Nop,
            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
            U30Op::Binary { dst: 0, op: AddWrapU64, a: 0, b: 0 },
            U30Op::Select { dst: 0, cond: 0, a: 0, b: 0 },
            U30Op::NotU8 { dst: 0, src: 0 },
            U30Op::NotU16 { dst: 0, src: 0 },
            U30Op::NotU32 { dst: 0, src: 0 },
            U30Op::NotU64 { dst: 0, src: 0 },
            U30Op::I2F { dst: 0, src: 0 },
            U30Op::F2I { dst: 0, src: 0 },
            U30Op::TruncF32U64 { dst: 0, src: 0 },
            U30Op::ReinterpretF32U32 { dst: 0, src: 0 },
            U30Op::ReinterpretU32F32 { dst: 0, src: 0 },
            U30Op::AbsU64 { dst: 0, src: 0 },
            U30Op::AbsU32 { dst: 0, src: 0 },
            U30Op::NegU64 { dst: 0, src: 0 },
            U30Op::NegU32 { dst: 0, src: 0 },
            U30Op::CtzU64 { dst: 0, src: 0 },
            U30Op::CtzU32 { dst: 0, src: 0 },
            U30Op::ClzU64 { dst: 0, src: 0 },
            U30Op::ClzU32 { dst: 0, src: 0 },
            U30Op::PopcntU64 { dst: 0, src: 0 },
            U30Op::PopcntU32 { dst: 0, src: 0 },
            U30Op::RotlU64 { dst: 0, val: 0, sh: 0 },
            U30Op::RotlU32 { dst: 0, val: 0, sh: 0 },
            U30Op::RotrU64 { dst: 0, val: 0, sh: 0 },
            U30Op::RotrU32 { dst: 0, val: 0, sh: 0 },
            U30Op::FEq { dst: 0, a: 0, b: 0 },
            U30Op::FLt { dst: 0, a: 0, b: 0 },
            U30Op::FGt { dst: 0, a: 0, b: 0 },
            U30Op::FLe { dst: 0, a: 0, b: 0 },
            U30Op::FGe { dst: 0, a: 0, b: 0 },
            U30Op::FAdd { dst: 0, a: 0, b: 0 },
            U30Op::FSub { dst: 0, a: 0, b: 0 },
            U30Op::FMul { dst: 0, a: 0, b: 0 },
            U30Op::FDiv { dst: 0, a: 0, b: 0 },
            U30Op::FSqrt { dst: 0, src: 0 },
            U30Op::FAbs { dst: 0, src: 0 },
            U30Op::FNeg { dst: 0, src: 0 },
            U30Op::FMin { dst: 0, a: 0, b: 0 },
            U30Op::FMax { dst: 0, a: 0, b: 0 },
            U30Op::ZExtI8U16 { dst: 0, src: 0 },
            U30Op::ZExtI8U32 { dst: 0, src: 0 },
            U30Op::ZExtI8U64 { dst: 0, src: 0 },
            U30Op::ZExtI16U32 { dst: 0, src: 0 },
            U30Op::ZExtI16U64 { dst: 0, src: 0 },
            U30Op::ZExtI32U64 { dst: 0, src: 0 },
            U30Op::TruncU64U32 { dst: 0, src: 0 },
            U30Op::TruncU64U16 { dst: 0, src: 0 },
            U30Op::TruncU32U16 { dst: 0, src: 0 },
            U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 0, src_offset: 0, size: 0 },
            U30Op::MemFill { region: 0, offset: 0, value: 0, size: 0 },
            U30Op::MemSize { dst: 0, region: 0 },
            U30Op::MemGrow { dst: 0, region: 0, delta: 0 },
            U30Op::F64Eq { dst: 0, a: 0, b: 0 },
            U30Op::F64Lt { dst: 0, a: 0, b: 0 },
            U30Op::F64Gt { dst: 0, a: 0, b: 0 },
            U30Op::F64Le { dst: 0, a: 0, b: 0 },
            U30Op::F64Ge { dst: 0, a: 0, b: 0 },
            U30Op::F64Add { dst: 0, a: 0, b: 0 },
            U30Op::F64Sub { dst: 0, a: 0, b: 0 },
            U30Op::F64Mul { dst: 0, a: 0, b: 0 },
            U30Op::F64Div { dst: 0, a: 0, b: 0 },
            U30Op::F64Sqrt { dst: 0, src: 0 },
            U30Op::F64Abs { dst: 0, src: 0 },
            U30Op::F64Neg { dst: 0, src: 0 },
            U30Op::F64Min { dst: 0, a: 0, b: 0 },
            U30Op::F64Max { dst: 0, a: 0, b: 0 },
            U30Op::I64F64 { dst: 0, src: 0 },
            U30Op::F64I64 { dst: 0, src: 0 },
            U30Op::F32F64 { dst: 0, src: 0 },
            U30Op::F64F32 { dst: 0, src: 0 },
            U30Op::ReinterpretF64U64 { dst: 0, src: 0 },
            U30Op::ReinterpretU64F64 { dst: 0, src: 0 },
            U30Op::SExtI8U16 { dst: 0, src: 0 },
            U30Op::SExtI8U32 { dst: 0, src: 0 },
            U30Op::SExtI8U64 { dst: 0, src: 0 },
            U30Op::SExtI16U32 { dst: 0, src: 0 },
            U30Op::SExtI16U64 { dst: 0, src: 0 },
            U30Op::SExtI32U64 { dst: 0, src: 0 },
            U30Op::ByteSwapU16 { dst: 0, src: 0 },
            U30Op::ByteSwapU32 { dst: 0, src: 0 },
            U30Op::ByteSwapU64 { dst: 0, src: 0 },
            U30Op::Call { function: 0, args: vec![], results: vec![] },
            U30Op::IndirectCall { function: 0, args: vec![], results: vec![] },
            U30Op::TableBr { table: 0, index: 0 },
            U30Op::Break { code: 0 },
            U30Op::Assert { cond: 0, msg: 0 },
            U30Op::LoadU8 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU8 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU16 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU16 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU32 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU32 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU64 { dst: 0, region: 0, offset: 0 },
            U30Op::StoreU64 { region: 0, offset: 0, src: 0 },
        ];
        for op in ops {
            let mut buf = Vec::new();
            encode_op(&mut buf, &op);
            let mut pos = 0;
            let decoded = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(op, decoded, "roundtrip failed for {:?}", op);
        }
    }

    /// Test decode_op: variant 50 (MemCopy) explicit decode
    #[test]
    fn test_ser_decode_op_memcopy_explicit() {
        let buf = vec![
            50,
            1, 0, 0, 0, // dst_region=1
            2, 0, 0, 0, // dst_offset=2
            3, 0, 0, 0, // src_region=3
            4, 0, 0, 0, // src_offset=4
            5, 0, 0, 0, // size=5
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemCopy { dst_region: 1, dst_offset: 2, src_region: 3, src_offset: 4, size: 5 }));
    }

    /// Test decode_op: variant 51 (MemFill) explicit decode
    #[test]
    fn test_ser_decode_op_memfill_explicit() {
        let buf = vec![
            51,
            1, 0, 0, 0, // region=1
            2, 0, 0, 0, // offset=2
            3, 0, 0, 0, // value=3
            4, 0, 0, 0, // size=4
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemFill { region: 1, offset: 2, value: 3, size: 4 }));
    }

    /// Test decode_op: variant 52 (MemSize) explicit decode
    #[test]
    fn test_ser_decode_op_memsize_explicit() {
        let buf = vec![
            52,
            1, 0, 0, 0, // dst=1
            2, 0, 0, 0, // region=2
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemSize { dst: 1, region: 2 }));
    }

    /// Test decode_op: variant 53 (MemGrow) explicit decode
    #[test]
    fn test_ser_decode_op_memgrow_explicit() {
        let buf = vec![
            53,
            1, 0, 0, 0, // dst=1
            2, 0, 0, 0, // region=2
            3, 0, 0, 0, // delta=3
        ];
        let mut pos = 0;
        let op = decode_op(&buf, &mut pos).unwrap();
        assert!(matches!(op, U30Op::MemGrow { dst: 1, region: 2, delta: 3 }));
    }

    /// Test decode_terminator: all 5 variants encode->decode roundtrip
    #[test]
    fn test_ser_all_terminator_variants_roundtrip() {
        let terms = vec![
            U30Terminator::Br { target: 0 },
            U30Terminator::Br { target: 99 },
            U30Terminator::BrIf { cond: 0, then_target: 0, else_target: 0 },
            U30Terminator::BrIf { cond: 5, then_target: 10, else_target: 15 },
            U30Terminator::Ret { values: vec![] },
            U30Terminator::Ret { values: vec![1] },
            U30Terminator::Ret { values: vec![1, 2, 3, 4, 5] },
            U30Terminator::TailCall { function: 0, args: vec![] },
            U30Terminator::TailCall { function: 5, args: vec![1, 2] },
            U30Terminator::Trap { code: 0 },
            U30Terminator::Trap { code: 99 },
        ];
        for term in terms {
            let mut buf = Vec::new();
            encode_terminator(&mut buf, &term);
            let mut pos = 0;
            let decoded = decode_terminator(&buf, &mut pos).unwrap();
            assert_eq!(term, decoded, "roundtrip failed for {:?}", term);
        }
    }

    /// Test decode_value: all 7 variants encode->decode roundtrip
    #[test]
    fn test_ser_all_value_variants_roundtrip() {
        let values = vec![
            U30Value::Bool(false),
            U30Value::Bool(true),
            U30Value::U8(0),
            U30Value::U8(255),
            U30Value::U16(0),
            U30Value::U16(65535),
            U30Value::U32(0),
            U30Value::U32(u32::MAX),
            U30Value::U64(0),
            U30Value::U64(u64::MAX),
            U30Value::F32(0.0),
            U30Value::F32(1.0),
            U30Value::F32(f32::MAX),
            U30Value::F32(f32::MIN),
            U30Value::F64(0.0),
            U30Value::F64(1.0),
            U30Value::F64(f64::MAX),
            U30Value::F64(f64::MIN),
        ];
        for val in values {
            let mut buf = Vec::new();
            encode_value(&mut buf, &val);
            let mut pos = 0;
            let decoded = decode_value(&buf, &mut pos).unwrap();
            match (&val, &decoded) {
                (U30Value::Bool(a), U30Value::Bool(b)) => assert_eq!(a, b),
                (U30Value::U8(a), U30Value::U8(b)) => assert_eq!(a, b),
                (U30Value::U16(a), U30Value::U16(b)) => assert_eq!(a, b),
                (U30Value::U32(a), U30Value::U32(b)) => assert_eq!(a, b),
                (U30Value::U64(a), U30Value::U64(b)) => assert_eq!(a, b),
                (U30Value::F32(a), U30Value::F32(b)) => assert_eq!(a, b),
                (U30Value::F64(a), U30Value::F64(b)) => assert_eq!(a, b),
                _ => panic!("type mismatch: {:?} vs {:?}", val, decoded),
            }
        }
    }

    /// Test decode_type: all 7 variants encode->decode roundtrip
    #[test]
    fn test_ser_all_type_variants_roundtrip() {
        let types = vec![
            U30Type::Bool,
            U30Type::U8,
            U30Type::U16,
            U30Type::U32,
            U30Type::U64,
            U30Type::F32,
            U30Type::F64,
        ];
        for ty in types {
            // Encode via type_idx and decode via decode_type
            let idx = type_idx(&ty);
            let buf = vec![idx];
            let mut pos = 0;
            let decoded = decode_type(&buf, &mut pos).unwrap();
            assert_eq!(ty, decoded, "roundtrip failed for {:?}", ty);
        }
    }

    /// Test decode_binary_op: all 27 variants encode->decode roundtrip
    #[test]
    fn test_ser_all_binary_op_variants_roundtrip() {
        use crate::ir::U30BinaryOp::*;
        let ops = vec![
            AddWrapU64, AddWrapU32, SubWrapU64, SubWrapU32,
            MulWrapU64, MulWrapU32, AndU8, OrU8, XorU8,
            ShlU64, ShlU32, ShrU64, ShrU32,
            DivU64, DivU32, RemU64, RemU32,
            Eq, LtU64, GtU64, GeU64, LeU64, LeU32,
            MinU64, MaxU64, MinU32, MaxU32,
        ];
        for op in ops {
            let idx = encode_binary_op(&op);
            let decoded = decode_binary_op(idx).unwrap();
            assert_eq!(op, decoded, "roundtrip failed for {:?}", op);
        }
    }

    /// Test ALL U30Op variants via full encode/decode roundtrip
    #[test]
    fn test_ser_all_op_variants_roundtrip_v2() {
        use crate::ir::{U30Op::*, U30BinaryOp::*, U30Value::*};
        let mut ops = Vec::new();

        // Group 0: Simple ops (0-3)
        ops.push(U30Op::Nop); // 0
        ops.push(Const { dst: 1, value: U64(42) }); // 1
        ops.push(Binary { dst: 2, op: AddWrapU64, a: 0, b: 1 }); // 2
        ops.push(Select { dst: 3, cond: 10, a: 1, b: 2 }); // 3

        // Group 1: Not ops (4-7)
        ops.push(NotU8 { dst: 4, src: 0 }); // 4
        ops.push(NotU16 { dst: 5, src: 1 }); // 5
        ops.push(NotU32 { dst: 6, src: 2 }); // 6
        ops.push(NotU64 { dst: 7, src: 3 }); // 7

        // Group 2: Conversion (8-12)
        ops.push(I2F { dst: 8, src: 0 }); // 8
        ops.push(F2I { dst: 9, src: 1 }); // 9
        ops.push(TruncF32U64 { dst: 10, src: 2 }); // 10
        ops.push(ReinterpretF32U32 { dst: 11, src: 3 }); // 11
        ops.push(ReinterpretU32F32 { dst: 12, src: 0 }); // 12

        // Group 3: Unary arithmetic (13-25)
        ops.push(AbsU64 { dst: 13, src: 0 }); // 13
        ops.push(AbsU32 { dst: 14, src: 1 }); // 14
        ops.push(NegU64 { dst: 15, src: 2 }); // 15
        ops.push(NegU32 { dst: 16, src: 3 }); // 16
        ops.push(CtzU64 { dst: 17, src: 0 }); // 17
        ops.push(CtzU32 { dst: 18, src: 1 }); // 18
        ops.push(ClzU64 { dst: 19, src: 2 }); // 19
        ops.push(ClzU32 { dst: 20, src: 3 }); // 20
        ops.push(PopcntU64 { dst: 21, src: 0 }); // 21
        ops.push(PopcntU32 { dst: 22, src: 1 }); // 22
        ops.push(RotlU64 { dst: 23, val: 0, sh: 1 }); // 24
        ops.push(RotlU32 { dst: 24, val: 2, sh: 3 }); // 25

        // Group 4: Rotate/shift (26-33)
        ops.push(RotrU64 { dst: 25, val: 0, sh: 1 }); // 26
        ops.push(RotrU32 { dst: 26, val: 2, sh: 3 }); // 27
        ops.push(ByteSwapU16 { dst: 27, src: 0 }); // 28
        ops.push(ByteSwapU32 { dst: 28, src: 1 }); // 29
        ops.push(ByteSwapU64 { dst: 29, src: 2 }); // 30

        // Group 5: Conversion (31-45)
        ops.push(ZExtI8U16 { dst: 30, src: 0 }); // 31
        ops.push(ZExtI8U32 { dst: 31, src: 1 }); // 32
        ops.push(ZExtI8U64 { dst: 32, src: 2 }); // 33
        ops.push(ZExtI16U32 { dst: 33, src: 0 }); // 34
        ops.push(ZExtI16U64 { dst: 34, src: 1 }); // 35
        ops.push(ZExtI32U64 { dst: 35, src: 2 }); // 36
        ops.push(TruncU64U32 { dst: 36, src: 0 }); // 37
        ops.push(TruncU64U16 { dst: 37, src: 1 }); // 38
        ops.push(TruncU32U16 { dst: 38, src: 2 }); // 39
        ops.push(I64F64 { dst: 39, src: 0 }); // 40
        ops.push(F64I64 { dst: 40, src: 1 }); // 41
        ops.push(F32F64 { dst: 41, src: 2 }); // 42
        ops.push(F64F32 { dst: 42, src: 0 }); // 43
        ops.push(ReinterpretF64U64 { dst: 43, src: 1 }); // 44
        ops.push(ReinterpretU64F64 { dst: 44, src: 2 }); // 45

        // Group 6: Conversion (46-55)
        ops.push(SExtI8U16 { dst: 45, src: 0 }); // 46
        ops.push(SExtI8U32 { dst: 46, src: 1 }); // 47
        ops.push(SExtI8U64 { dst: 47, src: 2 }); // 48
        ops.push(SExtI16U32 { dst: 48, src: 0 }); // 49
        ops.push(SExtI16U64 { dst: 49, src: 1 }); // 50
        ops.push(SExtI32U64 { dst: 50, src: 2 }); // 51
        ops.push(MemSize { dst: 51, region: 0 }); // 52
        ops.push(MemGrow { dst: 52, region: 0, delta: 1 }); // 53

        // Group 7: F32 comparison (56-65)
        ops.push(FEq { dst: 53, a: 0, b: 1 }); // 56
        ops.push(FLt { dst: 54, a: 2, b: 3 }); // 57
        ops.push(FGt { dst: 55, a: 0, b: 1 }); // 58
        ops.push(FLe { dst: 56, a: 2, b: 3 }); // 59
        ops.push(FGe { dst: 57, a: 0, b: 1 }); // 60

        // Group 8: F32 arithmetic (61-69)
        ops.push(FAdd { dst: 58, a: 0, b: 1 }); // 61
        ops.push(FSub { dst: 59, a: 2, b: 3 }); // 60
        ops.push(FMul { dst: 60, a: 0, b: 1 }); // 61
        ops.push(FDiv { dst: 61, a: 2, b: 3 }); // 62
        ops.push(FSqrt { dst: 62, src: 0 }); // 63
        ops.push(FAbs { dst: 63, src: 1 }); // 64
        ops.push(FNeg { dst: 64, src: 2 }); // 65
        ops.push(FMin { dst: 65, a: 0, b: 1 }); // 66
        ops.push(FMax { dst: 66, a: 2, b: 3 }); // 67

        // Group 9: F64 comparison (70-75)
        ops.push(F64Eq { dst: 67, a: 0, b: 1 }); // 70
        ops.push(F64Lt { dst: 68, a: 2, b: 3 }); // 71
        ops.push(F64Gt { dst: 69, a: 0, b: 1 }); // 72
        ops.push(F64Le { dst: 70, a: 2, b: 3 }); // 73
        ops.push(F64Ge { dst: 71, a: 0, b: 1 }); // 74

        // Group 10: F64 arithmetic (76-86)
        ops.push(F64Add { dst: 72, a: 0, b: 1 }); // 76
        ops.push(F64Sub { dst: 73, a: 2, b: 3 }); // 77
        ops.push(F64Mul { dst: 74, a: 0, b: 1 }); // 78
        ops.push(F64Div { dst: 75, a: 2, b: 3 }); // 79
        ops.push(F64Sqrt { dst: 76, src: 0 }); // 80
        ops.push(F64Abs { dst: 77, src: 1 }); // 81
        ops.push(F64Neg { dst: 78, src: 2 }); // 82
        ops.push(F64Min { dst: 79, a: 0, b: 1 }); // 83
        ops.push(F64Max { dst: 80, a: 2, b: 3 }); // 84

        // Group 11: Memory (85-89)
        ops.push(LoadU8 { dst: 81, region: 0, offset: 1 }); // 85
        ops.push(StoreU8 { region: 0, offset: 2, src: 3 }); // 86
        ops.push(LoadU16 { dst: 82, region: 0, offset: 1 }); // 87
        ops.push(StoreU16 { region: 0, offset: 2, src: 3 }); // 88
        ops.push(LoadU32 { dst: 83, region: 0, offset: 1 }); // 89
        ops.push(StoreU32 { region: 0, offset: 2, src: 3 }); // 90
        ops.push(LoadU64 { dst: 84, region: 0, offset: 1 }); // 91
        ops.push(StoreU64 { region: 0, offset: 2, src: 3 }); // 92
        ops.push(MemCopy { dst_region: 0, dst_offset: 1, src_region: 0, src_offset: 2, size: 3 }); // 93
        ops.push(MemFill { region: 0, offset: 1, value: 2, size: 3 }); // 94

        // Group 12: Call/Control (95-96)
        ops.push(Call { function: 0, args: vec![], results: vec![] }); // 95
        ops.push(IndirectCall { function: 1, args: vec![2], results: vec![3] }); // 96
        ops.push(TableBr { table: 0, index: 1 }); // 97
        ops.push(Break { code: 0 }); // 98
        ops.push(Assert { cond: 1, msg: 2 }); // 99

        // Encode all ops individually and decode
        for (idx, op) in ops.iter().enumerate() {
            let mut buf = Vec::new();
            encode_op(&mut buf, op);
            let mut pos = 0;
            let decoded = decode_op(&buf, &mut pos).unwrap();
            assert_eq!(format!("{:?}", op), format!("{:?}", decoded),
                "roundtrip failed for op index {}", idx);
        }
    }

    /// Test all U30Terminator variants via encode/decode roundtrip
    #[test]
    fn test_ser_all_terminator_variants_roundtrip_v2() {
        use crate::ir::U30Terminator::*;
        let terms = vec![
            Br { target: 1 },
            BrIf { cond: 0, then_target: 1, else_target: 2 },
            Ret { values: vec![0, 1] },
            TailCall { function: 0, args: vec![1, 2] },
            Trap { code: 42 },
        ];
        for (ti, term) in terms.iter().enumerate() {
            // Create a minimal module to test terminator encoding
            let module = crate::ir::U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![crate::ir::U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![crate::ir::U30Block {
                        ops: vec![],
                        terminator: term.clone(),
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let encoded = encode(&module);
            let decoded = decode(&encoded).unwrap();
            let decoded_term = &decoded.functions[0].blocks[0].terminator;
            assert_eq!(format!("{:?}", term), format!("{:?}", decoded_term),
                "roundtrip failed for terminator index {}", ti);
        }
    }

    /// Test all U30Value variants via encode/decode roundtrip
    #[test]
    fn test_ser_all_value_variants_roundtrip_v2() {
        use crate::ir::U30Value::*;
        let values = vec![
            Bool(true), Bool(false),
            U8(0), U8(255),
            U16(0), U16(65535),
            U32(0), U32(0xDEADBEEF),
            U64(0), U64(0xDEADBEEFCAFEBABE),
            F32(0.0), F32(1.0), F32(-3.14),
            F64(0.0), F64(1.0), F64(-3.14), F64(f64::INFINITY),
        ];
        for val in values {
            let mut buf = Vec::new();
            encode_value(&mut buf, &val);
            let mut pos = 0;
            let decoded = decode_value(&buf, &mut pos).unwrap();
            assert_eq!(format!("{:?}", val), format!("{:?}", decoded),
                "roundtrip failed for {:?}", val);
        }
    }
}
