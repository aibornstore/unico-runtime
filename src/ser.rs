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
}
