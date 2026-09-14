//! UNICO U30 IR — executable experimental subset.
//!
//! This module is intentionally narrow. It implements only the typed operations
//! needed by the ANVAYA GAME-001 movement kernel. It does NOT freeze canonical
//! U30 byte encoding and does NOT change any UNICO readiness/release claim.

use crate::error::{Error, Result};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum U30Type {
    Bool,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum U30Value {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
}

impl U30Value {
    pub fn value_type(&self) -> U30Type {
        match self {
            Self::Bool(_) => U30Type::Bool,
            Self::U8(_) => U30Type::U8,
            Self::U16(_) => U30Type::U16,
            Self::U32(_) => U30Type::U32,
            Self::U64(_) => U30Type::U64,
            Self::F32(_) => U30Type::F32,
            Self::F64(_) => U30Type::F64,
        }
    }

    pub fn as_bool(&self) -> Result<bool> {
        match self {
            Self::Bool(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected bool, got {:?}", other.value_type()))),
        }
    }

    pub fn as_u8(&self) -> Result<u8> {
        match self {
            Self::U8(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected u8, got {:?}", other.value_type()))),
        }
    }

    pub fn as_u16(&self) -> Result<u16> {
        match self {
            Self::U16(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected u16, got {:?}", other.value_type()))),
        }
    }

    pub fn as_u32(&self) -> Result<u32> {
        match self {
            Self::U32(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected u32, got {:?}", other.value_type()))),
        }
    }

    pub fn as_u64(&self) -> Result<u64> {
        match self {
            Self::U8(v) => Ok(*v as u64),
            Self::U16(v) => Ok(*v as u64),
            Self::U32(v) => Ok(*v as u64),
            Self::U64(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected integer, got {:?}", other.value_type()))),
        }
    }

    pub fn as_i64(&self) -> Result<i64> {
        match self {
            Self::U8(v) => Ok(*v as i64),
            Self::U16(v) => Ok(*v as i64),
            Self::U32(v) => Ok(*v as i64),
            Self::U64(v) => Ok(*v as i64),
            other => Err(Error::Generic(format!("U30X type error: expected integer, got {:?}", other.value_type()))),
        }
    }

    pub fn as_f32(&self) -> Result<f32> {
        match self {
            Self::F32(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected f32, got {:?}", other.value_type()))),
        }
    }

    pub fn as_f64(&self) -> Result<f64> {
        match self {
            Self::F64(v) => Ok(*v),
            other => Err(Error::Generic(format!("U30X type error: expected f64, got {:?}", other.value_type()))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30RegionDecl {
    pub id: u32,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub initial: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30TableDecl {
    pub id: u32,
    pub targets: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum U30BinaryOp {
    AddWrapU64,
    AddWrapU32,
    SubWrapU64,
    SubWrapU32,
    MulWrapU64,
    MulWrapU32,
    AndU8,
    OrU8,
    XorU8,
    ShlU64,
    ShlU32,
    ShrU64,
    ShrU32,
    DivU64,
    DivU32,
    RemU64,
    RemU32,
    Eq,
    LtU64,
    GtU64,
    GeU64,
    LeU64,
    LeU32,
    MinU64,
    MaxU64,
    MinU32,
    MaxU32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum U30Op {
    Const { dst: u32, value: U30Value },
    Binary { dst: u32, op: U30BinaryOp, a: u32, b: u32 },
    Select { dst: u32, cond: u32, a: u32, b: u32 },
    NotU8 { dst: u32, src: u32 },
    NotU16 { dst: u32, src: u32 },
    NotU32 { dst: u32, src: u32 },
    NotU64 { dst: u32, src: u32 },
    I2F { dst: u32, src: u32 },
    F2I { dst: u32, src: u32 },
    TruncF32U64 { dst: u32, src: u32 },
    ReinterpretF32U32 { dst: u32, src: u32 },
    ReinterpretU32F32 { dst: u32, src: u32 },
    AbsU64 { dst: u32, src: u32 },
    AbsU32 { dst: u32, src: u32 },
    NegU64 { dst: u32, src: u32 },
    NegU32 { dst: u32, src: u32 },
    CtzU64 { dst: u32, src: u32 },
    CtzU32 { dst: u32, src: u32 },
    ClzU64 { dst: u32, src: u32 },
    ClzU32 { dst: u32, src: u32 },
    PopcntU64 { dst: u32, src: u32 },
    PopcntU32 { dst: u32, src: u32 },
    RotlU64 { dst: u32, val: u32, sh: u32 },
    RotlU32 { dst: u32, val: u32, sh: u32 },
    RotrU64 { dst: u32, val: u32, sh: u32 },
    RotrU32 { dst: u32, val: u32, sh: u32 },
    FEq { dst: u32, a: u32, b: u32 },
    FLt { dst: u32, a: u32, b: u32 },
    FGt { dst: u32, a: u32, b: u32 },
    FLe { dst: u32, a: u32, b: u32 },
    FGe { dst: u32, a: u32, b: u32 },
    FAdd { dst: u32, a: u32, b: u32 },
    FSub { dst: u32, a: u32, b: u32 },
    FMul { dst: u32, a: u32, b: u32 },
    FDiv { dst: u32, a: u32, b: u32 },
    FSqrt { dst: u32, src: u32 },
    FAbs { dst: u32, src: u32 },
    FNeg { dst: u32, src: u32 },
    FMin { dst: u32, a: u32, b: u32 },
    FMax { dst: u32, a: u32, b: u32 },
    ZExtI8U16 { dst: u32, src: u32 },
    ZExtI8U32 { dst: u32, src: u32 },
    ZExtI8U64 { dst: u32, src: u32 },
    ZExtI16U32 { dst: u32, src: u32 },
    ZExtI16U64 { dst: u32, src: u32 },
    ZExtI32U64 { dst: u32, src: u32 },
    TruncU64U32 { dst: u32, src: u32 },
    TruncU64U16 { dst: u32, src: u32 },
    TruncU32U16 { dst: u32, src: u32 },
    MemCopy { dst_region: u32, dst_offset: u32, src_region: u32, src_offset: u32, size: u32 },
    MemFill { region: u32, offset: u32, value: u32, size: u32 },
    MemSize { dst: u32, region: u32 },
    MemGrow { dst: u32, region: u32, delta: u32 },
    // F64 arithmetic
    F64Eq { dst: u32, a: u32, b: u32 },
    F64Lt { dst: u32, a: u32, b: u32 },
    F64Gt { dst: u32, a: u32, b: u32 },
    F64Le { dst: u32, a: u32, b: u32 },
    F64Ge { dst: u32, a: u32, b: u32 },
    F64Add { dst: u32, a: u32, b: u32 },
    F64Sub { dst: u32, a: u32, b: u32 },
    F64Mul { dst: u32, a: u32, b: u32 },
    F64Div { dst: u32, a: u32, b: u32 },
    F64Sqrt { dst: u32, src: u32 },
    F64Abs { dst: u32, src: u32 },
    F64Neg { dst: u32, src: u32 },
    F64Min { dst: u32, a: u32, b: u32 },
    F64Max { dst: u32, a: u32, b: u32 },
    // F64 conversions
    I64F64 { dst: u32, src: u32 },
    F64I64 { dst: u32, src: u32 },
    F32F64 { dst: u32, src: u32 },
    F64F32 { dst: u32, src: u32 },
    ReinterpretF64U64 { dst: u32, src: u32 },
    ReinterpretU64F64 { dst: u32, src: u32 },
    // Sign extend (preserve sign bit)
    SExtI8U16 { dst: u32, src: u32 },
    SExtI8U32 { dst: u32, src: u32 },
    SExtI8U64 { dst: u32, src: u32 },
    SExtI16U32 { dst: u32, src: u32 },
    SExtI16U64 { dst: u32, src: u32 },
    SExtI32U64 { dst: u32, src: u32 },
    // Byte swap
    ByteSwapU16 { dst: u32, src: u32 },
    ByteSwapU32 { dst: u32, src: u32 },
    ByteSwapU64 { dst: u32, src: u32 },
    Call { function: u32, args: Vec<u32>, results: Vec<u32> },
    TableBr { table: u32, index: u32 },
    Break { code: u32 },
    Assert { cond: u32, msg: u32 },
    Nop,
    LoadU8 { dst: u32, region: u32, offset: u32 },
    StoreU8 { region: u32, offset: u32, src: u32 },
    LoadU16 { dst: u32, region: u32, offset: u32 },
    StoreU16 { region: u32, offset: u32, src: u32 },
    LoadU32 { dst: u32, region: u32, offset: u32 },
    StoreU32 { region: u32, offset: u32, src: u32 },
    LoadU64 { dst: u32, region: u32, offset: u32 },
    StoreU64 { region: u32, offset: u32, src: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum U30Terminator {
    Br { target: usize },
    BrIf { cond: u32, then_target: usize, else_target: usize },
    Ret { values: Vec<u32> },
    /// Tail-call: transfer control to another function, replacing the current frame.
    /// No return address is saved — the callee's return goes to our caller.
    TailCall { function: u32, args: Vec<u32> },
    Trap { code: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct U30Block {
    pub ops: Vec<U30Op>,
    pub terminator: U30Terminator,
}

#[derive(Debug, Clone, PartialEq)]
pub struct U30Function {
    pub params: Vec<U30Type>,
    pub results: Vec<U30Type>,
    pub blocks: Vec<U30Block>,
    pub entry_block: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct U30Module {
    pub regions: Vec<U30RegionDecl>,
    pub tables: Vec<U30TableDecl>,
    pub functions: Vec<U30Function>,
    pub entry_function: usize,
}

impl U30Module {
    pub fn verify_experimental(&self) -> Result<()> {
        if self.functions.is_empty() || self.entry_function >= self.functions.len() {
            return Err(Error::Verification("U30X invalid entry function".into()));
        }
        let mut region_ids = BTreeSet::new();
        for region in &self.regions {
            if !region_ids.insert(region.id) {
                return Err(Error::Verification(format!("U30X duplicate region {}", region.id)));
            }
            if region.initial.len() > region.size {
                return Err(Error::Verification(format!("U30X region {} initializer overflow", region.id)));
            }
        }
        let mut table_ids = BTreeSet::new();
        for table in &self.tables {
            if !table_ids.insert(table.id) {
                return Err(Error::Verification(format!("U30X duplicate table {}", table.id)));
            }
            for &target in &table.targets {
                if target >= self.functions.len() {
                    return Err(Error::Verification(format!("U30X table {} has invalid target block", table.id)));
                }
            }
        }
        for (fn_index, function) in self.functions.iter().enumerate() {
            self.verify_function(fn_index, function, &region_ids, &table_ids)?;
        }
        Ok(())
    }

    fn verify_function(
        &self,
        fn_index: usize,
        function: &U30Function,
        region_ids: &BTreeSet<u32>,
        table_ids: &BTreeSet<u32>,
    ) -> Result<()> {
        if function.blocks.is_empty() || function.entry_block >= function.blocks.len() {
            return Err(Error::Verification(format!("U30X function {fn_index} has invalid entry block")));
        }
        let mut global_defined: BTreeSet<u32> = (0..function.params.len() as u32).collect();
        for (block_index, block) in function.blocks.iter().enumerate() {
            // Each block has its own definition scope; start from params
            // (params are live-in to all blocks), but allow redefinition within block
            let mut block_defined: BTreeSet<u32> = global_defined.clone();
            let mut defined = &mut block_defined; // local alias for brevity
            for op in &block.ops {
                let dst = match op {
                    U30Op::Const { dst, .. }
                    | U30Op::Binary { dst, .. }
                    | U30Op::Select { dst, .. }
                    | U30Op::NotU8 { dst, .. }
                    | U30Op::NotU16 { dst, .. }
                    | U30Op::NotU32 { dst, .. }
                    | U30Op::NotU64 { dst, .. }
                    | U30Op::I2F { dst, .. }
                    | U30Op::F2I { dst, .. }
                    | U30Op::TruncF32U64 { dst, .. }
                    | U30Op::ReinterpretF32U32 { dst, .. }
                    | U30Op::ReinterpretU32F32 { dst, .. }
                    | U30Op::AbsU64 { dst, .. }
                    | U30Op::AbsU32 { dst, .. }
                    | U30Op::NegU64 { dst, .. }
                    | U30Op::NegU32 { dst, .. }
                    | U30Op::CtzU64 { dst, .. }
                    | U30Op::CtzU32 { dst, .. }
                    | U30Op::ClzU64 { dst, .. }
                    | U30Op::ClzU32 { dst, .. }
                    | U30Op::PopcntU64 { dst, .. }
                    | U30Op::PopcntU32 { dst, .. }
                    | U30Op::RotlU64 { dst, .. }
                    | U30Op::RotlU32 { dst, .. }
                    | U30Op::RotrU64 { dst, .. }
                    | U30Op::RotrU32 { dst, .. }
                    | U30Op::FEq { dst, .. }
                    | U30Op::FLt { dst, .. }
                    | U30Op::FGt { dst, .. }
                    | U30Op::FLe { dst, .. }
                    | U30Op::FGe { dst, .. }
                    | U30Op::FAdd { dst, .. }
                    | U30Op::FSub { dst, .. }
                    | U30Op::FMul { dst, .. }
                    | U30Op::FDiv { dst, .. }
                    | U30Op::FSqrt { dst, .. }
                    | U30Op::FAbs { dst, .. }
                    | U30Op::FNeg { dst, .. }
                    | U30Op::FMin { dst, .. }
                    | U30Op::FMax { dst, .. }
                    | U30Op::F64Eq { dst, .. }
                    | U30Op::F64Lt { dst, .. }
                    | U30Op::F64Gt { dst, .. }
                    | U30Op::F64Le { dst, .. }
                    | U30Op::F64Ge { dst, .. }
                    | U30Op::F64Add { dst, .. }
                    | U30Op::F64Sub { dst, .. }
                    | U30Op::F64Mul { dst, .. }
                    | U30Op::F64Div { dst, .. }
                    | U30Op::F64Sqrt { dst, .. }
                    | U30Op::F64Abs { dst, .. }
                    | U30Op::F64Neg { dst, .. }
                    | U30Op::F64Min { dst, .. }
                    | U30Op::F64Max { dst, .. }
                    | U30Op::I64F64 { dst, .. }
                    | U30Op::F64I64 { dst, .. }
                    | U30Op::F32F64 { dst, .. }
                    | U30Op::F64F32 { dst, .. }
                    | U30Op::ReinterpretF64U64 { dst, .. }
                    | U30Op::ReinterpretU64F64 { dst, .. }
                    | U30Op::SExtI8U16 { dst, .. }
                    | U30Op::SExtI8U32 { dst, .. }
                    | U30Op::SExtI8U64 { dst, .. }
                    | U30Op::SExtI16U32 { dst, .. }
                    | U30Op::SExtI16U64 { dst, .. }
                    | U30Op::SExtI32U64 { dst, .. }
                    | U30Op::ByteSwapU16 { dst, .. }
                    | U30Op::ByteSwapU32 { dst, .. }
                    | U30Op::ByteSwapU64 { dst, .. }
                    | U30Op::ZExtI8U16 { dst, .. }
                    | U30Op::ZExtI8U32 { dst, .. }
                    | U30Op::ZExtI8U64 { dst, .. }
                    | U30Op::ZExtI16U32 { dst, .. }
                    | U30Op::ZExtI16U64 { dst, .. }
                    | U30Op::ZExtI32U64 { dst, .. }
                    | U30Op::TruncU64U32 { dst, .. }
                    | U30Op::TruncU64U16 { dst, .. }
                    | U30Op::TruncU32U16 { dst, .. }
                    | U30Op::MemSize { dst, .. }
                    | U30Op::MemGrow { dst, .. }
                    | U30Op::LoadU8 { dst, .. }
                    | U30Op::LoadU16 { dst, .. }
                    | U30Op::LoadU32 { dst, .. }
                    | U30Op::LoadU64 { dst, .. } => Some(*dst),
                    U30Op::StoreU8 { .. }
                    | U30Op::StoreU16 { .. }
                    | U30Op::StoreU32 { .. }
                    | U30Op::StoreU64 { .. }
                    | U30Op::MemCopy { .. }
                    | U30Op::MemFill { .. }
                    | U30Op::Call { .. }
                    | U30Op::TableBr { .. }
                    | U30Op::Break { .. }
                    | U30Op::Assert { .. }
                    | U30Op::Nop => None,
                };
                if let Some(dst) = dst {
                    // Parameters can be overwritten (SSA allows assigning over parameters)
                    // Only flag redefinition if dst is NOT a parameter (i.e., dst >= params.len)
                    if dst >= function.params.len() as u32 && !defined.insert(dst) {
                        return Err(Error::Verification(format!(
                            "U30X function {fn_index} redefines value %{dst}"
                        )));
                    }
                }
                // Validate that operands reference defined values
                match op {
                    U30Op::Const { .. } => {}
                    U30Op::Binary { a, b, .. } => {
                        if !defined.contains(a) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{a}"
                            )));
                        }
                        if !defined.contains(b) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{b}"
                            )));
                        }
                    }
                    U30Op::Select { cond, a, b, .. } => {
                        if !defined.contains(cond) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined condition value %{cond}"
                            )));
                        }
                        if !defined.contains(a) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{a}"
                            )));
                        }
                        if !defined.contains(b) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{b}"
                            )));
                        }
                    }
                    U30Op::NotU8 { src, .. }
                    | U30Op::NotU16 { src, .. }
                    | U30Op::NotU32 { src, .. }
                    | U30Op::NotU64 { src, .. }
                    | U30Op::I2F { src, .. }
                    | U30Op::F2I { src, .. }
                    | U30Op::TruncF32U64 { src, .. }
                    | U30Op::ReinterpretF32U32 { src, .. }
                    | U30Op::ReinterpretU32F32 { src, .. }
                    | U30Op::AbsU64 { src, .. }
                    | U30Op::AbsU32 { src, .. }
                    | U30Op::NegU64 { src, .. }
                    | U30Op::NegU32 { src, .. }
                    | U30Op::CtzU64 { src, .. }
                    | U30Op::CtzU32 { src, .. }
                    | U30Op::ClzU64 { src, .. }
                    | U30Op::ClzU32 { src, .. }
                    | U30Op::PopcntU64 { src, .. }
                    | U30Op::PopcntU32 { src, .. } => {
                        if !defined.contains(src) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{src}"
                            )));
                        }
                    }
                    U30Op::RotlU64 { val, sh, .. }
                    | U30Op::RotlU32 { val, sh, .. }
                    | U30Op::RotrU64 { val, sh, .. }
                    | U30Op::RotrU32 { val, sh, .. } => {
                        if !defined.contains(val) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined val value %{val}"
                            )));
                        }
                        if !defined.contains(sh) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined sh value %{sh}"
                            )));
                        }
                    }
                    U30Op::FEq { a, b, .. }
                    | U30Op::FLt { a, b, .. }
                    | U30Op::FGt { a, b, .. }
                    | U30Op::FLe { a, b, .. }
                    | U30Op::FGe { a, b, .. }
                    | U30Op::F64Eq { a, b, .. }
                    | U30Op::F64Lt { a, b, .. }
                    | U30Op::F64Gt { a, b, .. }
                    | U30Op::F64Le { a, b, .. }
                    | U30Op::F64Ge { a, b, .. } => {
                        if !defined.contains(a) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{a}"
                            )));
                        }
                        if !defined.contains(b) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{b}"
                            )));
                        }
                    }
                    U30Op::LoadU8 { region, offset, .. }
                    | U30Op::LoadU16 { region, offset, .. }
                    | U30Op::LoadU32 { region, offset, .. }
                    | U30Op::LoadU64 { region, offset, .. } => {
                        if !region_ids.contains(region) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: unknown region {region}"
                            )));
                        }
                        if !defined.contains(offset) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined offset value %{offset}"
                            )));
                        }
                    }
                    U30Op::StoreU8 { region, offset, src }
                    | U30Op::StoreU16 { region, offset, src }
                    | U30Op::StoreU32 { region, offset, src }
                    | U30Op::StoreU64 { region, offset, src } => {
                        if !region_ids.contains(region) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: unknown region {region}"
                            )));
                        }
                        if !defined.contains(offset) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined offset value %{offset}"
                            )));
                        }
                        if !defined.contains(src) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined src value %{src}"
                            )));
                        }
                    }
                    U30Op::FAdd { a, b, .. }
                    | U30Op::FSub { a, b, .. }
                    | U30Op::FMul { a, b, .. }
                    | U30Op::FDiv { a, b, .. }
                    | U30Op::FMin { a, b, .. }
                    | U30Op::FMax { a, b, .. }
                    | U30Op::F64Add { a, b, .. }
                    | U30Op::F64Sub { a, b, .. }
                    | U30Op::F64Mul { a, b, .. }
                    | U30Op::F64Div { a, b, .. }
                    | U30Op::F64Min { a, b, .. }
                    | U30Op::F64Max { a, b, .. } => {
                        if !defined.contains(a) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined a value %{a}"
                            )));
                        }
                        if !defined.contains(b) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined b value %{b}"
                            )));
                        }
                    }
                    U30Op::FSqrt { src, .. }
                    | U30Op::FAbs { src, .. }
                    | U30Op::FNeg { src, .. }
                    | U30Op::F64Sqrt { src, .. }
                    | U30Op::F64Abs { src, .. }
                    | U30Op::F64Neg { src, .. }
                    | U30Op::ZExtI8U16 { src, .. }
                    | U30Op::ZExtI8U32 { src, .. }
                    | U30Op::ZExtI8U64 { src, .. }
                    | U30Op::ZExtI16U32 { src, .. }
                    | U30Op::ZExtI16U64 { src, .. }
                    | U30Op::ZExtI32U64 { src, .. }
                    | U30Op::TruncU64U32 { src, .. }
                    | U30Op::TruncU64U16 { src, .. }
                    | U30Op::TruncU32U16 { src, .. }
                    | U30Op::SExtI8U16 { src, .. }
                    | U30Op::SExtI8U32 { src, .. }
                    | U30Op::SExtI8U64 { src, .. }
                    | U30Op::SExtI16U32 { src, .. }
                    | U30Op::SExtI16U64 { src, .. }
                    | U30Op::SExtI32U64 { src, .. }
                    | U30Op::ByteSwapU16 { src, .. }
                    | U30Op::ByteSwapU32 { src, .. }
                    | U30Op::ByteSwapU64 { src, .. }
                    | U30Op::I64F64 { src, .. }
                    | U30Op::F64I64 { src, .. }
                    | U30Op::F32F64 { src, .. }
                    | U30Op::F64F32 { src, .. }
                    | U30Op::ReinterpretF64U64 { src, .. }
                    | U30Op::ReinterpretU64F64 { src, .. } => {
                        if !defined.contains(src) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined src value %{src}"
                            )));
                        }
                    }
                    U30Op::MemCopy { dst_region, dst_offset, src_region, src_offset, size } => {
                        if !region_ids.contains(dst_region) {
                            return Err(Error::Verification(format!("U30X unknown dst region")));
                        }
                        if !region_ids.contains(src_region) {
                            return Err(Error::Verification(format!("U30X unknown src region")));
                        }
                        for r in &[dst_offset, src_offset, size] {
                            if !defined.contains(r) {
                                return Err(Error::Verification(format!("U30X undefined value in memcopy")));
                            }
                        }
                    }
                    U30Op::MemFill { region, offset, value, size } => {
                        if !region_ids.contains(region) {
                            return Err(Error::Verification(format!("U30X unknown region")));
                        }
                        for r in &[offset, value, size] {
                            if !defined.contains(r) {
                                return Err(Error::Verification(format!("U30X undefined value in memfill")));
                            }
                        }
                    }
                    U30Op::MemSize { region, .. } => {
                        if !region_ids.contains(region) {
                            return Err(Error::Verification(format!("U30X unknown region")));
                        }
                    }
                    U30Op::MemGrow { region, delta, .. } => {
                        if !region_ids.contains(region) {
                            return Err(Error::Verification(format!("U30X unknown region")));
                        }
                        if !defined.contains(delta) {
                            return Err(Error::Verification(format!("U30X undefined delta")));
                        }
                    }
                    U30Op::Call { function: _, args, results } => {
                        for r in args {
                            if !defined.contains(r) {
                                return Err(Error::Verification(format!("U30X undefined arg")));
                            }
                        }
                        // Call defines its result registers
                        for r in results {
                            defined.insert(*r);
                        }
                    }
                    U30Op::TableBr { table, index } => {
                        if !table_ids.contains(table) {
                            return Err(Error::Verification(format!("U30X unknown table {}", table)));
                        }
                        if !defined.contains(index) {
                            return Err(Error::Verification(format!("U30X undefined table index")));
                        }
                    }
                    U30Op::Break { code } => {
                        if !defined.contains(code) {
                            return Err(Error::Verification(format!("U30X undefined break code")));
                        }
                    }
                    U30Op::Assert { cond, msg: _ } => {
                        if !defined.contains(cond) {
                            return Err(Error::Verification(format!("U30X undefined assert cond")));
                        }
                    }
                    U30Op::Nop => {}
                }
            }
            // Merge block's definitions into global set for cross-block tracking
            global_defined.extend(block_defined.iter().cloned());
            self.verify_terminator(fn_index, block_index, function, &block.terminator, &block_defined)?;
        }
        Ok(())
    }

    fn verify_terminator(
        &self,
        fn_index: usize,
        block_index: usize,
        function: &U30Function,
        term: &U30Terminator,
        defined: &BTreeSet<u32>,
    ) -> Result<()> {
        let block_count = function.blocks.len();
        match term {
            U30Terminator::Br { target } => {
                if *target >= block_count {
                    return Err(Error::Verification(format!("U30X fn {fn_index} block {block_index}: bad branch target")));
                }
            }
            U30Terminator::BrIf { then_target, else_target, .. } => {
                if *then_target >= block_count || *else_target >= block_count {
                    return Err(Error::Verification(format!("U30X fn {fn_index} block {block_index}: bad conditional target")));
                }
            }
            U30Terminator::Ret { values } => {
                if values.len() != function.results.len() {
                    return Err(Error::Verification(format!("U30X fn {fn_index} block {block_index}: bad result arity")));
                }
            }
            U30Terminator::TailCall { function: fn_idx, args } => {
                // Args must be defined
                for r in args {
                    if !defined.contains(r) {
                        return Err(Error::Verification(format!("U30X fn {fn_index} block {block_index}: undefined arg in TailCall")));
                    }
                }
            }
            U30Terminator::Trap { .. } => {}
        }
        Ok(())
    }
}
