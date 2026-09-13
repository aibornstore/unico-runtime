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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum U30Value {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl U30Value {
    pub fn value_type(&self) -> U30Type {
        match self {
            Self::Bool(_) => U30Type::Bool,
            Self::U8(_) => U30Type::U8,
            Self::U16(_) => U30Type::U16,
            Self::U32(_) => U30Type::U32,
            Self::U64(_) => U30Type::U64,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30RegionDecl {
    pub id: u32,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub initial: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum U30Op {
    Const { dst: u32, value: U30Value },
    Binary { dst: u32, op: U30BinaryOp, a: u32, b: u32 },
    Select { dst: u32, cond: u32, a: u32, b: u32 },
    NotU8 { dst: u32, src: u32 },
    NotU16 { dst: u32, src: u32 },
    NotU32 { dst: u32, src: u32 },
    NotU64 { dst: u32, src: u32 },
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
    Trap { code: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30Block {
    pub ops: Vec<U30Op>,
    pub terminator: U30Terminator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30Function {
    pub params: Vec<U30Type>,
    pub results: Vec<U30Type>,
    pub blocks: Vec<U30Block>,
    pub entry_block: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U30Module {
    pub regions: Vec<U30RegionDecl>,
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
        for (fn_index, function) in self.functions.iter().enumerate() {
            self.verify_function(fn_index, function, &region_ids)?;
        }
        Ok(())
    }

    fn verify_function(
        &self,
        fn_index: usize,
        function: &U30Function,
        region_ids: &BTreeSet<u32>,
    ) -> Result<()> {
        if function.blocks.is_empty() || function.entry_block >= function.blocks.len() {
            return Err(Error::Verification(format!("U30X function {fn_index} has invalid entry block")));
        }
        let mut defined: BTreeSet<u32> = (0..function.params.len() as u32).collect();
        for (block_index, block) in function.blocks.iter().enumerate() {
            for op in &block.ops {
                let dst = match op {
                    U30Op::Const { dst, .. }
                    | U30Op::Binary { dst, .. }
                    | U30Op::Select { dst, .. }
                    | U30Op::NotU8 { dst, .. }
                    | U30Op::NotU16 { dst, .. }
                    | U30Op::NotU32 { dst, .. }
                    | U30Op::NotU64 { dst, .. }
                    | U30Op::LoadU8 { dst, .. }
                    | U30Op::LoadU16 { dst, .. }
                    | U30Op::LoadU32 { dst, .. }
                    | U30Op::LoadU64 { dst, .. } => Some(*dst),
                    U30Op::StoreU8 { .. }
                    | U30Op::StoreU16 { .. }
                    | U30Op::StoreU32 { .. }
                    | U30Op::StoreU64 { .. } => None,
                };
                if let Some(dst) = dst {
                    if !defined.insert(dst) {
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
                    | U30Op::NotU64 { src, .. } => {
                        if !defined.contains(src) {
                            return Err(Error::Verification(format!(
                                "U30X function {fn_index} block {block_index}: undefined source value %{src}"
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
                }
            }
            self.verify_terminator(fn_index, block_index, function, &block.terminator)?;
        }
        Ok(())
    }

    fn verify_terminator(
        &self,
        fn_index: usize,
        block_index: usize,
        function: &U30Function,
        term: &U30Terminator,
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
            U30Terminator::Trap { .. } => {}
        }
        Ok(())
    }
}
