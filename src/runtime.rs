//! UNICO U30 experimental interpreter subset.
//!
//! The accepted U30 specification remains normative. This interpreter is a
//! narrow executable experiment for GAME-001 and is not a release/readiness
//! promotion. Canonical serialization and full verifier are still open gates.

use crate::error::{Error, Result};
use crate::ir::{
    U30BinaryOp, U30Module, U30Op, U30Terminator, U30Value,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct U30ExecutionOutcome {
    pub results: Vec<U30Value>,
    pub regions: BTreeMap<u32, Vec<u8>>,
    pub steps: u64,
}

#[derive(Debug, Clone)]
struct RegionState {
    bytes: Vec<u8>,
    readable: bool,
    writable: bool,
}

#[derive(Debug, Clone)]
pub struct U30Runtime {
    pub fuel_limit: u64,
}

impl Default for U30Runtime {
    fn default() -> Self {
        Self { fuel_limit: 100_000 }
    }
}

impl U30Runtime {
    pub fn execute_experimental(
        &self,
        module: &U30Module,
        args: &[U30Value],
    ) -> Result<U30ExecutionOutcome> {
        module.verify_experimental()?;
        let function = &module.functions[module.entry_function];
        if args.len() != function.params.len() {
            return Err(Error::Verification("U30X entry argument arity mismatch".into()));
        }
        for (index, (arg, expected)) in args.iter().zip(&function.params).enumerate() {
            if arg.value_type() != *expected {
                return Err(Error::Verification(format!(
                    "U30X entry argument {index} type mismatch"
                )));
            }
        }

        let mut regs = BTreeMap::<u32, U30Value>::new();
        for (index, arg) in args.iter().cloned().enumerate() {
            regs.insert(index as u32, arg);
        }
        let mut regions = self.instantiate_regions(module)?;
        let mut block_index = function.entry_block;
        let mut steps = 0u64;

        loop {
            let block = &function.blocks[block_index];
            for op in &block.ops {
                self.charge(&mut steps)?;
                self.exec_op(op, &mut regs, &mut regions)?;
            }
            self.charge(&mut steps)?;
            match &block.terminator {
                U30Terminator::Br { target } => block_index = *target,
                U30Terminator::BrIf { cond, then_target, else_target } => {
                    block_index = if self.reg(&regs, *cond)?.as_bool()? {
                        *then_target
                    } else {
                        *else_target
                    };
                }
                U30Terminator::Ret { values } => {
                    let results = values
                        .iter()
                        .map(|id| self.reg(&regs, *id).cloned())
                        .collect::<Result<Vec<_>>>()?;
                    for (value, expected) in results.iter().zip(&function.results) {
                        if value.value_type() != *expected {
                            return Err(Error::Generic("U30X return type mismatch".into()));
                        }
                    }
                    let output_regions = regions
                        .into_iter()
                        .map(|(id, state)| (id, state.bytes))
                        .collect();
                    return Ok(U30ExecutionOutcome { results, regions: output_regions, steps });
                }
                U30Terminator::Trap { code } => {
                    return Err(Error::Generic(format!("U30X explicit trap {code}")));
                }
            }
        }
    }

    fn instantiate_regions(&self, module: &U30Module) -> Result<BTreeMap<u32, RegionState>> {
        let mut out = BTreeMap::new();
        for decl in &module.regions {
            let mut bytes = vec![0u8; decl.size];
            bytes[..decl.initial.len()].copy_from_slice(&decl.initial);
            out.insert(
                decl.id,
                RegionState {
                    bytes,
                    readable: decl.readable,
                    writable: decl.writable,
                },
            );
        }
        Ok(out)
    }

    fn charge(&self, steps: &mut u64) -> Result<()> {
        if *steps >= self.fuel_limit {
            return Err(Error::Generic("U30X fuel exhausted".into()));
        }
        *steps += 1;
        Ok(())
    }

    fn reg<'a>(&self, regs: &'a BTreeMap<u32, U30Value>, id: u32) -> Result<&'a U30Value> {
        regs.get(&id)
            .ok_or_else(|| Error::Generic(format!("U30X undefined value %{id}")))
    }

    fn exec_op(
        &self,
        op: &U30Op,
        regs: &mut BTreeMap<u32, U30Value>,
        regions: &mut BTreeMap<u32, RegionState>,
    ) -> Result<()> {
        match op {
            U30Op::Const { dst, value } => {
                regs.insert(*dst, value.clone());
            }
            U30Op::Binary { dst, op, a, b } => {
                let av = self.reg(regs, *a)?.clone();
                let bv = self.reg(regs, *b)?.clone();
                let value = self.binary(*op, av, bv)?;
                regs.insert(*dst, value);
            }
            U30Op::Select { dst, cond, a, b } => {
                let cond_val = self.reg(regs, *cond)?.as_bool()?;
                let av = self.reg(regs, *a)?.clone();
                let bv = self.reg(regs, *b)?.clone();
                let value = if cond_val { av } else { bv };
                regs.insert(*dst, value);
            }
            U30Op::NotU8 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u8()?;
                regs.insert(*dst, U30Value::U8(!v));
            }
            U30Op::NotU16 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u16()?;
                regs.insert(*dst, U30Value::U16(!v));
            }
            U30Op::NotU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U32(!v));
            }
            U30Op::NotU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(!v));
            }
            U30Op::I2F { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()? as f32;
                regs.insert(*dst, U30Value::F32(v));
            }
            U30Op::F2I { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                regs.insert(*dst, U30Value::U64(v as u64));
            }
            U30Op::LoadU8 { dst, region, offset } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let state = regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.readable {
                    return Err(Error::Generic(format!("U30X region {region} is not readable")));
                }
                let value = *state.bytes.get(offset)
                    .ok_or_else(|| Error::Generic("U30X load.u8 out of bounds".into()))?;
                regs.insert(*dst, U30Value::U8(value));
            }
            U30Op::StoreU8 { region, offset, src } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let value = self.reg(regs, *src)?.as_u8()?;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.writable {
                    return Err(Error::Generic(format!("U30X region {region} is not writable")));
                }
                let slot = state.bytes.get_mut(offset)
                    .ok_or_else(|| Error::Generic("U30X store.u8 out of bounds".into()))?;
                *slot = value;
            }
            U30Op::LoadU16 { dst, region, offset } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let state = regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.readable {
                    return Err(Error::Generic(format!("U30X region {region} is not readable")));
                }
                if offset + 2 > state.bytes.len() {
                    return Err(Error::Generic("U30X load.u16 out of bounds".into()));
                }
                let value = u16::from_le_bytes([state.bytes[offset], state.bytes[offset + 1]]);
                regs.insert(*dst, U30Value::U16(value));
            }
            U30Op::StoreU16 { region, offset, src } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let value = self.reg(regs, *src)?.as_u16()?;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.writable {
                    return Err(Error::Generic(format!("U30X region {region} is not writable")));
                }
                if offset + 2 > state.bytes.len() {
                    return Err(Error::Generic("U30X store.u16 out of bounds".into()));
                }
                state.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
            U30Op::LoadU32 { dst, region, offset } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let state = regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.readable {
                    return Err(Error::Generic(format!("U30X region {region} is not readable")));
                }
                if offset + 4 > state.bytes.len() {
                    return Err(Error::Generic("U30X load.u32 out of bounds".into()));
                }
                let value = u32::from_le_bytes([
                    state.bytes[offset], state.bytes[offset + 1],
                    state.bytes[offset + 2], state.bytes[offset + 3],
                ]);
                regs.insert(*dst, U30Value::U32(value));
            }
            U30Op::StoreU32 { region, offset, src } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let value = self.reg(regs, *src)?.as_u32()?;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.writable {
                    return Err(Error::Generic(format!("U30X region {region} is not writable")));
                }
                if offset + 4 > state.bytes.len() {
                    return Err(Error::Generic("U30X store.u32 out of bounds".into()));
                }
                state.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            U30Op::LoadU64 { dst, region, offset } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let state = regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.readable {
                    return Err(Error::Generic(format!("U30X region {region} is not readable")));
                }
                if offset + 8 > state.bytes.len() {
                    return Err(Error::Generic("U30X load.u64 out of bounds".into()));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&state.bytes[offset..offset + 8]);
                let value = u64::from_le_bytes(buf);
                regs.insert(*dst, U30Value::U64(value));
            }
            U30Op::StoreU64 { region, offset, src } => {
                let offset = self.reg(regs, *offset)?.as_u64()? as usize;
                let value = self.reg(regs, *src)?.as_u64()?;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region {region}")))?;
                if !state.writable {
                    return Err(Error::Generic(format!("U30X region {region} is not writable")));
                }
                if offset + 8 > state.bytes.len() {
                    return Err(Error::Generic("U30X store.u64 out of bounds".into()));
                }
                state.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(())
    }

    fn binary(&self, op: U30BinaryOp, a: U30Value, b: U30Value) -> Result<U30Value> {
        let value = match op {
            U30BinaryOp::AddWrapU64 => U30Value::U64(a.as_u64()?.wrapping_add(b.as_u64()?)),
            U30BinaryOp::AddWrapU32 => U30Value::U32(a.as_u32()?.wrapping_add(b.as_u32()?)),
            U30BinaryOp::SubWrapU64 => U30Value::U64(a.as_u64()?.wrapping_sub(b.as_u64()?)),
            U30BinaryOp::SubWrapU32 => U30Value::U32(a.as_u32()?.wrapping_sub(b.as_u32()?)),
            U30BinaryOp::MulWrapU64 => U30Value::U64(a.as_u64()?.wrapping_mul(b.as_u64()?)),
            U30BinaryOp::MulWrapU32 => U30Value::U32(a.as_u32()?.wrapping_mul(b.as_u32()?)),
            U30BinaryOp::AndU8 => U30Value::U8(a.as_u8()? & b.as_u8()?),
            U30BinaryOp::OrU8 => U30Value::U8(a.as_u8()? | b.as_u8()?),
            U30BinaryOp::XorU8 => U30Value::U8(a.as_u8()? ^ b.as_u8()?),
            U30BinaryOp::ShlU64 => U30Value::U64(a.as_u64()?.wrapping_shl(b.as_u64()? as u32)),
            U30BinaryOp::ShlU32 => U30Value::U32(a.as_u32()?.wrapping_shl(b.as_u32()? as u32)),
            U30BinaryOp::ShrU64 => U30Value::U64(a.as_u64()?.wrapping_shr(b.as_u64()? as u32)),
            U30BinaryOp::ShrU32 => U30Value::U32(a.as_u32()?.wrapping_shr(b.as_u32()? as u32)),
            U30BinaryOp::DivU64 => {
                let bv = b.as_u64()?;
                if bv == 0 { return Err(Error::Generic("U30X div by zero".into())); }
                U30Value::U64(a.as_u64()? / bv)
            }
            U30BinaryOp::DivU32 => {
                let bv = b.as_u32()?;
                if bv == 0 { return Err(Error::Generic("U30X div by zero".into())); }
                U30Value::U32(a.as_u32()? / bv)
            }
            U30BinaryOp::RemU64 => {
                let bv = b.as_u64()?;
                if bv == 0 { return Err(Error::Generic("U30X rem by zero".into())); }
                U30Value::U64(a.as_u64()? % bv)
            }
            U30BinaryOp::RemU32 => {
                let bv = b.as_u32()?;
                if bv == 0 { return Err(Error::Generic("U30X rem by zero".into())); }
                U30Value::U32(a.as_u32()? % bv)
            }
            U30BinaryOp::Eq => {
                if a.value_type() != b.value_type() {
                    return Err(Error::Generic("U30X eq type mismatch".into()));
                }
                U30Value::Bool(a == b)
            }
            U30BinaryOp::LtU64 => U30Value::Bool(a.as_u64()? < b.as_u64()?),
            U30BinaryOp::GtU64 => U30Value::Bool(a.as_u64()? > b.as_u64()?),
            U30BinaryOp::GeU64 => U30Value::Bool(a.as_u64()? >= b.as_u64()?),
            U30BinaryOp::LeU64 => U30Value::Bool(a.as_u64()? <= b.as_u64()?),
            U30BinaryOp::LeU32 => U30Value::Bool(a.as_u32()? <= b.as_u32()?),
            U30BinaryOp::MinU64 => U30Value::U64(a.as_u64()?.min(b.as_u64()?)),
            U30BinaryOp::MaxU64 => U30Value::U64(a.as_u64()?.max(b.as_u64()?)),
            U30BinaryOp::MinU32 => U30Value::U32(a.as_u32()?.min(b.as_u32()?)),
            U30BinaryOp::MaxU32 => U30Value::U32(a.as_u32()?.max(b.as_u32()?)),
        };
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{U30Block, U30Function, U30RegionDecl, U30Type};

    fn store_load_module() -> U30Module {
        U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: true, initial: vec![0; 4],
            }],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U8(7) },
                        U30Op::StoreU8 { region: 0, offset: 0, src: 1 },
                        U30Op::LoadU8 { dst: 2, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        }
    }

    #[test]
    fn u30x_dynamic_store_load_executes() {
        let out = U30Runtime::default()
            .execute_experimental(&store_load_module(), &[U30Value::U64(2)])
            .expect("U30X execution");
        assert_eq!(out.results, vec![U30Value::U8(7)]);
        assert_eq!(out.regions[&0], vec![0, 0, 7, 0]);
        assert_eq!(out.steps, 4);
    }

    #[test]
    fn u30x_dynamic_memory_oob_fails_closed() {
        let err = U30Runtime::default()
            .execute_experimental(&store_load_module(), &[U30Value::U64(4)])
            .expect_err("offset 4 must be OOB for a 4-byte region");
        assert!(err.to_string().contains("out of bounds"));
    }

    #[test]
    fn u30x_binary_sub_wraps() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(5) },
                        U30Op::Const { dst: 1, value: U30Value::U64(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::SubWrapU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("sub wrap");
        assert_eq!(out.results, vec![U30Value::U64(u64::MAX - 1)]); // 5 - 7 = -2 = u64::MAX - 1
    }

    #[test]
    fn u30x_binary_mul_wraps() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(u64::MAX) },
                        U30Op::Const { dst: 1, value: U30Value::U64(2) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("mul wrap");
        assert_eq!(out.results, vec![U30Value::U64(u64::MAX - 1)]); // MAX * 2 = MAX << 1 | 1 = MAX - 1
    }

    #[test]
    fn u30x_binary_xor_u8() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xFF) },
                        U30Op::Const { dst: 1, value: U30Value::U8(0x0F) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::XorU8, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("xor");
        assert_eq!(out.results, vec![U30Value::U8(0xF0)]);
    }

    #[test]
    fn u30x_binary_shl_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(1) },
                        U30Op::Const { dst: 1, value: U30Value::U64(4) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::ShlU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("shl");
        assert_eq!(out.results, vec![U30Value::U64(16)]);
    }

    #[test]
    fn u30x_binary_shr_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(16) },
                        U30Op::Const { dst: 1, value: U30Value::U64(4) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::ShrU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("shr");
        assert_eq!(out.results, vec![U30Value::U64(1)]);
    }

    #[test]
    fn u30x_binary_shr_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(2) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::ShrU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("shr u32");
        assert_eq!(out.results, vec![U30Value::U32(25)]);
    }

    #[test]
    fn u30x_binary_add_wraps_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(u64::MAX) },
                        U30Op::Const { dst: 1, value: U30Value::U64(1) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("add wrap");
        assert_eq!(out.results, vec![U30Value::U64(0)]); // MAX + 1 = 0
    }

    #[test]
    fn u30x_binary_add_wraps_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(u32::MAX) },
                        U30Op::Const { dst: 1, value: U30Value::U32(1) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("add wrap u32");
        assert_eq!(out.results, vec![U30Value::U32(0)]); // MAX + 1 = 0
    }

    #[test]
    fn u30x_binary_sub_wraps_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(5) },
                        U30Op::Const { dst: 1, value: U30Value::U32(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::SubWrapU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("sub wrap u32");
        assert_eq!(out.results, vec![U30Value::U32(u32::MAX - 1)]); // 5 - 7 = -2 = u32::MAX - 1
    }

    #[test]
    fn u30x_binary_mul_wraps_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(u32::MAX) },
                        U30Op::Const { dst: 1, value: U30Value::U32(2) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::MulWrapU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("mul wrap u32");
        assert_eq!(out.results, vec![U30Value::U32(u32::MAX - 1)]); // MAX * 2 = MAX << 1 | 1 = MAX - 1
    }

    #[test]
    fn u30x_binary_and_u8() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xFF) },
                        U30Op::Const { dst: 1, value: U30Value::U8(0x0F) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::AndU8, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("and");
        assert_eq!(out.results, vec![U30Value::U8(0x0F)]);
    }

    #[test]
    fn u30x_binary_or_u8() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xF0) },
                        U30Op::Const { dst: 1, value: U30Value::U8(0x0F) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::OrU8, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("or");
        assert_eq!(out.results, vec![U30Value::U8(0xFF)]);
    }

    #[test]
    fn u30x_binary_eq_works() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::Const { dst: 1, value: U30Value::U32(42) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::Eq, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("eq");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_binary_lt_works() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(3) },
                        U30Op::Const { dst: 1, value: U30Value::U64(5) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::LtU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("lt");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_load_u16_u32_u64() {
        let mut region = vec![0u8; 16];
        region[0..2].copy_from_slice(&0x0102u16.to_le_bytes());
        region[4..8].copy_from_slice(&0x03040506u32.to_le_bytes());
        region[8..16].copy_from_slice(&0x0708090A0B0C0D0Eu64.to_le_bytes());

        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 16, readable: true, writable: false, initial: region.clone(),
            }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U16, U30Type::U32, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 4, value: U30Value::U32(4) },
                        U30Op::Const { dst: 5, value: U30Value::U32(8) },
                        U30Op::LoadU16 { dst: 1, region: 0, offset: 0 },
                        U30Op::LoadU32 { dst: 2, region: 0, offset: 4 },
                        U30Op::LoadU64 { dst: 3, region: 0, offset: 5 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("load multi");
        assert_eq!(out.results[0], U30Value::U16(0x0102));
        assert_eq!(out.results[1], U30Value::U32(0x03040506));
        assert_eq!(out.results[2], U30Value::U64(0x0708090A0B0C0D0E));
    }

    #[test]
    fn u30x_store_u16_u32_u64() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 16, readable: true, writable: true, initial: vec![0; 16],
            }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 4, value: U30Value::U32(4) },
                        U30Op::Const { dst: 5, value: U30Value::U32(8) },
                        U30Op::Const { dst: 1, value: U30Value::U16(0x0102) },
                        U30Op::StoreU16 { region: 0, offset: 0, src: 1 },
                        U30Op::Const { dst: 2, value: U30Value::U32(0x03040506) },
                        U30Op::StoreU32 { region: 0, offset: 4, src: 2 },
                        U30Op::Const { dst: 3, value: U30Value::U64(0x0708090A0B0C0D0E) },
                        U30Op::StoreU64 { region: 0, offset: 5, src: 3 },
                        U30Op::LoadU8 { dst: 6, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("store multi");
        assert_eq!(out.results, vec![U30Value::U8(0x02)]);
        let region = &out.regions[&0];
        assert_eq!(&region[0..2], &[0x02, 0x01]);
        assert_eq!(&region[4..8], &[0x06, 0x05, 0x04, 0x03]);
        assert_eq!(&region[8..16], &[0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07]);
    }

    #[test]
    fn u30x_store_u16_oob_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 2, readable: true, writable: true, initial: vec![0; 2],
            }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0x0102) },
                        U30Op::Const { dst: 4, value: U30Value::U32(1) },
                        U30Op::StoreU16 { region: 0, offset: 4, src: 0 },
                    ],
                    terminator: U30Terminator::Trap { code: 0 },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("should fail at offset+2 > size 2");
        assert!(err.to_string().contains("out of bounds"));
    }

    #[test]
    fn u30x_verify_multiple_functions_fails() {
        let module = U30Module {
            regions: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![],
                    entry_block: 0,
                },
            ],
            entry_function: 1,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("empty blocks should fail verification");
        assert!(err.to_string().contains("invalid entry block") || err.to_string().contains("redefine"));
    }

    #[test]
    fn u30x_verify_duplicate_region_fails() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 4, readable: true, writable: true, initial: vec![] },
                U30RegionDecl { id: 0, size: 8, readable: true, writable: true, initial: vec![] },
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
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("duplicate region id");
        assert!(err.to_string().contains("duplicate region"));
    }

    #[test]
    fn u30x_binary_shl_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::Const { dst: 1, value: U30Value::U32(4) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::ShlU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("shl u32");
        assert_eq!(out.results, vec![U30Value::U32(16)]);
    }

    #[test]
    fn u30x_binary_div_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) },
                        U30Op::Const { dst: 1, value: U30Value::U64(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::DivU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("div u64");
        assert_eq!(out.results, vec![U30Value::U64(14)]); // 100 / 7 = 14
    }

    #[test]
    fn u30x_binary_div_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::DivU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("div u32");
        assert_eq!(out.results, vec![U30Value::U32(14)]); // 100 / 7 = 14
    }

    #[test]
    fn u30x_binary_rem_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) },
                        U30Op::Const { dst: 1, value: U30Value::U64(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::RemU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("rem u64");
        assert_eq!(out.results, vec![U30Value::U64(2)]); // 100 % 7 = 2
    }

    #[test]
    fn u30x_binary_rem_u32() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(7) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::RemU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("rem u32");
        assert_eq!(out.results, vec![U30Value::U32(2)]); // 100 % 7 = 2
    }

    #[test]
    fn u30x_binary_gt_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(5) },
                        U30Op::Const { dst: 1, value: U30Value::U64(3) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::GtU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("gt");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_binary_ge_u64() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(3) },
                        U30Op::Const { dst: 1, value: U30Value::U64(3) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::GeU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("ge");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_select_works() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::Bool],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(10) },
                        U30Op::Const { dst: 2, value: U30Value::U64(20) },
                        U30Op::Select { dst: 3, cond: 0, a: 1, b: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::Bool(true)])
            .expect("select true");
        assert_eq!(out.results, vec![U30Value::U64(10)]);

        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::Bool(false)])
            .expect("select false");
        assert_eq!(out.results, vec![U30Value::U64(20)]);
    }

    #[test]
    fn u30x_div_by_zero_fails() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) },
                        U30Op::Const { dst: 1, value: U30Value::U64(0) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::DivU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("div by zero must fail");
        assert!(err.to_string().contains("div by zero"));
    }

    #[test]
    fn u30x_i2f_works() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::I2F { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U32(42)])
            .expect("i2f");
        assert_eq!(out.results, vec![U30Value::F32(42.0)]);
    }

    #[test]
    fn u30x_f2i_works() {
        let module = U30Module {
            regions: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F2I { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(99.9)])
            .expect("f2i");
        assert_eq!(out.results, vec![U30Value::U64(99)]);
    }
}
