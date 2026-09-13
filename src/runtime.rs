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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
        Ok(())
    }

    fn binary(&self, op: U30BinaryOp, a: U30Value, b: U30Value) -> Result<U30Value> {
        let value = match op {
            U30BinaryOp::AddWrapU64 => U30Value::U64(a.as_u64()?.wrapping_add(b.as_u64()?)),
            U30BinaryOp::AddWrapU32 => U30Value::U32(a.as_u32()?.wrapping_add(b.as_u32()?)),
            U30BinaryOp::AndU8 => U30Value::U8(a.as_u8()? & b.as_u8()?),
            U30BinaryOp::OrU8 => U30Value::U8(a.as_u8()? | b.as_u8()?),
            U30BinaryOp::Eq => {
                if a.value_type() != b.value_type() {
                    return Err(Error::Generic("U30X eq type mismatch".into()));
                }
                U30Value::Bool(a == b)
            }
            U30BinaryOp::LtU64 => U30Value::Bool(a.as_u64()? < b.as_u64()?),
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
}
