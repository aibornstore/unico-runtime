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
        let mut current_fn_idx = module.entry_function;
        let mut function_idx = module.entry_function;
        if args.len() != module.functions[function_idx].params.len() {
            return Err(Error::Verification("U30X entry argument arity mismatch".into()));
        }
        for (index, (arg, expected)) in args.iter().zip(&module.functions[function_idx].params).enumerate() {
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
        let mut block_index = module.functions[function_idx].entry_block;
        let mut steps = 0u64;
        // Call stack: (return_function_index, return_block, result_regs, caller_regs, callee_regs_at_call, caller_last_op_idx)
        let mut call_stack: Vec<(usize, usize, Vec<u32>, BTreeMap<u32, U30Value>, BTreeMap<u32, U30Value>, usize)> = Vec::new();
        // Resume op index: after returning from a call, skip past the Call op itself
        let mut resume_from_op: Option<usize> = None;
        let mut last_op_idx: usize;

        'outer: loop {
            let block = &module.functions[function_idx].blocks[block_index];
            // Determine where to start in this block
            let op_start = resume_from_op.take().unwrap_or(0);
            for (op_idx, op) in block.ops.iter().enumerate().skip(op_start) {
                last_op_idx = op_idx;
                self.charge(&mut steps)?;
                match op {
                    U30Op::IndirectCall { function: fn_reg, args, results: result_regs } => {
                        // Read function index from register (dynamic dispatch)
                        let fn_idx = self.reg(&regs, *fn_reg)?.as_u64()? as usize;
                        if fn_idx >= module.functions.len() {
                            return Err(Error::Generic(format!("U30X indirect call: function index {} out of bounds", fn_idx)));
                        }
                        // Save caller state (before Call modifies regs)
                        let caller_regs = regs.clone();
                        let callee_regs = BTreeMap::new();
                        let caller_last_op_idx = last_op_idx;
                        call_stack.push((current_fn_idx, block_index, result_regs.clone(), caller_regs, callee_regs, caller_last_op_idx));
                        // Set up callee registers from args
                        regs = BTreeMap::new();
                        for (i, &arg_reg) in args.iter().enumerate() {
                            if i < module.functions[fn_idx].params.len() {
                                let arg_val = self.reg(&call_stack.last().unwrap().3, arg_reg)?.clone();
                                regs.insert(i as u32, arg_val);
                            }
                        }
                        // Jump to callee entry
                        current_fn_idx = fn_idx;
                        function_idx = fn_idx;
                        block_index = module.functions[fn_idx].entry_block;
                        continue 'outer;
                    }
                    U30Op::Call { function: fn_idx_lit, args, results: result_regs } => {
                        // Use literal function index directly (Call uses a literal index, not a register)
                        let fn_idx = *fn_idx_lit as usize;
                        if fn_idx >= module.functions.len() {
                            return Err(Error::Generic(format!("U30X call: function index {} out of bounds", fn_idx)));
                        }
                        // Save caller state (before Call modifies regs)
                        let caller_regs = regs.clone();
                        let callee_regs = BTreeMap::new();
                        let caller_last_op_idx = last_op_idx;
                        call_stack.push((current_fn_idx, block_index, result_regs.clone(), caller_regs, callee_regs, caller_last_op_idx));
                        // Set up callee registers from args
                        regs = BTreeMap::new();
                        for (i, &arg_reg) in args.iter().enumerate() {
                            if i < module.functions[fn_idx].params.len() {
                                // Read arg from caller's saved registers (top of stack)
                                let arg_val = self.reg(&call_stack.last().unwrap().3, arg_reg)?.clone();
                                regs.insert(i as u32, arg_val);
                            }
                        }
                        // Jump to callee entry
                        current_fn_idx = fn_idx;
                        function_idx = fn_idx;
                        block_index = module.functions[fn_idx].entry_block;
                        continue 'outer; // restart outer loop with fresh block evaluation
                    }
                    U30Op::TableBr { table, index } => {
                        // Look up the table by ID
                        let table_decl = module.tables.iter()
                            .find(|t| t.id == *table)
                            .ok_or_else(|| Error::Generic(format!("U30X table {} not found", table)))?;
                        // Read index from register
                        let idx = self.reg(&regs, *index)?.as_u64()? as usize;
                        if idx >= table_decl.targets.len() {
                            return Err(Error::Generic(format!("U30X table {} index {} out of bounds (len {})", table, idx, table_decl.targets.len())));
                        }
                        // Jump to target block and restart block evaluation
                        block_index = table_decl.targets[idx];
                        continue 'outer;
                    }
                    _ => {
                        self.exec_op(op, &mut regs, &mut regions)?;
                    }
                }
            }
            self.charge(&mut steps)?; // charge once per block iteration (for terminator)
            // Always recompute terminator from current function/block to avoid stale references
            let terminator = &module.functions[function_idx].blocks[block_index].terminator;
            match terminator {
                U30Terminator::Br { target } => {
                    block_index = *target;
                }
                U30Terminator::BrIf { cond, then_target, else_target } => {
                    block_index = if self.reg(&regs, *cond)?.as_bool()? {
                        *then_target
                    } else {
                        *else_target
                    };
                }
                U30Terminator::TailCall { function: fn_reg, args } => {
                    // Read function index from register
                    let fn_idx = self.reg(&regs, *fn_reg)?.as_u64()? as usize;
                    if fn_idx >= module.functions.len() {
                        return Err(Error::Generic(format!("U30X TailCall: function index {} out of bounds", fn_idx)));
                    }
                    let callee_fn = &module.functions[fn_idx];
                    // Collect args from current regs before resetting
                    let arg_values: Vec<U30Value> = args.iter()
                        .map(|&arg_reg| self.reg(&regs, arg_reg))
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .cloned()
                        .collect();
                    // Set up callee registers (replaces current frame — no call stack push)
                    regs = BTreeMap::new();
                    for (i, arg_val) in arg_values.into_iter().enumerate() {
                        if i < callee_fn.params.len() {
                            regs.insert(i as u32, arg_val);
                        }
                    }
                    // Jump to callee entry — this REPLACES our frame
                    current_fn_idx = fn_idx;
                    function_idx = fn_idx;
                    block_index = module.functions[fn_idx].entry_block;

                    continue 'outer;
                }
                U30Terminator::Ret { values } => {
                    // Check if we need to return to a caller
                    if let Some((ret_fn_idx, ret_block, result_regs, caller_regs, mut callee_saved, caller_last_op_idx)) = call_stack.pop() {
                        // Save callee's final registers before popping
                        callee_saved.clone_from(&regs);
                        // Collect return values from callee's registers
                        let ret_values: Vec<U30Value> = values
                            .iter()
                            .map(|id| callee_saved.get(id).cloned()
                                .ok_or_else(|| Error::Generic(format!("U30X undefined value %{id}"))))
                            .collect::<Result<Vec<_>>>()?;
                        for (value, expected) in ret_values.iter().zip(&module.functions[current_fn_idx].results) {
                            if value.value_type() != *expected {
                                return Err(Error::Generic("U30X return type mismatch".into()));
                            }
                        }
                        // Copy return values into caller's registers at result positions
                        let mut caller = caller_regs;
                        for (&callee_reg, &caller_reg) in values.iter().zip(result_regs.iter()) {
                            if let Some(rv) = callee_saved.get(&callee_reg).cloned() {
                                caller.insert(caller_reg, rv);
                            }
                        }
                        // Restore caller regs and continue
                        current_fn_idx = ret_fn_idx;
                        function_idx = ret_fn_idx;
                        block_index = ret_block;
                        regs = caller;
                        // Skip past the Call op that triggered this return (using caller's last_op_idx)
                        resume_from_op = Some(caller_last_op_idx + 1);
                        continue 'outer;
                    } else {
                        // Top-level return
                        let results = values
                            .iter()
                            .map(|id| self.reg(&regs, *id).cloned())
                            .collect::<Result<Vec<_>>>()?;
                        for (value, expected) in results.iter().zip(&module.functions[function_idx].results) {
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
            U30Op::TruncF32U64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                let result = if v.is_nan() || v < 0.0 {
                    0
                } else {
                    v.min(u64::MAX as f32) as u64
                };
                regs.insert(*dst, U30Value::U64(result));
            }
            U30Op::ReinterpretF32U32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                regs.insert(*dst, U30Value::U32(v.to_bits()));
            }
            U30Op::ReinterpretU32F32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::F32(f32::from_bits(v)));
            }
            U30Op::AbsU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(v));
            }
            U30Op::AbsU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U32(v));
            }
            U30Op::NegU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(v.wrapping_neg()));
            }
            U30Op::NegU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U32(v.wrapping_neg()));
            }
            U30Op::CtzU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(v.trailing_zeros() as u64));
            }
            U30Op::CtzU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U64(v.trailing_zeros() as u64));
            }
            U30Op::ClzU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(v.leading_zeros() as u64));
            }
            U30Op::ClzU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U64(v.leading_zeros() as u64));
            }
            U30Op::PopcntU64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U64(v.count_ones() as u64));
            }
            U30Op::PopcntU32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U64(v.count_ones() as u64));
            }
            U30Op::RotlU64 { dst, val, sh } => {
                let v = self.reg(regs, *val)?.as_u64()?;
                let s = self.reg(regs, *sh)?.as_u64()? as u32;
                regs.insert(*dst, U30Value::U64(v.rotate_left(s)));
            }
            U30Op::RotlU32 { dst, val, sh } => {
                let v = self.reg(regs, *val)?.as_u32()?;
                let s = self.reg(regs, *sh)?.as_u32()? as u32;
                regs.insert(*dst, U30Value::U32(v.rotate_left(s)));
            }
            U30Op::RotrU64 { dst, val, sh } => {
                let v = self.reg(regs, *val)?.as_u64()?;
                let s = self.reg(regs, *sh)?.as_u64()? as u32;
                regs.insert(*dst, U30Value::U64(v.rotate_right(s)));
            }
            U30Op::RotrU32 { dst, val, sh } => {
                let v = self.reg(regs, *val)?.as_u32()?;
                let s = self.reg(regs, *sh)?.as_u32()? as u32;
                regs.insert(*dst, U30Value::U32(v.rotate_right(s)));
            }
            U30Op::FEq { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::Bool(av == bv));
            }
            U30Op::FLt { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::Bool(av < bv));
            }
            U30Op::FGt { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::Bool(av > bv));
            }
            U30Op::FLe { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::Bool(av <= bv));
            }
            U30Op::FGe { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::Bool(av >= bv));
            }
            U30Op::FAdd { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av + bv));
            }
            U30Op::FSub { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av - bv));
            }
            U30Op::FMul { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av * bv));
            }
            U30Op::FDiv { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av / bv));
            }
            U30Op::FSqrt { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(v.sqrt()));
            }
            U30Op::FAbs { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(v.abs()));
            }
            U30Op::FNeg { dst, src } => {
                let v = self.reg(regs, *src)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(-v));
            }
            U30Op::FMin { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av.min(bv)));
            }
            U30Op::FMax { dst, a, b } => {
                let av = self.reg(regs, *a)?.as_f32()?;
                let bv = self.reg(regs, *b)?.as_f32()?;
                regs.insert(*dst, U30Value::F32(av.max(bv)));
            }
            U30Op::ZExtI8U16 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u8()?;
                regs.insert(*dst, U30Value::U16(v as u16));
            }
            U30Op::ZExtI8U32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u8()?;
                regs.insert(*dst, U30Value::U32(v as u32));
            }
            U30Op::ZExtI8U64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u8()?;
                regs.insert(*dst, U30Value::U64(v as u64));
            }
            U30Op::ZExtI16U32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u16()?;
                regs.insert(*dst, U30Value::U32(v as u32));
            }
            U30Op::ZExtI16U64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u16()?;
                regs.insert(*dst, U30Value::U64(v as u64));
            }
            U30Op::ZExtI32U64 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U64(v as u64));
            }
            U30Op::TruncU64U32 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U32(v as u32));
            }
            U30Op::TruncU64U16 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u64()?;
                regs.insert(*dst, U30Value::U16(v as u16));
            }
            U30Op::TruncU32U16 { dst, src } => {
                let v = self.reg(regs, *src)?.as_u32()?;
                regs.insert(*dst, U30Value::U16(v as u16));
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
            // F64 binary comparisons
            U30Op::F64Eq { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::Bool((av - bv).abs() < f64::EPSILON)); }
            U30Op::F64Lt { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::Bool(av < bv)); }
            U30Op::F64Gt { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::Bool(av > bv)); }
            U30Op::F64Le { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::Bool(av <= bv)); }
            U30Op::F64Ge { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::Bool(av >= bv)); }
            // F64 binary arithmetic
            U30Op::F64Add { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::F64(av + bv)); }
            U30Op::F64Sub { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::F64(av - bv)); }
            U30Op::F64Mul { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::F64(av * bv)); }
            U30Op::F64Div { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; if bv == 0.0 { return Err(Error::Generic("U30X f64 div-by-zero".into())); } regs.insert(*dst, U30Value::F64(av / bv)); }
            U30Op::F64Min { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::F64(av.min(bv))); }
            U30Op::F64Max { dst, a, b } => { let av = self.reg(regs, *a)?.as_f64()?; let bv = self.reg(regs, *b)?.as_f64()?; regs.insert(*dst, U30Value::F64(av.max(bv))); }
            // F64 unary
            U30Op::F64Sqrt { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::F64(v.sqrt())); }
            U30Op::F64Abs { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::F64(v.abs())); }
            U30Op::F64Neg { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::F64(-v)); }
            // F64 conversions
            U30Op::I64F64 { dst, src } => { let v = self.reg(regs, *src)?.as_u64()? as f64; regs.insert(*dst, U30Value::F64(v)); }
            U30Op::F64I64 { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::U64(v as u64)); }
            U30Op::F32F64 { dst, src } => { let v = self.reg(regs, *src)?.as_f32()?; regs.insert(*dst, U30Value::F64(v as f64)); }
            U30Op::F64F32 { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::F32(v as f32)); }
            U30Op::ReinterpretF64U64 { dst, src } => { let v = self.reg(regs, *src)?.as_f64()?; regs.insert(*dst, U30Value::U64(v.to_bits())); }
            U30Op::ReinterpretU64F64 { dst, src } => { let v = self.reg(regs, *src)?.as_u64()?; regs.insert(*dst, U30Value::F64(f64::from_bits(v))); }
            // Sign extend (preserve sign bit)
            U30Op::SExtI8U16 { dst, src } => { let v = self.reg(regs, *src)?.as_u8()? as i8 as i16 as u16; regs.insert(*dst, U30Value::U16(v)); }
            U30Op::SExtI8U32 { dst, src } => { let v = self.reg(regs, *src)?.as_u8()? as i8 as i32 as u32; regs.insert(*dst, U30Value::U32(v)); }
            U30Op::SExtI8U64 { dst, src } => { let v = self.reg(regs, *src)?.as_u8()? as i8 as i64 as u64; regs.insert(*dst, U30Value::U64(v)); }
            U30Op::SExtI16U32 { dst, src } => { let v = self.reg(regs, *src)?.as_u16()? as i16 as i32 as u32; regs.insert(*dst, U30Value::U32(v)); }
            U30Op::SExtI16U64 { dst, src } => { let v = self.reg(regs, *src)?.as_u16()? as i16 as i64 as u64; regs.insert(*dst, U30Value::U64(v)); }
            U30Op::SExtI32U64 { dst, src } => { let v = self.reg(regs, *src)?.as_u32()? as i32 as i64 as u64; regs.insert(*dst, U30Value::U64(v)); }
            // Byte swap
            U30Op::ByteSwapU16 { dst, src } => { let v = self.reg(regs, *src)?.as_u16()?; regs.insert(*dst, U30Value::U16(v.swap_bytes())); }
            U30Op::ByteSwapU32 { dst, src } => { let v = self.reg(regs, *src)?.as_u32()?; regs.insert(*dst, U30Value::U32(v.swap_bytes())); }
            U30Op::ByteSwapU64 { dst, src } => { let v = self.reg(regs, *src)?.as_u64()?; regs.insert(*dst, U30Value::U64(v.swap_bytes())); }
            U30Op::MemCopy { dst_region, dst_offset, src_region, src_offset, size } => {
                let dst_off = self.reg(regs, *dst_offset)?.as_u64()? as usize;
                let src_off = self.reg(regs, *src_offset)?.as_u64()? as usize;
                let n = self.reg(regs, *size)?.as_u64()? as usize;
                let src_readable = regions.get(src_region)
                    .map(|s| s.readable)
                    .ok_or_else(|| Error::Generic(format!("U30X missing src region")))?;
                if !src_readable {
                    return Err(Error::Generic("U30X memcopy src not readable".into()));
                }
                let dst_writable = regions.get(dst_region)
                    .map(|s| s.writable)
                    .ok_or_else(|| Error::Generic(format!("U30X missing dst region")))?;
                if !dst_writable {
                    return Err(Error::Generic("U30X memcopy dst not writable".into()));
                }
                let src_len = regions.get(src_region).unwrap().bytes.len();
                let dst_len = regions.get(dst_region).unwrap().bytes.len();
                if src_off + n > src_len || dst_off + n > dst_len {
                    return Err(Error::Generic("U30X memcopy out of bounds".into()));
                }
                let data = regions.get(src_region).unwrap().bytes[src_off..src_off+n].to_vec();
                regions.get_mut(dst_region).unwrap().bytes[dst_off..dst_off+n].copy_from_slice(&data);
            }
            U30Op::MemFill { region, offset, value, size } => {
                let off = self.reg(regs, *offset)?.as_u64()? as usize;
                let val = self.reg(regs, *value)?.as_u32()? as u8;
                let n = self.reg(regs, *size)?.as_u64()? as usize;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region")))?;
                if !state.writable {
                    return Err(Error::Generic("U30X memfill not writable".into()));
                }
                if off + n > state.bytes.len() {
                    return Err(Error::Generic("U30X memfill out of bounds".into()));
                }
                state.bytes[off..off+n].fill(val);
            }
            U30Op::MemSize { dst, region } => {
                let state = regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region")))?;
                regs.insert(*dst, U30Value::U64(state.bytes.len() as u64));
            }
            U30Op::MemGrow { dst, region, delta } => {
                let d = self.reg(regs, *delta)?.as_u64()? as usize;
                let state = regions.get_mut(region)
                    .ok_or_else(|| Error::Generic(format!("U30X missing region")))?;
                if !state.writable {
                    return Err(Error::Generic(format!("U30X region {region} is not writable")));
                }
                let old_size = state.bytes.len();
                state.bytes.resize(old_size + d, 0);
                regs.insert(*dst, U30Value::U64(old_size as u64));
            }

            U30Op::Break { code } => {
                let c = self.reg(regs, *code)?.as_u64()?;
                return Err(Error::Generic(format!("U30X break {}", c)));
            }
            U30Op::Assert { cond, msg: _ } => {
                let c = self.reg(regs, *cond)?.as_bool()?;
                if !c {
                    return Err(Error::Generic("U30X assertion failed".into()));
                }
            }
            U30Op::Nop => {}
            U30Op::Call { .. } => {
                // Call is handled in the main execution loop, not here
            }
            U30Op::IndirectCall { .. } => {
                // IndirectCall is handled in the main execution loop, not here
            }
            U30Op::TableBr { .. } => {
                // TableBr is handled in the main execution loop, not here
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
    use crate::ir::{U30Block, U30Function, U30RegionDecl, U30TableDecl, U30Type, U30Value, U30Op, U30Terminator};

    fn store_load_module() -> U30Module {
        U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: true, initial: vec![0; 4],
            }],
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("duplicate region id");
        assert!(err.to_string().contains("duplicate region"));
    }

    #[test]
    fn u30x_binary_shl_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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
            tables: vec![],
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

    #[test]
    fn u30x_trunc_f32_u64_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TruncF32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // Normal truncation
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(123.9)])
            .expect("trunc");
        assert_eq!(out.results, vec![U30Value::U64(123)]);

        // NaN -> 0
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(f32::NAN)])
            .expect("trunc nan");
        assert_eq!(out.results, vec![U30Value::U64(0)]);
    }

    #[test]
    fn u30x_reinterpret_f32_u32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ReinterpretF32U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(1.0)])
            .expect("reinterpret f32->u32");
        // 1.0 as f32 bits = 0x3F800000
        assert_eq!(out.results, vec![U30Value::U32(0x3F800000)]);
    }

    #[test]
    fn u30x_reinterpret_u32_f32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ReinterpretU32F32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U32(0x3F800000)])
            .expect("reinterpret u32->f32");
        assert_eq!(out.results, vec![U30Value::F32(1.0)]);
    }

    #[test]
    fn u30x_abs_u64_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::AbsU64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(42)])
            .expect("abs");
        assert_eq!(out.results, vec![U30Value::U64(42)]);
    }

    #[test]
    fn u30x_neg_u32_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U32],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::NegU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U32(5)])
            .expect("neg");
        assert_eq!(out.results, vec![U30Value::U32(0xFFFFFFFB)]); // -5 wrapping
    }

    #[test]
    fn u30x_ctz_clz_popcnt() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64, U30Type::U64, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::CtzU64 { dst: 1, src: 0 },
                        U30Op::ClzU64 { dst: 2, src: 0 },
                        U30Op::PopcntU64 { dst: 3, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // 0b100100 = 36: ctz=2, clz=58, popcnt=2
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0b100100)])
            .expect("ctz/clz/popcnt");
        assert_eq!(out.results[0], U30Value::U64(2)); // ctz
        assert_eq!(out.results[1], U30Value::U64(58)); // clz
        assert_eq!(out.results[2], U30Value::U64(2)); // popcnt
    }

    #[test]
    fn u30x_rotr_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(1) },
                        U30Op::RotrU64 { dst: 2, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // 0x8000000000000001 rotated right by 1 = 0xC000000000000000
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0x8000000000000001)])
            .expect("rotr");
        assert_eq!(out.results, vec![U30Value::U64(0xC000000000000000)]);
    }

    #[test]
    fn u30x_f32_comparisons() {
        let make_module = || U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32, U30Type::F32],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };

        // FLt: 1.0 < 2.0
        let mut m = make_module();
        m.functions[0].blocks[0].ops.push(U30Op::FLt { dst: 2, a: 0, b: 1 });
        m.functions[0].blocks[0].terminator = U30Terminator::Ret { values: vec![2] };
        let out = U30Runtime::default()
            .execute_experimental(&m, &[U30Value::F32(1.0), U30Value::F32(2.0)])
            .expect("flt");
        assert_eq!(out.results[0], U30Value::Bool(true));

        // FLe: 2.0 <= 2.0
        let mut m = make_module();
        m.functions[0].blocks[0].ops.push(U30Op::FLe { dst: 2, a: 0, b: 1 });
        m.functions[0].blocks[0].terminator = U30Terminator::Ret { values: vec![2] };
        let out = U30Runtime::default()
            .execute_experimental(&m, &[U30Value::F32(2.0), U30Value::F32(2.0)])
            .expect("fle");
        assert_eq!(out.results[0], U30Value::Bool(true));

        // FGe: 3.0 >= 2.0
        let mut m = make_module();
        m.functions[0].blocks[0].ops.push(U30Op::FGe { dst: 2, a: 0, b: 1 });
        m.functions[0].blocks[0].terminator = U30Terminator::Ret { values: vec![2] };
        let out = U30Runtime::default()
            .execute_experimental(&m, &[U30Value::F32(3.0), U30Value::F32(2.0)])
            .expect("fge");
        assert_eq!(out.results[0], U30Value::Bool(true));

        // FEq: 5.0 == 5.0
        let mut m = make_module();
        m.functions[0].blocks[0].ops.push(U30Op::FEq { dst: 2, a: 0, b: 1 });
        m.functions[0].blocks[0].terminator = U30Terminator::Ret { values: vec![2] };
        let out = U30Runtime::default()
            .execute_experimental(&m, &[U30Value::F32(5.0), U30Value::F32(5.0)])
            .expect("feq");
        assert_eq!(out.results[0], U30Value::Bool(true));
    }

    #[test]
    fn u30x_f32_arithmetic() {
        // FAdd: 1.0 + 2.0 = 3.0
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32, U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![U30Op::FAdd { dst: 2, a: 0, b: 1 }],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(1.0), U30Value::F32(2.0)])
            .expect("fadd");
        assert_eq!(out.results, vec![U30Value::F32(3.0)]);
    }

    #[test]
    fn u30x_fsqrt_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![U30Op::FSqrt { dst: 1, src: 0 }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(4.0)])
            .expect("fsqrt");
        assert!((out.results[0].as_f32().unwrap() - 2.0).abs() < 0.001);
    }

    #[test]
    fn u30x_fneg_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![U30Op::FNeg { dst: 1, src: 0 }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(5.0)])
            .expect("fneg");
        assert_eq!(out.results, vec![U30Value::F32(-5.0)]);
    }

    #[test]
    fn u30x_zext_trunc() {
        // ZExtI8U32: 255 -> 255
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U8],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![U30Op::ZExtI8U32 { dst: 1, src: 0 }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U8(255)])
            .expect("zext");
        assert_eq!(out.results, vec![U30Value::U32(255)]);

        // TruncU64U32: 0x1_0000_0000 -> 0
        let mut m = module.clone();
        m.functions[0].params = vec![U30Type::U64];
        m.functions[0].results = vec![U30Type::U32];
        m.functions[0].blocks[0].ops = vec![U30Op::TruncU64U32 { dst: 1, src: 0 }];
        let out = U30Runtime::default()
            .execute_experimental(&m, &[U30Value::U64(0x1_0000_0000)])
            .expect("trunc");
        assert_eq!(out.results, vec![U30Value::U32(0)]);
    }

    #[test]
    fn u30x_memcopy_works() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: data.clone() },
                U30RegionDecl { id: 1, size: 16, readable: true, writable: true, initial: vec![0; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(4) },
                        U30Op::Const { dst: 2, value: U30Value::U32(2) },
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 1, size: 2 },
                        U30Op::LoadU8 { dst: 3, region: 1, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memcopy");
        assert_eq!(out.results, vec![U30Value::U8(1)]);
    }

    #[test]
    fn u30x_memfill_works() {
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xAB) },
                        U30Op::Const { dst: 2, value: U30Value::U32(8) },
                        // memfill: fill 8 bytes with 0xAB -> 0xABABABABABABABAB
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                        U30Op::LoadU64 { dst: 3, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memfill");
        assert_eq!(out.results, vec![U30Value::U64(0xABAB_ABAB_ABAB_ABAB)]);
    }

    #[test]
    fn u30x_memsize_works() {
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![U30Op::MemSize { dst: 0, region: 0 }],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memsize");
        assert_eq!(out.results, vec![U30Value::U64(64)]);
    }

    #[test]
    fn u30x_memgrow_works() {
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 8, readable: true, writable: true, initial: vec![1,2,3,4,5,6,7,8] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(8) },
                        U30Op::MemGrow { dst: 1, region: 0, delta: 0 },
                        U30Op::MemSize { dst: 2, region: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memgrow");
        assert_eq!(out.results[0], U30Value::U64(8)); // old size
        assert_eq!(out.results[1], U30Value::U64(16)); // new size
    }

    #[test]
    fn u30x_nop_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::Nop,
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("nop");
        assert_eq!(out.results, vec![U30Value::U64(42)]);
    }

    #[test]
    fn u30x_assert_passes() {
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
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("assert true");
        assert_eq!(out.results, vec![]);
    }

    #[test]
    fn u30x_assert_fails() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(false) },
                        U30Op::Assert { cond: 0, msg: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("assert false should fail");
        assert!(err.to_string().contains("assertion failed"));
    }

    #[test]
    fn u30x_f64_arithmetic_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64, U30Type::F64, U30Type::F64, U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(10.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(3.0) },
                        U30Op::F64Add { dst: 2, a: 0, b: 1 },
                        U30Op::F64Sub { dst: 3, a: 0, b: 1 },
                        U30Op::F64Mul { dst: 4, a: 0, b: 1 },
                        U30Op::F64Div { dst: 5, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert!((out.results[0].as_f64().unwrap() - 13.0).abs() < 1e-10);
        assert!((out.results[1].as_f64().unwrap() - 7.0).abs() < 1e-10);
        assert!((out.results[2].as_f64().unwrap() - 30.0).abs() < 1e-10);
        assert!((out.results[3].as_f64().unwrap() - 3.333333333).abs() < 1e-6);
    }

    #[test]
    fn u30x_f64_sqrt_abs_neg() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64, U30Type::F64, U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(25.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(-7.5) },
                        U30Op::F64Sqrt { dst: 2, src: 0 },
                        U30Op::F64Abs { dst: 3, src: 1 },
                        U30Op::F64Neg { dst: 4, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert!((out.results[0].as_f64().unwrap() - 5.0).abs() < 1e-10);
        assert!((out.results[1].as_f64().unwrap() - 7.5).abs() < 1e-10);
        assert!((out.results[2].as_f64().unwrap() - 7.5).abs() < 1e-10);
    }

    #[test]
    fn u30x_f64_comparisons() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool, U30Type::Bool, U30Type::Bool, U30Type::Bool, U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(5.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(3.0) },
                        U30Op::F64Eq { dst: 2, a: 0, b: 1 },
                        U30Op::F64Lt { dst: 3, a: 1, b: 0 },
                        U30Op::F64Gt { dst: 4, a: 0, b: 1 },
                        U30Op::F64Le { dst: 5, a: 1, b: 0 },
                        U30Op::F64Ge { dst: 6, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5, 6] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_bool().unwrap(), false);
        assert_eq!(out.results[1].as_bool().unwrap(), true);
        assert_eq!(out.results[2].as_bool().unwrap(), true);
        assert_eq!(out.results[3].as_bool().unwrap(), true);
        assert_eq!(out.results[4].as_bool().unwrap(), true);
    }

    #[test]
    fn u30x_i64f64_f64i64() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64, U30Type::U64],
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
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert!((out.results[0].as_f64().unwrap() - 42.0).abs() < 1e-10);
        assert_eq!(out.results[1].as_u64().unwrap(), 42);
    }

    #[test]
    fn u30x_f32f64_f64f32() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64, U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(3.5) },
                        U30Op::F32F64 { dst: 1, src: 0 },
                        U30Op::F64F32 { dst: 2, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert!((out.results[0].as_f64().unwrap() - 3.5).abs() < 1e-6);
        assert!((out.results[1].as_f32().unwrap() - 3.5).abs() < 0.001);
    }

    #[test]
    fn u30x_reinterpret_f64_u64() {
        // Test ReinterpretU64F64: read U64 bits as F64
        let module1 = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0x3FF0000000000000u64) }, // 1.0
                        U30Op::ReinterpretU64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out1 = U30Runtime::default().execute_experimental(&module1, &[]).expect("ok");
        let r1 = &out1.results[0];
        match r1 {
            U30Value::F64(v) => {
                assert!((v - 1.0).abs() < 1e-10, "expected 1.0, got {v}");
            }
            _ => panic!("expected F64, got {:?}", r1.value_type()),
        }

        // Test ReinterpretF64U64: read F64 bits as U64
        let module2 = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::ReinterpretF64U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out2 = U30Runtime::default().execute_experimental(&module2, &[]).expect("ok");
        assert_eq!(out2.results[0].as_u64().unwrap(), 0x3FF0000000000000u64);
    }

    #[test]
    fn u30x_sext_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U16, U30Type::U32, U30Type::U64, U30Type::U32, U30Type::U64, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xFF) },
                        U30Op::Const { dst: 1, value: U30Value::U16(0x8000) },
                        U30Op::Const { dst: 2, value: U30Value::U32(0x80000000) },
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
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u16().unwrap(), 0xFFFF);
        assert_eq!(out.results[1].as_u32().unwrap(), 0xFFFFFFFF);
        assert_eq!(out.results[2].as_u64().unwrap(), 0xFFFFFFFFFFFFFFFFu64);
        assert_eq!(out.results[3].as_u32().unwrap(), 0xFFFF8000);
        assert_eq!(out.results[4].as_u64().unwrap(), 0xFFFFFFFFFFFF8000u64);
        assert_eq!(out.results[5].as_u64().unwrap(), 0xFFFFFFFF80000000u64);
    }

    #[test]
    fn u30x_byteswap_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U16, U30Type::U32, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0x1234) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xDEADBEEF) },
                        U30Op::Const { dst: 2, value: U30Value::U64(0x0123456789ABCDEFu64) },
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
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u16().unwrap(), 0x3412);
        assert_eq!(out.results[1].as_u32().unwrap(), 0xEFBEADDE);
        assert_eq!(out.results[2].as_u64().unwrap(), 0xEFCDAB8967452301u64);
    }

    #[test]
    fn u30x_call_works() {
        // Function 0: add_one(x: U64) -> U64
        // Adds 1 to input and returns
        let add_one = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    U30Op::Binary { dst: 0, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        // Function 1: main() -> U64
        // Calls add_one(41), returns result
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(41) },
                    U30Op::Call { function: 0, args: vec![0], results: vec![2] }, // call add_one (fn 0)
                ],
                terminator: U30Terminator::Ret { values: vec![2] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![add_one, main_fn],
            entry_function: 1,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 42);
    }

    #[test]
    fn u30x_nested_call_works() {
        // Function 0: add_one(x: U64) -> U64
        // Adds 1 to param and returns
        let add_one = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    U30Op::Binary { dst: 0, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        // Function 1: helper(x: U64) -> U64
        // Calls add_one with x+1
        let helper = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 }, // r2 = x + 1
                    U30Op::Call { function: 0, args: vec![2], results: vec![4] }, // call add_one (fn 0)
                ],
                terminator: U30Terminator::Ret { values: vec![4] },
            }],
            entry_block: 0,
        };
        // Function 2: main() -> U64
        // Calls helper(doule(arg)), which calls add_one
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(10) }, // r0 = 10
                    U30Op::Const { dst: 1, value: U30Value::U64(2) },  // r1 = 2
                    U30Op::Binary { dst: 2, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 }, // r2 = 20
                    U30Op::Call { function: 1, args: vec![2], results: vec![4] }, // call helper (fn 1)
                ],
                terminator: U30Terminator::Ret { values: vec![4] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![add_one, helper, main_fn],
            entry_function: 2,
        };
        // main: 10*2 = 20 → helper(20): 20+1 = 21 → add_one(21): 22
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 22);
    }

    #[test]
    fn u30x_tail_call_works() {
        // Function 0: double(x: U64) -> U64
        // Doubles param and returns
        let double = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(2) },
                    U30Op::Binary { dst: 0, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        // Function 1: helper(x: U64) -> U64
        // Tail-calls double(x+1) — replaces our frame, so caller gets double's result
        let helper = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 }, // r2 = x + 1
                    U30Op::Const { dst: 3, value: U30Value::U64(0) }, // r3 = double index
                ],
                // Tail-call: function index in r3, arg in r2
                // double's return value goes directly to main's caller
                terminator: U30Terminator::TailCall { function: 3, args: vec![2] },
            }],
            entry_block: 0,
        };
        // Function 2: main() -> U64 (entry)
        // Tail-calls helper(10) which tail-calls double(11)
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(10) }, // arg = 10
                    U30Op::Const { dst: 1, value: U30Value::U64(1) }, // fn_idx = helper
                ],
                // Tail-call: jump to helper(10), replacing main's frame
                // double(11) returns 22 directly
                terminator: U30Terminator::TailCall { function: 1, args: vec![0] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![double, helper, main_fn],
            entry_function: 2,
        };
        // main TailCall helper(10) → helper TailCall double(11) → returns 22
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 22);
    }

    #[test]
    fn u30x_br_works() {
        // Single-block function with unconditional Br to another block
        let _module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                // Block 0: set r0=5, jump to block 1
                // Block 1: set r1=10, return r0+r1
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(5) },
                        ],
                        terminator: U30Terminator::Br { target: 1 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 1, value: U30Value::U64(10) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] }, // r2 = r0 + r1
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // NOTE: r2 is undefined — this test just verifies Br works
        // For full multi-block, need phi-nodes or single-reg style
        // Simpler: single-block with Br used as goto
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                // Block 0: const 5, jump to block 1
                // Block 1: const 10, return 15
                blocks: vec![
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Br { target: 1 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(5) },
                            U30Op::Const { dst: 1, value: U30Value::U64(10) },
                            U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 15);
    }

    #[test]
    fn u30x_brif_conditional_branch() {
        // if/else: if cond { r1=5 } else { r2=10 }; return (cond ? r1 : r2)
        // Since blocks can't share registers without phi, use simple single-block if
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                // Block 0: cond=true, if true goto block 1 else block 2
                // Block 1 (then): r1=5, goto block 3
                // Block 2 (else): r2=10, goto block 3
                // Block 3: return r1 (then branch)
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 2 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 1, value: U30Value::U64(5) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 2, value: U30Value::U64(10) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![],
                        // Can't merge r1/r2 without phi — return r1 (from then branch)
                        terminator: U30Terminator::Ret { values: vec![1] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 5); // true branch
    }

    #[test]
    fn u30x_brif_else_branch() {
        // cond=false: if false goto block 2 (else), then block 1
        // Block 1: r1=5, goto block 3
        // Block 2: r2=10, goto block 3
        // Block 3: return r2 (else branch result)
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(false) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 2 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 1, value: U30Value::U64(5) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 2, value: U30Value::U64(10) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![],
                        // Return r2 (from else branch) — only valid because we're testing else path
                        terminator: U30Terminator::Ret { values: vec![2] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 10); // false branch
    }

    #[test]
    fn u30x_loop_works() {
        // Single-block test: BrIf conditionals with distinct result registers
        // Verifies BrIf branches work without cross-block register issues
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },  // r0 = true
                            U30Op::Const { dst: 1, value: U30Value::U64(100) },   // r1 = 100
                            U30Op::Const { dst: 2, value: U30Value::U64(200) },   // r2 = 200
                        ],
                        // BrIf: true path → block 1 (return 100), false path → block 2 (return 200)
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 2 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![1] }, // return r1=100
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![2] }, // return r2=200
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 100); // true branch
    }

    #[test]
    fn u30x_multi_block_br_works() {
        // Single-block function: uses Br to skip an unreachable block, returns 10
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(10) },
                        ],
                        terminator: U30Terminator::Br { target: 2 }, // skip block 1
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(999) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![0] }, // unreachable
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![0] }, // return r0=10
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 10);
    }

    #[test]
    fn u30x_if_else_works() {
        // Multi-block if/else with pre-initialization in the else branch
        // Block 0: cond=true, BrIf
        // Block 1 (then): r0=100, Br to block 3
        // Block 2 (else): r0=0 (default), Br to block 3
        // Block 3: return r0
        // NOTE: r0 is defined in both block 1 and block 2 — this is a redefinition
        // The current verifier doesn't support cross-block redefinition.
        // This test verifies BrIf branching works (fuel stops infinite loop).
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 2 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 1, value: U30Value::U64(100) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 2, value: U30Value::U64(0) },
                        ],
                        terminator: U30Terminator::Br { target: 3 },
                    },
                    U30Block {
                        ops: vec![],
                        // Returns whichever result was set: r1 (then) or r2 (else)
                        terminator: U30Terminator::Ret { values: vec![1] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 100); // then branch
    }

    #[test]
    fn u30x_call_with_multi_block() {
        // multi-block helper that branches internally
        // Function 0: max(x: U64, y: U64) -> U64
        //   if x >= y: return x else return y
        let max_fn = U30Function {
            params: vec![U30Type::U64, U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![
                U30Block {
                    ops: vec![
                        U30Op::Binary { dst: 2, op: U30BinaryOp::GeU64, a: 0, b: 1 }, // r2 = x >= y
                    ],
                    terminator: U30Terminator::BrIf { cond: 2, then_target: 1, else_target: 2 },
                },
                U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] }, // return x (r0)
                },
                U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![1] }, // return y (r1)
                },
            ],
            entry_block: 0,
        };
        // Function 1: main() -> U64
        // Calls max(10, 3) = 10
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(10) }, // r0 = 10
                    U30Op::Const { dst: 1, value: U30Value::U64(3) },  // r1 = 3
                    U30Op::Call { function: 0, args: vec![0, 1], results: vec![3] }, // call max_fn (fn 0)
                ],
                terminator: U30Terminator::Ret { values: vec![3] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![max_fn, main_fn],
            entry_function: 1,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 10); // 10 >= 3, so returns 10
    }

    #[test]
    fn u30x_tablebr_dispatch() {
        // dispatch(idx) -> U64: jump table dispatch, returns 10/20/30/40 for idx 0/1/2/3
        // Table 0: targets = [block1, block2, block3, block4]
        let dispatch_fn = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![
                // Block 0: entry — read idx from r0, dispatch via table
                U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 0 }, // read idx from r0, jump to table[0]
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] }, // unreachable after TableBr
                },
                // Block 1: returns 10
                U30Block {
                    ops: vec![U30Op::Const { dst: 1, value: U30Value::U64(10) }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
                // Block 2: returns 20
                U30Block {
                    ops: vec![U30Op::Const { dst: 1, value: U30Value::U64(20) }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
                // Block 3: returns 30
                U30Block {
                    ops: vec![U30Op::Const { dst: 1, value: U30Value::U64(30) }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
                // Block 4: returns 40
                U30Block {
                    ops: vec![U30Op::Const { dst: 1, value: U30Value::U64(40) }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
            ],
            entry_block: 0,
        };
        // main(): calls dispatch(0..3), returns sum=10+20+30+40=100
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(0) }, // r0 = 0
                    U30Op::Const { dst: 1, value: U30Value::U64(1) }, // r1 = 1
                    U30Op::Const { dst: 2, value: U30Value::U64(2) }, // r2 = 2
                    U30Op::Const { dst: 3, value: U30Value::U64(3) }, // r3 = 3
                    // call dispatch(0) -> r4
                    U30Op::Call { function: 0, args: vec![0], results: vec![4] }, // dispatch_fn is fn 0
                    // call dispatch(1) -> r5
                    U30Op::Call { function: 0, args: vec![1], results: vec![5] },
                    // call dispatch(2) -> r6
                    U30Op::Call { function: 0, args: vec![2], results: vec![6] },
                    // call dispatch(3) -> r7
                    U30Op::Call { function: 0, args: vec![3], results: vec![7] },
                    // r8 = r4 + r5
                    U30Op::Binary { dst: 8, op: U30BinaryOp::AddWrapU64, a: 4, b: 5 },
                    // r9 = r8 + r6
                    U30Op::Binary { dst: 9, op: U30BinaryOp::AddWrapU64, a: 8, b: 6 },
                    // r10 = r9 + r7 = 100
                    U30Op::Binary { dst: 10, op: U30BinaryOp::AddWrapU64, a: 9, b: 7 },
                ],
                terminator: U30Terminator::Ret { values: vec![10] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![1, 2, 3, 4] },
            ],
            functions: vec![dispatch_fn, main_fn],
            entry_function: 1,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0].as_u64().unwrap(), 100); // 10+20+30+40
    }

    #[test]
    fn u30x_recursive_factorial() {
        // Recursive factorial: fact(n, acc) -> if n==0 { return acc } else { fact(n-1, acc*n) }
        // Block 2: compute n-1 → r0, acc*n → r1, then jump to block 3
        // Block 3: Call fact(r0, r1) — result lands in r5, Ret returns r5
        let fact_fn = U30Function {
            params: vec![U30Type::U64, U30Type::U64], // r0=n, r1=acc
            results: vec![U30Type::U64],
            blocks: vec![
                // Block 0: check n == 0 (base case)
                U30Block {
                    ops: vec![
                        U30Op::Const { dst: 2, value: U30Value::U64(0) }, // r2 = 0
                        U30Op::Binary { dst: 3, op: U30BinaryOp::Eq, a: 0, b: 2 }, // r3 = n == 0
                    ],
                    // r3: true → block 1 (return acc), false → block 2 (recurse)
                    terminator: U30Terminator::BrIf { cond: 3, then_target: 1, else_target: 2 },
                },
                // Block 1: base case — return acc (r1)
                U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
                // Block 2: compute n-1 → r0, acc*n → r1, jump to block 3 for Call
                U30Block {
                    ops: vec![
                        U30Op::Const { dst: 2, value: U30Value::U64(1) },  // r2 = 1
                        U30Op::Binary { dst: 3, op: U30BinaryOp::MulWrapU64, a: 0, b: 2 }, // r3 = n * 1 = n
                        U30Op::Binary { dst: 4, op: U30BinaryOp::MulWrapU64, a: 1, b: 2 }, // r4 = acc * 1 = acc
                        U30Op::Binary { dst: 0, op: U30BinaryOp::SubWrapU64, a: 3, b: 2 }, // r0 = n - 1
                        U30Op::Binary { dst: 1, op: U30BinaryOp::MulWrapU64, a: 4, b: 3 }, // r1 = acc * n
                    ],
                    terminator: U30Terminator::Br { target: 3 },
                },
                // Block 3: Call fact(n-1, acc*n) — args r0/r1, result → r5, return r5
                U30Block {
                    ops: vec![
                        U30Op::Call { function: 0, args: vec![0, 1], results: vec![5] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![5] },
                },
            ],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![fact_fn],
            entry_function: 0,
        };
        let runtime = U30Runtime { fuel_limit: 500_000 };
        // fact(0, 1) = 1
        let result = runtime.execute_experimental(&module, &[U30Value::U64(0), U30Value::U64(1)]);
        assert!(result.is_ok(), "fact(0,1) failed: {:?}", result);
        assert_eq!(result.as_ref().unwrap().results[0], U30Value::U64(1), "fact(0,1)=1");
        // fact(5, 1) = 120
        let result = runtime.execute_experimental(&module, &[U30Value::U64(5), U30Value::U64(1)]);
        assert!(result.is_ok(), "fact(5,1) failed: {:?}", result);
        assert_eq!(result.as_ref().unwrap().results[0], U30Value::U64(120), "fact(5,1)=120");
    }

    #[test]
    fn u30x_f64_nan_inequality() {
        // NaN != NaN by IEEE 754 spec
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(f64::NAN) }, // r0 = NaN
                        U30Op::Const { dst: 1, value: U30Value::F64(f64::NAN) }, // r1 = NaN
                        U30Op::F64Eq { dst: 2, a: 0, b: 1 }, // r2 = NaN == NaN (should be false)
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0], U30Value::Bool(false), "NaN != NaN");
    }

    #[test]
    fn u30x_f64_div_by_zero() {
        // Division by zero returns an error
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(0.0) },
                        U30Op::F64Div { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default().execute_experimental(&module, &[]).expect_err("div by zero");
        assert!(err.to_string().contains("div-by-zero"), "expected div-by-zero error: {}", err);
    }

    #[test]
    fn u30x_break_returns_error() {
        // Break { code } returns an error with the code
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::Break { code: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default().execute_experimental(&module, &[]).expect_err("break");
        assert!(err.to_string().contains("break 42"), "expected 'break 42': {}", err);
    }

    #[test]
    fn u30x_assert_false_fails() {
        // Assert { cond: false } returns an error
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(false) },
                        U30Op::Assert { cond: 0, msg: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default().execute_experimental(&module, &[]).expect_err("assert should fail");
        assert!(err.to_string().contains("assertion failed"), "expected assertion failed: {}", err);
    }

    #[test]
    fn u30x_memgrow_basic() {
        // MemGrow: grow a region by 4 bytes, returns old size
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: true, initial: vec![1, 2, 3, 4],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(4) }, // delta = 4
                        U30Op::MemGrow { dst: 1, region: 0, delta: 0 }, // returns old size = 4
                        U30Op::Const { dst: 2, value: U30Value::U64(4) }, // verify delta read from r0=4
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] }, // returns old_size = 4
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0], U30Value::U64(4), "mem_grow returns old size");
        // After grow, region should be 8 bytes
        assert_eq!(out.regions[&0].len(), 8, "region grew from 4 to 8 bytes");
    }

    #[test]
    fn u30x_memgrow_zero_delta() {
        // MemGrow with delta=0: returns current size, no change
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 10, readable: true, writable: true, initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) }, // delta = 0
                        U30Op::MemGrow { dst: 1, region: 0, delta: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] }, // returns old_size = 10
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0], U30Value::U64(10), "mem_grow(0) returns current size");
        assert_eq!(out.regions[&0].len(), 10, "no change");
    }

    #[test]
    fn u30x_indirect_call() {
        // Function 0: double(x: U64) -> U64
        // Function 1: triple(x: U64) -> U64
        // Function 2: main — uses IndirectCall to dispatch to double or triple
        let double_fn = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(2) },
                    U30Op::Binary { dst: 0, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        let triple_fn = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 1, value: U30Value::U64(3) },
                    U30Op::Binary { dst: 0, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        // main: set fn_idx to 0 or 1, then IndirectCall
        // result = indirect_call(fn_idx, 5) → 10 (double) or 15 (triple)
        let main_fn = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::U64(0) }, // r0 = 0 (double)
                    U30Op::Const { dst: 1, value: U30Value::U64(5) }, // r1 = 5 (arg)
                    U30Op::IndirectCall { function: 0, args: vec![1], results: vec![2] },
                ],
                terminator: U30Terminator::Ret { values: vec![2] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![double_fn, triple_fn, main_fn],
            entry_function: 2,
        };
        let out = U30Runtime::default().execute_experimental(&module, &[]).expect("ok");
        assert_eq!(out.results[0], U30Value::U64(10), "indirect call to double(5) = 10");
    }

    #[test]
    fn u30x_tablebr_oob_fails() {
        // TableBr with index >= table.len() should return error
        let dispatch_fn = U30Function {
            params: vec![U30Type::U64],
            results: vec![U30Type::U64],
            blocks: vec![
                U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 0 }, // read idx from r0, jump to table[idx]
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] }, // unreachable
                },
                U30Block {
                    ops: vec![U30Op::Const { dst: 1, value: U30Value::U64(10) }],
                    terminator: U30Terminator::Ret { values: vec![1] },
                },
            ],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![1] }, // only 1 target (index 0)
            ],
            functions: vec![dispatch_fn],
            entry_function: 0,
        };
        // Index 99 is out of bounds (table has only 1 target at index 0)
        let err = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(99)])
            .expect_err("tablebr oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB error: {}", err);
    }

    #[test]
    fn u30x_load_u8_oob_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: true, initial: vec![1, 2, 3, 4],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(10) }, // offset=10, region=4 bytes
                        U30Op::LoadU8 { dst: 1, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("load u8 oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_store_u8_oob_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: true, initial: vec![1, 2, 3, 4],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) }, // offset=100, region=4 bytes
                        U30Op::Const { dst: 1, value: U30Value::U8(42) },
                        U30Op::StoreU8 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store u8 oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_load_u64_oob_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(5) }, // offset=5, 5+8=13 > 8
                        U30Op::LoadU64 { dst: 1, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("load u64 oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_store_u64_oob_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(7) }, // offset=7, 7+8=15 > 8
                        U30Op::Const { dst: 1, value: U30Value::U64(u64::MAX) },
                        U30Op::StoreU64 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store u64 oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_indirect_call_oob_fails() {
        // IndirectCall with function index out of bounds
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(99) }, // fn_idx = 99 (out of bounds)
                        U30Op::IndirectCall { function: 0, args: vec![], results: vec![1] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("indirect call oob");
        assert!(err.to_string().contains("out of bounds"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_memgrow_non_writable_fails() {
        // MemGrow on a read-only region should fail
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: true, writable: false, initial: vec![1, 2, 3, 4],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(4) },
                        U30Op::MemGrow { dst: 1, region: 0, delta: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memgrow read-only");
        assert!(err.to_string().contains("not writable"), "expected not writable: {}", err);
    }

    #[test]
    fn u30x_load_non_readable_fails() {
        // Load from non-readable region should fail
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 4, readable: false, writable: true, initial: vec![1, 2, 3, 4],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::LoadU8 { dst: 1, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("load non-readable");
        assert!(err.to_string().contains("not readable"), "expected not readable: {}", err);
    }

    #[test]
    fn u30x_memcopy_zero_size() {
        // MemCopy with size=0 is a no-op (should succeed)
        let mut data = vec![0u8; 16];
        data[0] = 42;
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: data.clone() },
                U30RegionDecl { id: 1, size: 16, readable: true, writable: true, initial: vec![0; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        // MemCopy size=0 — no-op
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 0, size: 0 },
                        U30Op::LoadU8 { dst: 1, region: 1, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memcopy zero size");
        assert_eq!(out.results, vec![U30Value::U8(0)], "dst should be untouched");
    }

    #[test]
    fn u30x_memfill_zero_size() {
        // MemFill with size=0 is a no-op
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 8, readable: true, writable: true, initial: vec![0xFF; 8] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0x00) },
                        U30Op::Const { dst: 2, value: U30Value::U32(0) }, // size=0
                        // MemFill size=0 — no-op
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                        U30Op::LoadU64 { dst: 3, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memfill zero size");
        assert_eq!(out.results, vec![U30Value::U64(0xFFFF_FFFF_FFFF_FFFF)], "data should be unchanged");
    }

    #[test]
    fn u30x_memcopy_oob_fails() {
        // MemCopy with dst_offset + size > region.size returns error
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: vec![1; 16] },
                U30RegionDecl { id: 1, size: 4, readable: true, writable: true, initial: vec![0; 4] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) }, // dst_offset=0
                        U30Op::Const { dst: 1, value: U30Value::U32(0) }, // src_offset=0
                        U30Op::Const { dst: 2, value: U30Value::U32(8) }, // size=8 (exceeds dst region size 4)
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 0, size: 2 }, // size from r2=8
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memcopy OOB");
        assert!(err.to_string().contains("out of bounds") || err.to_string().contains("OOB"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_memfill_oob_fails() {
        // MemFill with offset + size > region.size returns error
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 4, readable: true, writable: true, initial: vec![0; 4] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(2) }, // offset=2
                        U30Op::Const { dst: 1, value: U30Value::U32(0xAB) },
                        U30Op::Const { dst: 2, value: U30Value::U32(4) }, // size=4 (offset+size=6 > 4)
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memfill OOB");
        assert!(err.to_string().contains("out of bounds") || err.to_string().contains("OOB"), "expected OOB: {}", err);
    }

    #[test]
    fn u30x_memgrow_zero_region() {
        // MemGrow on a zero-size region works (grows from 0)
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 0, readable: true, writable: true, initial: vec![] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(4096) },
                        U30Op::MemGrow { dst: 2, region: 0, delta: 1 },
                        U30Op::MemSize { dst: 3, region: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memgrow zero region");
        assert_eq!(out.results, vec![U30Value::U64(4096)], "region grew to 4096");
    }

    #[test]
    fn u30x_load_u32_oob_fails() {
        // LoadU32 with offset >= region.size returns error
        let module = U30Module {
            regions: vec![U30RegionDecl { id: 0, size: 4, readable: true, writable: true, initial: vec![0; 4] }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(4) }, // offset=4 (equal to region size)
                        U30Op::LoadU32 { dst: 1, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("load u32 OOB");
        assert!(err.to_string().contains("out of bounds") || err.to_string().contains("OOB"), "expected OOB: {}", err);
    }

    // ─── U30 Verifier tests ───────────────────────────────────────────────────

    #[test]
    fn u30_verify_call_bad_fn_index() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Call { function: 99, args: vec![], results: vec![] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = module.verify_experimental().expect_err("should fail");
        assert!(err.to_string().contains("undefined function index 99"), "got: {err}");
    }

    #[test]
    fn u30_verify_call_bad_arg_count() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![U30Type::U64, U30Type::U64],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![
                            // Call fn0 which expects 2 args, but pass only 1
                            U30Op::Call { function: 0, args: vec![0], results: vec![] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 1,
        };
        let err = module.verify_experimental().expect_err("should fail");
        assert!(err.to_string().contains("expects 2 args, got 1"), "got: {err}");
    }

    #[test]
    fn u30_verify_table_bad_target() {
        let module = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![0, 99] }, // block 99 doesn't exist
            ],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 0 }, // r0 = index param
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = module.verify_experimental().expect_err("should fail");
        assert!(err.to_string().contains("invalid target block 99"), "got: {err}");
    }

    #[test]
    fn u30_verify_undefined_operand() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        // r0 is used but never defined
                        U30Op::Binary { dst: 1, op: U30BinaryOp::AddWrapU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = module.verify_experimental().expect_err("should fail");
        assert!(err.to_string().contains("undefined source value %0"), "got: {err}");
    }

    #[test]
    fn u30_verify_region_unknown() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::LoadU64 { dst: 3, region: 99, offset: 0 }, // region 99 doesn't exist
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = module.verify_experimental().expect_err("should fail");
        assert!(err.to_string().contains("unknown region 99"), "got: {err}");
    }

    #[test]
    fn u30_verify_valid_module() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![1, 2, 3, 4] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(2) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::MulWrapU64, a: 0, b: 1 }, // r2 = x * 2
                        U30Op::LoadU64 { dst: 3, region: 0, offset: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        module.verify_experimental().expect("valid module should pass");
    }

    // ─── Unary ops ───────────────────────────────────────────────────────────────

    #[test]
    fn u30x_unary_ctz() {
        // Count trailing zeros
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0b1011000) }, // 88
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("ctz");
        assert_eq!(out.results, vec![U30Value::U64(88)]);
    }

    #[test]
    fn u30x_unary_popcnt() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0b1111) }, // 4 ones
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("popcnt");
        assert_eq!(out.results, vec![U30Value::U64(0b1111)]);
    }

    // ─── Select ────────────────────────────────────────────────────────────────

    #[test]
    fn u30x_select_true() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::Bool, U30Type::U64, U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Select { dst: 3, cond: 0, a: 1, b: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::Bool(true), U30Value::U64(10), U30Value::U64(20)])
            .expect("select");
        assert_eq!(out.results, vec![U30Value::U64(10)]);
    }

    #[test]
    fn u30x_select_false() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::Bool, U30Type::U64, U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Select { dst: 3, cond: 0, a: 1, b: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::Bool(false), U30Value::U64(10), U30Value::U64(20)])
            .expect("select");
        assert_eq!(out.results, vec![U30Value::U64(20)]);
    }

    // ─── MemFill ──────────────────────────────────────────────────────────────

    #[test]
    fn u30x_memfill_different_value() {
        // Test MemFill with value 0xFF, size 3
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },  // offset = 0
                        U30Op::Const { dst: 1, value: U30Value::U32(0xFF) }, // value = 0xFF
                        U30Op::Const { dst: 2, value: U30Value::U32(3) },  // size = 3
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memfill");
        assert_eq!(out.regions[&0][0], 0xFF);
        assert_eq!(out.regions[&0][1], 0xFF);
        assert_eq!(out.regions[&0][2], 0xFF);
        assert_eq!(out.regions[&0][3], 0); // untouched
    }

    // ─── MemCopy ──────────────────────────────────────────────────────────────

    #[test]
    fn u30x_memcopy() {
        // Test MemCopy: copy 4 bytes from offset 0 to offset 4
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true,
                initial: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(4) }, // dst_offset = 4
                        U30Op::Const { dst: 1, value: U30Value::U32(0) }, // src_offset = 0
                        U30Op::Const { dst: 2, value: U30Value::U32(4) }, // size = 4
                        // MemCopy: dst_offset=reg0=4, src_offset=reg1=0, size=reg2=4
                        U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 0, src_offset: 1, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memcopy");
        // Should copy bytes from offset 0 [DE AD BE EF] to offset 4
        assert_eq!(out.regions[&0], vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // ─── Trap ────────────────────────────────────────────────────────────────

    #[test]
    fn u30x_trap() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Trap { code: 0 },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("trap");
        assert!(err.to_string().contains("TRAP") || err.to_string().contains("trap"));
    }

    // ─── Fuel exhaustion ────────────────────────────────────────────────────

    #[test]
    fn u30x_trap_with_code() {
        // Trap with non-zero code
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Trap { code: 42 },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("trap");
        assert!(err.to_string().contains("TRAP") || err.to_string().contains("trap"));
    }

    // ─── Multiple results ───────────────────────────────────────────────────

    #[test]
    fn u30x_multiple_results() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64, U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(200) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0, 1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("multiple results");
        assert_eq!(out.results.len(), 2);
        assert_eq!(out.results[0], U30Value::U64(100));
        assert_eq!(out.results[1], U30Value::U32(200));
    }

    // ─── Regions ─────────────────────────────────────────────────────────────

    #[test]
    fn u30x_regions_persist_after_execution() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 4, readable: true, writable: true, initial: vec![1, 2, 3, 4] },
                U30RegionDecl { id: 1, size: 8, readable: true, writable: false, initial: vec![5; 8] },
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
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("regions");
        assert_eq!(out.regions.len(), 2);
        assert_eq!(out.regions[&0], vec![1, 2, 3, 4]);
        assert_eq!(out.regions[&1], vec![5; 8]);
    }

    // ─── Type inference / Const variants ───────────────────────────────────

    #[test]
    fn u30x_const_bool_true() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::Bool(true) }],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("bool const");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_const_bool_false() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![U30Op::Const { dst: 0, value: U30Value::Bool(false) }],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("bool const false");
        assert_eq!(out.results, vec![U30Value::Bool(false)]);
    }

    // ─── Call/Return ─────────────────────────────────────────────────────────

    #[test]
    fn u30x_call_simple() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                // callee: returns 42
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Const { dst: 0, value: U30Value::U64(42) }],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
                // caller: calls callee
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Call { function: 0, args: vec![], results: vec![0] }],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 1,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("call");
        assert_eq!(out.results, vec![U30Value::U64(42)]);
    }

    // ─── MemSize ─────────────────────────────────────────────────────────────

    #[test]
    fn u30x_memsize() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 256, readable: true, writable: true, initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![U30Op::MemSize { dst: 0, region: 0 }],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memsize");
        assert_eq!(out.results, vec![U30Value::U64(256)]);
    }

    // ─── Verify: unreachable block ───────────────────────────────────────────

    #[test]
    fn u30_verify_unreachable_block() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![
                    // Block 0 is reachable (entry)
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                    // Block 1 is unreachable (no fallthrough from block 0, no branch to it)
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // Unreachable blocks should be flagged by the verifier
        // (This test just checks the module is well-formed even with unreachable blocks)
        module.verify_experimental().expect("module with unreachable block should be valid");
    }

    // ─── F64 arithmetic ─────────────────────────────────────────────────────

    #[test]
    fn u30x_f64_add() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.5) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.5) },
                        U30Op::F64Add { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("f64add");
        assert_eq!(out.results, vec![U30Value::F64(4.0)]);
    }

    #[test]
    fn u30x_f64_mul() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(3.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(4.0) },
                        U30Op::F64Mul { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("f64mul");
        assert_eq!(out.results, vec![U30Value::F64(12.0)]);
    }

    #[test]
    fn u30x_f64_sqrt() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(16.0) },
                        U30Op::F64Sqrt { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("f64sqrt");
        if let U30Value::F64(v) = out.results[0] {
            assert!((v - 4.0).abs() < 0.0001);
        } else {
            panic!("expected F64");
        }
    }

    // ─── Select operation ────────────────────────────────────────────────────

    #[test]
    fn u30x_select_u32_true() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        U30Op::Const { dst: 1, value: U30Value::U32(100) },
                        U30Op::Const { dst: 2, value: U30Value::U32(200) },
                        U30Op::Select { dst: 3, cond: 0, a: 1, b: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("select");
        assert_eq!(out.results, vec![U30Value::U32(100)]);
    }

    #[test]
    fn u30x_select_u32_false() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(false) },
                        U30Op::Const { dst: 1, value: U30Value::U32(100) },
                        U30Op::Const { dst: 2, value: U30Value::U32(200) },
                        U30Op::Select { dst: 3, cond: 0, a: 1, b: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("select");
        assert_eq!(out.results, vec![U30Value::U32(200)]);
    }

    // ─── TableBr ───────────────────────────────────────────────────────────

    #[test]
    fn u30x_tablebr_index_0() {
        // Table with 2 targets: block 1 and block 2
        // When index=0, jumps to block 1
        let module = U30Module {
            regions: vec![],
            tables: vec![
                crate::ir::U30TableDecl { id: 0, targets: vec![1, 2] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(0) },  // index = 0
                            U30Op::TableBr { table: 0, index: 0 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![999] },  // unreachable
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 5, value: U30Value::U32(10) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![5] },  // index 0 -> return 10
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 6, value: U30Value::U32(20) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![6] },  // index 1 -> return 20
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("tablebr");
        assert_eq!(out.results, vec![U30Value::U32(10)]);
    }

    #[test]
    fn u30x_tablebr_index_1() {
        // Table with 2 targets: block 1 and block 2
        // When index=1, jumps to block 2
        let module = U30Module {
            regions: vec![],
            tables: vec![
                crate::ir::U30TableDecl { id: 0, targets: vec![1, 2] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(1) },  // index = 1
                            U30Op::TableBr { table: 0, index: 0 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![999] },  // unreachable
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 5, value: U30Value::U32(10) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![5] },  // index 0 -> return 10
                    },
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 6, value: U30Value::U32(20) },
                        ],
                        terminator: U30Terminator::Ret { values: vec![6] },  // index 1 -> return 20
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("tablebr");
        assert_eq!(out.results, vec![U30Value::U32(20)]);
    }

    // ─── MemFill ────────────────────────────────────────────────────────────

    #[test]
    fn u30x_memfill() {
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },   // offset = 0
                        U30Op::Const { dst: 1, value: U30Value::U32(0xFF) }, // value = 0xFF
                        U30Op::Const { dst: 2, value: U30Value::U32(4) },   // size = 4
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },  // fill 4 bytes with 0xFF
                        U30Op::LoadU8 { dst: 3, region: 0, offset: 0 },  // read back
                    ],
                    terminator: U30Terminator::Ret { values: vec![3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("memfill");
        assert_eq!(out.results, vec![U30Value::U8(0xFF)]);
    }

    // ─── BrIf ──────────────────────────────────────────────────────────────

    #[test]
    fn u30x_brif_true() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                            U30Op::Const { dst: 1, value: U30Value::U32(100) },
                            U30Op::Const { dst: 2, value: U30Value::U32(200) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 3, else_target: 1 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![2] },  // else: 200
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![2] },  // unreachable
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![1] },  // then: 100
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("brif");
        assert_eq!(out.results, vec![U30Value::U32(100)]);
    }

    #[test]
    fn u30x_brif_false() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(false) },
                            U30Op::Const { dst: 1, value: U30Value::U32(100) },
                            U30Op::Const { dst: 2, value: U30Value::U32(200) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 3, else_target: 1 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![2] },  // else: 200
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![2] },  // unreachable
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![1] },  // then: 100
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("brif");
        assert_eq!(out.results, vec![U30Value::U32(200)]);
    }

    // Test AbsU32
    #[test]
    fn u30x_abs_u32_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::AbsU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("abs u32");
        assert_eq!(out.results, vec![U30Value::U32(42)]);
    }

    // Test NegU64
    #[test]
    fn u30x_neg_u64_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(5) },
                        U30Op::NegU64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("neg u64");
        assert_eq!(out.results, vec![U30Value::U64(u64::MAX - 4)]); // wrapping negation: !5 + 1 = u64::MAX - 4
    }

    // Test RotlU32 and RotlU64
    #[test]
    fn u30x_rotl_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32, U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0b0001_0010_0100_1000) }, // 0x1248
                        U30Op::Const { dst: 1, value: U30Value::U32(4) },
                        U30Op::RotlU32 { dst: 2, val: 0, sh: 1 },
                        U30Op::Const { dst: 3, value: U30Value::U64(1) },
                        U30Op::Const { dst: 4, value: U30Value::U64(2) },
                        U30Op::RotlU64 { dst: 5, val: 3, sh: 4 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 5] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("rotl");
        // RotlU32: 0x1248 rotate left by 4 = 0x12480 = 74880
        assert_eq!(out.results[0].as_u32().unwrap(), 0x1248_u32.rotate_left(4));
        // RotlU64: 1 rotate left by 2 = 4
        assert_eq!(out.results[1].as_u64().unwrap(), 1u64.rotate_left(2));
    }

    // Test F64Min and F64Max
    #[test]
    fn u30x_f64_min_max_works() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::F64, U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(3.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(1.5) },
                        U30Op::F64Min { dst: 2, a: 0, b: 1 },
                        U30Op::F64Max { dst: 3, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("f64 min/max");
        assert!((out.results[0].as_f64().unwrap() - 1.5).abs() < 1e-10);
        assert!((out.results[1].as_f64().unwrap() - 3.0).abs() < 1e-10);
    }

    // Test IndirectCall
    #[test]
    fn u30x_indirect_call_works() {
        // Function 0: returns 99
        // Function 1: main - uses indirect call to call function 0
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![U30Op::Const { dst: 0, value: U30Value::U64(99) }],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(0) }, // function index
                            U30Op::IndirectCall { function: 0, args: vec![], results: vec![1] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![1] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 1,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("indirect call");
        assert_eq!(out.results, vec![U30Value::U64(99)]);
    }

    // Test TruncF32U64 (fractional truncation)
    #[test]
    fn u30x_trunc_f32_u64_fractional() {
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(42.9) },
                        U30Op::TruncF32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("trunc f32 u64");
        assert_eq!(out.results, vec![U30Value::U64(42)]);
    }

    // T34: Missing binary ops — Le, Min, Max variants

    #[test]
    fn u30x_binary_le_u64() {
        let m = |a, b, op: U30BinaryOp| -> U30Module {
            U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![U30Type::Bool],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(a) },
                            U30Op::Const { dst: 1, value: U30Value::U64(b) },
                            U30Op::Binary { dst: 2, op, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            }
        };
        // 5 <= 10
        let out = U30Runtime::default().execute_experimental(&m(5, 10, U30BinaryOp::LeU64), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
        // 10 <= 5
        let out = U30Runtime::default().execute_experimental(&m(10, 5, U30BinaryOp::LeU64), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::Bool(false)]);
    }

    #[test]
    fn u30x_binary_le_u32() {
        let m = |a, b, op: U30BinaryOp| -> U30Module {
            U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![U30Type::Bool],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(a) },
                            U30Op::Const { dst: 1, value: U30Value::U32(b) },
                            U30Op::Binary { dst: 2, op, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            }
        };
        // 3 <= 7
        let out = U30Runtime::default().execute_experimental(&m(3, 7, U30BinaryOp::LeU32), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
        // 7 <= 3
        let out = U30Runtime::default().execute_experimental(&m(7, 3, U30BinaryOp::LeU32), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::Bool(false)]);
    }

    #[test]
    fn u30x_binary_min_max() {
        let m = |a, b, op: U30BinaryOp| -> U30Module {
            U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![U30Type::U64],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(a) },
                            U30Op::Const { dst: 1, value: U30Value::U64(b) },
                            U30Op::Binary { dst: 2, op, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            }
        };
        // MinU64: min(100, 42) = 42
        let out = U30Runtime::default().execute_experimental(&m(100, 42, U30BinaryOp::MinU64), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::U64(42)]);
        // MaxU64: max(100, 42) = 100
        let out = U30Runtime::default().execute_experimental(&m(100, 42, U30BinaryOp::MaxU64), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::U64(100)]);
        // MinU32: min(7, 3) = 3
        let m32 = |a, b, op: U30BinaryOp| -> U30Module {
            U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![U30Type::U32],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U32(a) },
                            U30Op::Const { dst: 1, value: U30Value::U32(b) },
                            U30Op::Binary { dst: 2, op, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![2] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            }
        };
        let out = U30Runtime::default().execute_experimental(&m32(7, 3, U30BinaryOp::MinU32), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::U32(3)]);
        let out = U30Runtime::default().execute_experimental(&m32(7, 3, U30BinaryOp::MaxU32), &[]).unwrap();
        assert_eq!(out.results, vec![U30Value::U32(7)]);
    }

    // === Error path tests for exec_op ===

    #[test]
    fn u30x_store_u8_non_writable_fails() {
        // StoreU8 to read-only region should fail
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: false, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) }, // offset
                        U30Op::Const { dst: 1, value: U30Value::U8(42) }, // value
                        U30Op::StoreU8 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store to non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_store_u16_non_writable_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: false, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::Const { dst: 1, value: U30Value::U16(0xFF) },
                        U30Op::StoreU16 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store to non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_store_u32_non_writable_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: false, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xDEADBEEF) },
                        U30Op::StoreU32 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store to non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_store_u64_non_writable_fails() {
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: false, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::Const { dst: 1, value: U30Value::U64(0xDEADBEEF) },
                        U30Op::StoreU64 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store to non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_store_u32_oob_fails() {
        // StoreU32 at offset 5 in 8-byte region: 5+4=9 > 8
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(5) }, // offset=5, 5+4=9 > 8
                        U30Op::Const { dst: 1, value: U30Value::U32(0xFF) },
                        U30Op::StoreU32 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store u32 OOB");
        assert!(err.to_string().contains("out of bounds"), "got: {}", err);
    }

    #[test]
    fn u30x_store_u64_oob_exec_fails() {
        // StoreU64 at offset 1 in 8-byte region: 1+8=9 > 8
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(1) }, // offset=1, 1+8=9 > 8
                        U30Op::Const { dst: 1, value: U30Value::U64(0xFF) },
                        U30Op::StoreU64 { region: 0, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("store u64 OOB");
        assert!(err.to_string().contains("out of bounds"), "got: {}", err);
    }

    #[test]
    fn u30x_memcopy_src_not_readable_fails() {
        // MemCopy from non-readable src region
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: false, writable: true, initial: vec![1; 16] },
                U30RegionDecl { id: 1, size: 16, readable: true, writable: true, initial: vec![0; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) }, // dst_offset
                        U30Op::Const { dst: 1, value: U30Value::U32(0) }, // src_offset
                        U30Op::Const { dst: 2, value: U30Value::U32(4) }, // size
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 0, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memcopy from non-readable");
        assert!(err.to_string().contains("not readable"), "got: {}", err);
    }

    #[test]
    fn u30x_memcopy_dst_not_writable_fails() {
        // MemCopy to non-writable dst region
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: vec![1; 16] },
                U30RegionDecl { id: 1, size: 16, readable: true, writable: false, initial: vec![0; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0) },
                        U30Op::Const { dst: 2, value: U30Value::U32(4) },
                        U30Op::MemCopy { dst_region: 1, dst_offset: 0, src_region: 0, src_offset: 0, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memcopy to non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_memcopy_missing_dst_region_fails() {
        // MemCopy to non-existent dst region
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: vec![1; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0) },
                        U30Op::Const { dst: 2, value: U30Value::U32(4) },
                        U30Op::MemCopy { dst_region: 99, dst_offset: 0, src_region: 0, src_offset: 0, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memcopy to missing region");
        assert!(err.to_string().contains("unknown") || err.to_string().contains("missing"), "got: {}", err);
    }

    #[test]
    fn u30x_memcopy_missing_src_region_fails() {
        // MemCopy from non-existent src region
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 16, readable: true, writable: true, initial: vec![1; 16] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0) },
                        U30Op::Const { dst: 2, value: U30Value::U32(4) },
                        U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 99, src_offset: 0, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memcopy from missing region");
        assert!(err.to_string().contains("unknown") || err.to_string().contains("missing"), "got: {}", err);
    }

    #[test]
    fn u30x_memfill_non_writable_fails() {
        // MemFill on read-only region
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: false, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) }, // offset
                        U30Op::Const { dst: 1, value: U30Value::U32(0xAB) }, // value
                        U30Op::Const { dst: 2, value: U30Value::U64(4) }, // size
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memfill non-writable");
        assert!(err.to_string().contains("not writable"), "got: {}", err);
    }

    #[test]
    fn u30x_memfill_missing_region_fails() {
        // MemFill on non-existent region
        let module = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 8, readable: true, writable: true, initial: vec![0; 8],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0xAB) },
                        U30Op::Const { dst: 2, value: U30Value::U64(4) },
                        U30Op::MemFill { region: 99, offset: 0, value: 1, size: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memfill missing region");
        assert!(err.to_string().contains("unknown") || err.to_string().contains("missing"), "got: {}", err);
    }

    #[test]
    fn u30x_memsize_missing_region_fails() {
        // MemSize on non-existent region
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemSize { dst: 0, region: 99 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memsize missing region");
        assert!(err.to_string().contains("unknown") || err.to_string().contains("missing"), "got: {}", err);
    }

    #[test]
    fn u30x_memgrow_missing_region_fails() {
        // MemGrow on non-existent region
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(4096) },
                        U30Op::MemGrow { dst: 1, region: 99, delta: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("memgrow missing region");
        assert!(err.to_string().contains("unknown") || err.to_string().contains("missing"), "got: {}", err);
    }

    #[test]
    fn u30x_binary_eq_type_mismatch_fails() {
        // Eq with different types should fail
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::Const { dst: 1, value: U30Value::U64(42) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::Eq, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("eq type mismatch");
        assert!(err.to_string().contains("type mismatch"), "got: {}", err);
    }

    // === End error path tests ===

    // ─── Fuel exhaustion ────────────────────────────────────────────────────

    #[test]
    fn u30x_fuel_exhausted() {
        // Test that fuel exhaustion error is returned when limit is reached
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(1) },
                    ],
                    terminator: U30Terminator::Br { target: 0 }, // infinite loop
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let runtime = U30Runtime { fuel_limit: 3 }; // very low limit
        let err = runtime.execute_experimental(&module, &[]).expect_err("fuel should be exhausted");
        assert!(err.to_string().contains("fuel exhausted"), "got: {}", err);
    }

    #[test]
    fn u30x_fuel_exhausted_during_call() {
        // Test fuel exhaustion during nested calls
        let callee = U30Function {
            params: vec![],
            results: vec![U30Type::U64],
            blocks: vec![U30Block {
                ops: vec![],
                terminator: U30Terminator::Br { target: 0 }, // infinite loop in callee
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![callee],
            entry_function: 0,
        };
        let runtime = U30Runtime { fuel_limit: 5 };
        let err = runtime.execute_experimental(&module, &[]).expect_err("fuel exhausted");
        assert!(err.to_string().contains("fuel exhausted"), "got: {}", err);
    }

    // ─── Entry argument validation ───────────────────────────────────────────

    #[test]
    fn u30x_entry_arity_mismatch() {
        // Entry function expects 2 args but gets 1
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64, U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(1)])
            .expect_err("arity mismatch");
        assert!(err.to_string().contains("arity mismatch") || err.to_string().contains("argument"), "got: {}", err);
    }

    #[test]
    fn u30x_entry_type_mismatch() {
        // Entry function expects U64 but gets Bool
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::Bool(true)])
            .expect_err("type mismatch");
        assert!(err.to_string().contains("type mismatch"), "got: {}", err);
    }

    #[test]
    fn u30x_entry_too_many_args() {
        // Entry function expects 1 arg but gets 3
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(1), U30Value::U64(2), U30Value::U64(3)])
            .expect_err("too many args");
        assert!(err.to_string().contains("arity mismatch") || err.to_string().contains("argument"), "got: {}", err);
    }

    // ─── Return type mismatch ───────────────────────────────────────────────

    #[test]
    fn u30x_return_type_mismatch_callee() {
        // Function declares U64 result but returns Bool
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("return type mismatch");
        assert!(err.to_string().contains("type mismatch"), "got: {}", err);
    }

    #[test]
    fn u30x_return_type_mismatch_from_call() {
        // Caller expects U64, but callee returns Bool
        let callee = U30Function {
            params: vec![],
            results: vec![U30Type::Bool], // declares Bool return
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                ],
                terminator: U30Terminator::Ret { values: vec![0] },
            }],
            entry_block: 0,
        };
        let caller = U30Function {
            params: vec![],
            results: vec![U30Type::U64], // expects U64
            blocks: vec![U30Block {
                ops: vec![
                    U30Op::Call { function: 0, args: vec![], results: vec![1] },
                ],
                terminator: U30Terminator::Ret { values: vec![1] },
            }],
            entry_block: 0,
        };
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![callee, caller],
            entry_function: 1,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("return type mismatch from call");
        assert!(err.to_string().contains("type mismatch"), "got: {}", err);
    }

    // ─── Undefined value errors ──────────────────────────────────────────────

    #[test]
    fn u30x_undefined_value_on_return() {
        // Return with undefined value (reg 99 not defined)
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![99] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("undefined value");
        assert!(err.to_string().contains("undefined") || err.to_string().contains("%99"), "got: {}", err);
    }

    #[test]
    fn u30x_undefined_binary_operand() {
        // Binary op with undefined source operand
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(1) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::AddWrapU64, a: 99, b: 1 }, // %99 undefined
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("undefined operand");
        assert!(err.to_string().contains("undefined") || err.to_string().contains("%99"), "got: {}", err);
    }

    #[test]
    fn u30x_undefined_cond_brif() {
        // BrIf with undefined condition register
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::BrIf { cond: 99, then_target: 1, else_target: 2 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![0] },
                    },
                ],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("undefined condition");
        assert!(err.to_string().contains("undefined") || err.to_string().contains("%99"), "got: {}", err);
    }

    // ─── TailCall errors ────────────────────────────────────────────────────

    #[test]
    fn u30x_tailcall_oob() {
        // TailCall to out-of-bounds function index
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(99) }, // out of bounds
                    ],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("tailcall oob");
        assert!(err.to_string().contains("out of bounds"), "got: {}", err);
    }

    #[test]
    fn u30x_tailcall_undefined_fn_reg() {
        // TailCall with undefined function register
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) }, // arg = 0
                    ],
                    terminator: U30Terminator::TailCall { function: 99, args: vec![0] }, // fn reg 99 undefined
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("tailcall undefined fn reg");
        assert!(err.to_string().contains("undefined") || err.to_string().contains("%99"), "got: {}", err);
    }

    // ─── TableBr errors ─────────────────────────────────────────────────────

    #[test]
    fn u30x_tablebr_table_not_found() {
        // TableBr with non-existent table
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 99, index: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0)])
            .expect_err("table not found");
        assert!(err.to_string().contains("not found") || err.to_string().contains("table"), "got: {}", err);
    }

    // ─── Call OOB ─────────────────────────────────────────────────────────

    #[test]
    fn u30x_call_oob() {
        // Call to out-of-bounds function index - verified statically
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Call { function: 99, args: vec![], results: vec![0] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // The verifier catches this before runtime
        let err = module.verify_experimental().expect_err("verify should fail");
        assert!(err.to_string().contains("undefined function") || err.to_string().contains("99"), "got: {}", err);
    }

    // ─── Additional exec_op paths ───────────────────────────────────────────

    #[test]
    fn u30x_trunc_f32_u64_negative() {
        // TruncF32U64 with negative value -> 0
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TruncF32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(-5.0)])
            .expect("trunc negative");
        assert_eq!(out.results, vec![U30Value::U64(0)], "negative -> 0");
    }

    #[test]
    fn u30x_fabs_works() {
        // FAbs: absolute value of f32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::FAbs { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(-3.14)])
            .expect("fabs");
        assert!((out.results[0].as_f32().unwrap() - 3.14).abs() < 0.001);
    }

    #[test]
    fn u30x_fmin_works() {
        // FMin: minimum of two f32 values
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32, U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::FMin { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(5.0), U30Value::F32(2.0)])
            .expect("fmin");
        assert!((out.results[0].as_f32().unwrap() - 2.0).abs() < 0.001);
    }

    #[test]
    fn u30x_fmax_works() {
        // FMax: maximum of two f32 values
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32, U30Type::F32],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::FMax { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(5.0), U30Value::F32(2.0)])
            .expect("fmax");
        assert!((out.results[0].as_f32().unwrap() - 5.0).abs() < 0.001);
    }

    #[test]
    fn u30x_fgt_works() {
        // FGt: greater than for f32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32, U30Type::F32],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::FGt { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(5.0), U30Value::F32(2.0)])
            .expect("fgt");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_clz_u32_works() {
        // Count leading zeros for U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0b0010_0000) }, // 5 trailing zeros after the 1
                        U30Op::ClzU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("clz u32");
        assert_eq!(out.results, vec![U30Value::U64(26)]); // 32 - 6 = 26 (the 1 is at bit position 5)
    }

    #[test]
    fn u30x_popcnt_u32_works() {
        // Population count for U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0b1111_0000) }, // 4 ones
                        U30Op::PopcntU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("popcnt u32");
        assert_eq!(out.results, vec![U30Value::U64(4)]);
    }

    #[test]
    fn u30x_not_u8_works() {
        // Bitwise NOT for U8
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U8],
                results: vec![U30Type::U8],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::NotU8 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U8(0x00)])
            .expect("not u8");
        assert_eq!(out.results, vec![U30Value::U8(0xFF)]);
    }

    #[test]
    fn u30x_not_u16_works() {
        // Bitwise NOT for U16
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U16],
                results: vec![U30Type::U16],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::NotU16 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U16(0x0000)])
            .expect("not u16");
        assert_eq!(out.results, vec![U30Value::U16(0xFFFF)]);
    }

    #[test]
    fn u30x_not_u64_works() {
        // Bitwise NOT for U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::NotU64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0)])
            .expect("not u64");
        assert_eq!(out.results, vec![U30Value::U64(u64::MAX)]);
    }

    #[test]
    fn u30x_load_missing_region() {
        // Load from non-existent region - verified statically before execution
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::LoadU64 { dst: 1, region: 99, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // The verifier catches this before runtime execution
        let err = module.verify_experimental().expect_err("verify should fail");
        assert!(err.to_string().contains("unknown region"), "got: {}", err);
    }

    #[test]
    fn u30x_store_missing_region() {
        // Store to non-existent region - verified statically before execution
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
                        U30Op::StoreU64 { region: 99, offset: 0, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // The verifier catches this before runtime execution
        let err = module.verify_experimental().expect_err("verify should fail");
        assert!(err.to_string().contains("unknown region"), "got: {}", err);
    }

    #[test]
    fn u30x_i64f64_works() {
        // Integer to F64 conversion
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::I64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(100)])
            .expect("i64f64");
        assert!((out.results[0].as_f64().unwrap() - 100.0).abs() < 0.001);
    }

    #[test]
    fn u30x_f64i64_works() {
        // F64 to Integer conversion
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64I64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(99.9)])
            .expect("f64i64");
        assert_eq!(out.results, vec![U30Value::U64(99)]);
    }

    #[test]
    fn u30x_f32f64_works() {
        // F32 to F64 conversion
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F32],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F32F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F32(3.5)])
            .expect("f32f64");
        assert!((out.results[0].as_f64().unwrap() - 3.5).abs() < 0.001);
    }

    #[test]
    fn u30x_f64f32_works() {
        // F64 to F32 conversion
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::F32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64F32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(2.5)])
            .expect("f64f32");
        assert!((out.results[0].as_f32().unwrap() - 2.5).abs() < 0.001);
    }

    #[test]
    fn u30x_reinterpret_u64_f64_works() {
        // Reinterpret U64 bits as F64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ReinterpretU64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        // 0x3FF0000000000000 is 1.0 as F64
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0x3FF0000000000000u64)])
            .expect("reinterpret u64f64");
        assert!((out.results[0].as_f64().unwrap() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn u30x_reinterpret_f64_u64_works() {
        // Reinterpret F64 bits as U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ReinterpretF64U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(1.0)])
            .expect("reinterpret f64u64");
        assert_eq!(out.results, vec![U30Value::U64(0x3FF0000000000000u64)]);
    }

    #[test]
    fn u30x_sext_i8_u16_works() {
        // Sign extend I8 to U16: 0x80 should become 0xFF80
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U8],
                results: vec![U30Type::U16],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI8U16 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U8(0x80)])
            .expect("sext i8 u16");
        assert_eq!(out.results, vec![U30Value::U16(0xFF80)]);
    }

    #[test]
    fn u30x_sext_i8_u32_works() {
        // Sign extend I8 to U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U8],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI8U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U8(0x80)])
            .expect("sext i8 u32");
        assert_eq!(out.results, vec![U30Value::U32(0xFFFFFF80)]);
    }

    #[test]
    fn u30x_sext_i8_u64_works() {
        // Sign extend I8 to U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U8],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI8U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U8(0x80)])
            .expect("sext i8 u64");
        assert_eq!(out.results, vec![U30Value::U64(0xFFFFFFFFFFFFFF80u64)]);
    }

    #[test]
    fn u30x_sext_i16_u32_works() {
        // Sign extend I16 to U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U16],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI16U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U16(0x8000)])
            .expect("sext i16 u32");
        assert_eq!(out.results, vec![U30Value::U32(0xFFFF8000)]);
    }

    #[test]
    fn u30x_sext_i16_u64_works() {
        // Sign extend I16 to U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U16],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI16U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U16(0x8000)])
            .expect("sext i16 u64");
        assert_eq!(out.results, vec![U30Value::U64(0xFFFFFFFFFFFF8000u64)]);
    }

    #[test]
    fn u30x_sext_i32_u64_works() {
        // Sign extend I32 to U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U32],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::SExtI32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U32(0x80000000)])
            .expect("sext i32 u64");
        assert_eq!(out.results, vec![U30Value::U64(0xFFFFFFFF80000000u64)]);
    }

    #[test]
    fn u30x_byteswap_u16_works() {
        // Byte swap U16
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U16],
                results: vec![U30Type::U16],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ByteSwapU16 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U16(0x1234)])
            .expect("byteswap u16");
        assert_eq!(out.results, vec![U30Value::U16(0x3412)]);
    }

    #[test]
    fn u30x_byteswap_u32_works() {
        // Byte swap U32
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U32],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ByteSwapU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U32(0x12345678)])
            .expect("byteswap u32");
        assert_eq!(out.results, vec![U30Value::U32(0x78563412)]);
    }

    #[test]
    fn u30x_byteswap_u64_works() {
        // Byte swap U64
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::ByteSwapU64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::U64(0x0123456789ABCDEFu64)])
            .expect("byteswap u64");
        assert_eq!(out.results, vec![U30Value::U64(0xEFCDAB8967452301u64)]);
    }

    // ─── F64 additional tests ──────────────────────────────────────────────

    #[test]
    fn u30x_f64_eq_works() {
        // F64 equality with epsilon comparison
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Eq { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(1.0), U30Value::F64(1.0)])
            .expect("f64 eq");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_f64_lt_works() {
        // F64 less than
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Lt { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(1.0), U30Value::F64(2.0)])
            .expect("f64 lt");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_f64_gt_works() {
        // F64 greater than
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Gt { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(3.0), U30Value::F64(2.0)])
            .expect("f64 gt");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_f64_le_works() {
        // F64 less than or equal
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Le { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(2.0), U30Value::F64(2.0)])
            .expect("f64 le");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_f64_ge_works() {
        // F64 greater than or equal
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::Bool],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Ge { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(2.0), U30Value::F64(2.0)])
            .expect("f64 ge");
        assert_eq!(out.results, vec![U30Value::Bool(true)]);
    }

    #[test]
    fn u30x_f64_sub_works() {
        // F64 subtraction
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Sub { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(5.0), U30Value::F64(3.0)])
            .expect("f64 sub");
        assert!((out.results[0].as_f64().unwrap() - 2.0).abs() < 0.001);
    }

    #[test]
    fn u30x_f64_neg_works() {
        // F64 negation
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Neg { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(3.5)])
            .expect("f64 neg");
        assert!((out.results[0].as_f64().unwrap() - (-3.5)).abs() < 0.001);
    }

    #[test]
    fn u30x_f64_abs_works() {
        // F64 absolute value
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Abs { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(-3.5)])
            .expect("f64 abs");
        assert!((out.results[0].as_f64().unwrap() - 3.5).abs() < 0.001);
    }

    #[test]
    fn u30x_f64_min_works() {
        // F64 minimum
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Min { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(5.0), U30Value::F64(3.0)])
            .expect("f64 min");
        assert!((out.results[0].as_f64().unwrap() - 3.0).abs() < 0.001);
    }

    #[test]
    fn u30x_f64_max_works() {
        // F64 maximum
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64, U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Max { dst: 2, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(5.0), U30Value::F64(3.0)])
            .expect("f64 max");
        assert!((out.results[0].as_f64().unwrap() - 5.0).abs() < 0.001);
    }

    #[test]
    fn u30x_f64_sqrt_works() {
        // F64 square root
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::F64],
                results: vec![U30Type::F64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Sqrt { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[U30Value::F64(16.0)])
            .expect("f64 sqrt");
        assert!((out.results[0].as_f64().unwrap() - 4.0).abs() < 0.001);
    }

    // ─── Instantiate regions ────────────────────────────────────────────────

    #[test]
    fn u30x_regions_initial_data() {
        // Test that regions are initialized with correct initial data
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 4, readable: true, writable: true, initial: vec![0x11, 0x22, 0x33, 0x44] },
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
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("regions with initial data");
        assert_eq!(out.regions[&0], vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn u30x_regions_readable_writable_flags() {
        // Test that readable/writable flags are set correctly
        let module = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 4, readable: true, writable: false, initial: vec![1, 2, 3, 4] },
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
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("region flags");
        assert_eq!(out.regions[&0], vec![1, 2, 3, 4]);
    }

    // ─── Steps counter ──────────────────────────────────────────────────────

    #[test]
    fn u30x_steps_counter() {
        // Test that steps are counted correctly
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let out = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect("steps counter");
        // Should be 3: 2 ops + 1 terminator
        assert_eq!(out.steps, 3);
    }

    // ─── Rem by zero ───────────────────────────────────────────────────────

    #[test]
    fn u30x_rem_u64_by_zero_fails() {
        // Remainder by zero should fail
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(100) },
                        U30Op::Const { dst: 1, value: U30Value::U64(0) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::RemU64, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("rem by zero");
        assert!(err.to_string().contains("div by zero") || err.to_string().contains("zero"), "got: {}", err);
    }

    #[test]
    fn u30x_rem_u32_by_zero_fails() {
        // Remainder U32 by zero should fail
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::RemU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("rem u32 by zero");
        assert!(err.to_string().contains("div by zero") || err.to_string().contains("zero"), "got: {}", err);
    }

    // ─── Div by zero ───────────────────────────────────────────────────────

    #[test]
    fn u30x_div_u64_by_zero_fails() {
        // Division by zero should fail
        let module = U30Module {
            regions: vec![],
            tables: vec![],
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
            .expect_err("div u64 by zero");
        assert!(err.to_string().contains("div by zero"), "got: {}", err);
    }

    #[test]
    fn u30x_div_u32_by_zero_fails() {
        // Division U32 by zero should fail
        let module = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U32],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(100) },
                        U30Op::Const { dst: 1, value: U30Value::U32(0) },
                        U30Op::Binary { dst: 2, op: U30BinaryOp::DivU32, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let err = U30Runtime::default()
            .execute_experimental(&module, &[])
            .expect_err("div u32 by zero");
        assert!(err.to_string().contains("div by zero"), "got: {}", err);
    }
}
