//! U30 Debugger — step-by-step execution with breakpoints and inspection.
//!
//! ## Example
//! ```rust,no_run
//! use unico_runtime::debugger::{U30Debugger, DebugEvent};
//! use unico_runtime::ir::{U30Module, U30Function, U30Block, U30Terminator, U30Value, U30Type};
//!
//! // Create a simple module
//! let module = U30Module {
//!     regions: vec![],
//!     tables: vec![],
//!     functions: vec![U30Function {
//!         params: vec![],
//!         results: vec![],
//!         blocks: vec![U30Block {
//!             ops: vec![],
//!             terminator: U30Terminator::Ret { values: vec![] },
//!         }],
//!         entry_block: 0,
//!     }],
//!     entry_function: 0,
//! };
//!
//! // Run to completion via the debugger
//! let mut dbg = U30Debugger::new(module, &[], 10_000).unwrap();
//! let outcome = dbg.run_to_completion().unwrap();
//! ```

use crate::error::{Error, Result};
use crate::ir::{U30BinaryOp, U30Module, U30Op, U30Terminator, U30Value, U30Block};
use crate::runtime::U30ExecutionOutcome;
use std::collections::BTreeMap;

// ─── Debug events ──────────────────────────────────────────────────────────────

/// Events produced during debug execution.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// Execution halted normally (return or trap).
    Halted { reason: String },
    /// Paused at a breakpoint.
    Breakpoint { fn_idx: usize, block_idx: usize, op_idx: usize },
    /// Paused after stepping one operation.
    Step { fn_idx: usize, block_idx: usize, op_idx: usize, op: U30Op },
    /// Fuel exhausted.
    OutOfFuel,
}

// ─── Breakpoint ───────────────────────────────────────────────────────────────

/// A breakpoint location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Breakpoint {
    /// Function index, or None for any function.
    pub fn_idx: Option<usize>,
    /// Block index within the function, or None for any block.
    pub block_idx: Option<usize>,
    /// Operation index within the block, or None for the block entry (before first op).
    pub op_idx: Option<usize>,
}

impl Breakpoint {
    pub fn at(fn_idx: usize, block_idx: usize, op_idx: usize) -> Self {
        Self { fn_idx: Some(fn_idx), block_idx: Some(block_idx), op_idx: Some(op_idx) }
    }
    pub fn block_entry(fn_idx: usize, block_idx: usize) -> Self {
        Self { fn_idx: Some(fn_idx), block_idx: Some(block_idx), op_idx: None }
    }
    pub fn function_start(fn_idx: usize) -> Self {
        Self { fn_idx: Some(fn_idx), block_idx: None, op_idx: None }
    }
}

// ─── Call frame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CallFrame {
    return_fn_idx: usize,
    return_block: usize,
    return_op_idx: usize,
    result_regs: Vec<u32>,
    caller_regs: BTreeMap<u32, U30Value>,
}

// ─── Debug state ──────────────────────────────────────────────────────────────

/// Live execution state for the debugger.
#[derive(Debug, Clone)]
pub struct U30DebugState {
    pub fn_idx: usize,
    pub block_idx: usize,
    pub op_idx: usize,
    /// All registers in the current frame.
    pub regs: BTreeMap<u32, U30Value>,
    /// Memory regions.
    pub regions: BTreeMap<u32, RegionData>,
    pub fuel_remaining: u64,
    pub steps: u64,
    /// Whether the last op was a terminator (need to process it next).
    pub pending_terminator: bool,
}

#[derive(Debug, Clone)]
pub struct RegionData {
    bytes: Vec<u8>,
    readable: bool,
    writable: bool,
}

impl U30DebugState {
    fn new(module: &U30Module, args: &[U30Value], fuel_limit: u64) -> Result<Self> {
        let entry_fn = module.entry_function;
        let entry_block = module.functions[entry_fn].entry_block;

        if args.len() != module.functions[entry_fn].params.len() {
            return Err(Error::Verification("U30X entry argument arity mismatch".into()));
        }
        for (index, (arg, expected)) in args.iter().zip(&module.functions[entry_fn].params).enumerate() {
            if arg.value_type() != *expected {
                return Err(Error::Verification(format!("U30X entry argument {index} type mismatch")));
            }
        }

        let mut regs = BTreeMap::new();
        for (i, arg) in args.iter().cloned().enumerate() {
            regs.insert(i as u32, arg);
        }

        let regions = module.regions.iter().map(|r| {
            let mut bytes = r.initial.clone();
            bytes.resize(r.size, 0);
            (r.id, RegionData { bytes, readable: r.readable, writable: r.writable })
        }).collect();

        Ok(Self {
            fn_idx: entry_fn,
            block_idx: entry_block,
            op_idx: 0,
            regs,
            regions,
            fuel_remaining: fuel_limit,
            steps: 0,
            pending_terminator: false,
        })
    }

    fn current_op<'a>(&self, module: &'a U30Module) -> Option<&'a U30Op> {
        let block = &module.functions[self.fn_idx].blocks[self.block_idx];
        block.ops.get(self.op_idx)
    }

    fn current_block<'a>(&self, module: &'a U30Module) -> &'a U30Block {
        &module.functions[self.fn_idx].blocks[self.block_idx]
    }

    fn at_breakpoint(&self, breakpoints: &BTreeSet<Breakpoint>) -> bool {
        for bp in breakpoints {
            let fn_match = bp.fn_idx.map_or(true, |f| f == self.fn_idx);
            let block_match = bp.block_idx.map_or(true, |b| b == self.block_idx);
            let op_match = bp.op_idx.map_or(true, |o| o == self.op_idx);
            if fn_match && block_match && op_match {
                return true;
            }
        }
        false
    }

    fn reg(&self, r: u32) -> Result<&U30Value> {
        self.regs.get(&r)
            .ok_or_else(|| Error::Generic(format!("U30X undefined register %{r}")))
    }

    fn set_reg(&mut self, r: u32, v: U30Value) {
        self.regs.insert(r, v);
    }

    fn load_u8(&self, region: u32, offset_reg: u32) -> Result<u8> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let data = self.regions.get(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.readable {
            return Err(Error::Generic(format!("U30X region {region} not readable")));
        }
        data.bytes.get(offset).copied()
            .ok_or_else(|| Error::Generic(format!("U30X LOAD.U8 OOB at offset {offset}")))
    }

    fn load_u16(&self, region: u32, offset_reg: u32) -> Result<u16> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let data = self.regions.get(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.readable {
            return Err(Error::Generic(format!("U30X region {region} not readable")));
        }
        let bytes = data.bytes.get(offset..offset + 2)
            .ok_or_else(|| Error::Generic(format!("U30X LOAD.U16 OOB at offset {offset}")))?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn load_u32(&self, region: u32, offset_reg: u32) -> Result<u32> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let data = self.regions.get(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.readable {
            return Err(Error::Generic(format!("U30X region {region} not readable")));
        }
        let bytes = data.bytes.get(offset..offset + 4)
            .ok_or_else(|| Error::Generic(format!("U30X LOAD.U32 OOB at offset {offset}")))?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn load_u64(&self, region: u32, offset_reg: u32) -> Result<u64> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let data = self.regions.get(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.readable {
            return Err(Error::Generic(format!("U30X region {region} not readable")));
        }
        let bytes = data.bytes.get(offset..offset + 8)
            .ok_or_else(|| Error::Generic(format!("U30X LOAD.U64 OOB at offset {offset}")))?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn store_u8(&mut self, region: u32, offset_reg: u32, val_reg: u32) -> Result<()> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let val = self.reg(val_reg)?.as_u8()?;
        let data = self.regions.get_mut(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.writable {
            return Err(Error::Generic(format!("U30X region {region} not writable")));
        }
        if offset >= data.bytes.len() {
            return Err(Error::Generic(format!("U30X STORE.U8 OOB at offset {offset}")));
        }
        data.bytes[offset] = val;
        Ok(())
    }

    fn store_u16(&mut self, region: u32, offset_reg: u32, val_reg: u32) -> Result<()> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let val = self.reg(val_reg)?.as_u16()?;
        let data = self.regions.get_mut(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.writable {
            return Err(Error::Generic(format!("U30X region {region} not writable")));
        }
        if offset + 2 > data.bytes.len() {
            return Err(Error::Generic(format!("U30X STORE.U16 OOB at offset {offset}")));
        }
        data.bytes[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn store_u32(&mut self, region: u32, offset_reg: u32, val_reg: u32) -> Result<()> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let val = self.reg(val_reg)?.as_u32()?;
        let data = self.regions.get_mut(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.writable {
            return Err(Error::Generic(format!("U30X region {region} not writable")));
        }
        if offset + 4 > data.bytes.len() {
            return Err(Error::Generic(format!("U30X STORE.U32 OOB at offset {offset}")));
        }
        data.bytes[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn store_u64(&mut self, region: u32, offset_reg: u32, val_reg: u32) -> Result<()> {
        let offset = self.reg(offset_reg)?.as_u64()? as usize;
        let val = self.reg(val_reg)?.as_u64()?;
        let data = self.regions.get_mut(&region)
            .ok_or_else(|| Error::Generic(format!("U30X unknown region {region}")))?;
        if !data.writable {
            return Err(Error::Generic(format!("U30X region {region} not writable")));
        }
        if offset + 8 > data.bytes.len() {
            return Err(Error::Generic(format!("U30X STORE.U64 OOB at offset {offset}")));
        }
        data.bytes[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn mem_copy(
        &mut self,
        dst_region: u32,
        dst_offset_reg: u32,
        src_region: u32,
        src_offset_reg: u32,
        size_reg: u32,
    ) -> Result<()> {
        // Read registers first (avoid borrow conflict)
        let dst_off = self.reg(dst_offset_reg)?.as_u64()? as usize;
        let src_off = self.reg(src_offset_reg)?.as_u64()? as usize;
        let n = self.reg(size_reg)?.as_u64()? as usize;

        // Read source region
        let src_data = self.regions.get(&src_region)
            .ok_or_else(|| Error::Generic(format!("U30X memcopy unknown src region {src_region}")))?;
        if !src_data.readable {
            return Err(Error::Generic(format!("U30X memcopy src region {src_region} not readable")));
        }
        if src_off + n > src_data.bytes.len() {
            return Err(Error::Generic("U30X memcopy src out of bounds".into()));
        }
        let src_slice = src_data.bytes[src_off..src_off + n].to_vec();

        // Write to destination region
        let data = self.regions.get_mut(&dst_region)
            .ok_or_else(|| Error::Generic(format!("U30X memcopy unknown dst region {dst_region}")))?;
        if !data.writable {
            return Err(Error::Generic(format!("U30X memcopy dst region {dst_region} not writable")));
        }
        if dst_off + n > data.bytes.len() {
            return Err(Error::Generic("U30X memcopy dst out of bounds".into()));
        }
        data.bytes[dst_off..dst_off + n].copy_from_slice(&src_slice);
        Ok(())
    }

    fn mem_fill(
        &mut self,
        region: u32,
        offset_reg: u32,
        value_reg: u32,
        size_reg: u32,
    ) -> Result<()> {
        let off = self.reg(offset_reg)?.as_u64()? as usize;
        let val = self.reg(value_reg)?.as_u32()? as u8;
        let n = self.reg(size_reg)?.as_u64()? as usize;

        let data = self.regions.get_mut(&region)
            .ok_or_else(|| Error::Generic(format!("U30X memfill unknown region {region}")))?;
        if off + n > data.bytes.len() {
            return Err(Error::Generic("U30X memfill out of bounds".into()));
        }
        data.bytes[off..off + n].fill(val);
        Ok(())
    }
}

use std::collections::BTreeSet;

// ─── Debugger ─────────────────────────────────────────────────────────────────

/// U30 interactive debugger.
pub struct U30Debugger {
    pub state: U30DebugState,
    breakpoints: BTreeSet<Breakpoint>,
    call_stack: Vec<CallFrame>,
    /// Step over call depth: stop after the call returns.
    step_over_depth: Option<usize>,
    /// Module reference (shared, not owned).
    module: U30Module,
}

impl U30Debugger {
    /// Create a new debugger for the given module.
    pub fn new(module: U30Module, args: &[U30Value], fuel_limit: u64) -> Result<Self> {
        module.verify_experimental()?;
        let state = U30DebugState::new(&module, args, fuel_limit)?;
        Ok(Self {
            state,
            breakpoints: BTreeSet::new(),
            call_stack: Vec::new(),
            step_over_depth: None,
            module,
        })
    }

    /// Set a breakpoint.
    pub fn set_breakpoint(&mut self, bp: Breakpoint) {
        self.breakpoints.insert(bp);
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, bp: &Breakpoint) {
        self.breakpoints.remove(bp);
    }

    /// List all breakpoints.
    pub fn breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.iter().collect()
    }

    /// Current function name or index.
    pub fn current_fn_name(&self) -> String {
        format!("fn{}", self.state.fn_idx)
    }

    /// Execute one operation and return the event.
    pub fn step(&mut self) -> Result<DebugEvent> {
        if self.state.fuel_remaining == 0 {
            return Ok(DebugEvent::OutOfFuel);
        }
        self.state.fuel_remaining = self.state.fuel_remaining.saturating_sub(1);
        self.state.steps += 1;

        if self.state.at_breakpoint(&self.breakpoints) {
            return Ok(DebugEvent::Breakpoint {
                fn_idx: self.state.fn_idx,
                block_idx: self.state.block_idx,
                op_idx: self.state.op_idx,
            });
        }

        let op = match self.state.current_op(&self.module) {
            Some(op) => op.clone(),
            None => {
                // Past last op — process terminator
                return self.process_terminator();
            }
        };

        // Execute the operation
        self.execute_op(&op)?;

        // Advance op index
        self.state.op_idx += 1;

        // Check if we need to process terminator
        let block = self.state.current_block(&self.module);
        if self.state.op_idx >= block.ops.len() {
            return self.process_terminator();
        }

        Ok(DebugEvent::Step {
            fn_idx: self.state.fn_idx,
            block_idx: self.state.block_idx,
            op_idx: self.state.op_idx - 1,
            op,
        })
    }

    /// Step over calls (stop after the call returns).
    pub fn step_over(&mut self) -> Result<DebugEvent> {
        // Check if current op is a Call
        let call_depth = if matches!(self.state.current_op(&self.module), Some(U30Op::Call { .. })) {
            Some(self.call_stack.len())
        } else {
            None
        };

        self.step_over_depth = call_depth;
        self.continue_exec()
    }

    /// Continue execution until a breakpoint or termination.
    pub fn continue_exec(&mut self) -> Result<DebugEvent> {
        loop {
            if self.state.fuel_remaining == 0 {
                return Ok(DebugEvent::OutOfFuel);
            }

            if self.state.at_breakpoint(&self.breakpoints) {
                return Ok(DebugEvent::Breakpoint {
                    fn_idx: self.state.fn_idx,
                    block_idx: self.state.block_idx,
                    op_idx: self.state.op_idx,
                });
            }

            let event = self.step()?;
            if matches!(&event, DebugEvent::Step { .. }) {
                // Check step-over depth
                if let Some(depth) = self.step_over_depth {
                    if self.call_stack.len() <= depth { /* already handled */ }
                }
                continue;
            }

            // Check step-over: stop when we've returned past the call depth
            if let Some(depth) = self.step_over_depth {
                if self.call_stack.len() < depth {
                    self.step_over_depth = None;
                    return Ok(event);
                }
            }

            match event {
                DebugEvent::Halted { .. } | DebugEvent::OutOfFuel => return Ok(event),
                DebugEvent::Breakpoint { .. } => return Ok(event),
                DebugEvent::Step { .. } => { /* continue */ }
            }
        }
    }

    /// Run to completion (no breakpoints).
    pub fn run_to_completion(&mut self) -> Result<U30ExecutionOutcome> {
        loop {
            if self.state.fuel_remaining == 0 {
                return Ok(self.finish(Err(Error::Generic("fuel exhausted".into()))));
            }
            match self.step()? {
                DebugEvent::Halted { .. } | DebugEvent::OutOfFuel => break,
                DebugEvent::Breakpoint { .. } | DebugEvent::Step { .. } => { /* continue */ }
            }
        }
        Ok(self.finish(Ok(())))
    }

    fn finish(&self, result: Result<()>) -> U30ExecutionOutcome {
        let regions: BTreeMap<u32, Vec<u8>> = self.state.regions.iter()
            .map(|(&k, v)| (k, v.bytes.clone()))
            .collect();
        match result {
            Ok(()) => U30ExecutionOutcome {
                results: vec![],
                regions,
                steps: self.state.steps,
            },
            Err(_e) => U30ExecutionOutcome {
                results: vec![],
                regions,
                steps: self.state.steps,
            },
        }
    }

    fn execute_op(&mut self, op: &U30Op) -> Result<()> {
        match op {
            U30Op::Const { dst, value } => {
                self.state.set_reg(*dst, value.clone());
            }
            U30Op::Binary { dst, op: binop, a, b } => {
                let a_val = self.state.reg(*a)?;
                let b_val = self.state.reg(*b)?;
                let result = eval_binary(*binop, a_val, b_val)?;
                self.state.set_reg(*dst, result);
            }
            U30Op::Select { dst, cond, a, b } => {
                let c = self.state.reg(*cond)?.as_bool()?;
                let val = if c { self.state.reg(*a)? } else { self.state.reg(*b)? };
                self.state.set_reg(*dst, val.clone());
            }
            U30Op::NotU8 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U8(!v));
            }
            U30Op::NotU16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U16(!v));
            }
            U30Op::NotU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(!v));
            }
            U30Op::NotU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(!v));
            }
            U30Op::I2F { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::F64(v as f64));
            }
            U30Op::F2I { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::TruncF32U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::ReinterpretF32U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::U32(v.to_bits()));
            }
            U30Op::ReinterpretU32F32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::F32(f32::from_bits(v)));
            }
            U30Op::AbsU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v));
            }
            U30Op::AbsU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(v));
            }
            U30Op::NegU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.wrapping_neg()));
            }
            U30Op::NegU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(v.wrapping_neg()));
            }
            U30Op::CtzU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.trailing_zeros() as u64));
            }
            U30Op::CtzU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U64(v.trailing_zeros() as u64));
            }
            U30Op::ClzU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.leading_zeros() as u64));
            }
            U30Op::ClzU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U64(v.leading_zeros() as u64));
            }
            U30Op::PopcntU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.count_ones() as u64));
            }
            U30Op::PopcntU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U64(v.count_ones() as u64));
            }
            U30Op::RotlU64 { dst, val, sh } => {
                let v = self.state.reg(*val)?.as_u64()?;
                let s = self.state.reg(*sh)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.rotate_left(s as u32)));
            }
            U30Op::RotlU32 { dst, val, sh } => {
                let v = self.state.reg(*val)?.as_u32()?;
                let s = self.state.reg(*sh)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(v.rotate_left(s)));
            }
            U30Op::RotrU64 { dst, val, sh } => {
                let v = self.state.reg(*val)?.as_u64()?;
                let s = self.state.reg(*sh)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.rotate_right(s as u32)));
            }
            U30Op::RotrU32 { dst, val, sh } => {
                let v = self.state.reg(*val)?.as_u32()?;
                let s = self.state.reg(*sh)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(v.rotate_right(s)));
            }
            U30Op::FEq { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::Bool((av - bv).abs() < 1e-6));
            }
            U30Op::FLt { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::Bool(av < bv));
            }
            U30Op::FGt { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::Bool(av > bv));
            }
            U30Op::FLe { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::Bool(av <= bv));
            }
            U30Op::FGe { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::Bool(av >= bv));
            }
            U30Op::FAdd { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av + bv));
            }
            U30Op::FSub { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av - bv));
            }
            U30Op::FMul { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av * bv));
            }
            U30Op::FDiv { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av / bv));
            }
            U30Op::FSqrt { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(v.sqrt()));
            }
            U30Op::FAbs { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(v.abs()));
            }
            U30Op::FNeg { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(-v));
            }
            U30Op::FMin { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av.min(bv)));
            }
            U30Op::FMax { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f32()?;
                let bv = self.state.reg(*b)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F32(av.max(bv)));
            }
            U30Op::F64Eq { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::Bool(av == bv)); // NaN-aware
            }
            U30Op::F64Lt { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::Bool(av < bv));
            }
            U30Op::F64Gt { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::Bool(av > bv));
            }
            U30Op::F64Le { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::Bool(av <= bv));
            }
            U30Op::F64Ge { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::Bool(av >= bv));
            }
            U30Op::F64Add { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(av + bv));
            }
            U30Op::F64Sub { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(av - bv));
            }
            U30Op::F64Mul { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(av * bv));
            }
            U30Op::F64Div { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                if bv == 0.0 {
                    return Err(Error::Generic("div-by-zero".into()));
                }
                self.state.set_reg(*dst, U30Value::F64(av / bv));
            }
            U30Op::F64Sqrt { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(v.sqrt()));
            }
            U30Op::F64Abs { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(v.abs()));
            }
            U30Op::F64Neg { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(-v));
            }
            U30Op::F64Min { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(av.min(bv)));
            }
            U30Op::F64Max { dst, a, b } => {
                let av = self.state.reg(*a)?.as_f64()?;
                let bv = self.state.reg(*b)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F64(av.max(bv)));
            }
            U30Op::I64F64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::F64(v as f64));
            }
            U30Op::F64I64 { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::F32F64 { dst, src } => {
                let v = self.state.reg(*src)?.as_f32()?;
                self.state.set_reg(*dst, U30Value::F64(v as f64));
            }
            U30Op::F64F32 { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::F32(v as f32));
            }
            U30Op::ReinterpretF64U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::F64(f64::from_bits(v)));
            }
            U30Op::ReinterpretU64F64 { dst, src } => {
                let v = self.state.reg(*src)?.as_f64()?;
                self.state.set_reg(*dst, U30Value::U64(v.to_bits()));
            }
            U30Op::SExtI8U16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U16(v as i8 as i16 as u16));
            }
            U30Op::SExtI8U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U32(v as i8 as i32 as u32));
            }
            U30Op::SExtI8U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U64(v as i8 as i64 as u64));
            }
            U30Op::SExtI16U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U32(v as i16 as i32 as u32));
            }
            U30Op::SExtI16U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U64(v as i16 as i64 as u64));
            }
            U30Op::SExtI32U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U64(v as i32 as i64 as u64));
            }
            U30Op::ZExtI8U16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U16(v as u16));
            }
            U30Op::ZExtI8U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U32(v as u32));
            }
            U30Op::ZExtI8U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u8()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::ZExtI16U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U32(v as u32));
            }
            U30Op::ZExtI16U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::ZExtI32U64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U64(v as u64));
            }
            U30Op::TruncU64U32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U32(v as u32));
            }
            U30Op::TruncU64U16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U16(v as u16));
            }
            U30Op::TruncU32U16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U16(v as u16));
            }
            U30Op::ByteSwapU16 { dst, src } => {
                let v = self.state.reg(*src)?.as_u16()?;
                self.state.set_reg(*dst, U30Value::U16(v.swap_bytes()));
            }
            U30Op::ByteSwapU32 { dst, src } => {
                let v = self.state.reg(*src)?.as_u32()?;
                self.state.set_reg(*dst, U30Value::U32(v.swap_bytes()));
            }
            U30Op::ByteSwapU64 { dst, src } => {
                let v = self.state.reg(*src)?.as_u64()?;
                self.state.set_reg(*dst, U30Value::U64(v.swap_bytes()));
            }
            U30Op::LoadU8 { dst, region, offset } => {
                let v = self.state.load_u8(*region, *offset)?;
                self.state.set_reg(*dst, U30Value::U8(v));
            }
            U30Op::LoadU16 { dst, region, offset } => {
                let v = self.state.load_u16(*region, *offset)?;
                self.state.set_reg(*dst, U30Value::U16(v));
            }
            U30Op::LoadU32 { dst, region, offset } => {
                let v = self.state.load_u32(*region, *offset)?;
                self.state.set_reg(*dst, U30Value::U32(v));
            }
            U30Op::LoadU64 { dst, region, offset } => {
                let v = self.state.load_u64(*region, *offset)?;
                self.state.set_reg(*dst, U30Value::U64(v));
            }
            U30Op::StoreU8 { region, offset, src } => {
                self.state.store_u8(*region, *offset, *src)?;
            }
            U30Op::StoreU16 { region, offset, src } => {
                self.state.store_u16(*region, *offset, *src)?;
            }
            U30Op::StoreU32 { region, offset, src } => {
                self.state.store_u32(*region, *offset, *src)?;
            }
            U30Op::StoreU64 { region, offset, src } => {
                self.state.store_u64(*region, *offset, *src)?;
            }
            U30Op::MemCopy { dst_region, dst_offset, src_region, src_offset, size } => {
                self.state.mem_copy(*dst_region, *dst_offset, *src_region, *src_offset, *size)?;
            }
            U30Op::MemFill { region, offset, value, size } => {
                self.state.mem_fill(*region, *offset, *value, *size)?;
            }
            U30Op::MemSize { dst, region } => {
                let data = self.state.regions.get(region)
                    .ok_or_else(|| Error::Generic(format!("U30X unknown region")))?;
                self.state.set_reg(*dst, U30Value::U64(data.bytes.len() as u64));
            }
            U30Op::MemGrow { dst, region: _, delta } => {
                let delta_val = self.state.reg(*delta)?.as_u64()?;
                // Simplified: just return delta as the new size
                self.state.set_reg(*dst, U30Value::U64(delta_val));
            }
            U30Op::Call { function, args, results } => {
                let fn_idx = *function as usize;
                if fn_idx >= self.module.functions.len() {
                    return Err(Error::Generic(format!("U30X call: function index {fn_idx} out of bounds")));
                }
                let caller_regs = self.state.regs.clone();
                let caller_fn_idx = self.state.fn_idx;
                let caller_block_idx = self.state.block_idx;
                let caller_op_idx = self.state.op_idx;
                self.call_stack.push(CallFrame {
                    return_fn_idx: caller_fn_idx,
                    return_block: caller_block_idx,
                    return_op_idx: caller_op_idx,
                    result_regs: results.clone(),
                    caller_regs,
                });
                // Set up callee registers
                let callee_fn = &self.module.functions[fn_idx];
                self.state.regs = BTreeMap::new();
                for (i, &arg_reg) in args.iter().enumerate() {
                    if i < callee_fn.params.len() {
                        let arg_val = self.state.reg(arg_reg)?.clone();
                        self.state.regs.insert(i as u32, arg_val);
                    }
                }
                self.state.fn_idx = fn_idx;
                self.state.block_idx = callee_fn.entry_block;
                self.state.op_idx = 0;
            }
            U30Op::IndirectCall { function, args, results } => {
                let fn_idx = self.state.reg(*function)?.as_u64()? as usize;
                if fn_idx >= self.module.functions.len() {
                    return Err(Error::Generic(format!("U30X indirect call: function index {fn_idx} out of bounds")));
                }
                let caller_regs = self.state.regs.clone();
                let caller_fn_idx = self.state.fn_idx;
                let caller_block_idx = self.state.block_idx;
                let caller_op_idx = self.state.op_idx;
                self.call_stack.push(CallFrame {
                    return_fn_idx: caller_fn_idx,
                    return_block: caller_block_idx,
                    return_op_idx: caller_op_idx,
                    result_regs: results.clone(),
                    caller_regs,
                });
                let callee_fn = &self.module.functions[fn_idx];
                self.state.regs = BTreeMap::new();
                for (i, &arg_reg) in args.iter().enumerate() {
                    if i < callee_fn.params.len() {
                        let arg_val = self.state.reg(arg_reg)?.clone();
                        self.state.regs.insert(i as u32, arg_val);
                    }
                }
                self.state.fn_idx = fn_idx;
                self.state.block_idx = callee_fn.entry_block;
                self.state.op_idx = 0;
            }
            U30Op::TableBr { table, index } => {
                let idx = self.state.reg(*index)?.as_u64()? as usize;
                let table_decl = self.module.tables.iter()
                    .find(|t| t.id == *table)
                    .ok_or_else(|| Error::Generic(format!("U30X unknown table {table}")))?;
                let target = *table_decl.targets.get(idx)
                    .ok_or_else(|| Error::Generic(format!("U30X TableBr: index {idx} out of bounds")))?;
                self.state.block_idx = target;
                self.state.op_idx = 0;
            }
            U30Op::Break { code } => {
                let c = self.state.reg(*code)?.as_u64()?;
                return Err(Error::Generic(format!("U30X break({c})")));
            }
            U30Op::Assert { cond, msg: _ } => {
                let c = self.state.reg(*cond)?.as_bool()?;
                if !c {
                    return Err(Error::Generic("U30X assertion failed".into()));
                }
            }
            U30Op::Nop => {}
        }
        Ok(())
    }

    fn process_terminator(&mut self) -> Result<DebugEvent> {
        let block = self.state.current_block(&self.module).clone();
        match &block.terminator {
            U30Terminator::Br { target } => {
                self.state.block_idx = *target;
                self.state.op_idx = 0;
            }
            U30Terminator::BrIf { cond, then_target, else_target } => {
                let c = self.state.reg(*cond)?.as_bool()?;
                self.state.block_idx = if c { *then_target } else { *else_target };
                self.state.op_idx = 0;
            }
            U30Terminator::Ret { values } => {
                if self.call_stack.is_empty() {
                    return Ok(DebugEvent::Halted { reason: "return".into() });
                }
                // Pop call frame
                let frame = self.call_stack.pop().unwrap();
                // Collect return values from current regs
                let mut ret_vals: Vec<U30Value> = Vec::new();
                for &reg in values {
                    ret_vals.push(self.state.reg(reg)?.clone());
                }
                // Restore caller state
                self.state.regs = frame.caller_regs;
                self.state.fn_idx = frame.return_fn_idx;
                self.state.block_idx = frame.return_block;
                self.state.op_idx = frame.return_op_idx + 1; // skip the Call op
                // Write result registers
                for (i, &result_reg) in frame.result_regs.iter().enumerate() {
                    if i < ret_vals.len() {
                        self.state.set_reg(result_reg, ret_vals[i].clone());
                    }
                }
            }
            U30Terminator::TailCall { function, args } => {
                // Read function index from register
                let fn_idx = self.state.reg(*function)?.as_u64()? as usize;
                if fn_idx >= self.module.functions.len() {
                    return Err(Error::Generic(format!("U30X TailCall: function index {fn_idx} out of bounds")));
                }
                // Collect args before resetting regs
                let arg_vals: Vec<U30Value> = args.iter()
                    .map(|&r| Ok(self.state.reg(r)?.clone()))
                    .collect::<std::result::Result<Vec<_>, Error>>()?;
                let callee_fn = &self.module.functions[fn_idx];
                self.state.regs = BTreeMap::new();
                for (i, arg_val) in arg_vals.into_iter().enumerate() {
                    if i < callee_fn.params.len() {
                        self.state.regs.insert(i as u32, arg_val);
                    }
                }
                self.state.fn_idx = fn_idx;
                self.state.block_idx = callee_fn.entry_block;
                self.state.op_idx = 0;
            }
            U30Terminator::Trap { code } => {
                return Ok(DebugEvent::Halted { reason: format!("trap({})", code) });
            }
        }
        Ok(DebugEvent::Step {
            fn_idx: self.state.fn_idx,
            block_idx: self.state.block_idx,
            op_idx: self.state.op_idx,
            op: U30Op::Nop,
        })
    }

    /// Get a formatted register dump.
    pub fn show_registers(&self) -> String {
        let mut lines = vec![format!("fn{}:block{}:op{}", self.state.fn_idx, self.state.block_idx, self.state.op_idx)];
        for (&r, v) in &self.state.regs {
            lines.push(format!("  %{r} = {v:?}"));
        }
        lines.join("\n")
    }

    /// Get a formatted region dump.
    pub fn show_memory(&self, region_id: u32) -> String {
        match self.state.regions.get(&region_id) {
            Some(data) => {
                let mut lines = vec![format!("Region {region_id} ({} bytes, r={}, w={}):", data.bytes.len(), data.readable, data.writable)];
                for (i, chunk) in data.bytes.chunks(16).enumerate() {
                    let hex: Vec<String> = chunk.iter().map(|&b| format!("{:02x}", b)).collect();
                    let ascii: String = chunk.iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect();
                    lines.push(format!("  {:04x}: {:16}  {}", i * 16, hex.join(" "), ascii));
                }
                lines.join("\n")
            }
            None => format!("Region {region_id} not found"),
        }
    }

    /// Get call stack.
    pub fn show_backtrace(&self) -> String {
        let mut lines = vec![format!("fn{}:block{}:op{}", self.state.fn_idx, self.state.block_idx, self.state.op_idx)];
        for (i, frame) in self.call_stack.iter().enumerate() {
            lines.push(format!("  #{i} fn{}:block{}:op{}", frame.return_fn_idx, frame.return_block, frame.return_op_idx));
        }
        lines.join("\n")
    }
}

// ─── Binary evaluator ────────────────────────────────────────────────────────

fn eval_binary(op: U30BinaryOp, a: &U30Value, b: &U30Value) -> Result<U30Value> {
    match op {
        U30BinaryOp::AddWrapU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.wrapping_add(bv)))
        }
        U30BinaryOp::AddWrapU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.wrapping_add(bv)))
        }
        U30BinaryOp::SubWrapU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.wrapping_sub(bv)))
        }
        U30BinaryOp::SubWrapU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.wrapping_sub(bv)))
        }
        U30BinaryOp::MulWrapU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.wrapping_mul(bv)))
        }
        U30BinaryOp::MulWrapU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.wrapping_mul(bv)))
        }
        U30BinaryOp::AndU8 => {
            let av = a.as_u8()?;
            let bv = b.as_u8()?;
            Ok(U30Value::U8(av & bv))
        }
        U30BinaryOp::OrU8 => {
            let av = a.as_u8()?;
            let bv = b.as_u8()?;
            Ok(U30Value::U8(av | bv))
        }
        U30BinaryOp::XorU8 => {
            let av = a.as_u8()?;
            let bv = b.as_u8()?;
            Ok(U30Value::U8(av ^ bv))
        }
        U30BinaryOp::ShlU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.wrapping_shl(bv as u32)))
        }
        U30BinaryOp::ShlU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.wrapping_shl(bv)))
        }
        U30BinaryOp::ShrU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.wrapping_shr(bv as u32)))
        }
        U30BinaryOp::ShrU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.wrapping_shr(bv)))
        }
        U30BinaryOp::DivU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            if bv == 0 { return Err(Error::Generic("div-by-zero".into())); }
            Ok(U30Value::U64(av / bv))
        }
        U30BinaryOp::DivU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            if bv == 0 { return Err(Error::Generic("div-by-zero".into())); }
            Ok(U30Value::U32(av / bv))
        }
        U30BinaryOp::RemU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            if bv == 0 { return Err(Error::Generic("div-by-zero".into())); }
            Ok(U30Value::U64(av % bv))
        }
        U30BinaryOp::RemU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            if bv == 0 { return Err(Error::Generic("div-by-zero".into())); }
            Ok(U30Value::U32(av % bv))
        }
        U30BinaryOp::Eq => {
            Ok(U30Value::Bool(a == b))
        }
        U30BinaryOp::LtU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::Bool(av < bv))
        }
        U30BinaryOp::GtU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::Bool(av > bv))
        }
        U30BinaryOp::GeU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::Bool(av >= bv))
        }
        U30BinaryOp::LeU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::Bool(av <= bv))
        }
        U30BinaryOp::LeU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::Bool(av <= bv))
        }
        U30BinaryOp::MinU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.min(bv)))
        }
        U30BinaryOp::MaxU64 => {
            let av = a.as_u64()?;
            let bv = b.as_u64()?;
            Ok(U30Value::U64(av.max(bv)))
        }
        U30BinaryOp::MinU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.min(bv)))
        }
        U30BinaryOp::MaxU32 => {
            let av = a.as_u32()?;
            let bv = b.as_u32()?;
            Ok(U30Value::U32(av.max(bv)))
        }
    }
}

// Export DebugEvent for CLI use
pub use DebugEvent as U30DebugEvent;
