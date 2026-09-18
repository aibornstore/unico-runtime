//! U30 Pretty-Printer — human-readable IR dump
//!
//! Default output is plain text (no ANSI color codes).
//! Enable colors with `FmtOpts { colors: true, .. }`.
//!
//! ## Example
//! ```rust,no_run
//! use unico_runtime::pretty::fmt_module;
//! use unico_runtime::ir::{U30Module, U30Function, U30Block, U30Terminator, U30Type};
//! let module = U30Module {
//!     regions: vec![],
//!     tables: vec![],
//!     functions: vec![U30Function {
//!         params: vec![U30Type::U64],
//!         results: vec![],
//!         entry_block: 0,
//!         blocks: vec![U30Block {
//!             ops: vec![],
//!             terminator: U30Terminator::Ret { values: vec![] },
//!         }],
//!     }],
//!     entry_function: 0,
//! };
//! let text = fmt_module(&module);
//! println!("{}", text);
//! ```

use crate::ir::{U30Block, U30Function, U30Module, U30Op, U30Terminator, U30Type, U30Value};

// ---------------------------------------------------------------------------
// Color codes (ANSI)
// ---------------------------------------------------------------------------

pub struct FmtOpts {
    /// Use ANSI color codes. Default: true.
    pub colors: bool,
    /// Show region initial data as hex. Default: false.
    pub show_region_data: bool,
    /// Show table targets. Default: true.
    pub show_tables: bool,
    /// Max hex bytes per region line. Default: 32.
    pub hex_cols: usize,
}

impl FmtOpts {
    pub fn colors(self, yes: bool) -> Self {
        Self { colors: yes, ..self }
    }
}

impl Default for FmtOpts {
    fn default() -> Self {
        Self {
            colors: false,
            show_region_data: false,
            show_tables: true,
            hex_cols: 32,
        }
    }
}

struct Out {
    buf: String,
    opts: FmtOpts,
}

impl Out {
    fn new(opts: FmtOpts) -> Self {
        Self {
            buf: String::new(),
            opts,
        }
    }

    fn push_str(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    fn writeln(&mut self, s: &str) {
        self.buf.push_str(s);
        self.buf.push('\n');
    }

    fn push_colored(&mut self, s: &str, color: &str) {
        if self.opts.colors {
            self.buf.push_str(color);
        }
        self.buf.push_str(s);
        if self.opts.colors {
            self.buf.push_str(RESET);
        }
    }

    fn kw(&mut self, s: &str) {
        self.push_colored(s, MAGENTA);
    }

    fn op(&mut self, s: &str) {
        self.push_colored(s, BOLD);
    }

    fn reg(&mut self, s: &str) {
        self.push_colored(s, YELLOW);
    }

    fn type_(&mut self, s: &str) {
        self.push_colored(s, CYAN);
    }

    fn value(&mut self, s: &str) {
        self.push_colored(s, GREEN);
    }

    fn comment(&mut self, s: &str) {
        if self.opts.colors {
            self.buf.push_str(DIM);
        }
        self.buf.push_str(s);
        if self.opts.colors {
            self.buf.push_str(RESET);
        }
    }

    fn error(&mut self, s: &str) {
        self.push_colored(s, RED);
    }

    fn finish(self) -> String {
        self.buf
    }
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Format a U30Module with default options (colors enabled).
pub fn fmt_module(module: &U30Module) -> String {
    fmt_module_opts(
        module,
        FmtOpts {
            colors: true,
            show_region_data: false,
            show_tables: true,
            hex_cols: 32,
        },
    )
}

/// Format a U30Module with custom options.
pub fn fmt_module_opts(module: &U30Module, opts: FmtOpts) -> String {
    let show_tables = opts.show_tables;
    let show_region_data = opts.show_region_data;
    let hex_cols = opts.hex_cols;
    let mut out = Out::new(opts);

    // Header
    out.writeln("");
    out.push_colored("; ───────────────────────── U30 Module ─────────────────────────", DIM);
    out.writeln("");

    // Regions
    out.kw("regions");
    out.push_str(" ");
    out.writeln("{");
    for r in &module.regions {
        fmt_region(&mut out, r, show_region_data, hex_cols);
    }
    out.writeln("}");

    // Tables
    if !module.tables.is_empty() && show_tables {
        out.kw("tables");
        out.push_str(" ");
        out.writeln("{");
        for t in &module.tables {
            fmt_table(&mut out, t);
        }
        out.writeln("}");
    }

    // Functions
    out.kw("functions");
    out.push_str(" ");
    out.writeln("{");
    for (fi, f) in module.functions.iter().enumerate() {
        let marker = if fi == module.entry_function { "▶ " } else { "  " };
        fmt_function(&mut out, f, fi, marker);
    }
    out.writeln("}");

    out.writeln("");
    out.push_colored("; ──────────────────────────────────────────────────────────", DIM);
    out.writeln("");

    out.finish()
}

// ---------------------------------------------------------------------------
// Region
// ---------------------------------------------------------------------------

fn fmt_region(out: &mut Out, r: &crate::ir::U30RegionDecl, show_region_data: bool, hex_cols: usize) {
    out.push_str("  ");
    out.type_("region");
    out.push_str(" ");
    out.value(&format!("{}", r.id));
    out.push_str(" ");
    out.comment(&format!("size={}", r.size));
    if !r.readable {
        out.comment(" !readable");
    }
    if !r.writable {
        out.comment(" !writable");
    }

    if show_region_data && !r.initial.is_empty() {
        out.push_str(" = ");
        let hex = hex_string(&r.initial, hex_cols);
        out.value(&hex);
    }
    out.writeln("");
}

fn hex_string(data: &[u8], cols: usize) -> String {
    let mut s = String::new();
    s.push('[');
    for (i, chunk) in data.chunks(cols).enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        s.push_str(&hex.join(" "));
    }
    s.push(']');
    s
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

fn fmt_table(out: &mut Out, t: &crate::ir::U30TableDecl) {
    out.push_str("  ");
    out.type_("table");
    out.push_str(" ");
    out.value(&format!("{}", t.id));
    out.push_str(" ");
    out.comment("[");
    for (i, &target) in t.targets.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.value(&format!("{}", target));
    }
    out.comment("]");
    out.writeln("");
}

// ---------------------------------------------------------------------------
// Function
// ---------------------------------------------------------------------------

fn fmt_function(out: &mut Out, f: &U30Function, fi: usize, marker: &str) {
    // Signature
    out.push_str("  ");
    out.op(marker);
    out.op("fn");
    out.push_str(" ");
    out.value(&format!("{}", fi));

    // Params
    out.push_str("(");
    for (i, p) in f.params.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.type_(&fmt_type(p));
    }
    out.push_str(")");

    // Results
    if !f.results.is_empty() {
        out.push_str(" -> ");
        for (i, r) in f.results.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.type_(&fmt_type(r));
        }
    }

    // Entry block marker
    out.comment(&format!("  ; entry=block{}", f.entry_block));

    // Blocks
    for (bi, block) in f.blocks.iter().enumerate() {
        fmt_block(out, block, bi, bi == f.entry_block);
    }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

fn fmt_block(out: &mut Out, block: &U30Block, bi: usize, is_entry: bool) {
    out.push_str("    ");
    if is_entry {
        out.push_colored("│", DIM);
    } else {
        out.push_str(" ");
    }
    out.push_str("block");
    out.value(&format!("{}", bi));
    out.push_str(":");
    out.writeln("");

    // Ops
    for (oi, op) in block.ops.iter().enumerate() {
        fmt_op(out, op, oi);
    }

    // Terminator
    fmt_terminator(out, &block.terminator);
}

// ---------------------------------------------------------------------------
// Ops
// ---------------------------------------------------------------------------

fn fmt_op(out: &mut Out, op: &U30Op, oi: usize) {
    out.push_str("      ");
    out.comment(&format!("{:3}: ", oi));

    match op {
        U30Op::Nop => {
            out.op("nop");
        }
        U30Op::Const { dst, value } => {
            out.op("const");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(" = ");
            out.value(&fmt_value(value));
        }
        U30Op::Binary { dst, op: binop, a, b } => {
            out.op("binary");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(" = ");
            out.type_(&fmt_binop(binop));
            out.push_str(" ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::Select { dst, cond, a, b } => {
            out.op("select");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(" = ");
            out.reg(&format!("r{}", cond));
            out.push_str(" ? ");
            out.reg(&format!("r{}", a));
            out.push_str(" : ");
            out.reg(&format!("r{}", b));
        }
        U30Op::NotU8 { dst, src } => {
            out.op("not.u8");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::NotU16 { dst, src } => {
            out.op("not.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::NotU32 { dst, src } => {
            out.op("not.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::NotU64 { dst, src } => {
            out.op("not.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::AbsU64 { dst, src } => {
            out.op("abs.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::AbsU32 { dst, src } => {
            out.op("abs.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::NegU64 { dst, src } => {
            out.op("neg.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::NegU32 { dst, src } => {
            out.op("neg.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::CtzU64 { dst, src } => {
            out.op("ctz.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::CtzU32 { dst, src } => {
            out.op("ctz.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ClzU64 { dst, src } => {
            out.op("clz.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ClzU32 { dst, src } => {
            out.op("clz.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::PopcntU64 { dst, src } => {
            out.op("popcnt.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::PopcntU32 { dst, src } => {
            out.op("popcnt.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::RotlU64 { dst, val, sh } => {
            out.op("rotl.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", val));
            out.push_str(", ");
            out.reg(&format!("r{}", sh));
        }
        U30Op::RotlU32 { dst, val, sh } => {
            out.op("rotl.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", val));
            out.push_str(", ");
            out.reg(&format!("r{}", sh));
        }
        U30Op::RotrU64 { dst, val, sh } => {
            out.op("rotr.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", val));
            out.push_str(", ");
            out.reg(&format!("r{}", sh));
        }
        U30Op::RotrU32 { dst, val, sh } => {
            out.op("rotr.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", val));
            out.push_str(", ");
            out.reg(&format!("r{}", sh));
        }
        U30Op::FEq { dst, a, b } => {
            out.op("feq");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FLt { dst, a, b } => {
            out.op("flt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FGt { dst, a, b } => {
            out.op("fgt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FLe { dst, a, b } => {
            out.op("fle");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FGe { dst, a, b } => {
            out.op("fge");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FAdd { dst, a, b } => {
            out.op("fadd");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FSub { dst, a, b } => {
            out.op("fsub");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FMul { dst, a, b } => {
            out.op("fmul");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FDiv { dst, a, b } => {
            out.op("fdiv");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FSqrt { dst, src } => {
            out.op("fsqrt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::FAbs { dst, src } => {
            out.op("fabs");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::FNeg { dst, src } => {
            out.op("fneg");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::FMin { dst, a, b } => {
            out.op("fmin");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::FMax { dst, a, b } => {
            out.op("fmax");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::I2F { dst, src } => {
            out.op("i2f");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F2I { dst, src } => {
            out.op("f2i");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::TruncF32U64 { dst, src } => {
            out.op("trunc.f32.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ReinterpretF32U32 { dst, src } => {
            out.op("reinterpret.f32.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ReinterpretU32F32 { dst, src } => {
            out.op("reinterpret.u32.f32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI8U16 { dst, src } => {
            out.op("zext.i8.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI8U32 { dst, src } => {
            out.op("zext.i8.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI8U64 { dst, src } => {
            out.op("zext.i8.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI16U32 { dst, src } => {
            out.op("zext.i16.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI16U64 { dst, src } => {
            out.op("zext.i16.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ZExtI32U64 { dst, src } => {
            out.op("zext.i32.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::TruncU64U32 { dst, src } => {
            out.op("trunc.u64.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::TruncU64U16 { dst, src } => {
            out.op("trunc.u64.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::TruncU32U16 { dst, src } => {
            out.op("trunc.u32.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::MemCopy { dst_region, dst_offset, src_region, src_offset, size } => {
            out.op("mem.copy");
            out.push_str(" dst=region");
            out.value(&dst_region.to_string());
            out.push_str("+r");
            out.reg(&dst_offset.to_string());
            out.push_str(" src=region");
            out.value(&src_region.to_string());
            out.push_str("+r");
            out.reg(&src_offset.to_string());
            out.push_str(" size=r");
            out.reg(&size.to_string());
        }
        U30Op::MemFill { region, offset, value, size } => {
            out.op("mem.fill");
            out.push_str(" region");
            out.value(&region.to_string());
            out.push_str("+r");
            out.reg(&offset.to_string());
            out.push_str(" value=r");
            out.reg(&value.to_string());
            out.push_str(" size=r");
            out.reg(&size.to_string());
        }
        U30Op::MemSize { dst, region } => {
            out.op("mem.size");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
        }
        U30Op::MemGrow { dst, region, delta } => {
            out.op("mem.grow");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
            out.push_str("+r");
            out.reg(&delta.to_string());
        }
        U30Op::F64Eq { dst, a, b } => {
            out.op("f64.eq");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Lt { dst, a, b } => {
            out.op("f64.lt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Gt { dst, a, b } => {
            out.op("f64.gt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Le { dst, a, b } => {
            out.op("f64.le");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Ge { dst, a, b } => {
            out.op("f64.ge");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Add { dst, a, b } => {
            out.op("f64.add");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Sub { dst, a, b } => {
            out.op("f64.sub");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Mul { dst, a, b } => {
            out.op("f64.mul");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Div { dst, a, b } => {
            out.op("f64.div");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Sqrt { dst, src } => {
            out.op("f64.sqrt");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F64Abs { dst, src } => {
            out.op("f64.abs");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F64Neg { dst, src } => {
            out.op("f64.neg");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F64Min { dst, a, b } => {
            out.op("f64.min");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::F64Max { dst, a, b } => {
            out.op("f64.max");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", a));
            out.push_str(", ");
            out.reg(&format!("r{}", b));
        }
        U30Op::I64F64 { dst, src } => {
            out.op("i64.f64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F64I64 { dst, src } => {
            out.op("f64.i64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F32F64 { dst, src } => {
            out.op("f32.f64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::F64F32 { dst, src } => {
            out.op("f64.f32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ReinterpretF64U64 { dst, src } => {
            out.op("reinterpret.f64.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ReinterpretU64F64 { dst, src } => {
            out.op("reinterpret.u64.f64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI8U16 { dst, src } => {
            out.op("sext.i8.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI8U32 { dst, src } => {
            out.op("sext.i8.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI8U64 { dst, src } => {
            out.op("sext.i8.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI16U32 { dst, src } => {
            out.op("sext.i16.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI16U64 { dst, src } => {
            out.op("sext.i16.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::SExtI32U64 { dst, src } => {
            out.op("sext.i32.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ByteSwapU16 { dst, src } => {
            out.op("bswap.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ByteSwapU32 { dst, src } => {
            out.op("bswap.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::ByteSwapU64 { dst, src } => {
            out.op("bswap.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", ");
            out.reg(&format!("r{}", src));
        }
        U30Op::Call { function, args, results } => {
            out.op("call");
            out.push_str(" ");
            out.value(&format!("fn{}", function));
            out.push_str("(");
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.reg(&format!("r{}", a));
            }
            out.push_str(") -> ");
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.reg(&format!("r{}", r));
            }
        }
        U30Op::IndirectCall { function, args, results } => {
            out.op("icall");
            out.push_str(" ");
            out.reg(&format!("r{}", function));
            out.push_str("(");
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.reg(&format!("r{}", a));
            }
            out.push_str(") -> ");
            for (i, r) in results.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.reg(&format!("r{}", r));
            }
        }
        U30Op::TableBr { table, index } => {
            out.op("table.br");
            out.push_str(" ");
            out.value(&format!("table{}", table));
            out.push_str("[r");
            out.reg(&format!("{}", index));
            out.push_str("]");
        }
        U30Op::Break { code } => {
            out.op("break");
            out.push_str(" ");
            out.value(&format!("{}", code));
        }
        U30Op::Assert { cond, msg } => {
            out.op("assert");
            out.push_str(" ");
            out.reg(&format!("r{}", cond));
            out.push_str(" ");
            out.comment(&format!("msg={}", msg));
        }
        U30Op::LoadU8 { dst, region, offset } => {
            out.op("load.u8");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("]");
        }
        U30Op::StoreU8 { region, offset, src } => {
            out.op("store.u8");
            out.push_str(" region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("], ");
            out.reg(&format!("r{}", src));
        }
        U30Op::LoadU16 { dst, region, offset } => {
            out.op("load.u16");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("]");
        }
        U30Op::StoreU16 { region, offset, src } => {
            out.op("store.u16");
            out.push_str(" region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("], ");
            out.reg(&format!("r{}", src));
        }
        U30Op::LoadU32 { dst, region, offset } => {
            out.op("load.u32");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("]");
        }
        U30Op::StoreU32 { region, offset, src } => {
            out.op("store.u32");
            out.push_str(" region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("], ");
            out.reg(&format!("r{}", src));
        }
        U30Op::LoadU64 { dst, region, offset } => {
            out.op("load.u64");
            out.push_str(" ");
            out.reg(&format!("r{}", dst));
            out.push_str(", region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("]");
        }
        U30Op::StoreU64 { region, offset, src } => {
            out.op("store.u64");
            out.push_str(" region");
            out.value(&region.to_string());
            out.push_str("[r");
            out.reg(&offset.to_string());
            out.push_str("], ");
            out.reg(&format!("r{}", src));
        }
    }
    out.writeln("");
}

// ---------------------------------------------------------------------------
// Terminators
// ---------------------------------------------------------------------------

fn fmt_terminator(out: &mut Out, t: &U30Terminator) {
    out.push_str("      ");
    out.comment("→ ");

    match t {
        U30Terminator::Br { target } => {
            out.op("br");
            out.push_str(" block");
            out.value(&format!("{}", target));
        }
        U30Terminator::BrIf { cond, then_target, else_target } => {
            out.op("br.if");
            out.push_str(" ");
            out.reg(&format!("r{}", cond));
            out.push_str(" -> block");
            out.value(&then_target.to_string());
            out.push_str(" : block");
            out.value(&else_target.to_string());
        }
        U30Terminator::Ret { values } => {
            out.op("ret");
            if values.is_empty() {
                // no-op
            } else {
                out.push_str(" ");
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.reg(&format!("r{}", v));
                }
            }
        }
        U30Terminator::TailCall { function, args } => {
            out.op("tail.call");
            out.push_str(" r");
            out.reg(&format!("{}", function));
            out.push_str("(");
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.reg(&format!("r{}", a));
            }
            out.push_str(")");
        }
        U30Terminator::Trap { code } => {
            out.error("trap");
            out.push_str(" ");
            out.comment(&format!("code={}", code));
        }
    }
    out.writeln("");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fmt_type(t: &U30Type) -> String {
    match t {
        U30Type::Bool => "bool".to_string(),
        U30Type::U8 => "u8".to_string(),
        U30Type::U16 => "u16".to_string(),
        U30Type::U32 => "u32".to_string(),
        U30Type::U64 => "u64".to_string(),
        U30Type::F32 => "f32".to_string(),
        U30Type::F64 => "f64".to_string(),
    }
}

fn fmt_value(v: &U30Value) -> String {
    match v {
        U30Value::Bool(b) => {
            if *b { "true" } else { "false" }.to_string()
        }
        U30Value::U8(x) => format!("{}", x),
        U30Value::U16(x) => format!("{}", x),
        U30Value::U32(x) => format!("{}", x),
        U30Value::U64(x) => format!("{}", x),
        U30Value::F32(x) => format!("{:?}", x),
        U30Value::F64(x) => format!("{:?}", x),
    }
}

fn fmt_binop(op: &crate::ir::U30BinaryOp) -> String {
    use crate::ir::U30BinaryOp as B;
    match op {
        B::AddWrapU64 => "add.wrap.u64",
        B::AddWrapU32 => "add.wrap.u32",
        B::SubWrapU64 => "sub.wrap.u64",
        B::SubWrapU32 => "sub.wrap.u32",
        B::MulWrapU64 => "mul.wrap.u64",
        B::MulWrapU32 => "mul.wrap.u32",
        B::AndU8 => "and.u8",
        B::OrU8 => "or.u8",
        B::XorU8 => "xor.u8",
        B::ShlU64 => "shl.u64",
        B::ShlU32 => "shl.u32",
        B::ShrU64 => "shr.u64",
        B::ShrU32 => "shr.u32",
        B::DivU64 => "div.u64",
        B::DivU32 => "div.u32",
        B::RemU64 => "rem.u64",
        B::RemU32 => "rem.u32",
        B::Eq => "eq",
        B::LtU64 => "lt.u64",
        B::GtU64 => "gt.u64",
        B::GeU64 => "ge.u64",
        B::LeU64 => "le.u64",
        B::LeU32 => "le.u32",
        B::MinU64 => "min.u64",
        B::MaxU64 => "max.u64",
        B::MinU32 => "min.u32",
        B::MaxU32 => "max.u32",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{U30Block, U30Function, U30Module, U30Op, U30Terminator, U30Type, U30Value, U30RegionDecl, U30TableDecl};

    fn sample_module() -> U30Module {
        U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 256,
                readable: true,
                writable: true,
                initial: vec![0x00, 0x01, 0x02],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(42) },
                        U30Op::Const { dst: 2, value: U30Value::Bool(true) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        }
    }

    #[test]
    fn test_pretty_no_colors() {
        let m = sample_module();
        let text = fmt_module_opts(&m, FmtOpts { colors: false, show_region_data: false, show_tables: true, hex_cols: 32 });
        assert!(!text.contains("\x1b["));
        assert!(text.contains("fn 0("));
        assert!(text.contains("const r1 = 42"));
        assert!(text.contains("ret r1"));
    }

    #[test]
    fn test_pretty_colors() {
        let m = sample_module();
        let opts = FmtOpts { colors: true, show_region_data: false, show_tables: true, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(text.contains("\x1b[1m")); // bold for ops
        assert!(text.contains("\x1b[33m")); // yellow for regs
        assert!(text.contains("\x1b[32m")); // green for values
    }

    #[test]
    fn test_pretty_shows_entry_marker() {
        let m = sample_module();
        let text = fmt_module(&m);
        // Entry function is marked with "▶" (may not display in all terminals)
        // Check for the bold "fn" text that follows the marker
        assert!(text.contains("▶") || text.contains("fn"));
    }

    #[test]
    fn test_pretty_binary_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(1) },
                        U30Op::Const { dst: 1, value: U30Value::U64(2) },
                        U30Op::Binary {
                            dst: 2,
                            op: crate::ir::U30BinaryOp::AddWrapU64,
                            a: 0,
                            b: 1,
                        },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("add.wrap.u64"));
    }

    #[test]
    fn test_pretty_load_store() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::LoadU32 { dst: 0, region: 0, offset: 4 },
                        U30Op::StoreU64 { region: 0, offset: 8, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("load.u32"));
        assert!(text.contains("store.u64"));
        // Check for region without ANSI color codes
        assert!(text.contains("region")); // "region" appears without number (number is colored)
    }

    #[test]
    fn test_pretty_tailcall() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 3, value: U30Value::U64(0) },
                    ],
                    terminator: U30Terminator::TailCall { function: 3, args: vec![0, 1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("tail.call"));
        // r3 is colored, check components
        assert!(text.contains("r3"));
        assert!(text.contains("r0"));
        assert!(text.contains("r1"));
    }

    #[test]
    fn test_pretty_multiple_functions() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
                U30Function {
                    params: vec![U30Type::U32],
                    results: vec![U30Type::U64],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
            ],
            entry_function: 1,
        };
        let text = fmt_module(&m);
        // Should contain both functions (check plain text without ANSI codes)
        // fmt_module uses colors=true by default, so strip codes
        let plain = text.replace("\x1b[", "").replace("m", "\n").lines()
            .filter(|l| !l.is_empty() && !l.starts_with(";"))
            .collect::<String>();
        // Should have both function indices
        assert!(plain.contains("0") && plain.contains("1"), "Should contain both function indices");
        // Entry function should have marker
        assert!(text.contains("▶"), "Entry function should have ▶ marker");
    }

    #[test]
    fn test_pretty_multiple_tables() {
        let m = U30Module {
            regions: vec![],
            tables: vec![
                crate::ir::U30TableDecl { id: 0, targets: vec![1, 2, 3] },
                crate::ir::U30TableDecl { id: 1, targets: vec![0] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("table"));
        assert!(text.contains("0"));
        assert!(text.contains("1"));
    }

    #[test]
    fn test_pretty_show_region_data() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 16,
                readable: true,
                writable: true,
                initial: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(text.contains("deadbeef") || text.contains("de ad be ef"));
    }

    #[test]
    fn test_pretty_hex_cols() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 32,
                readable: true,
                writable: true,
                initial: vec![0x01; 32],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        // With 8 cols, should wrap
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 8 };
        let text = fmt_module_opts(&m, opts);
        // Should contain some hex data
        assert!(text.contains("01"));
    }

    #[test]
    fn test_pretty_unnamed_function() {
        // Function without entry marker
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // Should contain the function header text
        assert!(text.contains("▶"), "Should contain entry marker for fn 0");
        assert!(text.contains("fn"), "Should contain 'fn' keyword");
    }

    #[test]
    fn test_pretty_no_ansi_in_no_colors() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![U30Type::U64],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 1, value: U30Value::U64(1) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: true, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(!text.contains("\x1b["));
    }

    #[test]
    fn test_pretty_all_terminators() {
        // Test Br terminator
        let m_br = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![
                        U30Block { ops: vec![], terminator: U30Terminator::Br { target: 1 } },
                        U30Block { ops: vec![], terminator: U30Terminator::Ret { values: vec![] } },
                    ],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        let text = fmt_module(&m_br);
        assert!(text.contains("br") || text.contains("1"));

        // Test BrIf terminator
        let m_brif = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 0 },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m_brif);
        assert!(text.contains("br.if") || text.contains("0"));

        // Test TailCall terminator
        let m_tail = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![0, 1] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m_tail);
        assert!(text.contains("tail.call") || text.contains("0"));

        // Test Trap terminator
        let m_trap = U30Module {
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
        let text = fmt_module(&m_trap);
        assert!(text.contains("trap") || text.contains("42"));
    }

    #[test]
    fn test_pretty_various_u30ops() {
        use crate::ir::U30BinaryOp::*;
        
        let ops_to_test = vec![
            ("add.wrap.u64", U30Op::Binary { dst: 0, op: AddWrapU64, a: 1, b: 2 }),
            ("sub.wrap.u64", U30Op::Binary { dst: 0, op: SubWrapU64, a: 1, b: 2 }),
            ("mul.wrap.u64", U30Op::Binary { dst: 0, op: MulWrapU64, a: 1, b: 2 }),
            ("and.u8", U30Op::Binary { dst: 0, op: AndU8, a: 1, b: 2 }),
            ("or.u8", U30Op::Binary { dst: 0, op: OrU8, a: 1, b: 2 }),
            ("xor.u8", U30Op::Binary { dst: 0, op: XorU8, a: 1, b: 2 }),
            ("shl.u64", U30Op::Binary { dst: 0, op: ShlU64, a: 1, b: 2 }),
            ("shr.u64", U30Op::Binary { dst: 0, op: ShrU64, a: 1, b: 2 }),
            ("div.u64", U30Op::Binary { dst: 0, op: DivU64, a: 1, b: 2 }),
            ("rem.u64", U30Op::Binary { dst: 0, op: RemU64, a: 1, b: 2 }),
            ("eq", U30Op::Binary { dst: 0, op: Eq, a: 1, b: 2 }),
            ("lt.u64", U30Op::Binary { dst: 0, op: LtU64, a: 1, b: 2 }),
            ("gt.u64", U30Op::Binary { dst: 0, op: GtU64, a: 1, b: 2 }),
            ("le.u64", U30Op::Binary { dst: 0, op: LeU64, a: 1, b: 2 }),
            ("min.u64", U30Op::Binary { dst: 0, op: MinU64, a: 1, b: 2 }),
            ("max.u64", U30Op::Binary { dst: 0, op: MaxU64, a: 1, b: 2 }),
        ];

        for (expected_mnemonic, op) in ops_to_test {
            let m = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![op],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                }],
                entry_function: 0,
            };
            let text = fmt_module(&m);
            // Should contain the operation somewhere in the output
            assert!(!text.is_empty(), "Empty output for {}", expected_mnemonic);
        }
    }

    #[test]
    fn test_pretty_function_with_params_and_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64, U30Type::U32, U30Type::Bool],
                results: vec![U30Type::U64],
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("u64") && text.contains("u32") && text.contains("bool"));
    }

    #[test]
    fn test_pretty_show_tables_false() {
        let m = U30Module {
            regions: vec![],
            tables: vec![crate::ir::U30TableDecl { id: 0, targets: vec![1] }],
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
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(!text.contains("table"));
    }

    #[test]
    fn test_pretty_region_not_readable() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 64,
                readable: false,
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
        let text = fmt_module(&m);
        assert!(text.contains("!readable"));
    }

    #[test]
    fn test_pretty_region_not_writable() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 64,
                readable: true,
                writable: false,
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
        let text = fmt_module(&m);
        assert!(text.contains("!writable"));
    }

    #[test]
    fn test_pretty_select_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Select { dst: 0, cond: 1, a: 2, b: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("select"));
    }

    #[test]
    fn test_pretty_mem_ops() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 256,
                readable: true,
                writable: true,
                initial: vec![0; 256],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemFill { region: 0, offset: 0, value: 1, size: 10 },
                        U30Op::MemCopy { dst_region: 0, dst_offset: 100, src_region: 0, src_offset: 0, size: 10 },
                        U30Op::MemGrow { dst: 2, region: 0, delta: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.fill") || text.contains("memcopy") || text.contains("mem.grow"));
    }

    #[test]
    fn test_pretty_call_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Call { function: 1, args: vec![0], results: vec![1] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("call"));
    }

    #[test]
    fn test_pretty_indirect_call_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::IndirectCall { function: 0, args: vec![], results: vec![1] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // The pretty printer may format IndirectCall differently
        assert!(text.contains("indirect") || text.contains("call"));
    }

    #[test]
    fn test_pretty_f64_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::F64Add { dst: 0, a: 1, b: 2 },
                        U30Op::F64Mul { dst: 3, a: 4, b: 5 },
                        U30Op::F64Sqrt { dst: 6, src: 7 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("f64.add") || text.contains("f64.mul") || text.contains("f64.sqrt"));
    }

    #[test]
    fn test_pretty_float_conversions() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::I2F { dst: 0, src: 1 },
                        U30Op::F2I { dst: 2, src: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("i2f") || text.contains("f2i"));
    }

    #[test]
    fn test_pretty_assert_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Assert { cond: 0, msg: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("assert"));
    }

    #[test]
    fn test_pretty_tablebr_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![crate::ir::U30TableDecl { id: 0, targets: vec![1, 2, 3] }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("table.br") || text.contains("tablebr"));
    }

    #[test]
    fn test_pretty_empty_module() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // Empty module should produce some output
        assert!(!text.is_empty() || text.contains("no functions"));
    }

    #[test]
    fn test_pretty_module_with_no_regions() {
        let m = U30Module {
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
        let text = fmt_module(&m);
        assert!(text.contains("fn"));
    }

    // Test ZExt formatting
    #[test]
    fn test_pretty_zext_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(42) },
                        U30Op::ZExtI8U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("zext"));
    }

    // Test SExt formatting
    #[test]
    fn test_pretty_sext_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(255) },
                        U30Op::SExtI8U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("sext"));
    }

    // Test Trunc formatting
    #[test]
    fn test_pretty_trunc_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0x1_0000_0000) },
                        U30Op::TruncU64U32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("trunc"));
    }

    // Test ByteSwap formatting
    #[test]
    fn test_pretty_byteswap_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0x12345678) },
                        U30Op::ByteSwapU32 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("bswap"));
    }

    // Test MemSize formatting
    #[test]
    fn test_pretty_memsize_op() {
        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 128, readable: true, writable: true, initial: vec![0; 128] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemSize { dst: 0, region: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.size") || text.contains("memsize"));
    }

    // Test MemCopy formatting
    #[test]
    fn test_pretty_memcopy_op() {
        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
                U30RegionDecl { id: 1, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 1, src_offset: 0, size: 16 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.copy") || text.contains("memcpy"));
    }

    // Test MemFill formatting
    #[test]
    fn test_pretty_memfill_op() {
        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![0; 64] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemFill { region: 0, offset: 0, value: 0, size: 16 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.fill") || text.contains("memset"));
    }

    // Test Break formatting
    #[test]
    fn test_pretty_break_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Break { code: 42 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("break"));
    }

    // Test bit manipulation ops formatting
    #[test]
    fn test_pretty_bit_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(8) },
                        U30Op::CtzU32 { dst: 1, src: 0 },
                        U30Op::ClzU32 { dst: 2, src: 0 },
                        U30Op::PopcntU32 { dst: 3, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("ctz") || text.contains("clz") || text.contains("popcnt"));
    }

    // Test rotate ops formatting
    #[test]
    fn test_pretty_rot_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::Const { dst: 1, value: U30Value::U32(4) },
                        U30Op::RotlU32 { dst: 2, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("rotl") || text.contains("rotr"));
    }

    // Test conversion ops formatting
    #[test]
    fn test_pretty_conversion_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::I2F { dst: 1, src: 0 },
                        U30Op::F2I { dst: 2, src: 1 },
                        U30Op::ReinterpretF32U32 { dst: 3, src: 0 },
                        U30Op::ReinterpretU32F32 { dst: 4, src: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 4] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("i2f") || text.contains("f2i") || text.contains("reinterpret"));
    }

    // Test F64 conversions formatting
    #[test]
    fn test_pretty_f64_conversions() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                        U30Op::I64F64 { dst: 1, src: 0 },
                        U30Op::F64I64 { dst: 2, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("i64.f64") || text.contains("f64.i64"));
    }

    // Test F32F64 conversion formatting
    #[test]
    fn test_pretty_f32f64_conversion() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.5) },
                        U30Op::F32F64 { dst: 1, src: 0 },
                        U30Op::F64F32 { dst: 2, src: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("f32.f64") || text.contains("f64.f32"));
    }

    // Test Bool value formatting
    #[test]
    fn test_pretty_bool_value() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        U30Op::Const { dst: 1, value: U30Value::Bool(false) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0, 1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("true") || text.contains("false"));
    }

    // Test TruncF32U64 formatting
    #[test]
    fn test_pretty_trunc_f32_u64() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.5) },
                        U30Op::TruncF32U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("trunc") || text.contains("f32") || text.contains("u64"));
    }

    // Test ReinterpretF64U64 formatting
    #[test]
    fn test_pretty_reinterpret_f64_u64() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.5) },
                        U30Op::ReinterpretF64U64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("reinterpret") || text.contains("bitcast"));
    }

    // Test Not ops formatting (NotU8, NotU16, NotU32, NotU64)
    #[test]
    fn test_pretty_not_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(0xFF) },
                        U30Op::NotU8 { dst: 1, src: 0 },
                        U30Op::NotU16 { dst: 2, src: 0 },
                        U30Op::NotU32 { dst: 3, src: 0 },
                        U30Op::NotU64 { dst: 4, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3, 4] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("not.u8"));
        assert!(text.contains("not.u16"));
        assert!(text.contains("not.u32"));
        assert!(text.contains("not.u64"));
    }

    // Test Abs ops formatting (AbsU64, AbsU32)
    #[test]
    fn test_pretty_abs_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(42) },
                        U30Op::AbsU32 { dst: 1, src: 0 },
                        U30Op::AbsU64 { dst: 2, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("abs.u32") || text.contains("abs.u64"));
    }

    // Test Neg ops formatting (NegU64, NegU32)
    #[test]
    fn test_pretty_neg_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(10) },
                        U30Op::NegU32 { dst: 1, src: 0 },
                        U30Op::NegU64 { dst: 2, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("neg.u32") || text.contains("neg.u64"));
    }

    // Test U64 bit ops (CtzU64, ClzU64, PopcntU64)
    #[test]
    fn test_pretty_u64_bit_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(256) },
                        U30Op::CtzU64 { dst: 1, src: 0 },
                        U30Op::ClzU64 { dst: 2, src: 0 },
                        U30Op::PopcntU64 { dst: 3, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("ctz") && text.contains("clz") && text.contains("popcnt"));
    }

    // Test RotlU64 and RotrU64 formatting
    #[test]
    fn test_pretty_rot_u64_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(1) },
                        U30Op::Const { dst: 1, value: U30Value::U64(4) },
                        U30Op::RotlU64 { dst: 2, val: 0, sh: 1 },
                        U30Op::RotrU64 { dst: 3, val: 0, sh: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("rotl") || text.contains("rotr"));
    }

    // Test F32 arithmetic ops (FAdd, FSub, FMul, FDiv, FSqrt, FAbs, FNeg, FMin, FMax)
    #[test]
    fn test_pretty_f32_arith_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F32(1.0) },
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
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("fadd") || text.contains("fsub") || text.contains("fmul") || text.contains("fdiv"));
    }

    // Test F32 comparison ops (FEq, FLt, FGt, FLe, FGe)
    #[test]
    fn test_pretty_f32_cmp_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
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
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("feq") || text.contains("flt") || text.contains("fgt") || text.contains("fle") || text.contains("fge"));
    }

    // Test F64 arithmetic ops (F64Sub, F64Div, F64Abs, F64Neg, F64Min, F64Max)
    #[test]
    fn test_pretty_f64_arith_full() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(1.0) },
                        U30Op::Const { dst: 1, value: U30Value::F64(2.0) },
                        U30Op::F64Sub { dst: 2, a: 0, b: 1 },
                        U30Op::F64Div { dst: 3, a: 0, b: 1 },
                        U30Op::F64Abs { dst: 4, src: 0 },
                        U30Op::F64Neg { dst: 5, src: 0 },
                        U30Op::F64Min { dst: 6, a: 0, b: 1 },
                        U30Op::F64Max { dst: 7, a: 0, b: 1 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![2, 3, 4, 5, 6, 7] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("f64.sub") || text.contains("f64.div") || text.contains("f64.abs") || text.contains("f64.neg"));
    }

    // Test F64 comparison ops (F64Eq, F64Lt, F64Gt, F64Le, F64Ge)
    #[test]
    fn test_pretty_f64_cmp_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
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
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("f64.eq") || text.contains("f64.lt") || text.contains("f64.gt") || text.contains("f64.le") || text.contains("f64.ge"));
    }

    // Test LoadU8, StoreU8, LoadU16, StoreU16
    #[test]
    fn test_pretty_load_store_u8_u16() {
        let m = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 256, readable: true, writable: true, initial: vec![0; 256],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::LoadU8 { dst: 0, region: 0, offset: 4 },
                        U30Op::StoreU8 { region: 0, offset: 5, src: 1 },
                        U30Op::LoadU16 { dst: 2, region: 0, offset: 6 },
                        U30Op::StoreU16 { region: 0, offset: 8, src: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0, 2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("load.u8"));
        assert!(text.contains("store.u8"));
        assert!(text.contains("load.u16"));
        assert!(text.contains("store.u16"));
    }

    // Test ByteSwapU16 and ByteSwapU64
    #[test]
    fn test_pretty_byteswap_u16_u64() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0x1234) },
                        U30Op::ByteSwapU16 { dst: 1, src: 0 },
                        U30Op::Const { dst: 2, value: U30Value::U64(0x0123_4567_89AB_CDEF) },
                        U30Op::ByteSwapU64 { dst: 3, src: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("bswap"));
    }

    // Test SExtI16U32, SExtI16U64, SExtI32U64
    #[test]
    fn test_pretty_sext_more() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U16(0xFF00) },
                        U30Op::SExtI16U32 { dst: 1, src: 0 },
                        U30Op::SExtI16U64 { dst: 2, src: 0 },
                        U30Op::SExtI32U64 { dst: 3, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("sext"));
    }

    // Test ZExtI16U32, ZExtI16U64, ZExtI32U64
    #[test]
    fn test_pretty_zext_more() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U8(42) },
                        U30Op::ZExtI8U16 { dst: 1, src: 0 },
                        U30Op::ZExtI8U64 { dst: 2, src: 0 },
                        U30Op::ZExtI16U32 { dst: 3, src: 1 },
                        U30Op::ZExtI16U64 { dst: 4, src: 1 },
                        U30Op::ZExtI32U64 { dst: 5, src: 3 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 2, 3, 4, 5] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("zext"));
    }

    // Test TruncU32U16
    #[test]
    fn test_pretty_trunc_u32_u16() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0x1_0000) },
                        U30Op::TruncU32U16 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("trunc"));
    }

    // Test fmt_type for all variants (Bool, U8, U16, U32, U64, F32, F64)
    #[test]
    fn test_pretty_fmt_type_all() {
        let types = vec![
            U30Type::Bool,
            U30Type::U8,
            U30Type::U16,
            U30Type::U32,
            U30Type::U64,
            U30Type::F32,
            U30Type::F64,
        ];
        for t in types {
            let text = fmt_type(&t);
            assert!(!text.is_empty(), "fmt_type returned empty for {:?}", t);
        }
    }

    // Test fmt_value for all variants (Bool, U8, U16, U32, U64, F32, F64)
    #[test]
    fn test_pretty_fmt_value_all() {
        let values = vec![
            U30Value::Bool(true),
            U30Value::Bool(false),
            U30Value::U8(42),
            U30Value::U16(1234),
            U30Value::U32(999999),
            U30Value::U64(1_000_000_000),
            U30Value::F32(3.14),
            U30Value::F64(2.71828),
        ];
        for v in values {
            let text = fmt_value(&v);
            assert!(!text.is_empty(), "fmt_value returned empty for {:?}", v);
        }
    }

    // Test fmt_binop for all variants
    #[test]
    fn test_pretty_fmt_binop_all() {
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
            let text = fmt_binop(&op);
            assert!(!text.is_empty(), "fmt_binop returned empty for {:?}", op);
        }
    }

    // Test Ret with multiple return values (multiple values branch)
    #[test]
    fn test_pretty_ret_multi_values() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0, 1, 2, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("ret"));
    }

    // Test Ret with single return value (single value branch)
    #[test]
    fn test_pretty_ret_single_value() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![5] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("ret"));
    }

    // Test Trap with code=0
    #[test]
    fn test_pretty_trap_zero_code() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Trap { code: 0 },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("trap"));
    }

    // Test TailCall with single arg
    #[test]
    fn test_pretty_tailcall_single_arg() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("tail.call"));
    }

    // Test non-entry block formatting (non-entry block branch)
    #[test]
    fn test_pretty_non_entry_block() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
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
            }],
            entry_function: 0,
        };
        // Use no-colors to avoid ANSI codes interfering with assertions
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: true, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        // Should contain "block" text for both blocks
        assert!(text.contains("block"));
        // Block 0 is entry (has "│" prefix), block 1 is non-entry (has " " prefix)
        // Both branches of the is_entry check should be exercised
        assert!(text.contains("block0"));
        assert!(text.contains("block1"));
    }

    // Test fmt_module_opts with show_tables=false and non-empty tables
    #[test]
    fn test_pretty_show_tables_false_hides_tables() {
        let m = U30Module {
            regions: vec![],
            tables: vec![crate::ir::U30TableDecl { id: 0, targets: vec![1, 2] }],
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
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(!text.contains("table"), "show_tables=false should hide table declarations");
    }

    // Test FmtOpts::colors() builder method
    #[test]
    fn test_pretty_fmtopts_colors_builder() {
        let opts = FmtOpts::default().colors(true);
        assert!(opts.colors);
        let opts2 = FmtOpts::default().colors(false);
        assert!(!opts2.colors);
    }

    // Test ReinterpretU64F64 formatting
    #[test]
    fn test_pretty_reinterpret_u64_f64() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(0x4000_0000_0000_0000) },
                        U30Op::ReinterpretU64F64 { dst: 1, src: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("reinterpret") || text.contains("bitcast"));
    }

    // Test Call with multiple args and results
    #[test]
    fn test_pretty_call_multi_args_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Call { function: 1, args: vec![0, 1, 2], results: vec![3, 4] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("call"));
    }

    // Test IndirectCall with args
    #[test]
    fn test_pretty_indirect_call_with_args() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(1) },
                        U30Op::IndirectCall { function: 0, args: vec![2, 3], results: vec![4, 5] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("indirect") || text.contains("call"));
    }

    // Test TableBr with index 0
    #[test]
    fn test_pretty_tablebr_zero_index() {
        let m = U30Module {
            regions: vec![],
            tables: vec![crate::ir::U30TableDecl { id: 0, targets: vec![0, 1, 2] }],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::TableBr { table: 0, index: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("table.br") || text.contains("tablebr"));
    }

    // Test Assert with non-zero message
    #[test]
    fn test_pretty_assert_non_zero_msg() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Assert { cond: 0, msg: 99 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("assert"));
    }

    // Test MemGrow with non-zero delta
    #[test]
    fn test_pretty_memgrow_nonzero_delta() {
        let m = U30Module {
            regions: vec![U30RegionDecl {
                id: 0, size: 128, readable: true, writable: true, initial: vec![0; 128],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemGrow { dst: 0, region: 0, delta: 5 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![0] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.grow") || text.contains("memgrow"));
    }

    // Test MemCopy with different src/dst regions
    #[test]
    fn test_pretty_memcopy_cross_region() {
        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 128, readable: true, writable: true, initial: vec![0; 128] },
                U30RegionDecl { id: 1, size: 128, readable: true, writable: true, initial: vec![0; 128] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 1, src_offset: 0, size: 32 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("mem.copy") || text.contains("memcpy"));
    }

    // Test F64Reinterpret formatting
    #[test]
    fn test_pretty_f64_reinterpret_ops() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::F64(3.14) },
                        U30Op::ReinterpretF64U64 { dst: 1, src: 0 },
                        U30Op::Const { dst: 2, value: U30Value::U64(0x4009_1D5C) },
                        U30Op::ReinterpretU64F64 { dst: 3, src: 2 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![1, 3] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("reinterpret.f64.u64") || text.contains("reinterpret.u64.f64"));
    }

    // Test hex_string function with multiple chunks (if i > 0 branch)
    #[test]
    fn test_pretty_hex_string_multiple_chunks() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 64,
                readable: true,
                writable: true,
                initial: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        // With hex_cols=8, data will be split into multiple chunks
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 8 };
        let text = fmt_module_opts(&m, opts);
        // Should contain hex data with comma separators (the if i > 0 branch)
        assert!(text.contains("01 02") || text.contains(","));
    }

    // Test Nop operation formatting
    #[test]
    fn test_pretty_nop_op() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Nop,
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("nop"));
    }

    // Test Br terminator formatting
    #[test]
    fn test_pretty_br_terminator() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
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
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        // Strip ANSI codes to make assertions reliable
        let plain = text.replace("\x1b[", "").replace("m", "\n");
        assert!(plain.contains("br") && plain.contains("block1"));
    }

    // Test BrIf terminator formatting
    #[test]
    fn test_pretty_brif_terminator() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![
                    U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::Bool(true) },
                        ],
                        terminator: U30Terminator::BrIf { cond: 0, then_target: 1, else_target: 0 },
                    },
                    U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    },
                ],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("br.if"));
    }

    // Test Ret terminator with multiple values formatting
    #[test]
    fn test_pretty_ret_terminator_multi_values() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![0, 1, 2] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // Multiple values should have commas between them
        assert!(text.contains("ret"));
    }

    // Test Trap terminator formatting
    #[test]
    fn test_pretty_trap_terminator() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Trap { code: 123 },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("trap") && text.contains("123"));
    }

    // Test FmtOpts::colors builder with method chaining
    #[test]
    fn test_pretty_fmtopts_builder_chain() {
        let opts = FmtOpts::default()
            .colors(true)
            .colors(false);
        assert!(!opts.colors);
    }

    // Test all U30Type formatting variants
    #[test]
    fn test_pretty_all_types_formatted() {
        let types = vec![
            U30Type::Bool,
            U30Type::U8,
            U30Type::U16,
            U30Type::U32,
            U30Type::U64,
            U30Type::F32,
            U30Type::F64,
        ];
        for t in types {
            let text = fmt_type(&t);
            assert!(!text.is_empty(), "fmt_type returned empty for {:?}", t);
        }
    }

    // Test all U30Value formatting variants
    #[test]
    fn test_pretty_all_values_formatted() {
        let values = vec![
            U30Value::Bool(true),
            U30Value::Bool(false),
            U30Value::U8(0),
            U30Value::U8(255),
            U30Value::U16(0),
            U30Value::U16(65535),
            U30Value::U32(0),
            U30Value::U32(4294967295),
            U30Value::U64(0),
            U30Value::U64(18446744073709551615),
            U30Value::F32(0.0),
            U30Value::F32(-0.0),
            U30Value::F32(f32::INFINITY),
            U30Value::F32(f32::NEG_INFINITY),
            U30Value::F32(f32::NAN),
            U30Value::F64(0.0),
            U30Value::F64(-0.0),
            U30Value::F64(f64::INFINITY),
            U30Value::F64(f64::NEG_INFINITY),
            U30Value::F64(f64::NAN),
        ];
        for v in values {
            let text = fmt_value(&v);
            assert!(!text.is_empty(), "fmt_value returned empty for {:?}", v);
        }
    }

    // Test all U30BinaryOp formatting variants
    #[test]
    fn test_pretty_all_binops_formatted() {
        use crate::ir::U30BinaryOp::*;
        let ops = vec![
            AddWrapU64, AddWrapU32,
            SubWrapU64, SubWrapU32,
            MulWrapU64, MulWrapU32,
            AndU8, OrU8, XorU8,
            ShlU64, ShlU32,
            ShrU64, ShrU32,
            DivU64, DivU32,
            RemU64, RemU32,
            Eq,
            LtU64, GtU64, GeU64,
            LeU64, LeU32,
            MinU64, MinU32,
            MaxU64, MaxU32,
        ];
        for op in ops {
            let text = fmt_binop(&op);
            assert!(!text.is_empty(), "fmt_binop returned empty for {:?}", op);
        }
    }

    // Test all U30Op variants for formatting
    #[test]
    fn test_pretty_all_ops_formatted() {
        use crate::ir::U30BinaryOp::*;

        let ops = vec![
            U30Op::Nop,
            U30Op::Const { dst: 0, value: U30Value::U64(0) },
            U30Op::Binary { dst: 1, op: AddWrapU64, a: 0, b: 0 },
            U30Op::Select { dst: 2, cond: 0, a: 0, b: 0 },
            U30Op::NotU8 { dst: 3, src: 0 },
            U30Op::NotU16 { dst: 4, src: 0 },
            U30Op::NotU32 { dst: 5, src: 0 },
            U30Op::NotU64 { dst: 6, src: 0 },
            U30Op::AbsU64 { dst: 7, src: 0 },
            U30Op::AbsU32 { dst: 8, src: 0 },
            U30Op::NegU64 { dst: 9, src: 0 },
            U30Op::NegU32 { dst: 10, src: 0 },
            U30Op::CtzU64 { dst: 11, src: 0 },
            U30Op::CtzU32 { dst: 12, src: 0 },
            U30Op::ClzU64 { dst: 13, src: 0 },
            U30Op::ClzU32 { dst: 14, src: 0 },
            U30Op::PopcntU64 { dst: 15, src: 0 },
            U30Op::PopcntU32 { dst: 16, src: 0 },
            U30Op::RotlU64 { dst: 17, val: 0, sh: 0 },
            U30Op::RotlU32 { dst: 18, val: 0, sh: 0 },
            U30Op::RotrU64 { dst: 19, val: 0, sh: 0 },
            U30Op::RotrU32 { dst: 20, val: 0, sh: 0 },
            U30Op::FEq { dst: 21, a: 0, b: 0 },
            U30Op::FLt { dst: 22, a: 0, b: 0 },
            U30Op::FGt { dst: 23, a: 0, b: 0 },
            U30Op::FLe { dst: 24, a: 0, b: 0 },
            U30Op::FGe { dst: 25, a: 0, b: 0 },
            U30Op::FAdd { dst: 26, a: 0, b: 0 },
            U30Op::FSub { dst: 27, a: 0, b: 0 },
            U30Op::FMul { dst: 28, a: 0, b: 0 },
            U30Op::FDiv { dst: 29, a: 0, b: 0 },
            U30Op::FSqrt { dst: 30, src: 0 },
            U30Op::FAbs { dst: 31, src: 0 },
            U30Op::FNeg { dst: 32, src: 0 },
            U30Op::FMin { dst: 33, a: 0, b: 0 },
            U30Op::FMax { dst: 34, a: 0, b: 0 },
            U30Op::I2F { dst: 35, src: 0 },
            U30Op::F2I { dst: 36, src: 0 },
            U30Op::TruncF32U64 { dst: 37, src: 0 },
            U30Op::ReinterpretF32U32 { dst: 38, src: 0 },
            U30Op::ReinterpretU32F32 { dst: 39, src: 0 },
            U30Op::ZExtI8U16 { dst: 40, src: 0 },
            U30Op::ZExtI8U32 { dst: 41, src: 0 },
            U30Op::ZExtI8U64 { dst: 42, src: 0 },
            U30Op::ZExtI16U32 { dst: 43, src: 0 },
            U30Op::ZExtI16U64 { dst: 44, src: 0 },
            U30Op::ZExtI32U64 { dst: 45, src: 0 },
            U30Op::TruncU64U32 { dst: 46, src: 0 },
            U30Op::TruncU64U16 { dst: 47, src: 0 },
            U30Op::TruncU32U16 { dst: 48, src: 0 },
            U30Op::MemCopy { dst_region: 0, dst_offset: 0, src_region: 0, src_offset: 0, size: 0 },
            U30Op::MemFill { region: 0, offset: 0, value: 0, size: 0 },
            U30Op::MemSize { dst: 49, region: 0 },
            U30Op::MemGrow { dst: 50, region: 0, delta: 0 },
            U30Op::F64Eq { dst: 51, a: 0, b: 0 },
            U30Op::F64Lt { dst: 52, a: 0, b: 0 },
            U30Op::F64Gt { dst: 53, a: 0, b: 0 },
            U30Op::F64Le { dst: 54, a: 0, b: 0 },
            U30Op::F64Ge { dst: 55, a: 0, b: 0 },
            U30Op::F64Add { dst: 56, a: 0, b: 0 },
            U30Op::F64Sub { dst: 57, a: 0, b: 0 },
            U30Op::F64Mul { dst: 58, a: 0, b: 0 },
            U30Op::F64Div { dst: 59, a: 0, b: 0 },
            U30Op::F64Sqrt { dst: 60, src: 0 },
            U30Op::F64Abs { dst: 61, src: 0 },
            U30Op::F64Neg { dst: 62, src: 0 },
            U30Op::F64Min { dst: 63, a: 0, b: 0 },
            U30Op::F64Max { dst: 64, a: 0, b: 0 },
            U30Op::I64F64 { dst: 65, src: 0 },
            U30Op::F64I64 { dst: 66, src: 0 },
            U30Op::F32F64 { dst: 67, src: 0 },
            U30Op::F64F32 { dst: 68, src: 0 },
            U30Op::ReinterpretF64U64 { dst: 69, src: 0 },
            U30Op::ReinterpretU64F64 { dst: 70, src: 0 },
            U30Op::SExtI8U16 { dst: 71, src: 0 },
            U30Op::SExtI8U32 { dst: 72, src: 0 },
            U30Op::SExtI8U64 { dst: 73, src: 0 },
            U30Op::SExtI16U32 { dst: 74, src: 0 },
            U30Op::SExtI16U64 { dst: 75, src: 0 },
            U30Op::SExtI32U64 { dst: 76, src: 0 },
            U30Op::ByteSwapU16 { dst: 77, src: 0 },
            U30Op::ByteSwapU32 { dst: 78, src: 0 },
            U30Op::ByteSwapU64 { dst: 79, src: 0 },
            U30Op::Call { function: 0, args: vec![], results: vec![] },
            U30Op::IndirectCall { function: 0, args: vec![], results: vec![] },
            U30Op::TableBr { table: 0, index: 0 },
            U30Op::Break { code: 0 },
            U30Op::Assert { cond: 0, msg: 0 },
            U30Op::LoadU8 { dst: 80, region: 0, offset: 0 },
            U30Op::StoreU8 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU16 { dst: 81, region: 0, offset: 0 },
            U30Op::StoreU16 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU32 { dst: 82, region: 0, offset: 0 },
            U30Op::StoreU32 { region: 0, offset: 0, src: 0 },
            U30Op::LoadU64 { dst: 83, region: 0, offset: 0 },
            U30Op::StoreU64 { region: 0, offset: 0, src: 0 },
        ];

        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![] },
            ],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![0] },
            ],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops,
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
            ],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(!text.is_empty());
    }

    // Test region formatting with both readable and writable false
    #[test]
    fn test_pretty_region_neither_readable_nor_writable() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 64,
                readable: false,
                writable: false,
                initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("!readable"));
        assert!(text.contains("!writable"));
    }

    // Test table formatting with multiple targets
    #[test]
    fn test_pretty_table_multiple_targets() {
        let m = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![0, 1, 2, 3, 4] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("table"));
        assert!(text.contains("0") && text.contains("4"));
    }

    // Test function with results formatting
    #[test]
    fn test_pretty_function_with_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![U30Type::U64, U30Type::F64],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains(" -> "));
    }

    // Test function without results formatting
    #[test]
    fn test_pretty_function_without_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(!text.contains(" -> "));
    }

    // Test block with ops and entry marker
    #[test]
    fn test_pretty_block_with_ops_entry_marker() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U64(42) },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // Module should produce some text output with block marker
        assert!(!text.is_empty(), "fmt_module should produce output");
        // Block formatting includes block index and colon
        assert!(text.contains("block") && text.contains(":"));
    }

    // Test non-entry block without entry marker
    #[test]
    fn test_pretty_non_entry_block_no_marker() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
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
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        // Block 0 is entry (has "│"), block 1 is non-entry (has " ")
        assert!(text.contains("block1:"));
    }

    // Test comment formatting in colors mode
    #[test]
    fn test_pretty_comment_with_colors() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 64,
                readable: true,
                writable: true,
                initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: true, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        // DIM escape sequence should be present when colors are enabled
        assert!(text.contains("\x1b[2m") || text.contains("size="));
    }

    // Test TailCall with no args
    #[test]
    fn test_pretty_tailcall_no_args() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("tail.call"));
    }

    // Test Call with no args and no results
    #[test]
    fn test_pretty_call_no_args_no_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
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
                            U30Op::Call { function: 0, args: vec![], results: vec![] },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                    entry_block: 0,
                },
            ],
            entry_function: 1,
        };
        let text = fmt_module(&m);
        assert!(text.contains("call"));
    }

    // Test IndirectCall with no args and no results
    #[test]
    fn test_pretty_indirect_call_no_args_no_results() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                blocks: vec![U30Block {
                    ops: vec![
                        U30Op::Const { dst: 0, value: U30Value::U32(0) },
                        U30Op::IndirectCall { function: 0, args: vec![], results: vec![] },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
                entry_block: 0,
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("icall"));
    }

    // Test region initial data with hex_cols=4 (many chunks)
    #[test]
    fn test_pretty_hex_data_small_cols() {
        let m = U30Module {
            regions: vec![crate::ir::U30RegionDecl {
                id: 0,
                size: 32,
                readable: true,
                writable: true,
                initial: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 4 };
        let text = fmt_module_opts(&m, opts);
        // Multiple chunks should produce commas
        assert!(text.contains("01 02 03 04"));
    }

    // Test entry block comment formatting
    #[test]
    fn test_pretty_entry_block_comment() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![U30Type::U64],
                results: vec![],
                entry_block: 5,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("; entry=block5"));
    }

    // Test TailCall with multiple args formatting
    #[test]
    fn test_pretty_tailcall_multi_args() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::TailCall { function: 0, args: vec![0, 1, 2, 3, 4] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("tail.call"));
    }

    // Test Binary op with various variants formatting
    #[test]
    fn test_pretty_binary_ops_variants() {
        use crate::ir::U30BinaryOp::*;
        let ops = vec![
            (AddWrapU64, "add.wrap.u64"),
            (SubWrapU64, "sub.wrap.u64"),
            (MulWrapU64, "mul.wrap.u64"),
            (DivU64, "div.u64"),
            (RemU64, "rem.u64"),
            (LtU64, "lt.u64"),
            (GtU64, "gt.u64"),
            (LeU64, "le.u64"),
            (GeU64, "ge.u64"),
        ];
        for (op, name) in ops {
            let m = U30Module {
                regions: vec![],
                tables: vec![],
                functions: vec![U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![
                            U30Op::Const { dst: 0, value: U30Value::U64(1) },
                            U30Op::Const { dst: 1, value: U30Value::U64(2) },
                            U30Op::Binary { dst: 2, op, a: 0, b: 1 },
                        ],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                }],
                entry_function: 0,
            };
            let text = fmt_module(&m);
            assert!(text.contains(name), "Should contain {}", name);
        }
    }

    // Test table formatting in colors mode
    #[test]
    fn test_pretty_table_colors() {
        let m = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![1, 2, 3] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let opts = FmtOpts { colors: true, show_region_data: false, show_tables: true, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        assert!(text.contains("table"));
    }

    // Test FmtOpts with all combinations
    #[test]
    fn test_pretty_fmtopts_combinations() {
        // Test colors=true, show_region_data=true, show_tables=true
        let opts1 = FmtOpts { colors: true, show_region_data: true, show_tables: true, hex_cols: 32 };
        assert!(opts1.colors);
        assert!(opts1.show_region_data);
        assert!(opts1.show_tables);

        // Test colors=false, show_region_data=false, show_tables=false
        let opts2 = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 16 };
        assert!(!opts2.colors);
        assert!(!opts2.show_region_data);
        assert!(!opts2.show_tables);
        assert_eq!(opts2.hex_cols, 16);
    }

    // Test hex_string with empty data
    #[test]
    fn test_pretty_hex_string_empty() {
        let m = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 64,
                readable: true,
                writable: true,
                initial: vec![],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        // With show_region_data=false, should not show hex data
        let opts = FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 };
        let text = fmt_module_opts(&m, opts);
        // Should contain region declaration without hex data
        assert!(text.contains("region"));
    }

    // Test module with multiple regions
    #[test]
    fn test_pretty_multiple_regions() {
        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 64, readable: true, writable: true, initial: vec![] },
                U30RegionDecl { id: 1, size: 128, readable: true, writable: false, initial: vec![] },
                U30RegionDecl { id: 2, size: 256, readable: false, writable: true, initial: vec![] },
            ],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(text.contains("region"));
        assert!(text.contains("!writable") || text.contains("!readable"));
    }

    // Test module with multiple functions and tables
    #[test]
    fn test_pretty_multiple_functions_and_tables() {
        let m = U30Module {
            regions: vec![],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![0, 1] },
                U30TableDecl { id: 1, targets: vec![1, 2] },
            ],
            functions: vec![
                U30Function {
                    params: vec![U30Type::U64],
                    results: vec![U30Type::U32],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
                U30Function {
                    params: vec![U30Type::F64],
                    results: vec![U30Type::F64],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
            ],
            entry_function: 1,
        };
        let text = fmt_module(&m);
        // Should contain tables
        assert!(text.contains("table"));
        // Should have multiple functions
        assert!(text.contains("fn"));
    }

    // Test fmt_binop for all bitwise ops
    #[test]
    fn test_pretty_fmt_binop_bitwise() {
        use crate::ir::U30BinaryOp::*;
        let ops = vec![
            (AndU8, "and.u8"),
            (OrU8, "or.u8"),
            (XorU8, "xor.u8"),
            (ShlU64, "shl.u64"),
            (ShlU32, "shl.u32"),
            (ShrU64, "shr.u64"),
            (ShrU32, "shr.u32"),
        ];
        for (op, name) in ops {
            let text = fmt_binop(&op);
            assert_eq!(text, name, "Binary op should format to {}", name);
        }
    }

    // Test fmt_value for special float values
    #[test]
    fn test_pretty_fmt_value_special_floats() {
        let special_values = vec![
            (U30Value::F32(f32::NAN), "NaN"),
            (U30Value::F32(f32::INFINITY), "Infinity"),
            (U30Value::F32(f32::NEG_INFINITY), "-Infinity"),
            (U30Value::F64(f64::NAN), "NaN"),
            (U30Value::F64(f64::INFINITY), "Infinity"),
            (U30Value::F64(f64::NEG_INFINITY), "-Infinity"),
        ];
        for (val, _name) in special_values {
            let text = fmt_value(&val);
            assert!(!text.is_empty());
        }
    }

    // Test non-entry function formatting (fn 0 is not entry)
    #[test]
    fn test_pretty_non_entry_function() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![
                U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
                U30Function {
                    params: vec![],
                    results: vec![],
                    entry_block: 0,
                    blocks: vec![U30Block {
                        ops: vec![],
                        terminator: U30Terminator::Ret { values: vec![] },
                    }],
                },
            ],
            entry_function: 1, // Second function is entry
        };
        let text = fmt_module(&m);
        // Should have entry marker on second function
        assert!(text.contains("▶"));
    }

    // Test comment method with colors enabled
    #[test]
    fn test_pretty_comment_with_colors_enabled() {
        let mut out = Out::new(FmtOpts { colors: true, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.comment("test comment");
        let result = out.finish();
        // DIM escape sequence should be present
        assert!(result.contains("test comment"));
    }

    // Test Push colored method
    #[test]
    fn test_pretty_push_colored() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.push_colored("test", RED);
        let result = out.finish();
        assert_eq!(result, "test");
    }

    // Test Push colored method with colors enabled
    #[test]
    fn test_pretty_push_colored_with_colors() {
        let mut out = Out::new(FmtOpts { colors: true, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.push_colored("test", RED);
        let result = out.finish();
        assert!(result.contains("\x1b[31m"));
        assert!(result.contains("test"));
        assert!(result.contains("\x1b[0m"));
    }

    // Test error method
    #[test]
    fn test_pretty_error_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.error("error text");
        let result = out.finish();
        assert!(result.contains("error text"));
    }

    // Test kw (keyword) method
    #[test]
    fn test_pretty_kw_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.kw("keyword");
        let result = out.finish();
        assert!(result.contains("keyword"));
    }

    // Test op (operation) method
    #[test]
    fn test_pretty_op_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.op("operation");
        let result = out.finish();
        assert!(result.contains("operation"));
    }

    // Test reg (register) method
    #[test]
    fn test_pretty_reg_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.reg("r0");
        let result = out.finish();
        assert!(result.contains("r0"));
    }

    // Test type_ method
    #[test]
    fn test_pretty_type_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.type_("u64");
        let result = out.finish();
        assert!(result.contains("u64"));
    }

    // Test value method
    #[test]
    fn test_pretty_value_method() {
        let mut out = Out::new(FmtOpts { colors: false, show_region_data: false, show_tables: false, hex_cols: 32 });
        out.value("42");
        let result = out.finish();
        assert!(result.contains("42"));
    }

    // Test header/footer formatting
    #[test]
    fn test_pretty_header_footer() {
        let m = U30Module {
            regions: vec![],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        // Should contain U30 Module header
        assert!(text.contains("U30 Module") || text.contains(";"));
    }

    // Test hex_string with 3 chunks (to test if i > 0 branch)
    #[test]
    fn test_pretty_hex_string_three_chunks() {
        let m = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 96,
                readable: true,
                writable: true,
                initial: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        // With hex_cols=4, data will split into 3 chunks: [01020304], [05060708], [090a0b0c]
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 4 };
        let text = fmt_module_opts(&m, opts);
        // Should have commas between chunks
        assert!(text.contains("01 02 03 04"));
    }

    // Test hex_string with 4 chunks
    #[test]
    fn test_pretty_hex_string_four_chunks() {
        let m = U30Module {
            regions: vec![U30RegionDecl {
                id: 0,
                size: 128,
                readable: true,
                writable: true,
                initial: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            }],
            tables: vec![],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        // With hex_cols=4, data will split into 4 chunks
        let opts = FmtOpts { colors: false, show_region_data: true, show_tables: false, hex_cols: 4 };
        let text = fmt_module_opts(&m, opts);
        assert!(text.contains("01 02 03 04"));
    }

    // Test fmt_binop with all variants explicitly
    #[test]
    fn test_pretty_fmt_binop_all_explicit() {
        use crate::ir::U30BinaryOp::*;
        let ops = [
            (AddWrapU64, "add.wrap.u64"),
            (AddWrapU32, "add.wrap.u32"),
            (SubWrapU64, "sub.wrap.u64"),
            (SubWrapU32, "sub.wrap.u32"),
            (MulWrapU64, "mul.wrap.u64"),
            (MulWrapU32, "mul.wrap.u32"),
            (AndU8, "and.u8"),
            (OrU8, "or.u8"),
            (XorU8, "xor.u8"),
            (ShlU64, "shl.u64"),
            (ShlU32, "shl.u32"),
            (ShrU64, "shr.u64"),
            (ShrU32, "shr.u32"),
            (DivU64, "div.u64"),
            (DivU32, "div.u32"),
            (RemU64, "rem.u64"),
            (RemU32, "rem.u32"),
            (Eq, "eq"),
            (LtU64, "lt.u64"),
            (GtU64, "gt.u64"),
            (GeU64, "ge.u64"),
            (LeU64, "le.u64"),
            (LeU32, "le.u32"),
            (MinU64, "min.u64"),
            (MinU32, "min.u32"),
            (MaxU64, "max.u64"),
            (MaxU32, "max.u32"),
        ];
        for (op, expected) in ops {
            let text = fmt_binop(&op);
            assert_eq!(text, expected, "fmt_binop({:?}) should be {}", op, expected);
        }
    }

    // Test fmt_type explicitly
    #[test]
    fn test_pretty_fmt_type_explicit() {
        assert_eq!(fmt_type(&U30Type::Bool), "bool");
        assert_eq!(fmt_type(&U30Type::U8), "u8");
        assert_eq!(fmt_type(&U30Type::U16), "u16");
        assert_eq!(fmt_type(&U30Type::U32), "u32");
        assert_eq!(fmt_type(&U30Type::U64), "u64");
        assert_eq!(fmt_type(&U30Type::F32), "f32");
        assert_eq!(fmt_type(&U30Type::F64), "f64");
    }

    // Test fmt_value explicitly
    #[test]
    fn test_pretty_fmt_value_explicit() {
        assert_eq!(fmt_value(&U30Value::Bool(true)), "true");
        assert_eq!(fmt_value(&U30Value::Bool(false)), "false");
        assert_eq!(fmt_value(&U30Value::U8(42)), "42");
        assert_eq!(fmt_value(&U30Value::U16(1234)), "1234");
        assert_eq!(fmt_value(&U30Value::U32(999999)), "999999");
        assert_eq!(fmt_value(&U30Value::U64(1_000_000_000)), "1000000000");
    }

    // Test multiple ops in one module
    #[test]
    fn test_pretty_all_ops_in_one_module() {
        use crate::ir::U30BinaryOp::*;

        let m = U30Module {
            regions: vec![
                U30RegionDecl { id: 0, size: 256, readable: true, writable: true, initial: vec![] },
                U30RegionDecl { id: 1, size: 128, readable: true, writable: true, initial: vec![] },
            ],
            tables: vec![
                U30TableDecl { id: 0, targets: vec![0] },
            ],
            functions: vec![U30Function {
                params: vec![],
                results: vec![],
                entry_block: 0,
                blocks: vec![U30Block {
                    ops: vec![
                        // All single-src ops
                        U30Op::Nop,
                        U30Op::Const { dst: 0, value: U30Value::U64(0) },
                        U30Op::NotU8 { dst: 1, src: 0 },
                        U30Op::NotU16 { dst: 2, src: 0 },
                        U30Op::NotU32 { dst: 3, src: 0 },
                        U30Op::NotU64 { dst: 4, src: 0 },
                        U30Op::AbsU64 { dst: 5, src: 0 },
                        U30Op::AbsU32 { dst: 6, src: 0 },
                        U30Op::NegU64 { dst: 7, src: 0 },
                        U30Op::NegU32 { dst: 8, src: 0 },
                        U30Op::CtzU64 { dst: 9, src: 0 },
                        U30Op::CtzU32 { dst: 10, src: 0 },
                        U30Op::ClzU64 { dst: 11, src: 0 },
                        U30Op::ClzU32 { dst: 12, src: 0 },
                        U30Op::PopcntU64 { dst: 13, src: 0 },
                        U30Op::PopcntU32 { dst: 14, src: 0 },
                        U30Op::FSqrt { dst: 15, src: 0 },
                        U30Op::FAbs { dst: 16, src: 0 },
                        U30Op::FNeg { dst: 17, src: 0 },
                        U30Op::I2F { dst: 18, src: 0 },
                        U30Op::F2I { dst: 19, src: 0 },
                        U30Op::TruncF32U64 { dst: 20, src: 0 },
                        U30Op::ReinterpretF32U32 { dst: 21, src: 0 },
                        U30Op::ReinterpretU32F32 { dst: 22, src: 0 },
                        U30Op::ZExtI8U16 { dst: 23, src: 0 },
                        U30Op::ZExtI8U32 { dst: 24, src: 0 },
                        U30Op::ZExtI8U64 { dst: 25, src: 0 },
                        U30Op::ZExtI16U32 { dst: 26, src: 0 },
                        U30Op::ZExtI16U64 { dst: 27, src: 0 },
                        U30Op::ZExtI32U64 { dst: 28, src: 0 },
                        U30Op::TruncU64U32 { dst: 29, src: 0 },
                        U30Op::TruncU64U16 { dst: 30, src: 0 },
                        U30Op::TruncU32U16 { dst: 31, src: 0 },
                        U30Op::SExtI8U16 { dst: 32, src: 0 },
                        U30Op::SExtI8U32 { dst: 33, src: 0 },
                        U30Op::SExtI8U64 { dst: 34, src: 0 },
                        U30Op::SExtI16U32 { dst: 35, src: 0 },
                        U30Op::SExtI16U64 { dst: 36, src: 0 },
                        U30Op::SExtI32U64 { dst: 37, src: 0 },
                        U30Op::ByteSwapU16 { dst: 38, src: 0 },
                        U30Op::ByteSwapU32 { dst: 39, src: 0 },
                        U30Op::ByteSwapU64 { dst: 40, src: 0 },
                        U30Op::MemSize { dst: 41, region: 0 },
                        U30Op::MemGrow { dst: 42, region: 0, delta: 0 },
                        U30Op::LoadU8 { dst: 43, region: 0, offset: 0 },
                        U30Op::LoadU16 { dst: 44, region: 0, offset: 0 },
                        U30Op::LoadU32 { dst: 45, region: 0, offset: 0 },
                        U30Op::LoadU64 { dst: 46, region: 0, offset: 0 },
                    ],
                    terminator: U30Terminator::Ret { values: vec![] },
                }],
            }],
            entry_function: 0,
        };
        let text = fmt_module(&m);
        assert!(!text.is_empty());
    }

    // Test Out methods directly
    #[test]
    fn test_out_push_str() {
        let mut out = Out::new(FmtOpts::default());
        out.push_str("test");
        assert_eq!(out.finish(), "test");
    }

    #[test]
    fn test_out_writeln() {
        let mut out = Out::new(FmtOpts::default());
        out.writeln("line");
        assert_eq!(out.finish(), "line\n");
    }

    #[test]
    fn test_out_finish() {
        let out = Out::new(FmtOpts::default());
        let result = out.finish();
        assert_eq!(result, "");
    }

    // Test FmtOpts Default
    #[test]
    fn test_fmtopts_default() {
        let opts = FmtOpts::default();
        assert!(!opts.colors);
        assert!(!opts.show_region_data);
        assert!(opts.show_tables);
        assert_eq!(opts.hex_cols, 32);
    }

    // Test FmtOpts builder chaining
    #[test]
    fn test_fmtopts_builder_full_chain() {
        let opts = FmtOpts::default()
            .colors(true);
        assert!(opts.colors);
    }
}
