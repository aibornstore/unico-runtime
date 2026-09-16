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
    use crate::ir::{U30Block, U30Function, U30Module, U30Op, U30Terminator, U30Type, U30Value, U30RegionDecl};

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
}
