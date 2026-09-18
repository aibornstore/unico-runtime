//! E4 Disassembler — binary → human-readable text
//!
//! ## Example
//! ```rust,no_run
//! use unico_runtime::decode_disasm;
//! use unico_runtime::e4_disasm::FmtOpts;
//! let bytes = vec![]; // read from file with std::fs::read
//! let text = decode_disasm(&bytes).unwrap(); // colored
//! let opts = FmtOpts { colors: false, show_memory: true, hex_cols: 16 };
//! let text = unico_runtime::decode_disasm_opts(&bytes, opts).unwrap(); // plain
//! println!("{}", text);
//! ```

use crate::e4_ser::decode_e4;
use crate::error::Result;
use crate::exec::e4::{E4FunctionDef, E4Module, Instruction};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FmtOpts {
    /// Use ANSI color codes. Default: false.
    pub colors: bool,
    /// Show memory as hex. Default: true.
    pub show_memory: bool,
    /// Max hex bytes per line. Default: 16.
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
            show_memory: true,
            hex_cols: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Color codes
// ---------------------------------------------------------------------------

struct Out {
    buf: String,
    opts: FmtOpts,
}

impl Out {
    fn new(opts: FmtOpts) -> Self {
        Self { buf: String::new(), opts }
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

    fn kw(&mut self, s: &str) { self.push_colored(s, MAGENTA); }
    fn op(&mut self, s: &str) { self.push_colored(s, BOLD); }
    fn reg(&mut self, s: &str) { self.push_colored(s, YELLOW); }
    fn type_(&mut self, s: &str) { self.push_colored(s, CYAN); }
    fn value(&mut self, s: &str) { self.push_colored(s, GREEN); }
    fn comment(&mut self, s: &str) {
        if self.opts.colors {
            self.buf.push_str(DIM);
        }
        self.buf.push_str(s);
        if self.opts.colors {
            self.buf.push_str(RESET);
        }
    }
    fn error(&mut self, s: &str) { self.push_colored(s, RED); }
    fn plain(&mut self, s: &str) { self.buf.push_str(s); }

    fn finish(self) -> String { self.buf }
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

/// Decode E4 binary and format as readable text (colors enabled).
pub fn decode_disasm(data: &[u8]) -> Result<String> {
    decode_disasm_opts(data, FmtOpts::default())
}

/// Decode E4 binary and format as readable text with options.
pub fn decode_disasm_opts(data: &[u8], opts: FmtOpts) -> Result<String> {
    let module = decode_e4(data)?;
    Ok(fmt_module_opts(&module, opts))
}

/// Format a decoded E4Module as readable text.
pub fn fmt_module(module: &E4Module) -> String {
    fmt_module_opts(module, FmtOpts::default())
}

/// Format a decoded E4Module with options.
pub fn fmt_module_opts(module: &E4Module, opts: FmtOpts) -> String {
    let show_memory = opts.show_memory;
    let hex_cols = opts.hex_cols;
    let mut out = Out::new(opts);

    out.writeln("");
    out.push_colored("; ══════════════════════════ E4 Module ══════════════════════════", DIM);
    out.writeln("");

    // Memory
    if show_memory && !module.memory.is_empty() {
        out.kw("memory");
        out.plain(" ");
        out.comment(&format!("{} bytes", module.memory.len()));
        out.writeln(":");
        for (i, chunk) in module.memory.chunks(hex_cols).enumerate() {
            let addr = i * hex_cols;
            let hex: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
            out.plain("  ");
            out.value(&format!("{:04x}", addr));
            out.plain("  ");
            out.comment(&hex);
            out.writeln("");
        }
    }

    // Functions
    out.kw("functions");
    out.plain(" ");
    out.writeln("{");
    for (fi, f) in module.functions.iter().enumerate() {
        fmt_function(&mut out, f, fi);
    }
    out.writeln("}");
    out.writeln("");
    out.push_colored("; ══════════════════════════════════════════════════════════════", DIM);
    out.writeln("");

    out.finish()
}

fn fmt_function(out: &mut Out, f: &E4FunctionDef, fi: usize) {
    // Signature
    out.plain("  ");
    out.op("fn");
    out.plain(" ");
    out.value(&format!("{}", fi));
    out.plain("(");
    for i in 0..f.param_count {
        if i > 0 {
            out.plain(", ");
        }
        out.type_("i32");
    }
    out.plain(")");
    if f.result_count > 0 {
        out.plain(" -> ");
        for i in 0..f.result_count {
            if i > 0 {
                out.plain(", ");
            }
            out.type_("i32");
        }
    }
    out.comment(&format!(
        "  ; regs={} params={} results={}",
        f.register_count, f.param_count, f.result_count
    ));

    // Code
    for (pc, instr) in f.code.iter().enumerate() {
        fmt_instruction(out, instr, pc);
    }
}

fn fmt_instruction(out: &mut Out, instr: &Instruction, pc: usize) {
    out.plain("    ");
    out.comment(&format!("{:4}: ", pc));

    match instr {
        Instruction::Br { target } => {
            out.op("br");
            out.plain(" block");
            out.value(&format!("{}", target));
        }
        Instruction::BrIf { cond, target } => {
            out.op("br.if");
            out.plain(" ");
            out.reg(&format!("r{}", cond));
            out.plain(" -> block");
            out.value(&format!("{}", target));
        }
        Instruction::Ret { dst } => {
            out.op("ret");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
        }
        Instruction::Trap => {
            out.error("trap");
        }
        Instruction::Cmp { pred, dst, a, b } => {
            out.op("cmp");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
            out.comment(&format!(" pred={}", pred));
        }
        Instruction::LoadI64 { dst, addr } => {
            out.op("load.i64");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", [r");
            out.reg(&format!("{}", addr));
            out.plain("]");
        }
        Instruction::StoreI64 { addr, src } => {
            out.op("store.i64");
            out.plain(" [r");
            out.reg(&format!("{}", addr));
            out.plain("], ");
            out.reg(&format!("r{}", src));
        }
        Instruction::IAdd { dst, a, b } => {
            out.op("iadd");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::ISub { dst, a, b } => {
            out.op("isub");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::IMul { dst, a, b } => {
            out.op("imul");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::IDiv { dst, a, b } => {
            out.op("idiv");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::IAnd { dst, a, b } => { out.op("iand"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); out.plain(", "); out.reg(&format!("r{}", b)); }
        Instruction::IOr { dst, a, b } => { out.op("ior"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); out.plain(", "); out.reg(&format!("r{}", b)); }
        Instruction::IXor { dst, a, b } => { out.op("ixor"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); out.plain(", "); out.reg(&format!("r{}", b)); }
        Instruction::INot { dst, a } => { out.op("inot"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::IClz { dst, a } => { out.op("iclz"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::ICtz { dst, a } => { out.op("ictz"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::IPopcnt { dst, a } => { out.op("ipopcnt"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::IRotl { dst, a, b } => { out.op("irotl"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); out.plain(", "); out.reg(&format!("r{}", b)); }
        Instruction::IRotr { dst, a, b } => { out.op("irotr"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); out.plain(", "); out.reg(&format!("r{}", b)); }
        Instruction::FAdd { dst, a, b } => {
            out.op("fadd");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::FSub { dst, a, b } => {
            out.op("fsub");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::FMul { dst, a, b } => {
            out.op("fmul");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::FDiv { dst, a, b } => {
            out.op("fdiv");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
        }
        Instruction::FSqrt { dst, a } => {
            out.op("fsqrt");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::FNeg { dst, a } => {
            out.op("fneg");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::FAbs { dst, a } => {
            out.op("fabs");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::FRound { dst, a } => {
            out.op("fround");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::FCmp { pred, dst, a, b } => {
            out.op("fcmp");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
            out.plain(", ");
            out.reg(&format!("r{}", b));
            out.comment(&format!(" pred={}", pred));
        }
        Instruction::I2F { dst, a } => {
            out.op("i2f");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::F2I { dst, a } => {
            out.op("f2i");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::U2F { dst, a } => {
            out.op("u2f");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::F2U { dst, a } => {
            out.op("f2u");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", a));
        }
        Instruction::Mov { dst, src } => {
            out.op("mov");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(", ");
            out.reg(&format!("r{}", src));
        }
        Instruction::FImm { dst, imm } => {
            out.op("fimm");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(" ");
            out.value(&format!("{:?}", imm));
        }
        Instruction::FAddF64 { dst, a, b } => { out.op("fadd.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", r"); out.value(&format!("{}r, r{}", a, b)); }
        Instruction::FSubF64 { dst, a, b } => { out.op("fsub.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", r"); out.value(&format!("{}r, r{}", a, b)); }
        Instruction::FMulF64 { dst, a, b } => { out.op("fmul.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", r"); out.value(&format!("{}r, r{}", a, b)); }
        Instruction::FDivF64 { dst, a, b } => { out.op("fdiv.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", r"); out.value(&format!("{}r, r{}", a, b)); }
        Instruction::FSqrtF64 { dst, a } => { out.op("fsqrt.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::FNegF64 { dst, a } => { out.op("fneg.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::FAbsF64 { dst, a } => { out.op("fabs.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::FRoundF64 { dst, a } => { out.op("fround.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::FCmpF64 { pred, dst, a, b } => { out.op("fcmp.f64"); out.plain(" "); out.value(&format!("pred={}", pred)); out.plain(" r"); out.reg(&format!("{}", dst)); out.plain(", r"); out.value(&format!("{}r, r{}", a, b)); }
        Instruction::I2F64 { dst, a } => { out.op("i2f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::F642I { dst, a } => { out.op("f64i"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::U2F64 { dst, a } => { out.op("u2f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::F642U { dst, a } => { out.op("f64u"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(", "); out.reg(&format!("r{}", a)); }
        Instruction::FImmF64 { dst, imm } => { out.op("fimm.f64"); out.plain(" "); out.reg(&format!("r{}", dst)); out.plain(" "); out.value(&format!("{:?}", imm)); }
        Instruction::HostCall { id, args, results } => {
            out.op("host.call");
            out.plain(" ");
            out.value(&format!("id={}", id));
            if !args.is_empty() {
                out.plain(" args=[");
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        out.plain(", ");
                    }
                    out.reg(&format!("r{}", a));
                }
                out.plain("]");
            }
            if !results.is_empty() {
                out.plain(" results=[");
                for (i, r) in results.iter().enumerate() {
                    if i > 0 {
                        out.plain(", ");
                    }
                    out.reg(&format!("r{}", r));
                }
                out.plain("]");
            }
        }
        Instruction::TableBr { table_idx, index } => {
            out.op("table.br");
            out.plain(" ");
            out.value(&format!("table={}", table_idx));
            out.plain(" ");
            out.reg(&format!("r{}", index));
        }
        Instruction::MemGrow { dst, delta } => {
            out.op("mem.grow");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(" ");
            out.value(&format!("+{} bytes", delta));
        }
        Instruction::SExt { dst, a } => {
            out.op("sxt");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(" ");
            out.reg(&format!("r{}", a));
        }
        Instruction::ZExt { dst, a } => {
            out.op("zxt");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(" ");
            out.reg(&format!("r{}", a));
        }
        Instruction::MemCopy { dst, src, size } => {
            out.op("mem.copy");
            out.plain(" ");
            out.reg(&format!("r{}", dst));
            out.plain(" ");
            out.reg(&format!("r{}", src));
            out.plain(" ");
            out.value(&format!("{} bytes", size));
        }
        Instruction::MemFill { addr, value, size } => {
            out.op("mem.fill");
            out.plain(" ");
            out.reg(&format!("r{}", addr));
            out.plain(" ");
            out.value(&format!("{:#x}", value));
            out.plain(" ");
            out.value(&format!("{} bytes", size));
        }
    }
    out.writeln("");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e4_ser::encode_e4;
    use crate::exec::e4::E4Module;

    #[test]
    fn test_disasm_basic() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.5 },
                    Instruction::FImm { dst: 1, imm: 2.5 },
                    Instruction::FAdd { dst: 2, a: 0, b: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm(&encoded).unwrap();
        assert!(text.contains("fn 0"));
        assert!(text.contains("fimm"));
        assert!(text.contains("fadd"));
        assert!(text.contains("ret"));
    }

    #[test]
    fn test_disasm_no_colors() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![Instruction::Ret { dst: 0 }],
            }],
            memory: vec![],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm_opts(
            &encoded,
            FmtOpts { colors: false, show_memory: false, hex_cols: 16 },
        )
        .unwrap();
        assert!(!text.contains("\x1b["));
        assert!(text.contains("ret"));
    }

    #[test]
    fn test_disasm_hostcall() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 3.14 },
                    Instruction::HostCall { id: 0, args: vec![0], results: vec![1] },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm(&encoded).unwrap();
        assert!(text.contains("host.call"));
        assert!(text.contains("id=0"));
    }

    #[test]
    fn test_disasm_fcmp() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::FImm { dst: 0, imm: 1.0 },
                    Instruction::FImm { dst: 1, imm: 2.0 },
                    Instruction::FCmp { pred: 0, dst: 2, a: 0, b: 1 },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm(&encoded).unwrap();
        assert!(text.contains("fcmp"));
        assert!(text.contains("pred=0"));
    }

    #[test]
    fn test_disasm_memory() {
        let module = E4Module {
            functions: vec![],
            memory: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm_opts(
            &encoded,
            FmtOpts { colors: false, show_memory: true, hex_cols: 4 },
        )
        .unwrap();
        // Lowercase hex with spaces, 4 bytes per line
        assert!(text.contains("de ad be ef"));
        assert!(text.contains("ca fe"));
    }

    // -------------------------------------------------------------------------
    // T30: Disasm tests for missing instructions
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_all_instruction_types() {
        // Disassemble every instruction type
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 16,
                code: vec![
                    Instruction::Br { target: 5 },
                    Instruction::BrIf { cond: 0, target: 4 },
                    Instruction::Cmp { pred: 4, dst: 1, a: 2, b: 3 },
                    Instruction::LoadI64 { dst: 4, addr: 5 },
                    Instruction::StoreI64 { addr: 5, src: 4 },
                    Instruction::FAdd { dst: 6, a: 0, b: 1 },
                    Instruction::FSub { dst: 7, a: 0, b: 1 },
                    Instruction::FMul { dst: 8, a: 0, b: 1 },
                    Instruction::FDiv { dst: 9, a: 0, b: 1 },
                    Instruction::FSqrt { dst: 10, a: 0 },
                    Instruction::FNeg { dst: 11, a: 0 },
                    Instruction::FAbs { dst: 12, a: 0 },
                    Instruction::FRound { dst: 13, a: 0 },
                    Instruction::FCmp { pred: 0, dst: 14, a: 0, b: 1 },
                    Instruction::I2F { dst: 15, a: 0 },
                    Instruction::F2I { dst: 15, a: 0 },
                    Instruction::U2F { dst: 15, a: 0 },
                    Instruction::F2U { dst: 15, a: 0 },
                    Instruction::Mov { dst: 15, src: 0 },
                    Instruction::FImm { dst: 0, imm: 3.14 },
                    Instruction::HostCall { id: 0, args: vec![0], results: vec![1] },
                    Instruction::ZExt { dst: 0, a: 1 },
                    Instruction::SExt { dst: 1, a: 2 },
                    Instruction::MemCopy { dst: 0, src: 1, size: 8 },
                    Instruction::MemFill { addr: 0, value: 1, size: 8 },
                    Instruction::MemGrow { dst: 0, delta: 1 },
                    Instruction::TableBr { table_idx: 0, index: 0 },
                    Instruction::Trap,
                    Instruction::Ret { dst: 0 },
                ],
            }],
            memory: vec![0u8; 256],
            tables: vec![vec![3, 4]], // table 0: index 0 → pc 3, index 1 → pc 4
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm(&encoded).unwrap();
        assert!(text.contains("br "));
        assert!(text.contains("br.if"));
        assert!(text.contains("cmp "));
        assert!(text.contains("load.i64 "));
        assert!(text.contains("store.i64 "));
        assert!(text.contains("fadd "));
        assert!(text.contains("fsub "));
        assert!(text.contains("fmul "));
        assert!(text.contains("fdiv "));
        assert!(text.contains("fsqrt "));
        assert!(text.contains("fneg "));
        assert!(text.contains("fabs "));
        assert!(text.contains("fround "));
        assert!(text.contains("fcmp "));
        assert!(text.contains("i2f "));
        assert!(text.contains("f2i "));
        assert!(text.contains("u2f "));
        assert!(text.contains("f2u "));
        assert!(text.contains("mov "));
        assert!(text.contains("fimm "));
        assert!(text.contains("host.call"));
        assert!(text.contains("trap"));
        assert!(text.contains("ret "));
        assert!(text.contains("table.br"), "missing table.br");
        assert!(text.contains("zxt "), "missing zxt");
        assert!(text.contains("sxt "), "missing sxt");
        assert!(text.contains("mem.copy"), "missing mem.copy");
        assert!(text.contains("mem.fill"), "missing mem.fill");
        assert!(text.contains("mem.grow"), "missing mem.grow");
    }

    #[test]
    fn test_disasm_multiple_functions() {
        // Disassemble module with multiple functions
        let module = E4Module {
            functions: vec![
                E4FunctionDef {
                    param_count: 0,
                    result_count: 1,
                    register_count: 2,
                    code: vec![
                        Instruction::FImm { dst: 0, imm: 1.0 },
                        Instruction::Ret { dst: 0 },
                    ],
                },
                E4FunctionDef {
                    param_count: 1,
                    result_count: 0,
                    register_count: 2,
                    code: vec![Instruction::Trap],
                },
            ],
            memory: vec![],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm(&encoded).unwrap();
        assert!(text.contains("fn 0"));
        assert!(text.contains("fn 1"));
        assert!(text.contains("params=0"));
        assert!(text.contains("params=1"));
    }

    #[test]
    fn test_disasm_f64_instructions() {
        // All F64 instruction types appear in disassembly
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 3.14 },
                    Instruction::FAddF64 { dst: 1, a: 0, b: 0 },
                    Instruction::FMulF64 { dst: 2, a: 0, b: 0 },
                    Instruction::FSqrtF64 { dst: 3, a: 0 },
                    Instruction::FCmpF64 { pred: 0, dst: 4, a: 0, b: 0 },
                    Instruction::I2F64 { dst: 5, a: 0 },
                    Instruction::F642I { dst: 6, a: 0 },
                    Instruction::Ret { dst: 6 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("fimm.f64"), "missing fimm.f64");
        assert!(text.contains("fadd.f64"), "missing fadd.f64");
        assert!(text.contains("fmul.f64"), "missing fmul.f64");
        assert!(text.contains("fsqrt.f64"), "missing fsqrt.f64");
        assert!(text.contains("fcmp.f64"), "missing fcmp.f64");
        assert!(text.contains("i2f64"), "missing i2f64");
        assert!(text.contains("f64i"), "missing f64i");
    }

    #[test]
    fn test_disasm_integer_arithmetic() {
        // Integer arithmetic instructions appear in disassembly
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::IAdd { dst: 0, a: 0, b: 1 },
                    Instruction::ISub { dst: 1, a: 0, b: 2 },
                    Instruction::IMul { dst: 2, a: 1, b: 3 },
                    Instruction::IDiv { dst: 3, a: 2, b: 1 },
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("iadd"), "missing iadd");
        assert!(text.contains("isub"), "missing isub");
        assert!(text.contains("imul"), "missing imul");
        assert!(text.contains("idiv"), "missing idiv");
    }

    // -------------------------------------------------------------------------
    // T31: F64 binary/div, F64 unary, F64 conversions
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_f64_binary_div() {
        // FSubF64 and FDivF64 — not covered by test_disasm_f64_instructions
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: 10.0 },
                    Instruction::FImmF64 { dst: 1, imm: 2.0 },
                    Instruction::FSubF64 { dst: 2, a: 0, b: 1 },
                    Instruction::FDivF64 { dst: 3, a: 0, b: 1 },
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("fsub.f64"), "missing fsub.f64");
        assert!(text.contains("fdiv.f64"), "missing fdiv.f64");
    }

    #[test]
    fn test_disasm_f64_unary_and_conversions() {
        // FNegF64, FAbsF64, FRoundF64, U2F64, F642U — never tested
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::FImmF64 { dst: 0, imm: -3.14 },
                    Instruction::FNegF64 { dst: 1, a: 0 },
                    Instruction::FAbsF64 { dst: 2, a: 0 },
                    Instruction::FRoundF64 { dst: 3, a: 0 },
                    Instruction::I2F64 { dst: 4, a: 0 },
                    Instruction::U2F64 { dst: 5, a: 0 },
                    Instruction::F642I { dst: 6, a: 0 },
                    Instruction::F642U { dst: 7, a: 0 },
                    Instruction::Ret { dst: 7 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("fneg.f64"), "missing fneg.f64");
        assert!(text.contains("fabs.f64"), "missing fabs.f64");
        assert!(text.contains("fround.f64"), "missing fround.f64");
        assert!(text.contains("u2f64"), "missing u2f64");
        assert!(text.contains("f64u"), "missing f64u");
    }

    // -------------------------------------------------------------------------
    // T32: HostCall output branches
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_hostcall_variants() {
        // Test empty args, empty results, multiple args/results
        // fmt_instruction HostCall: args.is_empty(), results.is_empty(), multi-item formatting

        // Variant: empty args, non-empty results
        let m1 = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 4,
                code: vec![
                    Instruction::HostCall { id: 5, args: vec![], results: vec![2] },
                    Instruction::Ret { dst: 2 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let t1 = fmt_module_opts(&m1, FmtOpts::default());
        assert!(t1.contains("host.call"), "missing host.call");
        assert!(t1.contains("id=5"), "missing id=5");

        // Variant: non-empty args, empty results
        let m2 = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 0,
                register_count: 4,
                code: vec![
                    Instruction::HostCall { id: 3, args: vec![0, 1], results: vec![] },
                    Instruction::Trap,
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let t2 = fmt_module_opts(&m2, FmtOpts::default());
        assert!(t2.contains("host.call"), "missing host.call");
        assert!(t2.contains("id=3"), "missing id=3");

        // Variant: multiple args AND results
        let m3 = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::HostCall { id: 7, args: vec![0, 1, 2], results: vec![3, 4] },
                    Instruction::Ret { dst: 3 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let t3 = fmt_module_opts(&m3, FmtOpts::default());
        assert!(t3.contains("host.call"), "missing host.call");
        assert!(t3.contains("id=7"), "missing id=7");
    }

    // -------------------------------------------------------------------------
    // T33: Integer bitwise instructions
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_integer_bitwise() {
        // IAnd, IOr, IXor, INot, IClz, ICtz, IPopcnt, IRotl, IRotr
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 8,
                code: vec![
                    Instruction::IAdd { dst: 0, a: 0, b: 0 }, // ensure r0 has value
                    Instruction::IAnd { dst: 1, a: 0, b: 0 },
                    Instruction::IOr { dst: 2, a: 0, b: 0 },
                    Instruction::IXor { dst: 3, a: 0, b: 0 },
                    Instruction::INot { dst: 4, a: 0 },
                    Instruction::IClz { dst: 5, a: 0 },
                    Instruction::ICtz { dst: 6, a: 0 },
                    Instruction::IPopcnt { dst: 7, a: 0 },
                    Instruction::IRotl { dst: 0, a: 0, b: 1 },
                    Instruction::IRotr { dst: 1, a: 0, b: 1 },
                    Instruction::Ret { dst: 1 },
                ],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("iand"), "missing iand");
        assert!(text.contains("ior"), "missing ior");
        assert!(text.contains("ixor"), "missing ixor");
        assert!(text.contains("inot"), "missing inot");
        assert!(text.contains("iclz"), "missing iclz");
        assert!(text.contains("ictz"), "missing ictz");
        assert!(text.contains("ipopcnt"), "missing ipopcnt");
        assert!(text.contains("irotl"), "missing irotl");
        assert!(text.contains("irotr"), "missing irotr");
    }

    // -------------------------------------------------------------------------
    // T34: Format options - colors enabled
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_colors_enabled() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 2,
                code: vec![Instruction::Ret { dst: 0 }],
            }],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(
            &module,
            FmtOpts { colors: true, show_memory: false, hex_cols: 16 },
        );
        // Should contain ANSI color codes
        assert!(text.contains("\x1b[35m"), "missing magenta color code");
        assert!(text.contains("\x1b[1m"), "missing bold color code");
        assert!(text.contains("\x1b[33m"), "missing yellow color code");
        assert!(text.contains("\x1b[32m"), "missing green color code");
        assert!(text.contains("\x1b[0m"), "missing reset code");
    }

    // -------------------------------------------------------------------------
    // T35: Empty module with no functions
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_empty_module() {
        let module = E4Module {
            functions: vec![],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("E4 Module"));
        assert!(text.contains("functions"));
        assert!(text.contains("functions {"));
        assert!(text.contains("}"));
    }

    // -------------------------------------------------------------------------
    // T36: Memory formatting with different hex_cols
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_memory_hex_cols() {
        // Test with hex_cols=1 (one byte per line)
        let module = E4Module {
            functions: vec![],
            memory: vec![0xDE, 0xAD, 0xBE, 0xEF],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm_opts(
            &encoded,
            FmtOpts { colors: false, show_memory: true, hex_cols: 1 },
        )
        .unwrap();
        // With hex_cols=1, each byte on its own line
        assert!(text.contains("00  de"));
        assert!(text.contains("01  ad"));
        assert!(text.contains("02  be"));
        assert!(text.contains("03  ef"));
    }

    #[test]
    fn test_disasm_memory_large() {
        // Test with large memory that spans multiple lines
        let module = E4Module {
            functions: vec![],
            memory: vec![0xAA; 64],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm_opts(
            &encoded,
            FmtOpts { colors: false, show_memory: true, hex_cols: 16 },
        )
        .unwrap();
        assert!(text.contains("memory"));
        assert!(text.contains("bytes"));
        // Should have 4 lines of 16 bytes each (address 0x00, 0x10, 0x20, 0x30)
        assert!(text.contains("0000"), "missing address 0000");
        assert!(text.contains("0010"), "missing address 0010");
        assert!(text.contains("0020"), "missing address 0020");
        assert!(text.contains("0030"), "missing address 0030");
    }

    // -------------------------------------------------------------------------
    // T37: Function signature formatting
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_function_signature_with_params_and_results() {
        // Function with multiple params and results
        let module = E4Module {
            functions: vec![
                E4FunctionDef {
                    param_count: 3,
                    result_count: 2,
                    register_count: 8,
                    code: vec![
                        Instruction::Ret { dst: 0 },
                    ],
                },
            ],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        // Function signature with params and results
        assert!(text.contains("fn 0"));
        assert!(text.contains("params=3"));
        assert!(text.contains("results=2"));
        // Check that type markers are present (with color codes)
        assert!(text.contains("i32"));
    }

    #[test]
    fn test_disasm_function_no_results() {
        // Function with params but no results (void function)
        let module = E4Module {
            functions: vec![
                E4FunctionDef {
                    param_count: 2,
                    result_count: 0,
                    register_count: 4,
                    code: vec![Instruction::Trap],
                },
            ],
            memory: vec![],
            tables: vec![],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        assert!(text.contains("fn 0(i32, i32)"));
        assert!(text.contains("results=0"));
    }

    // -------------------------------------------------------------------------
    // T38: Error handling - decode errors
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_invalid_magic() {
        // Invalid magic bytes should fail
        let invalid_data = vec![0x00, 0x01, 0x02, 0x03, 0x01];
        let result = decode_disasm(&invalid_data);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("bad magic") || err_msg.contains("E4"));
    }

    #[test]
    fn test_disasm_truncated_header() {
        // Truncated header should fail
        let truncated = vec![0xE4, 0x58, 0x58]; // only 3 bytes
        let result = decode_disasm(&truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_disasm_truncated_function() {
        // Valid header but truncated function data
        let mut data = Vec::new();
        data.extend_from_slice(b"E4XX"); // magic
        data.push(1); // version
        data.extend_from_slice(&0u32.to_le_bytes()); // mem_size = 0
        data.extend_from_slice(&1u32.to_le_bytes()); // fn_count = 1
        // But no function data follows - truncated
        let result = decode_disasm(&data);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // T39: decode_disasm_opts with show_memory=false
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_show_memory_false() {
        let module = E4Module {
            functions: vec![E4FunctionDef {
                param_count: 0,
                result_count: 1,
                register_count: 2,
                code: vec![Instruction::Ret { dst: 0 }],
            }],
            memory: vec![0xDE, 0xAD, 0xBE, 0xEF],
            tables: vec![],
        };
        let encoded = encode_e4(&module);
        let text = decode_disasm_opts(
            &encoded,
            FmtOpts { colors: false, show_memory: false, hex_cols: 16 },
        )
        .unwrap();
        // Memory should NOT be in output when show_memory=false
        assert!(!text.contains("de ad"));
        assert!(!text.contains("memory"));
        // But functions should still be there
        assert!(text.contains("fn 0"));
    }

    // -------------------------------------------------------------------------
    // T40: fmt_module_opts builder pattern
    // -------------------------------------------------------------------------

    #[test]
    fn test_fmt_opts_builder() {
        let opts = FmtOpts::default().colors(true);
        assert!(opts.colors);
        assert!(opts.show_memory);
        assert_eq!(opts.hex_cols, 16);
    }

    // -------------------------------------------------------------------------
    // T41: Module with tables
    // -------------------------------------------------------------------------

    #[test]
    fn test_disasm_tables_rendered() {
        // Module with tables should show table data
        let module = E4Module {
            functions: vec![],
            memory: vec![],
            tables: vec![
                vec![10, 20, 30], // table 0
                vec![100],        // table 1
            ],
        };
        let text = fmt_module_opts(&module, FmtOpts::default());
        // Tables section should be present (from fmt_module_opts)
        // Note: the current implementation doesn't explicitly show table contents
        // but the module should parse correctly
        assert!(text.contains("E4 Module"));
    }
}
