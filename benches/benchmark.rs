use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use unico_runtime::{E2Module, E2Executor, exec::e3::{E3Module, E3Executor, Instruction, build_e3}};

/// Build a Python-compatible E2 module with the given code bytes.
/// Python format: FUNC section = [func_count, param_count, result_count, register_count,
/// code_offset, code_size] (5 ULEB fields per function), code_offset is offset INTO
/// the code section (after the ULEB length prefix).
fn build_py_compat_module(code: Vec<u8>) -> Vec<u8> {
    fn uleb(mut v: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v as u8) & 0x7f;
            v >>= 7;
            if v != 0 { out.push(byte | 0x80); } else { out.push(byte); break; }
        }
        out
    }
    
    let mut func_payload = uleb(1); // 1 function
    func_payload.extend(uleb(0));  // param_count = 0
    func_payload.extend(uleb(1));  // result_count = 1
    func_payload.extend(uleb(4));  // register_count = 4
    func_payload.extend(uleb(0));  // code_offset = 0
    func_payload.extend(uleb(code.len())); // code_size
    
    let mut m = Vec::new();
    m.extend(b"UNICO\xe2");
    m.push(0x02); // FUNC section
    m.extend(uleb(func_payload.len()));
    m.extend(func_payload);
    m.push(0x03); // CODE section
    m.extend(uleb(code.len())); // code_section_len = actual code bytes
    m.extend(code);
    m.push(0x00); // END
    m
}

/// MEM42 workload: store 42 at addr=0, load it back, return 42.
/// Equivalent to Python's GOLDEN_MEM42.
fn build_mem42_module() -> Vec<u8> {
    // 5 instructions: K.I64 r0=0, K.I64 r1=42, STORE r0, r1, LOAD r2, r0, RET r2
    let code = vec![
        0x0b, 0x00, 0x00,  // K.I64 r0=0
        0x0b, 0x01, 0x2a, // K.I64 r1=42
        0x92, 0x00, 0x01,  // STORE addr=r0, src=r1
        0x91, 0x02, 0x00,  // LOAD r2, addr=r0
        0xa6, 0x01, 0x02,  // RET result_count=1, result=r2
    ];
    build_py_compat_module(code)
}

/// Parse + execute once
fn parse_and_exec(bytes: &[u8]) {
    let module = E2Module::parse(black_box(bytes)).expect("parse");
    let mut exec = E2Executor::new();
    let result = exec.execute(&module).expect("execute");
    assert_eq!(result.value, Some(42));
}

fn bench_e2_mem42(c: &mut Criterion) {
    let module_bytes = build_mem42_module();
    
    // Warm-up
    parse_and_exec(&module_bytes);
    
    // Single parse+exec
    c.bench_function("e2_mem42_once", |b| {
        b.iter(|| parse_and_exec(&module_bytes))
    });
    
    // Batch iterations
    let mut group = c.benchmark_group("e2_mem42_batch");
    for &count in &[100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                for _ in 0..count {
                    parse_and_exec(&module_bytes);
                }
            });
        });
    }
    group.finish();
}

fn bench_e2_repeated(c: &mut Criterion) {
    // Build 50 store/load pairs + RET = 103 instructions
    let mut code = vec![
        0x0b, 0x00, 0x00, // K.I64 r0=0
        0x0b, 0x01, 0x2a, // K.I64 r1=42
    ];
    for _ in 0..50 {
        code.extend_from_slice(&[0x92, 0x00, 0x01]); // STORE
        code.extend_from_slice(&[0x91, 0x02, 0x00]); // LOAD
    }
    code.extend_from_slice(&[0xa6, 0x01, 0x02]); // RET
    
    let module_bytes = build_py_compat_module(code);
    let module = E2Module::parse(&module_bytes).expect("parse");
    
    c.bench_function("e2_repeated_50x", |b| {
        b.iter(|| {
            let mut exec = E2Executor::new();
            let result = exec.execute(black_box(&module));
            black_box(result)
        });
    });
}

fn bench_e2_parser(c: &mut Criterion) {
    let module_bytes = build_mem42_module();
    let bytes = black_box(&module_bytes);
    c.bench_function("e2_parse_only", |b| {
        b.iter(|| E2Module::parse(bytes));
    });
}

fn bench_e2_executor_only(c: &mut Criterion) {
    let module_bytes = build_mem42_module();
    let module = E2Module::parse(&module_bytes).expect("parse");
    c.bench_function("e2_execute_only", |b| {
        b.iter(|| {
            let mut exec = E2Executor::new();
            let result = exec.execute(black_box(&module));
            black_box(result)
        });
    });
}

// E3 benchmarks
fn bench_e3_add(c: &mut Criterion) {
    let bytes = build_e3(&[
        Instruction::KImm { dst: 0, value: 10 },
        Instruction::KImm { dst: 1, value: 32 },
        Instruction::Add { dst: 0, a: 0, b: 1 }, // r0 = 10 + 32
        Instruction::Ret,
    ]);
    let module = E3Module::parse(&bytes).expect("parse");
    c.bench_function("e3_add", |b| {
        b.iter(|| {
            let mut e = E3Executor::new();
            let r = e.execute(black_box(&module));
            black_box(r)
        });
    });
}

fn bench_e3_parser(c: &mut Criterion) {
    let bytes = build_e3(&[
        Instruction::KImm { dst: 0, value: 42 },
        Instruction::Ret,
    ]);
    let bytes = black_box(bytes);
    c.bench_function("e3_parse_only", |b| {
        b.iter(|| E3Module::parse(&bytes));
    });
}

fn bench_e3_store_load(c: &mut Criterion) {
    let bytes = build_e3(&[
        Instruction::KImm { dst: 0, value: 0 },      // addr = 0
        Instruction::KImm { dst: 1, value: 999 },     // value = 999
        Instruction::StoreI64 { addr: 0, src: 1 },    // mem[0] = 999
        Instruction::LoadI64 { dst: 2, addr: 0 },     // r2 = mem[0]
        Instruction::Ret,
    ]);
    let module = E3Module::parse(&bytes).expect("parse");
    c.bench_function("e3_store_load", |b| {
        b.iter(|| {
            let mut e = E3Executor::new();
            let r = e.execute(black_box(&module));
            black_box(r)
        });
    });
}

fn bench_e3_repeated_arith(c: &mut Criterion) {
    // 100 add operations
    let mut instrs = vec![
        Instruction::KImm { dst: 0, value: 1 },
        Instruction::KImm { dst: 1, value: 2 },
    ];
    for _ in 0..100 {
        instrs.push(Instruction::Add { dst: 0, a: 0, b: 1 }); // r0 += r1
    }
    instrs.push(Instruction::Ret);
    let bytes = build_e3(&instrs);
    let module = E3Module::parse(&bytes).expect("parse");
    c.bench_function("e3_arith_100x", |b| {
        b.iter(|| {
            let mut e = E3Executor::new();
            let r = e.execute(black_box(&module));
            black_box(r)
        });
    });
}

fn bench_e3_div(c: &mut Criterion) {
    let bytes = build_e3(&[
        Instruction::KImm { dst: 0, value: 100 },
        Instruction::KImm { dst: 1, value: 7 },
        Instruction::DivI64 { dst: 2, a: 0, b: 1 }, // r2 = 100 / 7 = 14
        Instruction::Ret,
    ]);
    let module = E3Module::parse(&bytes).expect("parse");
    c.bench_function("e3_div", |b| {
        b.iter(|| {
            let mut e = E3Executor::new();
            let r = e.execute(black_box(&module));
            black_box(r)
        });
    });
}

criterion_group!(
    benches,
    bench_e2_mem42,
    bench_e2_repeated,
    bench_e2_parser,
    bench_e2_executor_only,
    bench_e3_add,
    bench_e3_parser,
    bench_e3_store_load,
    bench_e3_repeated_arith,
    bench_e3_div,
);
criterion_main!(benches);
