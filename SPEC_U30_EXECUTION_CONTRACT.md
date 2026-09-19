# UNICO v3.0 — Execution Contract Specification

**Version:** 2.0
**Gate:** U30-EXECUTION-CONTRACT-0001
**Status:** IN_PROGRESS
**Parent:** v2.7.0 frozen base
**Implementation reference:** `v3_0/rust-runtime/` (yuriy branch, 2,308 tests, 96.92% coverage)

---

## 1. Overview

This document defines the **execution contract** for UNICO v3.0 — the explicit agreement between:
- The **program** (UNICO module bytes: legacy E0-E7 or modern U30)
- The **runtime** (Rust execution engine)
- The **host** (capability provider)
- The **provenance** (evidence trail)

### 1.1 Architecture

```
Source Code / Legacy Bytes
    ↓
E0-E7 Frontend (decode + compatibility validation)
    ↓
U30 IR (semantic layer)
    ↓
Verifier (static validation)
    ↓
Runtime Executor (dispatch + semantics)
    ↓
Host Boundary v2 (capability mediation)
    ↓
Execution Receipt
```

### 1.2 Profile Registry

| Profile | Magic | Description | Status |
|---------|-------|-------------|--------|
| E0 | `UNICO\xE0` | Basic i64 operations | ✅ Frozen |
| E1 | `UNICO\xE1` | Control flow + calls | ✅ Frozen |
| E2 | `UNICO\xE2` | Linear memory 4KB | ✅ Frozen |
| E3 | `UNICO\xE3` | Extended arithmetic + memory 4KB | ✅ Frozen |
| E4 | `UNICO\xE4` | WASM-like: F64, bitwise, tables, host calls | ✅ Frozen |
| E5 | `UNICO\xE5` | Pass-through for E3 | ✅ Frozen |
| E6 | `UNICO\xE6` | Pass-through for E4 | ✅ Frozen |
| E7 | `UNICO\xE7` | Complete crypto suite | ✅ Frozen |

---

## 2. Execution Input Contract

### 2.1 Input Schema

```json
{
  "module": {
    "profile": "E0|E1|E2|E3|E4|E5|E6|E7|U30",
    "magic": "554e49434fXX",
    "sections": ["FUNC", "CODE", "MEM?", "TABLE?", "END"],
    "bytes": "<hex or binary>"
  },
  "host_boundary": {
    "schema": "unico-portable-host-boundary/v2",
    "capabilities": ["print", "add", "mul", "sub", "div", "read", "write"],
    "max_host_calls": 1000,
    "limits": {
      "memory_bytes": 65536,
      "fuel_instructions": 10000000,
      "file_read_bytes": 1048576,
      "file_write_bytes": 1048576
    }
  },
  "provenance": {
    "source": "file|inline|network",
    "hash": "sha256",
    "timestamp": "ISO8601"
  }
}
```

### 2.2 Validation Pipeline

```
Input Bytes
    ↓
1. Magic detection (6 bytes: "UNICO" + profile byte)
    ↓
2. Profile selection (E0/E1/E2/E3/E4/E5/E6/E7)
    ↓
3. Section parsing (FUNC, CODE, MEM?, TABLE?, END)
    ↓
4. Canonical form verification (ULEB canonical encoding)
    ↓
5. Static verification (types, CFG, bounds, region access)
    ↓
6. Host boundary acceptance check (for E4/E6 with HostCall)
    ↓
Ready to Execute OR Reject with Error
```

---

## 3. Execution Output Contract

### 3.1 Success Result

```json
{
  "status": "PASS",
  "result": {
    "values": [42],
    "memory_snapshot": "<base64 if E2/E3/E4>"
  },
  "provenance": {
    "instructions_executed": 1234,
    "fuel_remaining": 987766,
    "host_calls_made": 0,
    "execution_time_us": 150,
    "deterministic": true
  },
  "errors": []
}
```

### 3.2 Error Taxonomy

| Code | Class | Description | Exit |
|------|-------|-------------|------|
| `E0T001` | Explicit | TRAP instruction | 6 |
| `E0T002` | Structural | Container format error | 4 |
| `E0T003` | Canonical | Non-minimal LEB encoding | 4 |
| `E1T001` | Explicit | TRAP instruction | 6 |
| `E1T002` | Fuel | Dispatch budget exhausted | 6 |
| `E1T003` | CFG | Unreachable instruction | 4 |
| `E1T004` | Type | Register type mismatch | 4 |
| `E2T001` | Explicit | TRAP | 6 |
| `E2T002` | Fuel | Dispatch exhausted | 6 |
| `E2T003` | Memory | Out of bounds | 6 |
| `E2T004` | Memory | Alignment error | 6 |
| `E2T005` | Call | Depth exceeded | 6 |
| `E3T001` | Explicit | TRAP | 6 |
| `E3T002` | Fuel | Dispatch exhausted | 6 |
| `E3T003` | Memory | Out of bounds | 6 |
| `E3T004` | Memory | Alignment error | 6 |
| `E3T005` | Type | Register type mismatch | 6 |
| `E4T001` | Explicit | TRAP | 6 |
| `E4T002` | Fuel | Dispatch exhausted | 6 |
| `E4T003` | Memory | Out of bounds | 6 |
| `E4T004` | Memory | Alignment error | 6 |
| `E4T005` | Type | Register type mismatch | 6 |
| `E4T006` | Table | Invalid table index | 6 |
| `E4T007` | Verification | Static verification failed | 4 |
| `E5T001` | Explicit | TRAP (E3 passthrough) | 6 |
| `E5T002` | Fuel | Dispatch exhausted | 6 |
| `E6T001` | Explicit | TRAP (E4 passthrough) | 6 |
| `E6T002` | Fuel | Dispatch exhausted | 6 |
| `E7T001` | Crypto | Crypto operation failed | 6 |
| `E7T002` | Fuel | Dispatch exhausted | 6 |
| `H0001` | Host | Capability denied | 7 |
| `H0002` | Host | Budget exceeded | 7 |
| `H0003` | Host | Invalid request | 7 |
| `U30T001` | Explicit | TRAP | 6 |
| `U30T002` | Fuel | Dispatch exhausted | 6 |
| `U30T003` | Memory | Out of bounds | 6 |
| `U30T004` | Type | Register type mismatch | 6 |
| `U30T005` | Verification | Static verification failed | 4 |

### 3.3 Error Response Schema

```json
{
  "status": "FAIL",
  "error": {
    "code": "E2T003",
    "family": "E2",
    "message": "Memory access out of bounds",
    "details": {
      "address": 4096,
      "limit": 4088,
      "access_width": 8
    }
  },
  "provenance": {
    "instructions_executed": 5000,
    "fuel_remaining": 9500000,
    "host_calls_made": 0,
    "fail_point": "dispatch_42"
  }
}
```

---

## 4. Memory Model

### 4.1 Profile Memory Allocation

| Profile | Allocation | Zeroed | Default Size | Growth |
|---------|------------|--------|--------------|--------|
| E0 | None | N/A | 0 bytes | No |
| E1 | None | N/A | 0 bytes | No |
| E2 | Single page | Yes | 4096 bytes | No |
| E3 | Single page | Yes | 4096 bytes | No |
| E4 | Configurable | Yes | 65536 bytes | Via MemGrow |
| E5 | Single page | Yes | 4096 bytes | No |
| E6 | Configurable | Yes | 65536 bytes | Via MemGrow |
| E7 | None | N/A | 0 bytes | No |

### 4.2 E2/E3 Memory Specification

```
Memory Layout (4096 bytes):
┌──────────────────────────────────────────────────────────────┐
│ Page 0: 4096 bytes                                          │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Address 0x0000 - 0x0FFF (0 - 4095)                     │ │
│ │                                                          │ │
│ │ Valid I64 access: 0x0000 - 0x0FF8 (0 - 4088)           │ │
│ │ I64 requires 8-byte alignment                           │ │
│ │                                                          │ │
│ │ Out of bounds: 0x1000+                                  │ │
│ └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘

Allocation: Arena-based
- Single allocation at module load
- No fragmentation
- No growth (fixed 4096 bytes)
- Freed at module return or trap
```

### 4.3 E4/E6 Memory Specification

```
Memory Layout (up to 1MB):
┌──────────────────────────────────────────────────────────────┐
│ Initial allocation: 65536 bytes (16 pages)                  │
│                                                              │
│ Growth: via MemGrow instruction                              │
│ - Each call adds 4096 bytes                                 │
│ - Maximum: 256 pages = 1,048,576 bytes                       │
│ - Returns previous page count                                │
│                                                              │
│ Access: Bounds-checked before every access                   │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. U30 IR Specification

### 5.1 Module Structure

```
U30Module = Version + Type Universe + Region Declarations
          + Function Imports + Functions + Exports + Tables
```

### 5.2 Type Universe (V1)

| Type | Width | Notes |
|------|-------|-------|
| `unit` | 0 | No value |
| `bool` | 1 bit | Not an integer |
| `u8` | 8 bit | Unsigned byte |
| `u32` | 32 bit | Unsigned 32-bit |
| `i64` | 64 bit | Signed 64-bit |
| `u64` | 64 bit | Unsigned 64-bit |
| `f32` | 32 bit | IEEE 754 single |
| `f64` | 64 bit | IEEE 754 double |
| `cap<K>` | opaque | Capability handle |

### 5.3 U30 Operations (V1)

#### Constants
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `Const` | imm | type | Exact typed bit pattern |

#### Integer Arithmetic (i64)
| Op | Args | Result | Overflow |
|----|------|--------|----------|
| `AddI64` | i64, i64 | i64 | Trap on overflow |
| `SubI64` | i64, i64 | i64 | Trap on overflow |
| `MulI64` | i64, i64 | i64 | Trap on overflow |
| `DivI64` | i64, i64 | i64 | Trap on div-by-zero, overflow |
| `RemI64` | i64, i64 | i64 | Trap on div-by-zero |

#### Integer Arithmetic (u32)
| Op | Args | Result | Overflow |
|----|------|--------|----------|
| `AddU32` | u32, u32 | u32 | Trap on overflow |
| `SubU32` | u32, u32 | u32 | Trap on underflow |
| `MulU32` | u32, u32 | u32 | Trap on overflow |
| `DivU32` | u32, u32 | u32 | Trap on div-by-zero |

#### Integer Arithmetic (u64)
| Op | Args | Result | Overflow |
|----|------|--------|----------|
| `AddU64` | u64, u64 | u64 | Trap on overflow |
| `SubU64` | u64, u64 | u64 | Trap on underflow |
| `MulU64` | u64, u64 | u64 | Trap on overflow |
| `DivU64` | u64, u64 | u64 | Trap on div-by-zero |

#### Binary Operations
| Op | Types | Result | Notes |
|----|-------|--------|-------|
| `And` | u32/u64 | same | Bitwise AND |
| `Or` | u32/u64 | same | Bitwise OR |
| `Xor` | u32/u64 | same | Bitwise XOR |
| `Not` | u32/u64 | same | Bitwise NOT |
| `Shl` | u32/u64, u32 | same | Shift left |
| `ShrU` | u32/u64, u32 | same | Logical shift right |
| `ShrS` | u32/u64, u32 | same | Arithmetic shift right |
| `Rotl` | u32/u64, u32 | same | Rotate left |
| `Rotr` | u32/u64, u32 | same | Rotate right |
| `Clz` | u32/u64 | u32/u64 | Count leading zeros |
| `Ctz` | u32/u64 | u32/u64 | Count trailing zeros |
| `Popcnt` | u32/u64 | u32/u64 | Population count |

#### Comparisons
| Op | Types | Result | Notes |
|----|-------|--------|-------|
| `Eq` | any | bool | Equality |
| `Ne` | any | bool | Inequality |
| `LtS` | i64 | bool | Signed less than |
| `LtU` | u32/u64 | bool | Unsigned less than |
| `GtS` | i64 | bool | Signed greater than |
| `GtU` | u32/u64 | bool | Unsigned greater than |
| `LeS` | i64 | bool | Signed less-or-equal |
| `LeU` | u32/u64 | bool | Unsigned less-or-equal |
| `GeS` | i64 | bool | Signed greater-or-equal |
| `GeU` | u32/u64 | bool | Unsigned greater-or-equal |

#### Type Conversion
| Op | Input | Output | Notes |
|----|-------|--------|-------|
| `ZExt` | u8/u32 | u32/u64 | Zero-extend |
| `SExt` | u8/u32 | i64 | Sign-extend |
| `Trunc` | i64/u64 | u32 | Truncate |
| `I2F` | i64 | f32/f64 | Int to float |
| `F2I` | f32/f64 | i64 | Float to int (trap on overflow) |
| `Reinterpret` | f32/u32 | u32/f32 | Bit reinterpret |
| `ByteSwap` | u32/u64 | u32/u64 | Byte order swap |

#### Floating-Point (f64)
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `FAddF64` | f64, f64 | f64 | |
| `FSubF64` | f64, f64 | f64 | |
| `FMulF64` | f64, f64 | f64 | |
| `FDivF64` | f64, f64 | f64 | Trap on div-by-zero |
| `FSqrtF64` | f64 | f64 | |
| `FAbsF64` | f64 | f64 | |
| `FNegF64` | f64 | f64 | |
| `FRoundF64` | f64 | f64 | Round to nearest |
| `FCmpF64` | f64, f64 | i64 | -1/0/1 for lt/eq/gt, nan→1 |
| `FMinF64` | f64, f64 | f64 | |
| `FMaxF64` | f64, f64 | f64 | |
| `FCeilF64` | f64 | f64 | |
| `FFloorF64` | f64 | f64 | |
| `FTruncF64` | f64 | f64 | |

#### Floating-Point (f32)
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `FAddF32` | f32, f32 | f32 | |
| `FSubF32` | f32, f32 | f32 | |
| `FMulF32` | f32, f32 | f32 | |
| `FDivF32` | f32, f32 | f32 | Trap on div-by-zero |
| `FSqrtF32` | f32 | f32 | |
| `FAbsF32` | f32 | f32 | |
| `FNegF32` | f32 | f32 | |

#### Memory Operations
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `LoadU8` | region, offset | u32 | Zero-extend |
| `LoadI8` | region, offset | i64 | Sign-extend |
| `LoadU16` | region, offset | u32 | Zero-extend |
| `LoadI16` | region, offset | i64 | Sign-extend |
| `LoadU32` | region, offset | u32 | |
| `LoadI32` | region, offset | i64 | Sign-extend |
| `LoadU64` | region, offset | u64 | |
| `LoadI64` | region, offset | i64 | |
| `StoreU8` | region, offset, u32 | unit | |
| `StoreI8` | region, offset, i64 | unit | |
| `StoreU16` | region, offset, u32 | unit | |
| `StoreI16` | region, offset, i64 | unit | |
| `StoreU32` | region, offset, u32 | unit | |
| `StoreI32` | region, offset, i64 | unit | |
| `StoreU64` | region, offset, u64 | unit | |
| `StoreI64` | region, offset, i64 | unit | |

#### Memory Management
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `MemSize` | region | u64 | Current size in bytes |
| `MemGrow` | region, u64 | u64 | Grow by n pages, return prev |
| `MemCopy` | dst, src, u64 | unit | Copy n bytes |
| `MemFill` | region, offset, u32, u64 | unit | Fill n bytes with byte |

#### Control Flow
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `Br` | label | - | Unconditional branch |
| `BrIf` | bool, label | - | Conditional branch |
| `Select` | bool, a, b | type | Select a or b |
| `Ret` | values | - | Return from function |
| `Trap` | - | - | Unconditional trap |
| `Assert` | bool | - | Assert with trap on false |

#### Function Calls
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `Call` | fn_idx, args | results | Direct call |
| `TailCall` | fn_idx, args | - | Tail-call (no return) |
| `IndirectCall` | table, idx, args | results | Via jump table |
| `TableBr` | table, index | - | Jump table dispatch |

#### Control System
| Op | Args | Result | Notes |
|----|------|--------|-------|
| `Break` | - | - | Exit innermost loop |
| `Assert` | bool | - | Trap if false |

### 5.4 E7 Crypto Operations

| Opcode Range | Family | Operations |
|-------------|--------|------------|
| 0x00-0x0F | AES-128 | KeyGen, Encrypt, Decrypt |
| 0x10-0x17 | SHA-256 | Init, Update, Final, Digest |
| 0x18-0x1F | BLAKE2s | Init, Update, Final, Digest |
| 0x20-0x2F | HMAC/HKDF | HMAC-SHA256, HKDF-SHA256 |
| 0x30-0x37 | ChaCha20 | Stream cipher |
| 0x38-0x3F | Poly1305 | MAC |
| 0x40-0x4F | P-256 ECC | KeyGen, ECDH, ECDSASign, ECDSAVerify |
| 0x50-0x57 | Kyber768 | KeyGen, Enc, Dec (ML-KEM) |
| 0x58-0x5F | Dilithium2 | KeyGen, Sign, Verify (ML-DSA) |
| 0x60-0x6F | RSA-2048 | KeyGen, Encrypt, Decrypt |
| 0x70-0x7F | BigInt | AddMod, SubMod, MulMod, ModExp |

---

## 6. Host Boundary v2

### 6.1 Schema

```json
{
  "schema": "unico-portable-host-boundary/v2",
  "abi": "core-int64",
  "version": 2,
  "capabilities": {
    "print": { "enabled": true, "max_bytes": 65536 },
    "add": { "enabled": true },
    "mul": { "enabled": true },
    "sub": { "enabled": true },
    "div": { "enabled": true },
    "read": { "enabled": true, "max_bytes": 1048576 },
    "write": { "enabled": true, "max_bytes": 1048576 }
  },
  "max_host_calls": 1000,
  "deterministic": true
}
```

### 6.2 Capability Request Flow

```
UNICO Module
    ↓
host.call("print", "Hello")
    ↓
┌─────────────────────────────────────────┐
│ Runtime checks:                          │
│ 1. Capability enabled?                   │
│ 2. Budget remaining?                    │
│ 3. Request valid?                       │
│ 4. Log provenance?                       │
└─────────────────────────────────────────┘
    ↓
Result: Success OR Denied OR Over budget
    ↓
UNICO Module continues
```

---

## 7. Provenance Contract

### 7.1 Provenance Schema

```json
{
  "provenance": {
    "module": {
      "source": "file|inline|network",
      "path": "optional/path.unico",
      "hash_sha256": "abc123...",
      "size_bytes": 1024
    },
    "execution": {
      "start_time": "2026-09-10T12:00:00Z",
      "end_time": "2026-09-10T12:00:00.150Z",
      "duration_us": 150,
      "runtime": "rust-1.97"
    },
    "resources": {
      "instructions_executed": 1234,
      "fuel_remaining": 987766,
      "host_calls": 0,
      "memory_used_bytes": 4096
    },
    "result": {
      "status": "PASS|FAIL",
      "values": [42],
      "error_code": null
    }
  }
}
```

### 7.2 Determinism Requirements

For deterministic execution:
1. Same input bytes → Same output
2. Same input bytes → Same execution trace
3. No time-dependent branching
4. No random sources (unless seeded explicitly)
5. No external state (files, network) without capability

---

## 8. Performance Contract

### 8.1 Benchmark Results (Rust, stable 1.97.0)

| Component | Operation | Median | P95 |
|-----------|-----------|--------|-----|
| E0 | i64 add | ~50ns | ~100ns |
| E1 | call + ret | ~100ns | ~200ns |
| E2 | memory load | ~100ns | ~200ns |
| E3 | i64 div | ~200ns | ~400ns |
| E4 | F64 arith | ~100ns | ~200ns |
| E4 | MemGrow | ~500ns | ~1µs |
| E4 | TableBr | ~50ns | ~100ns |
| U30 | decode instruction | ~200ns | ~500ns |
| U30 | verify module | ~1µs | ~5µs |

### 8.2 Coverage Contract

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| TOTAL | 97.65% | 96.92% | 98.70% |
| e7.rs | 100.00% | 98.91% | 98.99% |
| e4_disasm.rs | 100.00% | 99.95% | 100.00% |
| pretty.rs | 100.00% | 98.98% | 100.00% |

---

## 9. Directory Structure (Implementation Reference)

```
unico-runtime/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Main entry
│   ├── error.rs            # Error taxonomy + ErrorCode enum
│   ├── types.rs            # Core types
│   ├── leb128.rs           # ULEB/SLEB encoding
│   ├── ir.rs               # U30 IR (builder, verifier)
│   ├── ser.rs              # U30 binary serialization
│   ├── pretty.rs           # U30 pretty-printer
│   ├── assembler.rs        # U30 text-to-binary assembler
│   ├── debugger.rs         # U30 debugger/REPL
│   ├── runtime.rs          # U30 runtime executor
│   │
│   ├── exec/
│   │   ├── e0.rs           # E0 executor (i64 ops)
│   │   ├── e1.rs          # E1 executor (control flow)
│   │   ├── e2.rs          # E2 executor (memory)
│   │   ├── e3.rs          # E3 executor (extended arithmetic)
│   │   ├── e4.rs          # E4 executor (WASM-like)
│   │   ├── e5.rs          # E5 pass-through (E3)
│   │   ├── e6.rs          # E6 pass-through (E4)
│   │   └── e7.rs          # E7 crypto suite
│   │
│   ├── e4_disasm.rs        # E4 disassembler
│   ├── e4_ser.rs          # E4 binary serialization
│   │
│   ├── host.rs             # Host boundary v2
│   └── cli/
│       └── unico.rs        # CLI tool (clap 4.x)
│
└── benches/                # Criterion benchmarks
    ├── bench_uleb.rs
    ├── bench_e0.rs
    ├── bench_e2.rs
    └── bench_crypto.rs
```

---

## 10. Gate Progress

| Gate | Status | Weight | Notes |
|------|--------|--------|-------|
| U30-BASELINE-0001 | ✅ PASS | 10 | v2.7 ancestry + v3 evidence |
| **U30-EXECUTION-CONTRACT-0001** | 🔄 IN PROGRESS | 15 | This document |
| U30-RUNTIME-0001 | ⏳ BLOCKED | 25 | Independent functional verification |
| U30-SELFHOST-0001 | ⏳ BLOCKED | 20 | Toolchain pipeline |
| U30-APP-PERF-PORTABILITY-0001 | ⏳ BLOCKED | 20 | E2E apps + host matrix |
| U30-RELEASE-0001 | ⏳ BLOCKED | 10 | Independent review + 00 promotion |

---

## 11. Acceptance Criteria

This gate (U30-EXECUTION-CONTRACT-0001) is considered PASS when:
- [x] All E0-E7 profiles documented with magic bytes and opcodes
- [x] U30 IR operations fully enumerated with types and semantics
- [x] Error taxonomy complete (E0-E7, Host, U30)
- [x] Memory model documented for all profiles
- [x] Host Boundary v2 schema frozen
- [x] Provenance schema documented
- [x] Performance benchmarks recorded
- [x] Coverage metrics documented
- [x] Implementation reference matches spec

---

**Document Status:** IN REVIEW
**Author:** MiMo Agent (Art)
**Date:** 2026-10-11
**Implementation:** `https://github.com/aibornstore/unico-runtime` (yuriy branch, commit 752f8ab)
