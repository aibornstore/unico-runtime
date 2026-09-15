# UNICO v3.0 Runtime

Rust execution runtime for the UNICO virtual machine (v3.0). Branch `yuriy` for Art's work on `aibornstore/unico-runtime`.

## Build

```bash
cargo build --lib
cargo test --lib      # 296 unit tests
cargo test            # + 16 integration tests + 3 doc tests = 315 total
cargo bench           # Criterion benchmarks (dev-dependency only)
```

## Architecture

| Module | Status |
|--------|--------|
| E0 | ✅ Complete |
| E1 | ✅ Complete |
| E2 | ✅ Complete |
| E3 | ✅ Complete |
| E4 | ✅ Complete (F64, integer arithmetic, bitwise ops, ZExt/SExt, TableBr, MemGrow, MemCopy/MemFill) |
| E5 (14/14) | ✅ All passing |
| E6 (11/11) | ✅ All passing |
| E7 (crypto) | ✅ Reconstructed, all crypto tests pass (AES-128/256, SHA-256, BLAKE2s, HMAC, HKDF, ChaCha20, Poly1305) |
| U30 IR | ✅ Complete (serialize, deserialize, verify, debug, pretty-print, CLI) |

## E4 Profile Features

- **F64 floating-point**: FAdd, FSub, FMul, FDiv, FSqrt, FNeg, FAbs, FRound, FCmp, FImm
- **Integer arithmetic**: IAdd, ISub, IMul, IDiv (with div-by-zero guard)
- **Bitwise operations**: IAnd, IOr, IXor, INot, IClz, ICtz, IPopcnt, IRotl, IRotr
- **Type conversions**: ZExt (zero-extend), SExt (sign-extend)
- **Memory**: LoadI64, StoreI64, MemGrow (dynamic growth up to 1MB), MemCopy, MemFill
- **Control flow**: Br, BrIf, Ret, Trap, Cmp, TableBr (indirect jump via jump tables)
- **Host boundary**: HostCall with function registry (print, add, mul, sub, div, read, write)
- **Binary format**: encode_e4/decode_e4 with magic "E4XX"
- **Disassembler**: decode_disasm for E4 binary to readable text

## E7 Crypto Features

- AES-128/256 (GCM mode)
- SHA-256
- BLAKE2s-256
- HMAC-SHA256
- HKDF-SHA256
- ChaCha20
- Poly1305 (ChaCha20-Poly1305 AEAD)

## Test Results

- `cargo test --lib`: **296 passed**
- `cargo test`: **315 passed** (296 lib + 16 integration + 3 doc)

## Git

- Remote: `https://github.com/aibornstore/unico-runtime.git`
- Branch: `yuriy`
