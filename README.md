# UNICO v3.0 Runtime

Rust execution runtime for the UNICO virtual machine (v3.0). Branch `yuriy` for Art's work on `aibornstore/unico-runtime`.

## Build

```bash
cargo build --lib
cargo test --lib      # 100 unit tests
cargo test            # + 16 integration tests
cargo bench           # Criterion benchmarks (dev-dependency only)
```

## Architecture

| Module | Status |
|--------|--------|
| E0 | ✅ Complete |
| E1 | ✅ Complete |
| E2 | ✅ Complete |
| E3 | ✅ Complete |
| E5 (14/14) | ✅ All passing |
| E6 (11/11) | ✅ All passing |
| E7 (crypto) | ✅ Reconstructed, all crypto tests pass (AES-128/256, SHA-256, BLAKE2s, HMAC, HKDF, ChaCha20, Poly1305) |

## T12 Fixes — E7 big-int modular arithmetic (`src/exec/e7.rs`)

- **AddMod**: was ignoring modulus (`m: _`). Now subtracts `m_lo` when `sum_lo >= m_lo`.
- **MulMod**: was truncating BI5 to `u128` via `wrapping_mul`. Now uses full 128-bit modular multiply.
- **ModExp**: was using `exp128 = base128` and looping `0..5` over 3-limb BI5. Now correct square-and-multiply over 130 bits of exponent.

## T14 — Property tests

- ULEB encode/decode roundtrip (1000 random + boundary values)
- SLEB encode/decode roundtrip (1000 random + i64 boundary values)
- AddMod/MulMod/ModExp properties (200/200/50 random values)

## Test Results

- `cargo test --lib`: **100 passed** (was 95, +5 property tests)
- `cargo test`: **116 passed** (95 lib + 16 integration + 5 property)

## Git

- Remote: `https://github.com/aibornstore/unico-runtime.git`
- Branch: `yuriy`
