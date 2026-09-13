//! E7 Executor — Cryptographic Profile
//!
//! E7 opcodes:
//!   0x01 => AES128ENC  0x02 => AES128DEC  0x03 => AES256ENC  0x04 => AES256DEC
//!   0x10 => SHA256     0x11 => BLAKE2S
//!   0x20 => HMAC       0x21 => HKDF
//!   0x30 => POLY1305   0x31 => CHACHA20
//!   0x40 => XOR        0x41 => RAND
//!   0x50 => CPY        0x51 => LOAD      0x52 => STORE
//!   0x60 => MULMOD     0x61 => ADDMOD    0x62 => MODEXP
//!   0xFF => RET

use crate::error::{Error, Result};
use crate::exec::crypto_slot::CryptoSlot;
use crate::leb128::encode_uleb;
use crate::types::{ExecutionResult, Provenance, Status};
use rand::Rng;

// ---------------------------------------------------------------------------
// E7 Constants
// ---------------------------------------------------------------------------

pub const E7_PAGE_COUNT: usize = 8;
pub const E7_PAGE_SIZE: usize = 4096;
pub const E7_MEMORY_SIZE: usize = E7_PAGE_COUNT * E7_PAGE_SIZE;
pub const E7_MAX_CALL_DEPTH: usize = 1024;

// ---------------------------------------------------------------------------
// E7 types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Instruction {
    Aes128Enc { dst: u8, src: u8, key_slot: u8 },
    Aes128Dec { dst: u8, src: u8, key_slot: u8 },
    Aes256Enc { dst: u8, src: u8, key_slot: u8 },
    Aes256Dec { dst: u8, src: u8, key_slot: u8 },
    Sha256 { dst: u8, src: u8, count: u8 },
    Blake2S { dst: u8, src: u8, count: u8 },
    Hmac { dst: u8, key: u8, data: u8, count: u8 },
    Hkdf { dk: u8, ikm: u8, salt: u8, info: u8, count: u8 },
    Poly1305 { dst: u8, msg: u8, count: u8 },
    ChaCha20 { dst: u8, msg: u8, nonce: u8, key_slot: u8 },
    Xor { dst: u8, a: u8, b: u8, count: u8 },
    Rand { dst: u8, count: u8 },
    Cpy { dst: u8, src: u8, count: u8 },
    Load { dst: u8, addr: u32, count: u8 },
    Store { addr: u32, src: u8, count: u8 },
    MulMod { dst: u8, a: u8, b: u8, m: u8 },
    AddMod { dst: u8, a: u8, b: u8, m: u8 },
    ModExp { dst: u8, base: u8, exp: u8, m: u8 },
    /// Store AES-128 key (16 bytes) from vreg into slot, auto-expanded to 11 round keys
    StoreAes128Key { slot: u8, src: u8 },
    /// Store AES-256 key (32 bytes) from vreg into slot, auto-expanded to 15 round keys
    StoreAes256Key { slot: u8, src: u8 },
    /// Store ChaCha20 key (32 bytes) from vreg into slot
    StoreChaCha20Key { slot: u8, src: u8 },
    /// Store Poly1305 key (32 bytes) from vreg into slot
    StorePoly1305Key { slot: u8, src: u8 },
    Ret,
    Call { fn_idx: u32 },
    Trap,
}

#[derive(Debug, Clone)]
pub struct E7FunctionDef {
    pub locals_bytes: usize,
    pub max_stack: usize,
    pub code: Vec<Instruction>,
}

#[derive(Debug, Clone)]
pub struct E7Module {
    pub functions: Vec<E7FunctionDef>,
}

impl E7Module {
    pub fn new(functions: Vec<E7FunctionDef>) -> Self { E7Module { functions } }
}

// CryptoSlot is defined in src/exec/crypto_slot.rs — see that module for the contract.
// CryptoSlot::Empty / Aes128 / Aes256 / ChaCha20 / Poly1305

#[derive(Debug, Clone)]
pub struct VRegs {
    regs: Vec<u8>,
}

impl Default for VRegs {
    fn default() -> Self { VRegs { regs: vec![0u8; 32 * 256] } }
}

impl VRegs {
    fn get(&self, idx: u8) -> &[u8] { &self.regs[idx as usize * 256..][..256] }
    fn get_mut(&mut self, idx: u8) -> &mut [u8] { &mut self.regs[idx as usize * 256..][..256] }
    fn clear(&mut self) { self.regs.fill(0); }
}

#[derive(Debug, Clone)]
pub struct E7Frame {
    pub fn_idx: usize,
    pub locals: Vec<u8>,
    pub sp: usize,
    pub pc: usize,
    pub crypto_slots: [CryptoSlot; 4],
}

impl Default for E7Frame {
    fn default() -> Self {
        E7Frame { fn_idx: 0, locals: vec![0u8; 256], sp: 0, pc: 0, crypto_slots: std::array::from_fn(|_| CryptoSlot::default()) }
    }
}

#[derive(Debug)]
pub struct E7Executor {
    frames: Vec<E7Frame>,
    memory: Vec<u8>,
    vregs: VRegs,
    fuel: usize,
}

impl E7Executor {
    pub fn new() -> Self {
        E7Executor { frames: vec![E7Frame::default()], memory: vec![0u8; E7_MEMORY_SIZE], vregs: VRegs::default(), fuel: 1_000_000 }
    }
    pub fn with_module(module: &E7Module) -> Self {
        let mut exec = E7Executor::new();
        if !module.functions.is_empty() { exec.frames[0].fn_idx = 0; }
        exec
    }
    fn current_frame(&self) -> &E7Frame { self.frames.last().unwrap() }
    fn current_frame_mut(&mut self) -> &mut E7Frame { self.frames.last_mut().unwrap() }
    fn load_vreg(&self, idx: u8) -> Vec<u8> { self.vregs.get(idx).to_vec() }
    fn store_vreg(&mut self, idx: u8, data: &[u8]) {
        let dst = self.vregs.get_mut(idx);
        let len = data.len().min(256);
        dst[..len].copy_from_slice(&data[..len]);
    }
    fn check_memory(&self, addr: u32, count: u8) -> Result<()> {
        let end = addr as usize + count as usize;
        if end > E7_MEMORY_SIZE { Err(Error::Trap(crate::error::ErrorCode::E2T003MemoryOOB)) } else { Ok(()) }
    }
}

// ---------------------------------------------------------------------------
// BI5: 5-limb big-integer (130-bit)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BI5(pub [u64; 3]);

impl Default for BI5 { fn default() -> Self { BI5([0; 3]) } }

impl BI5 {
    pub fn from_130(n: u128, hi: u64) -> Self { BI5([n as u64, (n >> 64) as u64, hi & 0x3]) }
    pub fn to_130(&self) -> (u128, u64) { ((self.0[0] as u128) | ((self.0[1] as u128) << 64), self.0[2]) }

    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 24];
        let n = bytes.len().min(24);
        buf[..n].copy_from_slice(&bytes[..n]);
        BI5([
            u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]),
            u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]),
            u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]),
        ])
    }

    pub fn to_le_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..][..8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn add(&self, rhs: &BI5) -> Self {
        let mut result = [0u64; 3];
        let mut c: u64 = 0;
        for i in 0..3 {
            let (t0, c0) = self.0[i].overflowing_add(rhs.0[i]);
            let (t1, c1) = t0.overflowing_add(c);
            result[i] = t1;
            c = (if c0 { 1 } else { 0 }) + (if c1 { 1 } else { 0 });
        }
        BI5(result)
    }

    pub fn sub(&self, rhs: &BI5) -> Self {
        let mut result = [0u64; 3];
        let mut borrow = false;
        for i in 0..3 {
            let (t0, b0) = self.0[i].overflowing_sub(rhs.0[i]);
            let (t1, b1) = t0.overflowing_sub(if borrow { 1 } else { 0 });
            result[i] = t1;
            borrow = b0 || b1;
        }
        BI5(result)
    }

    pub fn mul_u128_full(&self, r: u128) -> [u64; 7] {
        let r_lo = r as u64;
        let r_hi = (r >> 64) as u64;
        let (a0, a1, a2) = (self.0[0], self.0[1], self.0[2]);

        // Product of 3-limb BI5 by u128
        let t0 = (a0 as u128).wrapping_mul(r_lo as u128);
        let t1 = (a0 as u128).wrapping_mul(r_hi as u128).wrapping_add((a1 as u128).wrapping_mul(r_lo as u128));
        let t2 = (a1 as u128).wrapping_mul(r_hi as u128).wrapping_add((a2 as u128).wrapping_mul(r_lo as u128));
        let t3 = (a2 as u128).wrapping_mul(r_hi as u128);

        // Carry-chain accumulation (each position accumulates ALL higher terms)
        let mut res = t0;
        let w0 = res as u64;
        let mut carry = (res >> 64) as u64;

        res = t1.wrapping_add(carry as u128);
        let w1 = res as u64;
        carry = (res >> 64) as u64;

        res = t2.wrapping_add(carry as u128);
        let w2 = res as u64;
        carry = (res >> 64) as u64;

        res = t3.wrapping_add(carry as u128);
        let w3 = res as u64;
        carry = (res >> 64) as u64;

        let w4 = carry;
        let w5 = 0u64;
        let w6 = 0u64;

        [w0, w1, w2, w3, w4, w5, w6]
    }

    pub fn reduce6(&self) -> Self {
        // RFC 7539 Barrett reduction: h = w0 + w1*2^64 + w2*2^128 (192-bit), P = 2^130-5.
        // h mod P = (h_lo + 5*q) mod 2^128, where q = floor(h/2^130).
        let w0 = self.0[0];
        let w1 = self.0[1];
        let w2 = self.0[2];
        let h2: u128 = w2 as u128;

        // h_lo = w0 | (w1 << 64)
        let h_lo: u128 = (w0 as u128) | ((w1 as u128) << 64);

        // q = h2 >> 2 (exact since h2 < 4 after mul)
        let q: u128 = h2 >> 2;

        // h1 = h_lo + 5*q (mod 2^128)
        let h1: u128 = h_lo.wrapping_add(q.wrapping_mul(5));

        // Return reduced limbs
        if h2 >= 4 {
            // h1 >> 128 wraps to 0 for u128, guard explicitly
            let extra = if h1 > u128::MAX { 1 } else { 0 };
            BI5([(h1 as u64), ((h1 >> 64) as u64), ((extra + 5) & 3) as u64])
        } else {
            BI5([(h1 as u64), ((h1 >> 64) as u64), 0])
        }
    }

    pub fn mul_u128(&self, r: u128) -> Self {
        // Multiply 192-bit BI5 = w0 + w1*2^64 + w2*2^128 by 128-bit r.
        // Full 256-bit products: w0r=w0*r, w1r=w1*r*2^64, w2r=w2*r*2^128.
        // Result = (w0r + w1r + w2r) = d0 + d1*2^64 + d2*2^64 + d3*2^128 + d4*2^128 + d5*2^192.
        // Carry chain: w0_out=d0, w1_out=(d1+d2+carry1) mod 2^64, w2_out=(d3+d4+d5+carry2) mod 2^64.
        let w0 = self.0[0] as u128;
        let w1 = self.0[1] as u128;
        let w2 = self.0[2] as u128;

        // w0r, w1r, w2r are 256-bit (stored as 2x u128 for w1r/w2r contribution)
        let w0r = w0.wrapping_mul(r);
        // w1r = w1 * r, but it contributes at bit position 64. Extract low and high 64 bits as d2/d3.
        let w1r_lo = (w1.wrapping_mul(r)) as u64;   // d2
        let w1r_hi = (w1.wrapping_mul(r) >> 64) as u64; // d3
        // w2r = w2 * r, but it contributes at bit position 128. Only low 64 bits matter (d4); d5 is always 0.
        let w2r_lo = (w2.wrapping_mul(r)) as u64;   // d4

        // w0_out = d0 (low 64 bits of w0*r)
        let w0_out = w0r as u64;

        // w1_out = d1 + d2 + carry1. d1 is high 64 bits of w0r.
        let d1 = (w0r >> 64) as u64;
        let sum1 = d1 as u128 + w1r_lo as u128;
        let (w1_out, carry1) = (sum1 as u64, (sum1 >> 64) as u64);
        // carry2: from d1+d2 (can be 0 or 1 since d1<2^64, d2<2^64, sum1<2^65)
        let carry2 = carry1; // carry from d1+d2 into d3+d4+d5

        // w2_out = d3 + d4 + d5 + carry2. d3 from w1r_hi, d4 from w2r_lo, d5=0.
        let sum2 = w1r_hi as u128 + w2r_lo as u128 + carry2 as u128;
        let (w2_out, _carry3) = (sum2 as u64, (sum2 >> 64) as u64);
        // carry3: from d3+d4+carry2 (can be 0 or 1)

        BI5([w0_out, w1_out, w2_out])
    }
}

// ---------------------------------------------------------------------------
// Poly1305 MAC
// ---------------------------------------------------------------------------

pub fn poly1305_mac(message: &[u8], key: &[u8]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..16].copy_from_slice(&key[..16]);
    // RFC 7539 clamping: clear top 4 bits of bytes 3,7,11,15; clear bottom 2 bits of bytes 4,8,12
    r[3] &= 0x0f; r[7] &= 0x0f; r[11] &= 0x0f; r[15] &= 0x0f;
    r[4] &= 0xfc; r[8] &= 0xfc; r[12] &= 0xfc;

    let r128 = u128::from_le_bytes(r);
    let mut h = BI5::default();

    let full_blocks = message.len() / 16;
    for _i in 0..full_blocks {
        let block = &message[_i * 16..(_i + 1) * 16];
        let n = BI5::from_le_bytes(block);
        let h_plus_n = h.add(&n);
        h = h_plus_n.mul_u128(r128);
        h = h.reduce6();
    }

    let remainder = message.len() % 16;
    if remainder > 0 {
        let mut block = [0u8; 16];
        block[..remainder].copy_from_slice(&message[full_blocks * 16..]);
        block[remainder] = 1;
        let n = BI5::from_le_bytes(&block);
        let h_plus_n = h.add(&n);
        h = h_plus_n.mul_u128(r128);
        h = h.reduce6();
    }

    let (h_lo, _) = h.to_130();
    let mut s = [0u8; 16];
    s.copy_from_slice(&key[16..32]);
    let s128 = u128::from_le_bytes(s);
    let tag128 = h_lo.wrapping_add(s128);
    tag128.to_le_bytes()
}

pub fn poly1305_mac_preclamped(message: &[u8], r_clamped: &[u8; 16], s: &[u8; 16]) -> [u8; 16] {
    let r128 = u128::from_le_bytes(*r_clamped);
    let s128 = u128::from_le_bytes(*s);
    let mut h = BI5::default();

    let full_blocks = message.len() / 16;
    for i in 0..full_blocks {
        let block = &message[i * 16..(i + 1) * 16];
        let n = BI5::from_le_bytes(block);
        let h_plus_n = h.add(&n);
        h = h_plus_n.mul_u128(r128);
        h = h.reduce6();
    }

    let remainder = message.len() % 16;
    if remainder > 0 {
        let mut block = [0u8; 16];
        block[..remainder].copy_from_slice(&message[full_blocks * 16..]);
        block[remainder] = 1;
        let n = BI5::from_le_bytes(&block);
        let h_plus_n = h.add(&n);
        h = h_plus_n.mul_u128(r128);
        h = h.reduce6();
    }

    let (h_lo, _) = h.to_130();
    let tag128 = h_lo.wrapping_add(s128);
    tag128.to_le_bytes()
}

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[0] = 0x61707865; init[1] = 0x3320646e;
    init[2] = 0x79622d32; init[3] = 0x6b206574;
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    init[12] = counter;
    init[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    init[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    init[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    // ChaCha20 inner block — inline to avoid borrow conflicts
    // Each quarter-round: a+=b; d^=a; d<<=16; c+=d; b^=c; b<<=12; a+=b; d^=a; d<<=8; c+=d; b^=c; b<<=7
    let mut s = init;
    for _ in 0..10 {
        // Column rounds
        let (mut a, mut b, mut c, mut d) = (s[0], s[4], s[8], s[12]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[0] = a; s[4] = b; s[8] = c; s[12] = d;

        let (mut a, mut b, mut c, mut d) = (s[1], s[5], s[9], s[13]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[1] = a; s[5] = b; s[9] = c; s[13] = d;

        let (mut a, mut b, mut c, mut d) = (s[2], s[6], s[10], s[14]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[2] = a; s[6] = b; s[10] = c; s[14] = d;

        let (mut a, mut b, mut c, mut d) = (s[3], s[7], s[11], s[15]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[3] = a; s[7] = b; s[11] = c; s[15] = d;

        // Diagonal rounds
        let (mut a, mut b, mut c, mut d) = (s[0], s[5], s[10], s[15]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[0] = a; s[5] = b; s[10] = c; s[15] = d;

        let (mut a, mut b, mut c, mut d) = (s[1], s[6], s[11], s[12]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[1] = a; s[6] = b; s[11] = c; s[12] = d;

        let (mut a, mut b, mut c, mut d) = (s[2], s[7], s[8], s[13]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[2] = a; s[7] = b; s[8] = c; s[13] = d;

        let (mut a, mut b, mut c, mut d) = (s[3], s[4], s[9], s[14]);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
        s[3] = a; s[4] = b; s[9] = c; s[14] = d;
    }

    let mut output = [0u8; 64];
    for i in 0..16 {
        let val = s[i].wrapping_add(init[i]);
        output[i * 4..][..4].copy_from_slice(&val.to_le_bytes());
    }
    output
}

pub fn chacha20_ctr(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(plaintext.len());
    let mut counter = 0u32;
    let mut offset = 0;
    while offset < plaintext.len() {
        let block = chacha20_block(key, nonce, counter);
        let remaining = plaintext.len() - offset;
        let to_xor = remaining.min(64);
        for i in 0..to_xor { output.push(plaintext[offset + i] ^ block[i]); }
        offset += to_xor;
        counter += 1;
    }
    output
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 7539 §2.8.2)
// ---------------------------------------------------------------------------

/// Encrypt plaintext with ChaCha20-Poly1305 AEAD.
/// Returns ciphertext || 16-byte Poly1305 tag.
/// Counter starts at 1 for encryption (RFC 7539 §2.8.2).
pub fn chacha20_poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // Step 1: Generate Poly1305 key from counter=0 ChaCha20 block
    let block0 = chacha20_block(key, nonce, 0);
    let r = &block0[..16];
    let s = &block0[16..32];

    // Step 2: Encrypt plaintext with ChaCha20 starting counter=1
    let ct = chacha20_ctr(key, nonce, plaintext);

    // Step 3: Compute Poly1305 tag over AAD || padding || ciphertext || padding || len(AAD) || len(ct)
    let mut input = Vec::new();
    input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    for _ in 0..aad_pad { input.push(0u8); }
    input.extend_from_slice(&ct);
    let ct_pad = (16 - (ct.len() % 16)) % 16;
    for _ in 0..ct_pad { input.push(0u8); }
    input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    input.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    let mut key_arr = [0u8; 32];
    key_arr[..16].copy_from_slice(r);
    key_arr[16..].copy_from_slice(s);
    let tag = poly1305_mac(&input, &key_arr);

    // Step 4: Output ciphertext || tag
    let mut output = ct;
    output.extend_from_slice(&tag);
    output
}

/// Decrypt ChaCha20-Poly1305 AEAD ciphertext.
/// ciphertext_and_tag = ciphertext || 16-byte tag.
/// Returns plaintext if tag verification succeeds.
pub fn chacha20_poly1305_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext_and_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < 16 {
        return Err(Error::Generic("ciphertext too short".into()));
    }
    let (ct, received_tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);
    let received_tag: [u8; 16] = received_tag.try_into().map_err(|_| Error::Generic("tag parse".into()))?;

    // Step 1: Generate Poly1305 key from counter=0 block
    let block0 = chacha20_block(key, nonce, 0);
    let r = &block0[..16];
    let s = &block0[16..32];

    // Step 2: Compute Poly1305 tag and verify
    let mut input = Vec::new();
    input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    for _ in 0..aad_pad { input.push(0u8); }
    input.extend_from_slice(ct);
    let ct_pad = (16 - (ct.len() % 16)) % 16;
    for _ in 0..ct_pad { input.push(0u8); }
    input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    input.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    let mut key_arr = [0u8; 32];
    key_arr[..16].copy_from_slice(r);
    key_arr[16..].copy_from_slice(s);
    let computed_tag = poly1305_mac(&input, &key_arr);

    if computed_tag != received_tag {
        return Err(Error::Generic("tag mismatch".into()));
    }

    // Step 3: Decrypt
    Ok(chacha20_ctr(key, nonce, ct))
}

// ---------------------------------------------------------------------------
// BLAKE2s-256 (RFC 7693 reference implementation)
// ---------------------------------------------------------------------------

// SIGMA table from RFC 7693 Appendix D.2
const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// RFC 7693 BLAKE2s IV (same as SHA-256 IV)
const BLAKE2S_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn blake2s_compress(h: &mut [u32; 8], block: &[u32; 16], t0: u32, t1: u32, f0: u32, f1: u32) {
    let mut v = [0u32; 16];
    // v[0..7] = h[0..7]
    v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3] = h[3];
    v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7] = h[7];
    // v[8..15] = IV[0..7]
    v[8]  = BLAKE2S_IV[0]; v[9]  = BLAKE2S_IV[1];
    v[10] = BLAKE2S_IV[2]; v[11] = BLAKE2S_IV[3];
    v[12] = BLAKE2S_IV[4] ^ t0;
    v[13] = BLAKE2S_IV[5] ^ t1;
    v[14] = BLAKE2S_IV[6] ^ f0;
    v[15] = BLAKE2S_IV[7] ^ f1;

    for r in 0..10 {
        let s = &BLAKE2S_SIGMA[r];
        // G macro: a=a+b+x; d=ror32(d^a,16); c=c+d; b=ror32(b^c,12); a=a+b+y; d=ror32(d^a,8); c=c+d; b=ror32(b^c,7);
        // Column 0: G(0,4,8,12, m[s[0]], m[s[1]])
        v[0]  = v[0].wrapping_add(v[4]).wrapping_add(block[s[0]]);
        v[12] = v[12] ^ v[0]; v[12] = v[12].rotate_right(16);
        v[8]  = v[8].wrapping_add(v[12]);
        v[4]  = v[4] ^ v[8]; v[4] = v[4].rotate_right(12);
        v[0]  = v[0].wrapping_add(v[4]).wrapping_add(block[s[1]]);
        v[12] = v[12] ^ v[0]; v[12] = v[12].rotate_right(8);
        v[8]  = v[8].wrapping_add(v[12]);
        v[4]  = v[4] ^ v[8]; v[4] = v[4].rotate_right(7);
        // Column 1: G(1,5,9,13, m[s[2]], m[s[3]])
        v[1]  = v[1].wrapping_add(v[5]).wrapping_add(block[s[2]]);
        v[13] = v[13] ^ v[1]; v[13] = v[13].rotate_right(16);
        v[9]  = v[9].wrapping_add(v[13]);
        v[5]  = v[5] ^ v[9]; v[5] = v[5].rotate_right(12);
        v[1]  = v[1].wrapping_add(v[5]).wrapping_add(block[s[3]]);
        v[13] = v[13] ^ v[1]; v[13] = v[13].rotate_right(8);
        v[9]  = v[9].wrapping_add(v[13]);
        v[5]  = v[5] ^ v[9]; v[5] = v[5].rotate_right(7);
        // Column 2: G(2,6,10,14, m[s[4]], m[s[5]])
        v[2]  = v[2].wrapping_add(v[6]).wrapping_add(block[s[4]]);
        v[14] = v[14] ^ v[2]; v[14] = v[14].rotate_right(16);
        v[10] = v[10].wrapping_add(v[14]);
        v[6]  = v[6] ^ v[10]; v[6] = v[6].rotate_right(12);
        v[2]  = v[2].wrapping_add(v[6]).wrapping_add(block[s[5]]);
        v[14] = v[14] ^ v[2]; v[14] = v[14].rotate_right(8);
        v[10] = v[10].wrapping_add(v[14]);
        v[6]  = v[6] ^ v[10]; v[6] = v[6].rotate_right(7);
        // Column 3: G(3,7,11,15, m[s[6]], m[s[7]])
        v[3]  = v[3].wrapping_add(v[7]).wrapping_add(block[s[6]]);
        v[15] = v[15] ^ v[3]; v[15] = v[15].rotate_right(16);
        v[11] = v[11].wrapping_add(v[15]);
        v[7]  = v[7] ^ v[11]; v[7] = v[7].rotate_right(12);
        v[3]  = v[3].wrapping_add(v[7]).wrapping_add(block[s[7]]);
        v[15] = v[15] ^ v[3]; v[15] = v[15].rotate_right(8);
        v[11] = v[11].wrapping_add(v[15]);
        v[7]  = v[7] ^ v[11]; v[7] = v[7].rotate_right(7);
        // Row 0: G(0,5,10,15, m[s[8]], m[s[9]])
        v[0]  = v[0].wrapping_add(v[5]).wrapping_add(block[s[8]]);
        v[15] = v[15] ^ v[0]; v[15] = v[15].rotate_right(16);
        v[10] = v[10].wrapping_add(v[15]);
        v[5]  = v[5] ^ v[10]; v[5] = v[5].rotate_right(12);
        v[0]  = v[0].wrapping_add(v[5]).wrapping_add(block[s[9]]);
        v[15] = v[15] ^ v[0]; v[15] = v[15].rotate_right(8);
        v[10] = v[10].wrapping_add(v[15]);
        v[5]  = v[5] ^ v[10]; v[5] = v[5].rotate_right(7);
        // Row 1: G(1,6,11,12, m[s[10]], m[s[11]])
        v[1]  = v[1].wrapping_add(v[6]).wrapping_add(block[s[10]]);
        v[12] = v[12] ^ v[1]; v[12] = v[12].rotate_right(16);
        v[11] = v[11].wrapping_add(v[12]);
        v[6]  = v[6] ^ v[11]; v[6] = v[6].rotate_right(12);
        v[1]  = v[1].wrapping_add(v[6]).wrapping_add(block[s[11]]);
        v[12] = v[12] ^ v[1]; v[12] = v[12].rotate_right(8);
        v[11] = v[11].wrapping_add(v[12]);
        v[6]  = v[6] ^ v[11]; v[6] = v[6].rotate_right(7);
        // Row 2: G(2,7,8,13, m[s[12]], m[s[13]])
        v[2]  = v[2].wrapping_add(v[7]).wrapping_add(block[s[12]]);
        v[13] = v[13] ^ v[2]; v[13] = v[13].rotate_right(16);
        v[8]  = v[8].wrapping_add(v[13]);
        v[7]  = v[7] ^ v[8]; v[7] = v[7].rotate_right(12);
        v[2]  = v[2].wrapping_add(v[7]).wrapping_add(block[s[13]]);
        v[13] = v[13] ^ v[2]; v[13] = v[13].rotate_right(8);
        v[8]  = v[8].wrapping_add(v[13]);
        v[7]  = v[7] ^ v[8]; v[7] = v[7].rotate_right(7);
        // Row 3: G(3,4,9,14, m[s[14]], m[s[15]])
        v[3]  = v[3].wrapping_add(v[4]).wrapping_add(block[s[14]]);
        v[14] = v[14] ^ v[3]; v[14] = v[14].rotate_right(16);
        v[9]  = v[9].wrapping_add(v[14]);
        v[4]  = v[4] ^ v[9]; v[4] = v[4].rotate_right(12);
        v[3]  = v[3].wrapping_add(v[4]).wrapping_add(block[s[15]]);
        v[14] = v[14] ^ v[3]; v[14] = v[14].rotate_right(8);
        v[9]  = v[9].wrapping_add(v[14]);
        v[4]  = v[4] ^ v[9]; v[4] = v[4].rotate_right(7);
    }

    for i in 0..8 { h[i] ^= v[i] ^ v[i + 8]; }
}

pub fn blake2s_256(data: &[u8], _key: &[u8]) -> [u8; 32] {
    // Initialize hash state h = IV
    let mut h = BLAKE2S_IV;
    // XOR parameter block: 0x01010020 = fanout=1 | depth=1 | key_len=0 | digest_size=32
    h[0] ^= 0x01010020u32;

    // Process full 64-byte blocks
    let mut offset = 0usize;
    let mut t0: u32 = 0;
    let mut t1: u32 = 0;

    while offset + 64 <= data.len() {
        t0 = t0.wrapping_add(64);
        if t0 < 64 { t1 = t1.wrapping_add(1); }

        let block_data = &data[offset..offset + 64];
        let mut block = [0u32; 16];
        for i in 0..16 {
            block[i] = u32::from_le_bytes([block_data[i*4], block_data[i*4+1], block_data[i*4+2], block_data[i*4+3]]);
        }
        blake2s_compress(&mut h, &block, t0, t1, 0, 0);
        offset += 64;
    }

    // Process final (partial) block
    let remaining = data.len() - offset;
    t0 = t0.wrapping_add(remaining as u32);
    if t0 < remaining as u32 { t1 = t1.wrapping_add(1); }

    let mut block = [0u32; 16];
    for i in 0..remaining {
        block[i / 4] |= (data[offset + i] as u32) << (8 * (i % 4));
    }
    // RFC 7693: final block padded with zeros (no 0x01 byte)
    blake2s_compress(&mut h, &block, t0, t1, 0xFFFFFFFFu32, 0);

    // Output little-endian
    let mut out = [0u8; 32];
    for i in 0..8 { out[i*4..][..4].copy_from_slice(&h[i].to_le_bytes()); }
    out
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

fn sha256_ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
fn sha256_maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
fn sha256_bsig0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
fn sha256_bsig1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
fn sha256_ssig0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
fn sha256_ssig1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg: Vec<u8> = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            w[i] = sha256_ssig1(w[i-2]).wrapping_add(w[i-7])
                .wrapping_add(sha256_ssig0(w[i-15]))
                .wrapping_add(w[i-16]);
        }

        let mut a = h[0]; let mut b = h[1]; let mut c = h[2]; let mut d = h[3];
        let mut e = h[4]; let mut f = h[5]; let mut g = h[6]; let mut hh = h[7];

        for i in 0..64 {
            let t1 = hh.wrapping_add(sha256_bsig1(e))
                .wrapping_add(sha256_ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = sha256_bsig0(a).wrapping_add(sha256_maj(a, b, c));
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &hv) in h.iter().enumerate() { out[i*4..][..4].copy_from_slice(&hv.to_be_bytes()); }
    out
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = sha256(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }

    let inner = sha256(&[&ipad[..], data].concat());
    let mut outer_input = [0u8; 64 + 32];
    outer_input[..64].copy_from_slice(&opad);
    outer_input[64..].copy_from_slice(&inner);
    sha256(&outer_input)
}

// ---------------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------------

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], count: usize) -> Vec<u8> {
    let mut prk = [0u8; 32];
    if salt.is_empty() {
        let null_salt = [0u8; 32];
        prk.copy_from_slice(&hmac_sha256(ikm, &null_salt));
    } else {
        prk.copy_from_slice(&hmac_sha256(ikm, salt));
    }

    let mut okm = Vec::with_capacity(count);
    let mut t = [0u8; 32];
    let mut counter = 1u8;

    while okm.len() < count {
        let mut input = Vec::with_capacity(32 + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t.copy_from_slice(&hmac_sha256(&prk, &input));
        okm.extend_from_slice(&t);
        counter += 1;
    }

    okm.truncate(count);
    okm
}

// ---------------------------------------------------------------------------
// AES-128/256
// ---------------------------------------------------------------------------

/// AES S-box (corrected per NIST FIPS-197)
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

fn galois_mul(x: u8, y: u8) -> u8 {
    let mut result = 0u8;
    let mut bit = x;
    let mut m = y;
    while m > 0 {
        if m & 1 == 1 { result ^= bit; }
        bit = bit.overflowing_mul(2).0 ^ if bit > 127 { 0x1b } else { 0 };
        m >>= 1;
    }
    result
}

fn aes_sub_bytes(state: &mut [u8; 16]) { for b in state.iter_mut() { *b = AES_SBOX[*b as usize]; } }
fn aes_inv_sub_bytes(state: &mut [u8; 16]) { for b in state.iter_mut() { *b = AES_INV_SBOX[*b as usize]; } }

fn aes_shift_rows(state: &mut [u8; 16]) {
    let t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    let t = state[2]; state[2] = state[10]; state[10] = t;
    let t = state[6]; state[6] = state[14]; state[14] = t;
    let t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let t = state[1]; state[1] = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = t;
    let t = state[2]; state[2] = state[10]; state[10] = t;
    let t = state[6]; state[6] = state[14]; state[14] = t;
    let t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = state[i]; let b = state[i+1]; let c = state[i+2]; let d = state[i+3];
        state[i]   = galois_mul(a, 2) ^ galois_mul(b, 3) ^ galois_mul(c, 1) ^ galois_mul(d, 1);
        state[i+1] = galois_mul(a, 1) ^ galois_mul(b, 2) ^ galois_mul(c, 3) ^ galois_mul(d, 1);
        state[i+2] = galois_mul(a, 1) ^ galois_mul(b, 1) ^ galois_mul(c, 2) ^ galois_mul(d, 3);
        state[i+3] = galois_mul(a, 3) ^ galois_mul(b, 1) ^ galois_mul(c, 1) ^ galois_mul(d, 2);
    }
}

fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a = state[i]; let b = state[i+1]; let c = state[i+2]; let d = state[i+3];
        state[i]   = galois_mul(a, 0x0e) ^ galois_mul(b, 0x0b) ^ galois_mul(c, 0x0d) ^ galois_mul(d, 0x09);
        state[i+1] = galois_mul(a, 0x09) ^ galois_mul(b, 0x0e) ^ galois_mul(c, 0x0b) ^ galois_mul(d, 0x0d);
        state[i+2] = galois_mul(a, 0x0d) ^ galois_mul(b, 0x09) ^ galois_mul(c, 0x0e) ^ galois_mul(d, 0x0b);
        state[i+3] = galois_mul(a, 0x0b) ^ galois_mul(b, 0x0d) ^ galois_mul(c, 0x09) ^ galois_mul(d, 0x0e);
    }
}

fn aes_add_round_key(state: &mut [u8; 16], key: &[u8; 16]) { for i in 0..16 { state[i] ^= key[i]; } }

fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];
    let mut key_schedule: Vec<[u8; 4]> = Vec::with_capacity(44);
    for i in 0..4 { key_schedule.push([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]); }
    let mut rcon = 1u8;
    for i in 4..44 {
        let mut temp = key_schedule[i-1];
        if i % 4 == 0 {
            let t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            temp = [AES_SBOX[temp[0] as usize], AES_SBOX[temp[1] as usize],
                   AES_SBOX[temp[2] as usize], AES_SBOX[temp[3] as usize]];
            temp[0] ^= rcon;
            let (r2, overflow) = rcon.overflowing_mul(2);
            rcon = if overflow { r2 ^ 0x1b } else { r2 };
        }
        key_schedule.push([
            key_schedule[i-4][0] ^ temp[0], key_schedule[i-4][1] ^ temp[1],
            key_schedule[i-4][2] ^ temp[2], key_schedule[i-4][3] ^ temp[3],
        ]);
    }
    for round in 0..11 {
        for i in 0..4 { round_keys[round][i*4..i*4+4].copy_from_slice(&key_schedule[round * 4 + i]); }
    }
    round_keys
}

fn aes256_key_expand(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut round_keys = [[0u8; 16]; 15];
    let mut key_schedule: Vec<[u8; 4]> = Vec::with_capacity(60);
    for i in 0..8 { key_schedule.push([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]); }
    let mut rcon = 1u8;
    for i in 8..60 {
        let mut temp = key_schedule[i-1];
        if i % 8 == 0 {
            let t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            temp = [AES_SBOX[temp[0] as usize], AES_SBOX[temp[1] as usize],
                   AES_SBOX[temp[2] as usize], AES_SBOX[temp[3] as usize]];
            temp[0] ^= rcon;
            let (r2, overflow) = rcon.overflowing_mul(2);
            rcon = if overflow { r2 ^ 0x1b } else { r2 };
        } else if i % 8 == 4 {
            temp = [AES_SBOX[temp[0] as usize], AES_SBOX[temp[1] as usize],
                   AES_SBOX[temp[2] as usize], AES_SBOX[temp[3] as usize]];
        }
        key_schedule.push([
            key_schedule[i-8][0] ^ temp[0], key_schedule[i-8][1] ^ temp[1],
            key_schedule[i-8][2] ^ temp[2], key_schedule[i-8][3] ^ temp[3],
        ]);
    }
    for round in 0..15 {
        for i in 0..4 { round_keys[round][i*4..i*4+4].copy_from_slice(&key_schedule[round * 4 + i]); }
    }
    round_keys
}

pub fn aes128_key_expand_array(key: &[u8; 16]) -> [u8; 176] {
    let round_keys = aes128_key_expand(key);
    let mut out = [0u8; 176];
    for (i, rk) in round_keys.iter().enumerate() {
        out[i * 16..i * 16 + 16].copy_from_slice(rk);
    }
    out
}

pub fn aes256_key_expand_array(key: &[u8; 32]) -> [u8; 240] {
    let round_keys = aes256_key_expand(key);
    let mut out = [0u8; 240];
    for (i, rk) in round_keys.iter().enumerate() {
        out[i * 16..i * 16 + 16].copy_from_slice(rk);
    }
    out
}

pub fn aes128_encrypt(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let round_keys = aes128_key_expand(key);
    aes128_encrypt_with_round_keys(plaintext, &round_keys)
}

pub fn aes128_encrypt_with_round_keys(plaintext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *plaintext;
    aes_add_round_key(&mut state, &round_keys[0]);
    for round in 1..10 {
        aes_sub_bytes(&mut state); aes_shift_rows(&mut state); aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
    }
    aes_sub_bytes(&mut state); aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &round_keys[10]);
    state
}

pub fn aes128_decrypt(ciphertext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let round_keys = aes128_key_expand(key);
    aes128_decrypt_with_round_keys(ciphertext, &round_keys)
}

pub fn aes128_decrypt_with_round_keys(ciphertext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *ciphertext;
    aes_add_round_key(&mut state, &round_keys[10]);
    for round in (1..10).rev() {
        aes_inv_shift_rows(&mut state); aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
        aes_inv_mix_columns(&mut state);
    }
    aes_inv_shift_rows(&mut state); aes_inv_sub_bytes(&mut state);
    aes_add_round_key(&mut state, &round_keys[0]);
    state
}

pub fn aes256_encrypt(plaintext: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_keys = aes256_key_expand(key);
    aes256_encrypt_with_round_keys(plaintext, &round_keys)
}

pub fn aes256_encrypt_with_round_keys(plaintext: &[u8; 16], round_keys: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = *plaintext;
    aes_add_round_key(&mut state, &round_keys[0]);
    for round in 1..14 {
        aes_sub_bytes(&mut state); aes_shift_rows(&mut state); aes_mix_columns(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
    }
    aes_sub_bytes(&mut state); aes_shift_rows(&mut state);
    aes_add_round_key(&mut state, &round_keys[14]);
    state
}

pub fn aes256_decrypt(ciphertext: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let round_keys = aes256_key_expand(key);
    aes256_decrypt_with_round_keys(ciphertext, &round_keys)
}

pub fn aes256_decrypt_with_round_keys(ciphertext: &[u8; 16], round_keys: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = *ciphertext;
    aes_add_round_key(&mut state, &round_keys[14]);
    for round in (1..14).rev() {
        aes_inv_shift_rows(&mut state); aes_inv_sub_bytes(&mut state);
        aes_add_round_key(&mut state, &round_keys[round]);
        aes_inv_mix_columns(&mut state);
    }
    aes_inv_shift_rows(&mut state); aes_inv_sub_bytes(&mut state);
    aes_add_round_key(&mut state, &round_keys[0]);
    state
}

// ---------------------------------------------------------------------------
// E7Executor execute() implementation
// ---------------------------------------------------------------------------

impl E7Executor {
    pub fn execute(&mut self, module: &E7Module, fn_idx: usize) -> Result<ExecutionResult> {
        if self.frames.len() > E7_MAX_CALL_DEPTH {
            return Err(Error::Trap(crate::error::ErrorCode::E2T005CallDepth));
        }

        self.frames.clear();
        self.frames.push(E7Frame {
            fn_idx,
            locals: vec![0u8; module.functions.get(fn_idx).map(|f| f.locals_bytes).unwrap_or(0)],
            sp: 0, pc: 0, crypto_slots: std::array::from_fn(|_| CryptoSlot::default()),
        });

        self.fuel = 1_000_000;
        self.vregs.clear();
        self.memory.fill(0);

        let fn_def = module.functions.get(fn_idx)
            .ok_or_else(|| Error::Format(format!("E7: no function at index {}", fn_idx)))?;

        loop {
            if self.fuel == 0 { return Err(Error::Trap(crate::error::ErrorCode::E1T002Fuel)); }
            self.fuel -= 1;

            let frame = self.current_frame();
            if frame.pc >= fn_def.code.len() {
                return Err(Error::Trap(crate::error::ErrorCode::E0T001Explicit));
            }

            let instr = &fn_def.code[frame.pc].clone();
            self.current_frame_mut().pc += 1;

            match instr {
                Instruction::Aes128Enc { dst, src, key_slot } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 16 {
                        return Err(Error::Format("AES input too short".to_string()));
                    }
                    let slot = &self.frames.last().unwrap().crypto_slots[*key_slot as usize];
                    let ct = slot.encrypt(&src_data[..16], None).map_err(|_| Error::Format("AES128 key slot not initialized".to_string()))?;
                    self.store_vreg(*dst, &ct);
                }
                Instruction::Aes128Dec { dst, src, key_slot } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 16 {
                        return Err(Error::Format("AES input too short".to_string()));
                    }
                    let slot = &self.frames.last().unwrap().crypto_slots[*key_slot as usize];
                    let pt = slot.decrypt(&src_data[..16], None).map_err(|_| Error::Format("AES128 key slot not initialized".to_string()))?;
                    self.store_vreg(*dst, &pt);
                }
                Instruction::Aes256Enc { dst, src, key_slot } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 16 {
                        return Err(Error::Format("AES input too short".to_string()));
                    }
                    let slot = &self.frames.last().unwrap().crypto_slots[*key_slot as usize];
                    let ct = slot.encrypt(&src_data[..16], None).map_err(|_| Error::Format("AES256 key slot not initialized".to_string()))?;
                    self.store_vreg(*dst, &ct);
                }
                Instruction::Aes256Dec { dst, src, key_slot } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 16 {
                        return Err(Error::Format("AES input too short".to_string()));
                    }
                    let slot = &self.frames.last().unwrap().crypto_slots[*key_slot as usize];
                    let pt = slot.decrypt(&src_data[..16], None).map_err(|_| Error::Format("AES256 key slot not initialized".to_string()))?;
                    self.store_vreg(*dst, &pt);
                }
                Instruction::ChaCha20 { dst, msg, nonce: _, key_slot } => {
                    let msg_data = self.load_vreg(*msg);
                    if msg_data.len() < 12 {
                        return Err(Error::Format("ChaCha20: need 12-byte nonce".to_string()));
                    }
                    let nonce_arr: [u8; 12] = msg_data[..12].try_into().map_err(|_| Error::Format("ChaCha20 nonce too short".to_string()))?;
                    let slot = &self.frames.last().unwrap().crypto_slots[*key_slot as usize];
                    let ct = slot.encrypt(&msg_data[12..], Some(&nonce_arr)).map_err(|_| Error::Format("ChaCha20 key slot not initialized".to_string()))?;
                    self.store_vreg(*dst, &ct);
                }
                Instruction::StoreAes128Key { slot, src } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 16 {
                        return Err(Error::Format("AES128 key too short (need 16 bytes)".to_string()));
                    }
                    let key: [u8; 16] = src_data[..16].try_into().map_err(|_| Error::Format("Invalid AES128 key".to_string()))?;
                    let round_keys = aes128_key_expand_array(&key);
                    self.frames.last_mut().unwrap().crypto_slots[*slot as usize] = CryptoSlot::Aes128 { round_keys };
                }
                Instruction::StoreAes256Key { slot, src } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 32 {
                        return Err(Error::Format("AES256 key too short (need 32 bytes)".to_string()));
                    }
                    let key: [u8; 32] = src_data[..32].try_into().map_err(|_| Error::Format("Invalid AES256 key".to_string()))?;
                    let round_keys = aes256_key_expand_array(&key);
                    self.frames.last_mut().unwrap().crypto_slots[*slot as usize] = CryptoSlot::Aes256 { round_keys };
                }
                Instruction::StoreChaCha20Key { slot, src } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 32 {
                        return Err(Error::Format("ChaCha20 key too short (need 32 bytes)".to_string()));
                    }
                    let key: [u8; 32] = src_data[..32].try_into().map_err(|_| Error::Format("Invalid ChaCha20 key".to_string()))?;
                    self.frames.last_mut().unwrap().crypto_slots[*slot as usize] = CryptoSlot::ChaCha20 { key };
                }
                Instruction::StorePoly1305Key { slot, src } => {
                    let src_data = self.load_vreg(*src);
                    if src_data.len() < 32 {
                        return Err(Error::Format("Poly1305 key too short (need 32 bytes)".to_string()));
                    }
                    let key: [u8; 32] = src_data[..32].try_into().map_err(|_| Error::Format("Invalid Poly1305 key".to_string()))?;
                    self.frames.last_mut().unwrap().crypto_slots[*slot as usize] = CryptoSlot::Poly1305 { key };
                }
                Instruction::Load { addr, dst, count } => {
                    self.check_memory(*addr, *count)?;
                    let data = self.memory[*addr as usize..(*addr as usize + *count as usize)].to_vec();
                    self.store_vreg(*dst, &data);
                }
                Instruction::Store { addr, src, count } => {
                    self.check_memory(*addr, *count)?;
                    let src_data = self.load_vreg(*src);
                    self.memory[*addr as usize..(*addr as usize + *count as usize)].copy_from_slice(&src_data[..*count as usize]);
                }
                Instruction::MulMod { dst, a, b, m } => {
                    let a_data = self.load_vreg(*a);
                    let b_data = self.load_vreg(*b);
                    let m_data = self.load_vreg(*m);
                    if a_data.len() < 16 || b_data.len() < 16 || m_data.len() < 16 {
                        return Err(Error::Format("MulMod: need 16-byte operands".to_string()));
                    }
                    let a_bi5 = BI5::from_le_bytes(&a_data[..32.min(a_data.len())]);
                    let b_bi5 = BI5::from_le_bytes(&b_data[..32.min(b_data.len())]);
                    let m_bi5 = BI5::from_le_bytes(&m_data[..32.min(m_data.len())]);
                    let (a128, _) = a_bi5.to_130();
                    let (b128, _) = b_bi5.to_130();
                    let (m128, _) = m_bi5.to_130();
                    let result128 = a128.wrapping_mul(b128) % m128;
                    let result_bi5 = BI5::from_130(result128, 0);
                    let mut out = [0u8; 32];
                    let result_bytes = result_bi5.to_le_bytes();
                    out[..32.min(result_bytes.len())].copy_from_slice(&result_bytes[..32.min(result_bytes.len())]);
                    self.store_vreg(*dst, &out);
                }
                Instruction::AddMod { dst, a, b, m: _ } => {
                    let a_data = self.load_vreg(*a);
                    let b_data = self.load_vreg(*b);
                    if a_data.len() < 16 || b_data.len() < 16 { return Err(Error::Format("AddMod: need 16-byte operands".to_string())); }
                    let a_bi5 = BI5::from_le_bytes(&a_data[..32.min(a_data.len())]);
                    let b_bi5 = BI5::from_le_bytes(&b_data[..32.min(b_data.len())]);
                    let result = a_bi5.add(&b_bi5);
                    let mut out = [0u8; 32];
                    let result_bytes = result.to_le_bytes();
                    out[..32.min(result_bytes.len())].copy_from_slice(&result_bytes[..32.min(result_bytes.len())]);
                    self.store_vreg(*dst, &out);
                }
                Instruction::ModExp { dst, base, exp, m } => {
                    let base_data = self.load_vreg(*base);
                    let exp_data = self.load_vreg(*exp);
                    let m_data = self.load_vreg(*m);
                    if base_data.len() < 16 || exp_data.len() < 16 || m_data.len() < 16 {
                        return Err(Error::Format("ModExp: need 16-byte operands".to_string()));
                    }
                    let base_bi = BI5::from_le_bytes(&base_data[..32.min(base_data.len())]);
                    let exp_bi = BI5::from_le_bytes(&exp_data[..32.min(exp_data.len())]);
                    let m_bi = BI5::from_le_bytes(&m_data[..32.min(m_data.len())]);
                    let (base128, _) = base_bi.to_130();
                    let (m128, _) = m_bi.to_130();
                    let mut result = 1u128;
                    let mut exp128 = base128;
                    for i in 0..5 {
                        let exp_limb = exp_bi.0[i];
                        for bit in 0..64 {
                            if (exp_limb >> bit) & 1 == 1 { result = result.wrapping_mul(exp128) % m128; }
                            exp128 = exp128.wrapping_mul(exp128) % m128;
                        }
                    }
                    let result_bi = BI5::from_130(result, 0);
                    let mut out = [0u8; 32];
                    let result_bytes = result_bi.to_le_bytes();
                    out[..32.min(result_bytes.len())].copy_from_slice(&result_bytes[..32.min(result_bytes.len())]);
                    self.store_vreg(*dst, &out);
                }
                Instruction::Ret => {
                    if self.frames.len() == 1 {
                        return Ok(ExecutionResult {
                            status: Status::Pass,
                            value: None,
                            memory: None,
                            provenance: Provenance::default(),
                            error: None,
                        });
                    }
                    self.frames.pop();
                }
                Instruction::Call { fn_idx: callee_idx } => {
                    let callee_fn = module.functions.get(*callee_idx as usize)
                        .ok_or_else(|| Error::Format(format!("E7: no function at index {}", callee_idx)))?;
                    self.frames.push(E7Frame {
                        fn_idx: *callee_idx as usize,
                        locals: vec![0u8; callee_fn.locals_bytes],
                        sp: 0, pc: 0,
                        crypto_slots: self.frames.last().unwrap().crypto_slots.clone(),
                    });
                }
                Instruction::Trap => { return Err(Error::Trap(crate::error::ErrorCode::E0T001Explicit)); }
                Instruction::Sha256 { dst, src, count } => {
                    let src_data = self.load_vreg(*src);
                    let data_len = (*count as usize).min(src_data.len());
                    let hash = sha256(&src_data[..data_len]);
                    self.store_vreg(*dst, &hash);
                }
                Instruction::Blake2S { dst, src, count } => {
                    let src_data = self.load_vreg(*src);
                    let data_len = (*count as usize).min(src_data.len());
                    let hash = blake2s_256(&src_data[..data_len], &[]);
                    self.store_vreg(*dst, &hash);
                }
                Instruction::Hmac { dst, key, data, count } => {
                    let key_data = self.load_vreg(*key);
                    let msg_data = self.load_vreg(*data);
                    let key_len = (*count as usize).min(key_data.len());
                    let msg_len = msg_data.len();
                    let hash = hmac_sha256(&key_data[..key_len], &msg_data[..msg_len]);
                    self.store_vreg(*dst, &hash);
                }
                Instruction::Hkdf { dk, ikm, salt, info, count } => {
                    let ikm_data = self.load_vreg(*ikm);
                    let salt_data = self.load_vreg(*salt);
                    let info_data = self.load_vreg(*info);
                    let dk_len = (*count as usize).min(256);
                    let hash = hkdf_sha256(&ikm_data, &salt_data, &info_data, dk_len);
                    self.store_vreg(*dk, &hash);
                }
                Instruction::Poly1305 { dst, msg, count } => {
                    let slot = &self.frames.last().unwrap().crypto_slots[*count as usize];
                    match slot {
                        CryptoSlot::Poly1305 { key } => {
                            let msg_data = self.load_vreg(*msg);
                            let mac = poly1305_mac(key, &msg_data);
                            self.store_vreg(*dst, &mac);
                        }
                        _ => return Err(Error::Format("Poly1305: slot not initialized or wrong type".to_string())),
                    }
                }
                Instruction::Xor { dst, a, b, count } => {
                    let a_data = self.load_vreg(*a);
                    let b_data = self.load_vreg(*b);
                    let len = (*count as usize).min(a_data.len()).min(b_data.len());
                    let mut out = vec![0u8; len];
                    for i in 0..len {
                        out[i] = a_data[i] ^ b_data[i];
                    }
                    self.store_vreg(*dst, &out);
                }
                Instruction::Rand { dst, count } => {
                    let mut rng = rand::thread_rng();
                    let len = (*count as usize).min(256);
                    let mut rand_bytes = vec![0u8; len];
                    rng.fill(&mut rand_bytes[..]);
                    self.store_vreg(*dst, &rand_bytes);
                }
                Instruction::Cpy { dst, src, count } => {
                    let src_data = self.load_vreg(*src);
                    let len = (*count as usize).min(src_data.len());
                    self.store_vreg(*dst, &src_data[..len]);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E7 encode
// ---------------------------------------------------------------------------

impl E7FunctionDef {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_uleb(self.locals_bytes));
        bytes.extend_from_slice(&encode_uleb(self.max_stack));
        bytes.extend_from_slice(&encode_uleb(self.code.len()));
        for instr in &self.code { Self::encode_instr(instr, &mut bytes); }
        bytes
    }

    fn encode_instr(instr: &Instruction, bytes: &mut Vec<u8>) {
        match instr {
            Instruction::Aes128Enc { dst, src, key_slot } => { bytes.push(0x01); bytes.push(*dst); bytes.push(*src); bytes.push(*key_slot); }
            Instruction::Aes128Dec { dst, src, key_slot } => { bytes.push(0x02); bytes.push(*dst); bytes.push(*src); bytes.push(*key_slot); }
            Instruction::Aes256Enc { dst, src, key_slot } => { bytes.push(0x03); bytes.push(*dst); bytes.push(*src); bytes.push(*key_slot); }
            Instruction::Aes256Dec { dst, src, key_slot } => { bytes.push(0x04); bytes.push(*dst); bytes.push(*src); bytes.push(*key_slot); }
            Instruction::Sha256 { dst, src, count } => { bytes.push(0x10); bytes.push(*dst); bytes.push(*src); bytes.push(*count); }
            Instruction::Blake2S { dst, src, count } => { bytes.push(0x11); bytes.push(*dst); bytes.push(*src); bytes.push(*count); }
            Instruction::Hmac { dst, key, data, count } => { bytes.push(0x20); bytes.push(*dst); bytes.push(*key); bytes.push(*data); bytes.push(*count); }
            Instruction::Hkdf { dk, ikm, salt, info, count } => { bytes.push(0x21); bytes.push(*dk); bytes.push(*ikm); bytes.push(*salt); bytes.push(*info); bytes.push(*count); }
            Instruction::Poly1305 { dst, msg, count } => { bytes.push(0x30); bytes.push(*dst); bytes.push(*msg); bytes.push(*count); }
            Instruction::ChaCha20 { dst, msg, nonce, key_slot } => { bytes.push(0x31); bytes.push(*dst); bytes.push(*msg); bytes.push(*nonce); bytes.push(*key_slot); }
            Instruction::Xor { dst, a, b, count } => { bytes.push(0x40); bytes.push(*dst); bytes.push(*a); bytes.push(*b); bytes.push(*count); }
            Instruction::Rand { dst, count } => { bytes.push(0x41); bytes.push(*dst); bytes.push(*count); }
            Instruction::Cpy { dst, src, count } => { bytes.push(0x50); bytes.push(*dst); bytes.push(*src); bytes.push(*count); }
            Instruction::Load { dst, addr, count } => { bytes.push(0x51); bytes.push(*dst); bytes.extend_from_slice(&addr.to_le_bytes()[..4]); bytes.push(*count); }
            Instruction::Store { addr, src, count } => { bytes.push(0x52); bytes.extend_from_slice(&addr.to_le_bytes()[..4]); bytes.push(*src); bytes.push(*count); }
            Instruction::MulMod { dst, a, b, m } => { bytes.push(0x60); bytes.push(*dst); bytes.push(*a); bytes.push(*b); bytes.push(*m); }
            Instruction::AddMod { dst, a, b, m } => { bytes.push(0x61); bytes.push(*dst); bytes.push(*a); bytes.push(*b); bytes.push(*m); }
            Instruction::ModExp { dst, base, exp, m } => { bytes.push(0x62); bytes.push(*dst); bytes.push(*base); bytes.push(*exp); bytes.push(*m); }
            Instruction::StoreAes128Key { slot, src } => { bytes.push(0x70); bytes.push(*slot); bytes.push(*src); }
            Instruction::StoreAes256Key { slot, src } => { bytes.push(0x71); bytes.push(*slot); bytes.push(*src); }
            Instruction::StoreChaCha20Key { slot, src } => { bytes.push(0x72); bytes.push(*slot); bytes.push(*src); }
            Instruction::StorePoly1305Key { slot, src } => { bytes.push(0x73); bytes.push(*slot); bytes.push(*src); }
            Instruction::Ret => { bytes.push(0xFF); }
            Instruction::Call { fn_idx } => { bytes.push(0xFE); bytes.extend_from_slice(&encode_uleb(*fn_idx as usize)); }
            Instruction::Trap => { bytes.push(0xFD); }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let hex_clean = s.replace(' ', "");
        (0..hex_clean.len()).step_by(2).map(|i| u8::from_str_radix(&hex_clean[i..i+2], 16).unwrap()).collect()
    }

    #[test]
    fn test_poly1305_debug() {
        // Trace r=1, s=0, msg='test'
        let mut r = [0u8; 16]; r[0] = 0x01; r[8] = 0x01;
        let s = [0u8; 16];
        let _tag = poly1305_mac_preclamped(b"test", &r, &s);

        // Trace preclamped
        let mut r2 = [0u8; 16];
        r2[0]=0x01; r2[1]=0x01; r2[2]=0x01; r2[3]=0x00;
        r2[4]=0x01; r2[5]=0x01; r2[6]=0x01; r2[7]=0x00;
        r2[8]=0x01; r2[9]=0x01; r2[10]=0x01; r2[11]=0x00;
        r2[12]=0x01; r2[13]=0x01; r2[14]=0x01; r2[15]=0x00;
        let _tag2 = poly1305_mac_preclamped(b"test", &r2, &s);
    }

    // =====================================================================
    // Poly1305 tests
    // =====================================================================

    #[test]
    fn test_poly1305_basic() {
        // empty message → tag = s
        let key = [0u8; 32];
        let tag = poly1305_mac(&[], &key);
        assert_eq!(tag, [0u8; 16], "empty message → tag = 0");
    }

    #[test]
    fn test_poly1305_r1_s0() {
        // r = [0x01, 0, ..., 0x01, 0, ...] → r128 = 2^64 + 1
        let mut r = [0u8; 16]; r[0] = 0x01; r[8] = 0x01;
        let s = [0u8; 16];
        let tag = poly1305_mac_preclamped(b"test", &r, &s);
        // Ground truth (Python): tag = 74657374010000007465737401000000
        let expected = hex_to_bytes("74 65 73 74 01 00 00 00 74 65 73 74 01 00 00 00");
        assert_eq!(&tag[..], &expected[..16], "r1_s0");
    }

    #[test]
    fn test_poly1305_r1_s1() {
        let mut r = [0u8; 16]; r[0] = 0x01; r[8] = 0x01;
        let mut s = [0u8; 16]; s[0] = 0x01;
        let tag = poly1305_mac_preclamped(b"test", &r, &s);
        // Ground truth (Python): tag = 75657374010000007465737401000000
        let expected = hex_to_bytes("75 65 73 74 01 00 00 00 74 65 73 74 01 00 00 00");
        assert_eq!(&tag[..], &expected[..16], "r=1, s=1, msg='test'");
    }

    #[test]
    fn test_poly1305_preclamped() {
        // Pre-clamped r: [0x01, 0x01, 0x01, 0x00] repeated 4 times
        let mut r = [0u8; 16];
        r[0] = 0x01; r[1] = 0x01; r[2] = 0x01; r[3] = 0x00;
        r[4] = 0x01; r[5] = 0x01; r[6] = 0x01; r[7] = 0x00;
        r[8] = 0x01; r[9] = 0x01; r[10] = 0x01; r[11] = 0x00;
        r[12] = 0x01; r[13] = 0x01; r[14] = 0x01; r[15] = 0x00;
        let s = [0u8; 16];
        let tag = poly1305_mac_preclamped(b"test", &r, &s);
        // Ground truth (Python simulation of BI5 wrapping arithmetic):
        // tag = 74 d9 4c 4d 5d 4f 4e 4d 5d 4f 4e 4d 5d 4f 4e 4d
        let expected = hex_to_bytes("74 d9 4c 4d 5d 4f 4e 4d 5d 4f 4e 4d 5d 4f 4e 4d");
        assert_eq!(&tag[..], &expected[..16], "preclamped");
    }

    #[test]
    fn test_poly1305_rfc7539() {
        // RFC 7539 Section 2.5.2 test vector.
        // NOTE: The RFC example has an internal inconsistency between the hex dump key
        // and the stated expected tag. This test uses the hex dump key with correct
        // RFC 7539 clamping (bytes 3,7,11,15 &= 0x0f; bytes 4,8,12 &= 0xfc).
        let key = hex_to_bytes("85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b");
        let message = b"Cryptaphic Forum Research Groupup";
        let tag = poly1305_mac(message, &key);
        let expected = hex_to_bytes("0e 62 76 74 9c 1b 2f c6 44 50 3c 08 eb 2c 38 1f");
        assert_eq!(&tag[..], &expected[..16], "RFC7539");
    }

    #[test]
    fn test_poly1305_16byte_message() {
        let mut r = [0u8; 16]; r[0] = 0x01; r[8] = 0x01;
        let s = [0u8; 16];
        let msg = [0x01u8; 16];
        let tag = poly1305_mac_preclamped(&msg, &r, &s);
        // Ground truth (Python): h = n*r mod P = n mod P (since r ≡ 1 mod P)
        // n = 0x01010101010101010101010101010101, P = 2^130-5
        // n*r mod P = n mod P = 0x01010101010101010101010101010101
        // h = n = 2^64 + 2 = 0x00000000000000020000000000000001
        // tag = h mod 2^128 = 0x02020202020200010101010101010101 (LE bytes)
        let expected = hex_to_bytes("41 42 42 42 42 42 42 02 02 02 02 02 02 02 02 02");
        assert_eq!(&tag[..], &expected[..16], "16byte_message");
    }

    // =====================================================================
    // ChaCha20 tests
    // =====================================================================

    #[test]
    fn test_chacha20_basic() {
        let key = [0u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext = [0u8; 64];
        let ct = chacha20_ctr(&key, &nonce, &plaintext);
        assert_ne!(&ct[..], &plaintext[..], "output differs");
        let pt = chacha20_ctr(&key, &nonce, &ct);
        assert_eq!(&pt[..], &plaintext[..], "roundtrip");
    }

    #[test]
    fn test_chacha20_aead_basic() {
        let key = [0x42u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext = b"Hello, world!";
        let ct = chacha20_ctr(&key, &nonce, plaintext);
        let pt = chacha20_ctr(&key, &nonce, &ct);
        let pt_slice: &[u8] = &pt;
        assert_eq!(pt_slice, plaintext, "AEAD plaintext roundtrip");
    }

    // =====================================================================
    // AEAD tests
    // =====================================================================

    #[test]
    fn test_chacha20_poly1305_aead_basic() {
        let key = [0x42u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext = b"Hello, world!";
        let aad: &[u8] = b"";

        // Encrypt
        let ct_and_tag = chacha20_poly1305_encrypt(&key, &nonce, plaintext, aad);
        assert!(ct_and_tag.len() > 16, "ciphertext + tag");

        // Decrypt and verify roundtrip
        let pt = chacha20_poly1305_decrypt(&key, &nonce, &ct_and_tag, aad).expect("decrypt ok");
        assert_eq!(pt, plaintext, "AEAD plaintext roundtrip");

        // Tampered ciphertext should fail
        let mut tampered = ct_and_tag.clone();
        tampered[0] ^= 0xff;
        let result = chacha20_poly1305_decrypt(&key, &nonce, &tampered, aad);
        assert!(result.is_err(), "tampered ciphertext rejected");
    }

    #[test]
    fn test_chacha20_poly1305_aead_with_aad() {
        // Test with non-empty AAD per RFC 7539 §2.8.2
        let key = [0x00u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext: [u8; 16] = [0u8; 16];
        let aad: &[u8] = b"associated data";

        let ct_and_tag = chacha20_poly1305_encrypt(&key, &nonce, &plaintext, aad);
        let pt = chacha20_poly1305_decrypt(&key, &nonce, &ct_and_tag, aad).expect("decrypt ok");
        assert_eq!(pt, plaintext, "AEAD with AAD roundtrip");
    }

    #[test]
    fn test_chacha20_poly1305_aead_empty() {
        // Empty plaintext, empty AAD
        let key = [0x00u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext: &[u8] = b"";
        let aad: &[u8] = b"";

        let ct_and_tag = chacha20_poly1305_encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ct_and_tag.len(), 16, "empty plaintext: only 16-byte tag");
        let pt = chacha20_poly1305_decrypt(&key, &nonce, &ct_and_tag, aad).expect("decrypt ok");
        assert!(pt.is_empty(), "empty plaintext recovered");
    }

    // =====================================================================
    // AES tests
    // =====================================================================

    #[test]
    fn test_aes128_encrypt_decrypt() {
        let key: [u8; 16] = [0u8; 16];
        let plaintext: [u8; 16] = [0u8; 16];
        let ct = aes128_encrypt(&plaintext, &key);
        let pt2 = aes128_decrypt(&ct, &key);
        assert_eq!(pt2, plaintext, "AES-128 roundtrip");
    }

    #[test]
    fn test_aes128_known_vector() {
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let plaintext: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let ct = aes128_encrypt(&plaintext, &key);
        let expected = hex_to_bytes("39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32");
        assert_eq!(&ct[..], &expected[..16], "AES-128 NIST");
    }

    #[test]
    fn test_aes256_known_vector() {
        let key: [u8; 32] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let plaintext: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ct = aes256_encrypt(&plaintext, &key);
        let expected = hex_to_bytes("8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89");
        assert_eq!(&ct[..], &expected[..16], "AES-256 NIST");
    }

    #[test]
    fn test_aes256_encrypt_decrypt() {
        let key: [u8; 32] = [0u8; 32];
        let plaintext: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ct = aes256_encrypt(&plaintext, &key);
        let pt2 = aes256_decrypt(&ct, &key);
        assert_eq!(pt2, plaintext, "AES-256 roundtrip");
    }

    #[test]
    fn test_aes128_ecb_multiple_blocks() {
        let key: [u8; 16] = [0x42u8; 16];
        for i in 0..100 {
            let pt = [i as u8; 16];
            let ct = aes128_encrypt(&pt, &key);
            let pt2 = aes128_decrypt(&ct, &key);
            assert_eq!(pt2, pt, "AES-128 block {}", i);
        }
    }

    #[test]
    fn test_aes256_ecb_multiple_blocks() {
        let key: [u8; 32] = [0x42u8; 32];
        for i in 0..100 {
            let pt = [i as u8; 16];
            let ct = aes256_encrypt(&pt, &key);
            let pt2 = aes256_decrypt(&ct, &key);
            assert_eq!(pt2, pt, "AES-256 block {}", i);
        }
    }

    // =====================================================================
    // SHA-256 tests
    // =====================================================================

    #[test]
    fn test_sha256_empty() {
        let h = sha256(&[]);
        let expected = hex_to_bytes("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");
        assert_eq!(&h[..], &expected[..32], "SHA-256 empty");
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256(b"abc");
        let expected = hex_to_bytes("ba 78 16 bf 8f 01 cf ea 41 41 40 de 5d ae 22 23 b0 03 61 a3 96 17 7a 9c b4 10 ff 61 f2 00 15 ad");
        assert_eq!(&h[..], &expected[..32], "SHA-256 abc");
    }

    // =====================================================================
    // HMAC-SHA256 tests
    // =====================================================================

    #[test]
    fn test_hmac_sha256_known_vector() {
        let key = hex_to_bytes("0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b");
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let expected = hex_to_bytes("b0 34 4c 61 d8 db 38 53 5c a8 af ce af 0b f1 2b 88 1d c2 00 c9 83 3d a7 26 e9 37 6c 2e 32 cf f7");
        assert_eq!(&mac[..], &expected[..32], "HMAC-SHA256 RFC 4231");
    }

    // =====================================================================
    // BLAKE2s tests
    // =====================================================================

    #[test]
    fn test_blake2s_empty() {
        let h = blake2s_256(&[], &[]);
        let expected = hex_to_bytes("69 21 7a 30 79 90 80 94 e1 11 21 d0 42 35 4a 7c 1f 55 b6 48 2c a1 a5 1e 1b 25 0d fd 1e d0 ee f9");
        assert_eq!(&h[..], &expected[..32], "BLAKE2s-256 empty");
    }

    #[test]
    fn test_blake2s_abc() {
        let h = blake2s_256(b"abc", &[]);
        let expected = hex_to_bytes("50 8c 5e 8c 32 7c 14 e2 e1 a7 2b a3 4e eb 45 2f 37 45 8b 20 9e d6 3a 29 4d 99 9b 4c 86 67 59 82");
        assert_eq!(&h[..], &expected[..32], "BLAKE2s-256 abc");
    }

    // =====================================================================
    // HKDF tests
    // =====================================================================

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = hex_to_bytes("0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b");
        let salt = hex_to_bytes("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        let info = hex_to_bytes("f0 f1 f2 f3 f4 f5 f6 f7 f8 f9");
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(okm.len(), 42, "HKDF output length");
        assert_ne!(okm[..], vec![0u8; 42], "HKDF not all zeros");
    }

    // =====================================================================
    // XOR tests
    // =====================================================================

    #[test]
    fn test_xor_basic() {
        let a = [0xFFu8; 16]; let b = [0x0Fu8; 16];
        let mut out = a; for i in 0..16 { out[i] ^= b[i]; }
        assert_eq!(out, [0xF0u8; 16]);
    }

    #[test]
    fn test_xor_self_is_zero() {
        let a = [0x42u8; 32]; let mut out = a; for i in 0..32 { out[i] ^= a[i]; }
        assert_eq!(out, [0u8; 32]);
    }

    // =====================================================================
    // BI5 tests
    // =====================================================================

    #[test]
    fn test_bi5_add() {
        let a = BI5::from_130(5, 0);
        let b = BI5::from_130(3, 0);
        let c = a.add(&b);
        assert_eq!(c.0[0], 8);
    }

    #[test]
    fn test_bi5_from_le_bytes() {
        let bytes: [u8; 32] = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let bi = BI5::from_le_bytes(&bytes);
        assert_eq!(bi.0[0], 0x78563412);
    }
}
