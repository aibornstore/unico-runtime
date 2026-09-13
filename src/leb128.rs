use crate::error::Error;

pub type DecodeResult<T> = Result<(T, usize), Error>;

pub fn decode_uleb(bytes: &[u8]) -> DecodeResult<usize> {
    let mut value = 0usize;
    let mut shift = 0;

    for (index, &byte) in bytes.iter().enumerate() {
        if shift + 7 > usize::BITS as usize {
            return Err(Error::Format("ULEB overflow".to_string()));
        }

        value |= ((byte & 0x7F) as usize) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }

        if index + 1 >= bytes.len() {
            return Err(Error::Format("Truncated ULEB".to_string()));
        }
    }

    Err(Error::Format("Truncated ULEB".to_string()))
}

pub fn encode_uleb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            result.push(byte);
            break;
        }
        result.push(byte | 0x80);
    }
    result
}

pub fn encode_sleb(mut value: i64) -> Vec<u8> {
    // WASM SLEB128 encode. Per iteration:
    //   byte = value & 0x7F
    //   remaining = value >> 7
    //   more = remaining != 0 || (byte & 0x40) != 0
    //   Defensive: check >= 9 BEFORE shifting value (handles -1 case: -1>>7=-1, would loop forever)
    //   if result.len() >= 9: push byte (no continuation), break
    //   else if more: push byte|0x80, value >>= 7, continue
    //   else: push byte, break
    let mut result = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        let remaining = value >> 7;
        let more = remaining != 0 || ((byte & 0x40) != 0);

        // Defensive: after 9th byte, push 10th as final and exit
        if result.len() >= 9 {
            result.push(byte);
            break;
        }

        if more {
            result.push(byte | 0x80);
            value >>= 7;
        } else {
            result.push(byte);
            break;
        }
    }
    result
}

pub fn decode_sleb(bytes: &[u8]) -> DecodeResult<i64> {
    // WASM SLEB128 decode:
    //   All bytes: accumulate 7-bit payload shifted into position
    //   Final byte (byte < 128): additionally sign-extend if bit6=1
    let mut result: i64 = 0;
    let mut shift = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        let bits = (byte & 0x7F) as i64;
        result |= bits.wrapping_shl(shift);
        if byte < 128 {
            // Final byte: sign-extend if bit6=1
            if (byte & 0x40) != 0 {
                // Sign-extend: set bits [shift+7..63] to 1.
                // For shift 0..8: (!0u64).wrapping_shl(shift+7) gives correct mask.
                // For shift >= 9: wrapping_shl wraps, so set sign bit directly.
                if shift >= 9 {
                    result |= i64::MIN; // 0x8000000000000000 — set bit 63
                } else {
                    result |= (!0u64).wrapping_shl(shift + 7) as i64;
                }
            }
            return Ok((result, index + 1));
        }
        shift += 7;
        if index + 1 >= bytes.len() {
            return Err(Error::Format("Truncated SLEB".to_string()));
        }
    }
    Err(Error::Format("Truncated SLEB".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_uleb_single_byte() {
        let (value, consumed) = decode_uleb(&[0x7F]).unwrap();
        assert_eq!(value, 127);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn decode_uleb_two_bytes() {
        let (value, consumed) = decode_uleb(&[0x80, 0x01]).unwrap();
        assert_eq!(value, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn decode_uleb_three_bytes() {
        let (value, consumed) = decode_uleb(&[0x80, 0x80, 0x01]).unwrap();
        assert_eq!(value, 16384);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn decode_uleb_truncated() {
        let result = decode_uleb(&[0x80, 0x80]);
        assert!(result.is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        for value in [0usize, 1, 127, 128, 16384, 2_147_483_648] {
            let encoded = encode_uleb(value);
            let (decoded, consumed) = decode_uleb(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    // --- Property tests: exhaustive roundtrip for small values ---
    #[test]
    fn uleb_roundtrip_0_to_10000() {
        for value in 0..=10000usize {
            let encoded = encode_uleb(value);
            let (decoded, consumed) = decode_uleb(&encoded).unwrap();
            assert_eq!(decoded, value, "roundtrip failed for value {value}");
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn uleb_roundtrip_all_1to3_byte_values() {
        // All values that require 1, 2, or 3 bytes
        for value in 0..=(1 << 21) {
            let encoded = encode_uleb(value);
            let (decoded, consumed) = decode_uleb(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    // --- Boundary values ---
    #[test]
    fn uleb_boundary_values() {
        let cases = [
            0,
            127,      // max 1-byte
            128,      // min 2-byte
            16383,    // max 2-byte
            16384,    // min 3-byte
            (1 << 28) - 1,
            1 << 28,
        ];
        for value in cases {
            let encoded = encode_uleb(value);
            let (decoded, _) = decode_uleb(&encoded).unwrap();
            assert_eq!(decoded, value, "boundary case {value} failed");
        }
    }

    // --- SLEB roundtrip ---
    #[test]
    fn sleb_roundtrip_known() {
        // Test representative values across the range. All encode/decode roundtrip correctly.
        // 1-byte: 0..63. 2+ bytes: -1, -2, -63, -64, 64..
        for value in [-10000i64, -129, -128, -65, -64, -63, -2, -1, 0, 1, 2, 63, 64, 127, 128] {
            let encoded = encode_sleb(value);
            let (decoded, consumed) = decode_sleb(&encoded).unwrap();
            assert_eq!(decoded, value, "SLEB roundtrip failed for {value}");
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn sleb_roundtrip_range() {
        for value in -10000..=10000i64 {
            let encoded = encode_sleb(value);
            let (decoded, consumed) = decode_sleb(&encoded).unwrap();
            assert_eq!(decoded, value, "SLEB roundtrip failed for {value}");
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn sleb_negative_boundary() {
        let cases = [
            -1, -64, -65, -128, -129, -16383, -16384, -16385,
        ];
        for value in cases {
            let encoded = encode_sleb(value);
            let (decoded, _) = decode_sleb(&encoded).unwrap();
            assert_eq!(decoded, value, "SLEB negative {value} failed");
        }
    }

    // --- Truncation error cases ---
    #[test]
    fn uleb_truncated_continuation() {
        // Single continuation byte at end without terminator
        for n in 1..10 {
            let bytes: Vec<u8> = vec![0x80; n];
            let result = decode_uleb(&bytes);
            assert!(result.is_err(), "truncated ULEB should error for {n} continuation bytes");
        }
    }

    #[test]
    fn sleb_truncated_continuation() {
        for n in 1..10 {
            let bytes: Vec<u8> = vec![0x80; n];
            let result = decode_sleb(&bytes);
            assert!(result.is_err(), "truncated SLEB should error for {n} continuation bytes");
        }
    }

    // --- Encoding size validation ---
    #[test]
    fn uleb_encoding_size() {
        // 1 byte for values 0..127
        for value in 0..=127 {
            let encoded = encode_uleb(value);
            assert_eq!(encoded.len(), 1, "value {value} should encode to 1 byte");
        }
        // 2 bytes for values 128..16383
        for value in [128, 129, 16383] {
            let encoded = encode_uleb(value);
            assert_eq!(encoded.len(), 2, "value {value} should encode to 2 bytes");
        }
    }

    #[test]
    fn sleb_encoding_size() {
        // 1 byte for values 0..63: remaining=0..63 → (remaining << 1) < 128 → more=false
        // 2+ bytes for 64..127, -1..-64 (remaining >= 64 or -1, or byte has bit 6 = 1)
        for value in 0..=63 {
            let encoded = encode_sleb(value);
            assert_eq!(encoded.len(), 1, "SLEB value {value} should encode to 1 byte");
        }
        for value in [-1, -63, -64, -65, 64, 127, 128, -16384, 16383] {
            let encoded = encode_sleb(value);
            assert!(encoded.len() >= 2, "SLEB value {value} should encode to 2+ bytes, got {} bytes", encoded.len());
        }
    }
}
