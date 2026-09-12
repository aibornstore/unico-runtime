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

pub fn decode_sleb(bytes: &[u8]) -> DecodeResult<i64> {
    let mut value: i64 = 0;
    let mut shift = 0;

    for (index, &byte) in bytes.iter().enumerate() {
        value |= ((byte & 0x7F) as i64) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                value |= !0i64 << shift;
            }
            return Ok((value, index + 1));
        }

        if index + 1 >= bytes.len() {
            return Err(Error::Format("Truncated SLEB".to_string()));
        }
    }

    Err(Error::Format("Truncated SLEB".to_string()))
}

pub fn encode_sleb(mut value: i64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = (value as u8) & 0x7F;
        value >>= 7;
        let more = !(value == 0 || value == -1);
        if more {
            result.push(byte | 0x80);
        } else {
            result.push(byte);
            break;
        }
    }
    result
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
}
