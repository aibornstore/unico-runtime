// Canonical ULEB128 (unsigned) decoder for UNICO v3.0
// 
// This fixes the flawed `uleb_len(first: u8)` approach which cannot
// correctly determine length of multi-byte ULEB values.
//
// Correct approach: read bytes until continuation bit (0x80) is 0,
// return (value, consumed_bytes).

pub fn decode_uleb(bytes: &[u8]) -> Result<usize, &'static str> {
    let mut value = 0usize;
    let mut shift = 0;
    
    for (index, &byte) in bytes.iter().enumerate() {
        // Check for overflow
        if shift >= usize::BITS as usize {
            return Err("ULEB overflow");
        }
        
        value |= ((byte & 0x7F) as usize) << shift;
        shift += 7;
        
        // Continuation bit not set - this is the last byte
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        
        // Not enough bytes
        if index + 1 >= bytes.len() {
            return Err("Truncated ULEB");
        }
    }
    
    Err("Truncated ULEB")
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

#[cfg(test code would go in separate test module, but for brevity showing only decoder here)