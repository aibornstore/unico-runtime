/// Crypto slot contract for E7 hardware crypto operations.
/// Each slot can hold pre-expanded keys for different algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoSlot {
    /// Empty slot - no key material loaded
    Empty,
    /// AES-128: 11 round keys (16 bytes each = 176 bytes)
    Aes128 { round_keys: [u8; 176] },
    /// AES-256: 15 round keys (16 bytes each = 240 bytes)
    Aes256 { round_keys: [u8; 240] },
    /// ChaCha20: 32-byte key (nonce comes from message register at execution time)
    ChaCha20 { key: [u8; 32] },
    /// Poly1305: 32-byte key (r[16] || s[16])
    Poly1305 { key: [u8; 32] },
}

impl Default for CryptoSlot {
    fn default() -> Self { CryptoSlot::Empty }
}

impl CryptoSlot {
    pub fn is_empty(&self) -> bool {
        matches!(self, CryptoSlot::Empty)
    }

    /// Encrypt data using the key in this slot.
    /// For AES: expects 16-byte block. For ChaCha20: nonce is provided via `nonce` arg.
    /// For Poly1305: returns MAC tag.
    pub fn encrypt(&self, data: &[u8], nonce: Option<&[u8; 12]>) -> Result<Vec<u8>, crate::error::Error> {
        match self {
            CryptoSlot::Aes128 { round_keys } => {
                if data.len() < 16 {
                    return Err(crate::error::Error::Format("AES128 encrypt: need 16-byte block".into()));
                }
                let mut keys = [[0u8; 16]; 11];
                for i in 0..11 {
                    let start = i * 16;
                    keys[i].copy_from_slice(&round_keys[start..start + 16]);
                }
                let pt: [u8; 16] = data[..16].try_into()
                    .map_err(|_| crate::error::Error::Format("AES128 input too short".into()))?;
                let ct = crate::exec::e7::aes128_encrypt_with_round_keys(&pt, &keys);
                Ok(ct.to_vec())
            }
            CryptoSlot::Aes256 { round_keys } => {
                if data.len() < 16 {
                    return Err(crate::error::Error::Format("AES256 encrypt: need 16-byte block".into()));
                }
                let mut keys = [[0u8; 16]; 15];
                for i in 0..15 {
                    let start = i * 16;
                    keys[i].copy_from_slice(&round_keys[start..start + 16]);
                }
                let pt: [u8; 16] = data[..16].try_into()
                    .map_err(|_| crate::error::Error::Format("AES256 input too short".into()))?;
                let ct = crate::exec::e7::aes256_encrypt_with_round_keys(&pt, &keys);
                Ok(ct.to_vec())
            }
            CryptoSlot::ChaCha20 { key } => {
                let nonce = nonce.ok_or_else(|| crate::error::Error::Format("ChaCha20 encrypt: nonce required".into()))?;
                Ok(crate::exec::e7::chacha20_ctr(key, nonce, data))
            }
            CryptoSlot::Poly1305 { key } => {
                Ok(crate::exec::e7::poly1305_mac(data, key).to_vec())
            }
            CryptoSlot::Empty => Err(crate::error::Error::Format("encrypt: slot is empty".into())),
        }
    }

    /// Decrypt data using the key in this slot.
    /// For AES: expects 16-byte block. For ChaCha20: nonce is provided via `nonce` arg (CTR mode).
    /// For Poly1305: decrypt not applicable (MAC-only).
    pub fn decrypt(&self, data: &[u8], nonce: Option<&[u8; 12]>) -> Result<Vec<u8>, crate::error::Error> {
        match self {
            CryptoSlot::Aes128 { round_keys } => {
                if data.len() < 16 {
                    return Err(crate::error::Error::Format("AES128 decrypt: need 16-byte block".into()));
                }
                let mut keys = [[0u8; 16]; 11];
                for i in 0..11 {
                    let start = i * 16;
                    keys[i].copy_from_slice(&round_keys[start..start + 16]);
                }
                let ct: [u8; 16] = data[..16].try_into()
                    .map_err(|_| crate::error::Error::Format("AES128 input too short".into()))?;
                let pt = crate::exec::e7::aes128_decrypt_with_round_keys(&ct, &keys);
                Ok(pt.to_vec())
            }
            CryptoSlot::Aes256 { round_keys } => {
                if data.len() < 16 {
                    return Err(crate::error::Error::Format("AES256 decrypt: need 16-byte block".into()));
                }
                let mut keys = [[0u8; 16]; 15];
                for i in 0..15 {
                    let start = i * 16;
                    keys[i].copy_from_slice(&round_keys[start..start + 16]);
                }
                let ct: [u8; 16] = data[..16].try_into()
                    .map_err(|_| crate::error::Error::Format("AES256 input too short".into()))?;
                let pt = crate::exec::e7::aes256_decrypt_with_round_keys(&ct, &keys);
                Ok(pt.to_vec())
            }
            CryptoSlot::ChaCha20 { key } => {
                // ChaCha20 CTR mode: decrypt == encrypt
                let nonce = nonce.ok_or_else(|| crate::error::Error::Format("ChaCha20 decrypt: nonce required".into()))?;
                Ok(crate::exec::e7::chacha20_ctr(key, nonce, data))
            }
            CryptoSlot::Poly1305 { .. } => Err(crate::error::Error::Format("Poly1305: decrypt not supported (MAC only)".into())),
            CryptoSlot::Empty => Err(crate::error::Error::Format("decrypt: slot is empty".into())),
        }
    }
}
