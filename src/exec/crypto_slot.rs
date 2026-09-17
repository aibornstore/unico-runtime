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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_slot_empty_encrypt_fails() {
        let slot = CryptoSlot::Empty;
        let result = slot.encrypt(b"test data", None);
        assert!(result.is_err(), "Empty slot encrypt should fail");
    }

    #[test]
    fn test_crypto_slot_empty_decrypt_fails() {
        let slot = CryptoSlot::Empty;
        let result = slot.decrypt(b"test data", None);
        assert!(result.is_err(), "Empty slot decrypt should fail");
    }

    #[test]
    fn test_crypto_slot_poly1305_decrypt_fails() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::Poly1305 { key };
        let result = slot.decrypt(b"some ciphertext", None);
        assert!(result.is_err(), "Poly1305 decrypt should fail");
    }

    #[test]
    fn test_crypto_slot_chacha20_encrypt_requires_nonce() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::ChaCha20 { key };
        let result = slot.encrypt(b"test data", None);
        assert!(result.is_err(), "ChaCha20 encrypt without nonce should fail");
    }

    #[test]
    fn test_crypto_slot_chacha20_decrypt_requires_nonce() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::ChaCha20 { key };
        let result = slot.decrypt(b"test data", None);
        assert!(result.is_err(), "ChaCha20 decrypt without nonce should fail");
    }

    #[test]
    fn test_crypto_slot_chacha20_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::ChaCha20 { key };
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext = b"Hello, ChaCha20!";
        let ct = slot.encrypt(plaintext, Some(&nonce)).unwrap();
        let pt = slot.decrypt(&ct, Some(&nonce)).unwrap();
        assert_eq!(&pt[..], plaintext, "ChaCha20 roundtrip");
    }

    #[test]
    fn test_crypto_slot_chacha20_different_nonces_different_output() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::ChaCha20 { key };
        let nonce1: [u8; 12] = [0u8; 12];
        let nonce2: [u8; 12] = [1u8; 12];
        let plaintext = b"Test message";
        let ct1 = slot.encrypt(plaintext, Some(&nonce1)).unwrap();
        let ct2 = slot.encrypt(plaintext, Some(&nonce2)).unwrap();
        assert_ne!(&ct1[..], &ct2[..], "Different nonces should produce different ciphertext");
    }

    #[test]
    fn test_crypto_slot_poly1305_encrypt_produces_tag() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::Poly1305 { key };
        let result = slot.encrypt(b"test message", None).unwrap();
        assert_eq!(result.len(), 16, "Poly1305 should produce 16-byte tag");
    }

    #[test]
    fn test_crypto_slot_is_empty() {
        let empty = CryptoSlot::Empty;
        assert!(empty.is_empty(), "Empty slot should be empty");
        let key = [0u8; 32];
        let aes = CryptoSlot::Aes128 { round_keys: [0u8; 176] };
        assert!(!aes.is_empty(), "Aes128 slot should not be empty");
        let chacha = CryptoSlot::ChaCha20 { key };
        assert!(!chacha.is_empty(), "ChaCha20 slot should not be empty");
    }

    #[test]
    fn test_crypto_slot_aes128_encrypt_short_data_fails() {
        let round_keys = [0u8; 176];
        let slot = CryptoSlot::Aes128 { round_keys };
        let result = slot.encrypt(&[0u8; 8], None);
        assert!(result.is_err(), "AES128 encrypt with short data should fail");
    }

    #[test]
    fn test_crypto_slot_aes256_encrypt_short_data_fails() {
        let round_keys = [0u8; 240];
        let slot = CryptoSlot::Aes256 { round_keys };
        let result = slot.encrypt(&[0u8; 8], None);
        assert!(result.is_err(), "AES256 encrypt with short data should fail");
    }

    #[test]
    fn test_crypto_slot_aes128_decrypt_short_data_fails() {
        let round_keys = [0u8; 176];
        let slot = CryptoSlot::Aes128 { round_keys };
        let result = slot.decrypt(&[0u8; 8], None);
        assert!(result.is_err(), "AES128 decrypt with short data should fail");
    }

    #[test]
    fn test_crypto_slot_aes256_decrypt_short_data_fails() {
        let round_keys = [0u8; 240];
        let slot = CryptoSlot::Aes256 { round_keys };
        let result = slot.decrypt(&[0u8; 8], None);
        assert!(result.is_err(), "AES256 decrypt with short data should fail");
    }
}
