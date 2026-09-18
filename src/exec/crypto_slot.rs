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

    #[test]
    fn test_crypto_slot_default_is_empty() {
        let slot = CryptoSlot::default();
        assert!(slot.is_empty());
    }

    #[test]
    fn test_crypto_slot_poly1305_not_empty() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::Poly1305 { key };
        assert!(!slot.is_empty());
    }

    #[test]
    fn test_crypto_slot_aes256_not_empty() {
        let round_keys = [0u8; 240];
        let slot = CryptoSlot::Aes256 { round_keys };
        assert!(!slot.is_empty());
    }

    #[test]
    fn test_crypto_slot_debug_output() {
        // Test Debug output doesn't panic and produces output
        let _empty = format!("{:?}", CryptoSlot::Empty);
        let _aes128 = format!("{:?}", CryptoSlot::Aes128 { round_keys: [0u8; 176] });
        let _aes256 = format!("{:?}", CryptoSlot::Aes256 { round_keys: [0u8; 240] });
        let _chacha = format!("{:?}", CryptoSlot::ChaCha20 { key: [0u8; 32] });
        let _poly = format!("{:?}", CryptoSlot::Poly1305 { key: [0u8; 32] });
    }

    #[test]
    fn test_crypto_slot_equality() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let slot1 = CryptoSlot::ChaCha20 { key: key1 };
        let slot2 = CryptoSlot::ChaCha20 { key: key1 };
        let slot3 = CryptoSlot::ChaCha20 { key: key2 };
        assert_eq!(slot1, slot2);
        assert_ne!(slot1, slot3);
        assert_ne!(slot1, CryptoSlot::Empty);
    }

    #[test]
    fn test_crypto_slot_clone() {
        let key = [0x42u8; 32];
        let slot = CryptoSlot::ChaCha20 { key };
        let cloned = slot.clone();
        assert_eq!(slot, cloned);
    }

    #[test]
    fn test_crypto_slot_chacha20_nonzero() {
        // Test ChaCha20 with non-zero key
        let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20];
        let slot = CryptoSlot::ChaCha20 { key };
        let nonce: [u8; 12] = [0u8; 12];
        let plaintext = b"Test message with non-zero key";
        let ct = slot.encrypt(plaintext, Some(&nonce)).unwrap();
        let pt = slot.decrypt(&ct, Some(&nonce)).unwrap();
        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn test_crypto_slot_poly1305_mac() {
        // Test Poly1305 MAC production
        let key = [0x42u8; 32];
        let slot = CryptoSlot::Poly1305 { key };
        let result = slot.encrypt(b"", None).unwrap();
        assert_eq!(result.len(), 16);

        let result = slot.encrypt(b"a", None).unwrap();
        assert_eq!(result.len(), 16);

        let result = slot.encrypt(b"Hello Poly1305!", None).unwrap();
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_crypto_slot_empty_errors() {
        let slot = CryptoSlot::Empty;
        // Encrypt with non-empty data
        let result = slot.encrypt(b"test", None);
        assert!(result.is_err());
        let result = slot.decrypt(b"test", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_crypto_slot_aes128_encrypt_decrypt() {
        // Test AES128 with valid 16-byte key schedule (all zeros is valid)
        let round_keys = [0u8; 176];
        let slot = CryptoSlot::Aes128 { round_keys };
        let plaintext = [0u8; 16];
        let ct = slot.encrypt(&plaintext, None).unwrap();
        assert_eq!(ct.len(), 16);

        let pt = slot.decrypt(&ct, None).unwrap();
        assert_eq!(pt.len(), 16);
    }

    #[test]
    fn test_crypto_slot_aes256_encrypt_decrypt() {
        // Test AES256 with valid 16-byte key schedule (all zeros is valid)
        let round_keys = [0u8; 240];
        let slot = CryptoSlot::Aes256 { round_keys };
        let plaintext = [0u8; 16];
        let ct = slot.encrypt(&plaintext, None).unwrap();
        assert_eq!(ct.len(), 16);

        let pt = slot.decrypt(&ct, None).unwrap();
        assert_eq!(pt.len(), 16);
    }
}
