//! Unit tests for the CryptoSlot contract.

use unico_runtime::exec::crypto_slot::CryptoSlot;

#[test]
fn test_crypto_slot_default_is_empty() {
    let slot = CryptoSlot::default();
    assert!(slot.is_empty(), "default slot must be Empty");
}

#[test]
fn test_crypto_slot_is_empty_on_empty_variant() {
    let slot = CryptoSlot::Empty;
    assert!(slot.is_empty(), "Empty variant must report is_empty() == true");
}

#[test]
fn test_crypto_slot_is_not_empty_on_aes128_variant() {
    let slot = CryptoSlot::Aes128 { round_keys: [0u8; 176] };
    assert!(!slot.is_empty(), "Aes128 variant must not be empty");
}

#[test]
fn test_crypto_slot_is_not_empty_on_aes256_variant() {
    let slot = CryptoSlot::Aes256 { round_keys: [0u8; 240] };
    assert!(!slot.is_empty(), "Aes256 variant must not be empty");
}

#[test]
fn test_crypto_slot_is_not_empty_on_chacha20_variant() {
    let slot = CryptoSlot::ChaCha20 { key: [0u8; 32] };
    assert!(!slot.is_empty(), "ChaCha20 variant must not be empty");
}

#[test]
fn test_crypto_slot_is_not_empty_on_poly1305_variant() {
    let slot = CryptoSlot::Poly1305 { key: [0u8; 32] };
    assert!(!slot.is_empty(), "Poly1305 variant must not be empty");
}

#[test]
fn test_crypto_slot_equality() {
    let slot1 = CryptoSlot::Aes128 { round_keys: [0u8; 176] };
    let slot2 = CryptoSlot::Aes128 { round_keys: [0u8; 176] };
    assert_eq!(slot1, slot2, "two identical Aes128 slots must be equal");

    let slot3 = CryptoSlot::Aes128 { round_keys: [1u8; 176] };
    assert_ne!(slot1, slot3, "different round keys must not be equal");
}

#[test]
fn test_crypto_slot_debug_output() {
    let slot = CryptoSlot::ChaCha20 { key: [7u8; 32] };
    let debug = format!("{:?}", slot);
    assert!(debug.contains("ChaCha20"), "Debug output must contain variant name");
}

/// Encrypt/decrypt round-trip for AES-128
#[test]
fn test_crypto_slot_aes128_encrypt_decrypt() {
    let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let round_keys = unico_runtime::exec::e7::aes128_key_expand_array(&key);
    let slot = CryptoSlot::Aes128 { round_keys };

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let expected_ciphertext = [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                               0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97];

    let ciphertext = slot.encrypt(&plaintext, None).expect("encryption failed");
    assert_eq!(&ciphertext[..16], &expected_ciphertext, "AES-128 encryption mismatch");

    let decrypted = slot.decrypt(&ciphertext, None).expect("decryption failed");
    assert_eq!(&decrypted[..16], &plaintext, "AES-128 decryption mismatch (round-trip)");
}

/// Encrypt/decrypt round-trip for AES-256
#[test]
fn test_crypto_slot_aes256_encrypt_decrypt() {
    let key = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
               0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
               0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
    let round_keys = unico_runtime::exec::e7::aes256_key_expand_array(&key);
    let slot = CryptoSlot::Aes256 { round_keys };

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let expected_ciphertext = [0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                               0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8];

    let ciphertext = slot.encrypt(&plaintext, None).expect("encryption failed");
    assert_eq!(&ciphertext[..16], &expected_ciphertext, "AES-256 encryption mismatch");

    let decrypted = slot.decrypt(&ciphertext, None).expect("decryption failed");
    assert_eq!(&decrypted[..16], &plaintext, "AES-256 decryption mismatch (round-trip)");
}

/// ChaCha20 encrypt/decrypt round-trip (CTR mode)
#[test]
fn test_crypto_slot_chacha20_encrypt_decrypt() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let slot = CryptoSlot::ChaCha20 { key };

    let plaintext = b"Hello, ChaCha20 CTR mode test!";
    let ciphertext = slot.encrypt(plaintext, Some(&nonce)).expect("encryption failed");
    let decrypted = slot.decrypt(&ciphertext, Some(&nonce)).expect("decryption failed");

    assert_eq!(&decrypted[..plaintext.len()], plaintext, "ChaCha20 round-trip failed");
}

/// ChaCha20 with non-zero key/nonce
#[test]
fn test_crypto_slot_chacha20_nonzero() {
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let slot = CryptoSlot::ChaCha20 { key };

    let plaintext = b"Test message for ChaCha20";
    let ciphertext = slot.encrypt(plaintext, Some(&nonce)).expect("encryption failed");
    let decrypted = slot.decrypt(&ciphertext, Some(&nonce)).expect("decryption failed");

    assert_eq!(&decrypted[..plaintext.len()], plaintext);
    assert_ne!(&ciphertext[..plaintext.len()], plaintext, "ciphertext must differ from plaintext");
}

/// Poly1305 MAC generation
#[test]
fn test_crypto_slot_poly1305_mac() {
    let key = [0u8; 32];
    let slot = CryptoSlot::Poly1305 { key };

    let message = b"Poly1305 test message";
    let mac = slot.encrypt(message, None).expect("MAC failed");
    assert_eq!(mac.len(), 16, "Poly1305 MAC must be 16 bytes");
}

/// Poly1305 with known test vector (RFC 7539 §2.5.2)
#[test]
fn test_crypto_slot_poly1305_rfc7539() {
    // RFC 7539 test vector from e7.rs test_poly1305_rfc7539.
    // Key bytes 3,7,11,15 &= 0x0f; bytes 4,8,12 &= 0xfc (already clamped in key).
    // Message: "Cryptaphic Forum Research Groupup"
    // Expected tag: 0e 62 76 74 9c 1b 2f c6 44 50 3c 08 eb 2c 38 1f
    let r = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
             0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8];
    let s = [0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
             0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b];
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&r);
    key[16..].copy_from_slice(&s);

    let slot = CryptoSlot::Poly1305 { key };
    let message = b"Cryptaphic Forum Research Groupup";
    let mac = slot.encrypt(message, None).expect("MAC failed");

    let expected = [0x0e, 0x62, 0x76, 0x74, 0x9c, 0x1b, 0x2f, 0xc6,
                    0x44, 0x50, 0x3c, 0x08, 0xeb, 0x2c, 0x38, 0x1f];
    assert_eq!(&mac[..16], &expected, "Poly1305 RFC 7539 vector mismatch");
}

/// Empty slot returns error on encrypt/decrypt
#[test]
fn test_crypto_slot_empty_errors() {
    let slot = CryptoSlot::Empty;

    assert!(slot.encrypt(b"data", None).is_err(), "encrypt on Empty must error");
    assert!(slot.decrypt(b"data", None).is_err(), "decrypt on Empty must error");
}

/// Poly1305 decrypt returns error
#[test]
fn test_crypto_slot_poly1305_decrypt_error() {
    let slot = CryptoSlot::Poly1305 { key: [0u8; 32] };
    assert!(slot.decrypt(b"data", None).is_err(), "Poly1305 decrypt must error");
}