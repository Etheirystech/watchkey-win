use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::WatchkeyError;

/// Derive a 32-byte AES-256 key from a Windows Hello signature using HKDF-SHA256.
pub fn derive_key(signature: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"watchkey-v1"), signature);
    let mut key = [0u8; 32];
    hk.expand(b"aes-256-gcm-key", &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// Encrypt plaintext with AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, WatchkeyError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| WatchkeyError::CryptoError(e.to_string()))?;

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(combined))
}

/// Decrypt base64(nonce || ciphertext) with AES-256-GCM. Returns plaintext bytes.
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, WatchkeyError> {
    let combined = BASE64
        .decode(encoded)
        .map_err(|e| WatchkeyError::CryptoError(e.to_string()))?;

    if combined.len() < 12 {
        return Err(WatchkeyError::CryptoError(
            "ciphertext too short".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WatchkeyError::MasterKeyCorrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = derive_key(b"test-signature-data");
        let plaintext = b"super secret value";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key(b"signature-1");
        let key2 = derive_key(b"signature-2");
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let k1 = derive_key(b"same-input");
        let k2 = derive_key(b"same-input");
        assert_eq!(k1, k2);
    }
}
