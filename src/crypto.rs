// In a new file like src/crypto.rs or src/utils/crypto.rs
use crate::prelude::*;
use argon2::{
    password_hash::{rand_core::OsRng, Salt, SaltString},
    Algorithm, Argon2, Params, PasswordHasher, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    AeadCore, ChaCha20Poly1305, Key,
};

pub struct CryptoUtils;
// Constants for the crypto utils
// Derived key length with Argon2
const DERIVED_KEY_LENGTH : usize = 32;
// Salt size and nonce size
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

impl CryptoUtils {
    /// Derive a key from password and salt with Argon2
    pub fn derive_key(password: &str, salt: &SaltString) -> Result<Vec<u8>, ServiceError> {
        // Common key derivation logic
        let params = Params::new(
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_P_COST * 2,
            Some(Params::DEFAULT_OUTPUT_LEN),
        )
        .map_err(|_| ServiceError::EncryptionError("Error creating params".to_string()))?;
    
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let password_hash = argon2
            .hash_password(password.as_bytes(), salt)
            .map_err(|_| ServiceError::EncryptionError("Error hashing password".to_string()))?;
    
        let key = password_hash
            .hash
            .ok_or_else(|| ServiceError::EncryptionError("Error getting hash".to_string()))?;
        let key_bytes = key.as_bytes();
        if key_bytes.len() != DERIVED_KEY_LENGTH {
            return Err(ServiceError::EncryptionError(
                "Key length is not 32 bytes".to_string(),
            ));
        }
        Ok(key_bytes.to_vec())
    }
    
    /// Encrypt data with the provided key and return a base64 encoded string to store in the database
    pub fn encrypt(data: &[u8], key: &[u8], salt: &[u8]) -> Result<String, ServiceError> {
        // Encryption logic
        // Check key length
        if key.len() != DERIVED_KEY_LENGTH {
            return Err(ServiceError::EncryptionError(
                "Key length is not 32 bytes".to_string(),
            ));
        }
        // Check salt length
        if salt.len() != SALT_SIZE {
            return Err(ServiceError::EncryptionError(
                "Salt length is not 16 bytes".to_string(),
            ));
        }
         // Create cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        // Generate nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

        // Encrypt data
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| ServiceError::EncryptionError(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut encrypted = Vec::with_capacity(NONCE_SIZE + SALT_SIZE + ciphertext.len());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(salt);
        encrypted.extend_from_slice(&ciphertext);

        // --- Encoding to String ---
        // Encode the binary ciphertext into a Base64 String
        let ciphertext_base64 = BASE64_STANDARD.encode(&encrypted);
        Ok(ciphertext_base64)
    }
    
    /// Decrypt data with the provided key
    fn decrypt(ciphertext: &[u8], nonce: &[u8; NONCE_SIZE], key: &[u8; 32]) -> Result<Vec<u8>, ServiceError> {
        // Decryption logic
    }
    
    // Then your public API functions that use these helpers:
    pub fn decrypt_data(data: String, password: Option<&SecretString>) -> Result<String, ServiceError> {
        // Use the helper functions
    }
    
    pub fn store_encrypted(
        idkey: &str,
        password: Option<&SecretString>,
        fixed_salt: Option<SaltString>,
    ) -> Result<String, ServiceError> {
        // Use the helper functions
    }
}