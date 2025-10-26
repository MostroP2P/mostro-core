// In a new file like src/crypto.rs or src/utils/crypto.rs
use crate::prelude::*;
use argon2::{
    password_hash::{rand_core::OsRng, Salt, SaltString},
    Algorithm, Argon2, Params, PasswordHasher, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    AeadCore, ChaCha20Poly1305,
};
use secrecy::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, RwLock};
use zeroize::Zeroize;

// 🔐 Cache: global static or pass it explicitly
static KEY_CACHE: LazyLock<RwLock<SecretBox<SimpleCache>>> =
    LazyLock::new(|| RwLock::new(SecretBox::new(Box::new(SimpleCache::new()))));

// Constants for the crypto utils
// Derived key length with Argon2
const DERIVED_KEY_LENGTH: usize = 32;
// Salt size and nonce size
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
// ----- SIMPLE FIXED-SIZE CACHE -----
const MAX_CACHE_SIZE: usize = 50;

// blake3 hash for cache key
type CacheKey = blake3::Hash; // 256-bit

struct SimpleCache {
    map: HashMap<CacheKey, [u8; 32]>,
    order: VecDeque<CacheKey>,
}

impl SimpleCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: CacheKey) -> Option<[u8; 32]> {
        if let Some(value) = self.map.get(&key) {
            self.order.retain(|&k| k != key);
            self.order.push_back(key);
            Some(*value)
        } else {
            None
        }
    }

    fn put(&mut self, key: CacheKey, value: [u8; 32]) {
        if !self.map.contains_key(&key) && self.map.len() >= MAX_CACHE_SIZE {
            if let Some(oldest_key) = self.order.pop_front() {
                self.map.remove(&oldest_key);
            }
        }
        self.order.retain(|&k| k != key);
        self.order.push_back(key);
        self.map.insert(key, value);
    }
}

// Implementation of zeroize required by secretbox
impl Zeroize for SimpleCache {
    fn zeroize(&mut self) {
        for value in self.map.values_mut() {
            value.zeroize();
        }
        self.map.clear();
        self.order.clear();
    }
}

// On drop, zeroize the cache
impl Drop for SimpleCache {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// make blake3 hash for cache key from password and salt
fn make_cache_key(password: &str, salt: &[u8]) -> CacheKey {
    blake3::hash([password.as_bytes(), salt].concat().as_slice())
}

pub struct CryptoUtils;

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
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| ServiceError::EncryptionError("Invalid key length".to_string()))?;
        let cipher = ChaCha20Poly1305::new(&key_array.into());
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
    /// In case of cached values return the cached value to speed up search
    fn decrypt(data: Vec<u8>, password: &str) -> Result<Vec<u8>, ServiceError> {
        // Split the encrypted data into nonce and data
        let (nonce, data) = data.split_at(NONCE_SIZE);

        let nonce: [u8; NONCE_SIZE] = nonce
            .try_into()
            .map_err(|e| ServiceError::DecryptionError(format!("Error converting nonce: {}", e)))?;

        let (salt, ciphertext) = data.split_at(SALT_SIZE);

        // Enecode salt from base64 to bytes
        let salt = SaltString::encode_b64(salt)
            .map_err(|e| ServiceError::DecryptionError(format!("Error decoding salt: {}", e)))?;

        // get hash value from salt and password
        let cache_key = make_cache_key(password, salt.as_str().as_bytes());

        let mut cache = KEY_CACHE
            .write()
            .map_err(|_| ServiceError::DecryptionError("Error in key cache".to_string()))?;
        // Check if the key is already in the cache
        // If the key is in the cache, use it
        let key_bytes = if let Some(cached_key) = cache.expose_secret_mut().get(cache_key) {
            cached_key
        } else {
            // Key not cached, derive it
            let key_bytes = CryptoUtils::derive_key(password, &salt)
                .map_err(|_| ServiceError::DecryptionError("Error deriving key".to_string()))?;
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);
            cache.expose_secret_mut().put(cache_key, key_array);
            key_array
        };

        // Create cipher
        let cipher = ChaCha20Poly1305::new(&key_bytes.into());

        // Decrypt the data
        let decrypted = cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|e| ServiceError::DecryptionError(e.to_string()))?;

        Ok(decrypted)
    }

    /// Decrypt an identity key from the database
    pub fn decrypt_data(
        data: String,
        password: Option<&SecretString>,
    ) -> Result<String, ServiceError> {
        // If password is not provided, return data as it is
        let password = match password {
            Some(password) => password,
            None => return Ok(data),
        };
        // Decode the encrypted data from base64 to bytes
        let encrypted_bytes = BASE64_STANDARD.decode(&data).map_err(|_| {
            ServiceError::DecryptionError("Error decoding encrypted data".to_string())
        })?;

        // Validate input length before processing
        if encrypted_bytes.len() < NONCE_SIZE + SALT_SIZE {
            return Err(ServiceError::DecryptionError(
                "Invalid encrypted data: too short for nonce and salt".to_string(),
            ));
        }

        // Extract key bytes, salt and ciphered text
        let decrypted_data = CryptoUtils::decrypt(encrypted_bytes, password.expose_secret())?;

        // Convert the decrypted data to a string and return it
        String::from_utf8(decrypted_data).map_err(|_| {
            ServiceError::DecryptionError("Error converting encrypted data to string".to_string())
        })
    }

    /// Encrypt a string to save it in the database
    ///
    /// # Parameters
    /// * `idkey` - The string data to be encrypted
    /// * `password` - Optional password used for encryption. If None, returns the data unencrypted
    /// * `fixed_salt` - Optional fixed salt for encryption. If None, generates a random salt.
    ///   This parameter is primarily used for unit testing to ensure consistent encryption results.
    ///
    /// # Returns
    /// Returns a Result containing either:
    /// * Ok(String) - The encrypted data encoded in base64
    /// * Err(ServiceError) - If encryption fails
    pub fn store_encrypted(
        idkey: &str,
        password: Option<&SecretString>,
        fixed_salt: Option<SaltString>,
    ) -> Result<String, ServiceError> {
        // If password is not provided, return data as it is
        let password = match password {
            Some(password) => password,
            None => return Ok(idkey.to_string()),
        };

        // Salt generation
        let salt = match fixed_salt {
            Some(salt) => salt,
            None => SaltString::generate(&mut OsRng),
        };

        // Buffer to decode salt
        let buf = &mut [0u8; Salt::RECOMMENDED_LENGTH];
        // Decode salt from base64 to bytes
        let salt_decoded = salt
            .decode_b64(buf)
            .map_err(|e| ServiceError::EncryptionError(format!("Error decoding salt: {}", e)))?;

        // Derive key as bytes
        let key_bytes = CryptoUtils::derive_key(password.expose_secret(), &salt)
            .map_err(|e| ServiceError::EncryptionError(format!("Error deriving key: {}", e)))?;

        // Encrypt data and return base64 encoded string
        let ciphertext_base64 = CryptoUtils::encrypt(idkey.as_bytes(), &key_bytes, salt_decoded)
            .map_err(|e| ServiceError::EncryptionError(format!("Error encrypting data: {}", e)))?;

        Ok(ciphertext_base64)
    }
}
