use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, Key, KeyInit};

/// Encrypted blobs are prefixed with "v20", followed by a 12-byte IV, the
/// ciphertext and a 16-byte GCM tag.
const V20_PREFIX: &[u8] = b"v20";
const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

pub fn decrypt_v20(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    let overhead = V20_PREFIX.len() + GCM_IV_LENGTH + GCM_TAG_LENGTH;
    if blob.len() < overhead || &blob[..V20_PREFIX.len()] != V20_PREFIX {
        return Err("blob is missing the v20 prefix".to_string());
    }

    let nonce = Nonce::<Aes256Gcm>::from_slice(
        &blob[V20_PREFIX.len()..V20_PREFIX.len() + GCM_IV_LENGTH],
    );
    let ciphertext_and_tag = &blob[V20_PREFIX.len() + GCM_IV_LENGTH..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| "AES-256-GCM decryption failed (wrong key or corrupt blob)".to_string())
}
