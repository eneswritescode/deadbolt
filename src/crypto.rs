use anyhow::{Context, Result, bail};
use pqc_kyber::{
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES,
    keypair, encapsulate, decapsulate
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::path::{Path, PathBuf};

// Constants
pub const KYBER_PUBLIC_KEY_BYTES: usize = KYBER_PUBLICKEYBYTES;
pub const KYBER_SECRET_KEY_BYTES: usize = KYBER_SECRETKEYBYTES;
pub const KYBER_CIPHERTEXT_BYTES: usize = KYBER_CIPHERTEXTBYTES;
const AES_NONCE_SIZE: usize = 12;

/// Generate a new Kyber-1024 keypair
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)
        .map_err(|e| anyhow::anyhow!("Keypair generation failed: {:?}", e))?;
    
    Ok((keys.public.to_vec(), keys.secret.to_vec()))
}

/// Save keypair to files
pub fn save_keypair(public_key: &[u8], secret_key: &[u8], 
                    pubkey_path: &Path, privkey_path: &Path) -> Result<()> {
    fs::write(pubkey_path, public_key)
        .context("Failed to write public key")?;
    fs::write(privkey_path, secret_key)
        .context("Failed to write private key")?;
    Ok(())
}

/// Encrypt a file using hybrid encryption (Kyber + AES-GCM)
pub fn encrypt_file(file_path: &Path, pubkey_path: &Path) -> Result<PathBuf> {
    // Load public key
    let pubkey_bytes = fs::read(pubkey_path)
        .context("Failed to read public key")?;
    
    if pubkey_bytes.len() != KYBER_PUBLIC_KEY_BYTES {
        bail!("Invalid public key size. Expected {} bytes, got {}", 
              KYBER_PUBLIC_KEY_BYTES, pubkey_bytes.len());
    }
    
    let mut public_key = [0u8; KYBER_PUBLIC_KEY_BYTES];
    public_key.copy_from_slice(&pubkey_bytes);
    
    // Kyber encapsulation
    let mut rng = rand::thread_rng();
    let (ciphertext, shared_secret) = encapsulate(&public_key, &mut rng)
        .map_err(|e| anyhow::anyhow!("Encapsulation failed: {:?}", e))?;
    
    // Read plaintext
    let plaintext = fs::read(file_path)
        .context("Failed to read input file")?;
    
    // AES-256-GCM encryption
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|_| anyhow::anyhow!("Failed to create AES cipher"))?;
    
    let nonce_bytes: [u8; AES_NONCE_SIZE] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES encryption failed"))?;
    
    // Construct output file
    let mut output_data = Vec::new();
    output_data.extend_from_slice(&ciphertext);
    output_data.extend_from_slice(&nonce_bytes);
    output_data.extend_from_slice(&ciphertext_with_tag);
    
    // Determine output path - append .deadbolt instead of replacing extension
    let output_path = PathBuf::from(format!("{}.deadbolt", file_path.display()));
    fs::write(&output_path, output_data)
        .context("Failed to write encrypted file")?;
    
    Ok(output_path)
}

/// Decrypt a file using hybrid decryption (Kyber + AES-GCM)
pub fn decrypt_file(file_path: &Path, privkey_path: &Path) -> Result<PathBuf> {
    // Load private key
    let privkey_bytes = fs::read(privkey_path)
        .context("Failed to read private key")?;
    
    if privkey_bytes.len() != KYBER_SECRET_KEY_BYTES {
        bail!("Invalid private key size. Expected {} bytes, got {}", 
              KYBER_SECRET_KEY_BYTES, privkey_bytes.len());
    }
    
    let mut secret_key = [0u8; KYBER_SECRET_KEY_BYTES];
    secret_key.copy_from_slice(&privkey_bytes);
    
    // Read encrypted file
    let encrypted_data = fs::read(file_path)
        .context("Failed to read encrypted file")?;
    
    let min_size = KYBER_CIPHERTEXT_BYTES + AES_NONCE_SIZE + 16;
    if encrypted_data.len() < min_size {
        bail!("File too small to be valid");
    }
    
    // Parse file structure
    let kyber_ct_bytes = &encrypted_data[..KYBER_CIPHERTEXT_BYTES];
    let nonce_bytes = &encrypted_data[KYBER_CIPHERTEXT_BYTES..KYBER_CIPHERTEXT_BYTES + AES_NONCE_SIZE];
    let ciphertext_with_tag = &encrypted_data[KYBER_CIPHERTEXT_BYTES + AES_NONCE_SIZE..];
    
    let mut kyber_ciphertext = [0u8; KYBER_CIPHERTEXT_BYTES];
    kyber_ciphertext.copy_from_slice(kyber_ct_bytes);
    
    // Kyber decapsulation
    let shared_secret = decapsulate(&kyber_ciphertext, &secret_key)
        .map_err(|e| anyhow::anyhow!("Decapsulation failed: {:?}", e))?;
    
    // AES-256-GCM decryption
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|_| anyhow::anyhow!("Failed to create AES cipher"))?;
    
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| anyhow::anyhow!("Decryption failed! Wrong key or corrupted data."))?;
    
    // Determine output path - remove .deadbolt extension
    let output_path = if let Some(file_name) = file_path.file_name() {
        if let Some(name_str) = file_name.to_str() {
            if let Some(without_ext) = name_str.strip_suffix(".deadbolt") {
                file_path.with_file_name(without_ext)
            } else {
                file_path.with_file_name(format!("{}.decrypted", name_str))
            }
        } else {
            file_path.with_file_name("decrypted_file")
        }
    } else {
        PathBuf::from("decrypted_file")
    };
    
    fs::write(&output_path, plaintext)
        .context("Failed to write decrypted file")?;
    
    Ok(output_path)
}
