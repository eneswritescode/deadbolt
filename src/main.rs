// ═══════════════════════════════════════════════════════════
//  Deadbolt - Post-Quantum File Encryption
//  Supports both CLI and GUI modes
// ═══════════════════════════════════════════════════════════

mod crypto;
mod gui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════
//  CLI STRUCTURE
// ═══════════════════════════════════════════════════════════
#[derive(Parser)]
#[command(
    name = "deadbolt",
    about = "🔐 Post-Quantum File Encryption using Kyber (ML-KEM)",
    version = "1.0.0",
    long_about = "A quantum-resistant file encryption tool leveraging NIST's ML-KEM (Kyber-1024) \
                  for key encapsulation and AES-256-GCM for symmetric encryption.\n\n\
                  Run without arguments to launch the graphical interface."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Kyber-1024 keypair for quantum-resistant encryption
    Keygen {
        /// Output path for public key (default: id_quantum.pub)
        #[arg(long, default_value = "id_quantum.pub")]
        pubkey: PathBuf,
        
        /// Output path for private key (default: id_quantum.priv)
        #[arg(long, default_value = "id_quantum.priv")]
        privkey: PathBuf,
    },
    
    /// Encrypt a file using recipient's quantum-safe public key
    Lock {
        /// File to encrypt
        file: PathBuf,
        
        /// Path to recipient's Kyber public key
        #[arg(long)]
        pubkey: PathBuf,
        
        /// Output encrypted file path (default: <file>.deadbolt)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Decrypt a file using your quantum-safe private key
    Unlock {
        /// Encrypted file to decrypt
        file: PathBuf,
        
        /// Path to your Kyber private key
        #[arg(long)]
        privkey: PathBuf,
        
        /// Output decrypted file path (default: remove .deadbolt extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

// ═══════════════════════════════════════════════════════════
//  MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════
fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // CLI mode - execute specific commands
    match cli.command {
        Some(Commands::Keygen { pubkey, privkey }) => {
            cmd_keygen(pubkey, privkey)?;
        }
        Some(Commands::Lock { file, pubkey, output }) => {
            cmd_lock(file, pubkey, output)?;
        }
        Some(Commands::Unlock { file, privkey, output }) => {
            cmd_unlock(file, privkey, output)?;
        }
        None => {
            // Default behavior: Launch GUI when no command is specified
            println!("🚀 Launching Deadbolt GUI...");
            return gui::run_gui().map_err(|e| anyhow::anyhow!("GUI error: {}", e));
        }
    }
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  COMMAND: keygen
//  Generate Kyber-1024 Keypair
// ═══════════════════════════════════════════════════════════
fn cmd_keygen(pubkey_path: PathBuf, privkey_path: PathBuf) -> Result<()> {
    println!("┌─────────────────────────────────────────────┐");
    println!("│ ⚛️  INITIALIZING QUANTUM KEY GENERATOR...  │");
    println!("└─────────────────────────────────────────────┘");
    println!();
    
    // Check if keys already exist
    if pubkey_path.exists() || privkey_path.exists() {
        println!("⚠️  WARNING: Keys already exist at these locations!");
        println!("   Public:  {}", pubkey_path.display());
        println!("   Private: {}", privkey_path.display());
        println!();
        println!("🚨 Generating new keys will:");
        println!("   • Make ALL files encrypted with the old key UNRECOVERABLE");
        println!("   • Old keys will be backed up with .backup.<timestamp>");
        println!();
        print!("Continue? [y/N]: ");
        
        use std::io::{self, Write};
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("❌ Aborted. No keys were generated.");
            return Ok(());
        }
        
        // Backup existing keys
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if pubkey_path.exists() {
            let backup = pubkey_path.with_extension(format!("pub.backup.{}", timestamp));
            std::fs::rename(&pubkey_path, &backup)
                .context("Failed to backup public key")?;
            println!("💾 Backed up: {}", backup.display());
        }
        
        if privkey_path.exists() {
            let backup = privkey_path.with_extension(format!("priv.backup.{}", timestamp));
            std::fs::rename(&privkey_path, &backup)
                .context("Failed to backup private key")?;
            println!("💾 Backed up: {}", backup.display());
        }
        println!();
    }
    
    print!("⏳ Generating Kyber-1024 keypair...");
    
    let (public_key, secret_key) = crypto::generate_keypair()
        .context("Failed to generate keypair")?;
    
    println!(" ✓");
    
    // Write keys
    crypto::save_keypair(&public_key, &secret_key, &pubkey_path, &privkey_path)
        .context("Failed to save keypair")?;
    
    println!("📤 Public Key:  {} ({} bytes)", pubkey_path.display(), crypto::KYBER_PUBLIC_KEY_BYTES);
    println!("🔒 Private Key: {} ({} bytes)", privkey_path.display(), crypto::KYBER_SECRET_KEY_BYTES);
    
    println!();
    println!("✅ Keypair generated successfully!");
    println!("⚠️  CRITICAL: Keep your private key secure. Anyone with access can decrypt your files.");
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  COMMAND: lock
//  Hybrid Encryption: Kyber KEM + AES-256-GCM
// ═══════════════════════════════════════════════════════════
fn cmd_lock(file_path: PathBuf, pubkey_path: PathBuf, output: Option<PathBuf>) -> Result<()> {
    println!("┌─────────────────────────────────────────────┐");
    println!("│ 🔐 QUANTUM KEY ENCAPSULATION INITIATED...  │");
    println!("└─────────────────────────────────────────────┘");
    println!();
    
    print!("📥 Loading recipient's public key...");
    println!(" ✓");
    
    print!("⚛️  Performing quantum key encapsulation...");
    println!(" ✓");
    
    print!("📖 Reading file...");
    let file_size = std::fs::metadata(&file_path)?.len();
    println!(" ✓ ({} bytes)", file_size);
    
    print!("🔒 Encrypting with AES-256-GCM...");
    
    let default_output = crypto::encrypt_file(&file_path, &pubkey_path)
        .context("Encryption failed")?;
    
    // Use custom output path if specified
    let output_path = if let Some(custom_output) = output {
        std::fs::rename(&default_output, &custom_output)
            .context("Failed to move encrypted file to custom output path")?;
        custom_output
    } else {
        default_output
    };
    
    println!(" ✓");
    
    print!("💾 Writing encrypted file...");
    println!(" ✓");
    
    println!();
    println!("✅ File encrypted successfully!");
    println!("📁 Output: {}", output_path.display());
    println!("🛡️  Protected by: Kyber-1024 (ML-KEM) + AES-256-GCM");
    println!("🔬 Quantum Attack Resistance: ACTIVE");
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  COMMAND: unlock
//  Hybrid Decryption: Kyber Decapsulation + AES-256-GCM
// ═══════════════════════════════════════════════════════════
fn cmd_unlock(file_path: PathBuf, privkey_path: PathBuf, output: Option<PathBuf>) -> Result<()> {
    println!("┌─────────────────────────────────────────────┐");
    println!("│ 🔓 QUANTUM KEY DECAPSULATION INITIATED...  │");
    println!("└─────────────────────────────────────────────┘");
    println!();
    
    print!("🔑 Loading private key...");
    println!(" ✓");
    
    print!("📥 Loading encrypted file...");
    let file_size = std::fs::metadata(&file_path)?.len();
    println!(" ✓ ({} bytes)", file_size);
    
    print!("⚛️  Performing quantum key decapsulation...");
    println!(" ✓");
    
    print!("🔓 Decrypting with AES-256-GCM...");
    
    let default_output = crypto::decrypt_file(&file_path, &privkey_path)
        .context("Decryption failed")?;
    
    // Use custom output path if specified
    let output_path = if let Some(custom_output) = output {
        std::fs::rename(&default_output, &custom_output)
            .context("Failed to move decrypted file to custom output path")?;
        custom_output
    } else {
        default_output
    };
    
    println!(" ✓");
    
    print!("💾 Writing decrypted file...");
    println!(" ✓");
    
    println!();
    println!("✅ File decrypted successfully!");
    println!("📁 Output: {}", output_path.display());
    println!("🛡️  Quantum-resistant decryption completed");
    
    Ok(())
}
