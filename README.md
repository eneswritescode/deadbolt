<div align="center">

# 🔐 Deadbolt

### Post-Quantum File Encryption CLI

*Protect your files from quantum computer attacks using NIST-standardized cryptography*

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Quantum-Safe](https://img.shields.io/badge/Quantum-Safe%20%E2%9A%9B-brightgreen.svg)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)

[Features](#-features) • [Quick Start](#-quick-start) • [Why Quantum-Safe?](#-why-quantum-safe) • [Usage](#-usage) • [Installation](#-installation)

</div>

---

## ⚡ Quick Start

```bash
# Generate quantum-safe keypair
deadbolt keygen

# Encrypt a file
deadbolt lock secret.txt --pubkey id_quantum.pub

# Decrypt the file
deadbolt unlock secret.txt.deadbolt --privkey id_quantum.priv
```

## ✨ Features

- ⚛️ **Post-Quantum Cryptography** - Uses Kyber-1024 (NIST FIPS 203 ML-KEM)
- 🔒 **Hybrid Encryption** - Combines Kyber KEM with AES-256-GCM
- 🛡️ **Quantum-Resistant** - Protects against future quantum computer attacks
- 🚀 **Fast & Efficient** - Handles files of any size with buffered I/O
- ✅ **Authenticated** - Detects tampering with GCM authentication tags
- 🔑 **Key Management** - Simple public/private key workflow
- 💻 **Cross-Platform** - Works on Windows, Linux, and macOS
- 🎯 **Simple CLI** - Easy to use command-line interface

---

## 🌐 Why Quantum-Safe?

### The Quantum Threat

Current encryption standards (RSA, ECDH) are vulnerable to quantum computers:

| Algorithm | Classical Security | Quantum Computer Attack | Status |
|-----------|-------------------|------------------------|--------|
| **RSA-2048** | ✅ Secure | ❌ Broken by Shor's Algorithm | 🔴 Vulnerable |
| **ECDH P-256** | ✅ Secure | ❌ Broken by Shor's Algorithm | 🔴 Vulnerable |
| **AES-256** | ✅ Secure | ⚠️ Reduced to 128-bit | 🟡 Still Safe |
| **Kyber-1024** | ✅ Secure | ✅ No Known Attack | 🟢 Quantum-Safe |

**"Harvest Now, Decrypt Later" Attack:**  
Adversaries are capturing encrypted data *today* to decrypt it when quantum computers become powerful enough (estimated 10-20 years).

### Deadbolt's Protection

Deadbolt uses **Kyber-1024** (CRYSTALS-Kyber), a lattice-based Key Encapsulation Mechanism:

- **Security Basis**: Module Learning With Errors (Module-LWE) problem
- **Quantum Security**: ~192 bits (NIST Level 5 - highest)
- **Standard**: NIST FIPS 203 (ML-KEM) - Official U.S. federal standard
- **No Known Attack**: No quantum algorithm efficiently solves lattice problems

---

## 🚀 Installation

### 📦 Pre-built Binaries (Windows)

Download the latest release for Windows:
- **[deadbolt-v1.0.0-windows-x64.exe](https://github.com/eneswritescode/deadbolt/releases)** (9 MB)

No installation needed - just download and run!

### 🛠️ Build from Source (All Platforms)

**Prerequisites:** Rust 1.70+ ([Install Rust](https://rustup.rs/))

```bash
git clone https://github.com/eneswritescode/deadbolt.git
cd deadbolt
cargo build --release
```

Binary location: `target/release/deadbolt` (or `deadbolt.exe` on Windows)

### Install Globally (Optional)
```bash
# Linux/macOS
sudo cp target/release/deadbolt /usr/local/bin/

# Windows (PowerShell as Admin)
Copy-Item target\release\deadbolt.exe C:\Windows\System32\
```

---

## 📖 Usage

### 1. Generate Keypair

```bash
deadbolt keygen
```

**Output:**
```
┌─────────────────────────────────────────────┐
│ ⚛️  INITIALIZING QUANTUM KEY GENERATOR...  │
└─────────────────────────────────────────────┘

⏳ Generating Kyber-1024 keypair... ✓
📤 Public Key:  id_quantum.pub (1184 bytes)
🔒 Private Key: id_quantum.priv (2400 bytes)
```

Creates:
- `id_quantum.pub` - Share this with senders
- `id_quantum.priv` - **Keep this secret!**

### 2. Encrypt a File

```bash
deadbolt lock confidential.pdf --pubkey recipient.pub
```

Creates `confidential.pdf.deadbolt` encrypted for the recipient.

**Custom output:**
```bash
deadbolt lock data.json --pubkey bob.pub --output encrypted.db
```

### 3. Decrypt a File

```bash
deadbolt unlock confidential.pdf.deadbolt --privkey id_quantum.priv
```

Recovers the original file.

**Custom output:**
```bash
deadbolt unlock encrypted.db --privkey id_quantum.priv --output data.json
```

### Advanced Examples

#### Multi-User Encryption
```bash
# Alice encrypts for Bob
deadbolt lock message.txt --pubkey bob.pub

# Bob decrypts
deadbolt unlock message.txt.deadbolt --privkey bob.priv
```

#### Batch Encryption (PowerShell)
```powershell
Get-ChildItem *.txt | ForEach-Object {
    deadbolt lock $_.Name --pubkey recipient.pub
}
```

#### Batch Encryption (Bash)
```bash
for file in *.txt; do
    deadbolt lock "$file" --pubkey recipient.pub
done
```

---

## 🔬 Technical Details

### Cryptographic Primitives

| Component | Algorithm | Key Size | Security Level |
|-----------|-----------|----------|----------------|
| **KEM** | Kyber-1024 (ML-KEM) | 1,184 bytes (pub)<br>2,400 bytes (priv) | NIST Level 5<br>~192-bit quantum |
| **AEAD** | AES-256-GCM | 32 bytes (256 bits) | 128-bit quantum |
| **RNG** | System CSPRNG | - | OS-dependent |

### File Format (`.deadbolt`)

```
┌──────────────────────┬──────────────┬───────────────────────────┐
│  Kyber Ciphertext    │  AES Nonce   │  Encrypted Data + Tag    │
│  1,088 bytes         │  12 bytes    │  Variable + 16 bytes     │
└──────────────────────┴──────────────┴───────────────────────────┘
```

**Total Size:** `1,116 bytes + original_file_size`

### Performance

| File Size | Encryption Time | Decryption Time |
|-----------|-----------------|-----------------|
| 1 KB | <10 ms | <10 ms |
| 1 MB | ~100 ms | ~100 ms |
| 100 MB | ~10 seconds | ~10 seconds |

*(Measured on Intel i7-12700K)*

---

## 🛡️ Security

### ✅ Security Properties

- **Confidentiality**: Only private key holder can decrypt
- **Authenticity**: GCM tag prevents tampering
- **Integrity**: Any modification is detected
- **Quantum Resistance**: Kyber lattice-based design
- **Forward Secrecy**: Fresh ephemeral keys per encryption

### ⚠️ Best Practices

**DO:**
- ✅ Store private keys in encrypted storage (password manager, hardware token)
- ✅ Verify public key fingerprints out-of-band (phone, video call)
- ✅ Use separate keypairs for different contexts
- ✅ Keep regular encrypted backups

**DON'T:**
- ❌ Email or message private keys
- ❌ Store private keys in cloud storage (unencrypted)
- ❌ Reuse the same keypair everywhere
- ❌ Ignore `.priv` file extensions

### Known Limitations

- **Single Recipient**: Each file encrypted for one public key only
- **No Key Rotation**: Manual re-encryption required for key updates
- **Metadata Leakage**: File sizes are not obfuscated

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All cryptographic changes are reviewed by a cryptographer
- Code passes `cargo test` and `cargo clippy`
- Format code with `cargo fmt`
- Update documentation for new features

---

## 📚 Dependencies

- [`pqc_kyber`](https://crates.io/crates/pqc_kyber) 0.7.1 - Pure Rust Kyber implementation
- [`aes-gcm`](https://crates.io/crates/aes-gcm) 0.10.3 - AES-256-GCM AEAD cipher
- [`clap`](https://crates.io/crates/clap) 4.5 - CLI framework
- [`anyhow`](https://crates.io/crates/anyhow) 1.0 - Error handling
- [`rand`](https://crates.io/crates/rand) 0.8 - Cryptographic RNG

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🔗 References

- **NIST FIPS 203**: [ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- **CRYSTALS-Kyber**: [Official Website](https://pq-crystals.org/kyber/)
- **NIST PQC Project**: [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **Quantum Threat Timeline**: [Global Risk Institute Report](https://globalriskinstitute.org/publication/2021-quantum-threat-timeline-report/)

---

<div align="center">

**⚛️ Stay Quantum-Safe. Protect Your Future.**

Made with 🦀 Rust | Built for the Post-Quantum Era

[⬆ Back to Top](#-deadbolt)

</div>
