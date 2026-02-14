use iced::{
    widget::{button, column, container, row, text, Space},
    Alignment, Color, Element, Length, Sandbox, Settings, Size, Theme,
    theme::Palette,
};
use rfd::FileDialog;
use std::path::PathBuf;

// Main GUI state
#[derive(Debug, Clone)]
pub struct DeadboltGUI {
    status_message: String,
    status_color: Color,
    selected_file: Option<PathBuf>,
    public_key_path: Option<PathBuf>,
    private_key_path: Option<PathBuf>,
    current_mode: Mode,
}

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    Home,
    Keygen,
    Encrypt,
    Decrypt,
}

// Messages that can be sent in the GUI
#[derive(Debug, Clone)]
pub enum Message {
    // Mode switching
    ShowHome,
    ShowKeygen,
    ShowEncrypt,
    ShowDecrypt,
    
    // Keypair generation
    GenerateKeypair,
    
    // File encryption
    SelectFileToEncrypt,
    SelectPublicKey,
    EncryptFile,
    
    // File decryption
    SelectFileToDecrypt,
    SelectPrivateKey,
    DecryptFile,
}

impl Sandbox for DeadboltGUI {
    type Message = Message;

    fn new() -> Self {
        Self {
            status_message: "Welcome to Deadbolt - Post-Quantum File Encryption".to_string(),
            status_color: Color::from_rgb(0.7, 0.7, 0.7),
            selected_file: None,
            public_key_path: None,
            private_key_path: None,
            current_mode: Mode::Home,
        }
    }

    fn title(&self) -> String {
        "🔐 Deadbolt - Quantum-Safe Encryption".to_string()
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::ShowHome => {
                self.current_mode = Mode::Home;
                self.status_message = "Welcome! Choose an operation below.".to_string();
                self.status_color = Color::from_rgb(0.7, 0.7, 0.7);
                self.selected_file = None;
                self.public_key_path = None;
                self.private_key_path = None;
            }
            Message::ShowKeygen => {
                self.current_mode = Mode::Keygen;
                self.status_message = "Generate a new Kyber-1024 quantum-safe keypair".to_string();
                self.status_color = Color::from_rgb(0.5, 0.7, 1.0);
            }
            Message::ShowEncrypt => {
                self.current_mode = Mode::Encrypt;
                self.status_message = "Select file and recipient's public key to encrypt".to_string();
                self.status_color = Color::from_rgb(0.3, 0.8, 0.5);
                self.selected_file = None;
                self.public_key_path = None;
            }
            Message::ShowDecrypt => {
                self.current_mode = Mode::Decrypt;
                self.status_message = "Select encrypted file and your private key to decrypt".to_string();
                self.status_color = Color::from_rgb(1.0, 0.7, 0.3);
                self.selected_file = None;
                self.private_key_path = None;
            }
            
            Message::GenerateKeypair => {
                // Check if keys already exist
                let pub_path = std::path::Path::new("id_quantum.pub");
                let priv_path = std::path::Path::new("id_quantum.priv");
                
                // Backup existing keys with timestamp
                if pub_path.exists() || priv_path.exists() {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    
                    if pub_path.exists() {
                        let _ = std::fs::rename(pub_path, format!("id_quantum.pub.backup.{}", timestamp));
                    }
                    if priv_path.exists() {
                        let _ = std::fs::rename(priv_path, format!("id_quantum.priv.backup.{}", timestamp));
                    }
                    
                    self.status_message = "[!] Old keys backed up. Generating new keypair...".to_string();
                    self.status_color = Color::from_rgb(1.0, 0.7, 0.3);
                } else {
                    self.status_message = "[...] Generating Kyber-1024 keypair...".to_string();
                    self.status_color = Color::from_rgb(1.0, 0.8, 0.3);
                }
                
                match crate::crypto::generate_keypair() {
                    Ok((public_key, secret_key)) => {
                        // Anahtarları dosyaya kaydet
                        match crate::crypto::save_keypair(
                            &public_key, 
                            &secret_key, 
                            pub_path,
                            priv_path
                        ) {
                            Ok(_) => {
                                self.status_message = "[OK] Keys saved: id_quantum.pub & id_quantum.priv | ⚠️ Old keys backed up if existed".to_string();
                                self.status_color = Color::from_rgb(0.3, 1.0, 0.3);
                            }
                            Err(e) => {
                                self.status_message = format!("[X] Failed to save keys: {}", e);
                                self.status_color = Color::from_rgb(1.0, 0.3, 0.3);
                            }
                        }
                    }
                    Err(e) => {
                        self.status_message = format!("[X] Generation failed: {}", e);
                        self.status_color = Color::from_rgb(1.0, 0.3, 0.3);
                    }
                }
            }
            
            Message::SelectFileToEncrypt => {
                if let Some(path) = FileDialog::new()
                    .set_title("Select File to Encrypt")
                    .pick_file()
                {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    self.selected_file = Some(path);
                    self.status_message = format!("[>] File selected: {}", filename);
                    self.status_color = Color::from_rgb(0.5, 0.7, 1.0);
                }
            }
            
            Message::SelectPublicKey => {
                if let Some(path) = FileDialog::new()
                    .set_title("Select Recipient's Public Key")
                    .add_filter("Public Key", &["pub"])
                    .pick_file()
                {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    self.public_key_path = Some(path);
                    self.status_message = format!("[+] Public key selected: {}", filename);
                    self.status_color = Color::from_rgb(0.5, 0.7, 1.0);
                }
            }
            
            Message::EncryptFile => {
                if let (Some(file), Some(pubkey)) = (&self.selected_file, &self.public_key_path) {
                    self.status_message = "[...] Encrypting with Kyber-1024 + AES-256-GCM...".to_string();
                    self.status_color = Color::from_rgb(1.0, 0.8, 0.3);
                    
                    match crate::crypto::encrypt_file(file, pubkey) {
                        Ok(output) => {
                            let full_path = output.canonicalize()
                                .unwrap_or(output.clone());
                            self.status_message = format!("[OK] Encrypted! Saved to: {}", full_path.display());
                            self.status_color = Color::from_rgb(0.3, 1.0, 0.3);
                            self.selected_file = None;
                            self.public_key_path = None;
                        }
                        Err(e) => {
                            self.status_message = format!("[X] Encryption failed: {}", e);
                            self.status_color = Color::from_rgb(1.0, 0.3, 0.3);
                        }
                    }
                }
            }
            
            Message::SelectFileToDecrypt => {
                if let Some(path) = FileDialog::new()
                    .set_title("Select Encrypted File")
                    .add_filter("Deadbolt Encrypted", &["deadbolt"])
                    .pick_file()
                {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    self.selected_file = Some(path);
                    self.status_message = format!("[#] Encrypted file selected: {}", filename);
                    self.status_color = Color::from_rgb(1.0, 0.7, 0.3);
                }
            }
            
            Message::SelectPrivateKey => {
                if let Some(path) = FileDialog::new()
                    .set_title("Select Your Private Key")
                    .add_filter("Private Key", &["priv"])
                    .pick_file()
                {
                    let filename = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    self.private_key_path = Some(path);
                    self.status_message = format!("[+] Private key selected: {}", filename);
                    self.status_color = Color::from_rgb(1.0, 0.7, 0.3);
                }
            }
            
            Message::DecryptFile => {
                if let (Some(file), Some(privkey)) = (&self.selected_file, &self.private_key_path) {
                    self.status_message = "[...] Decrypting with quantum-safe key...".to_string();
                    self.status_color = Color::from_rgb(1.0, 0.8, 0.3);
                    
                    match crate::crypto::decrypt_file(file, privkey) {
                        Ok(output) => {
                            let full_path = output.canonicalize()
                                .unwrap_or(output.clone());
                            self.status_message = format!("[OK] Decrypted! Saved to: {}", full_path.display());
                            self.status_color = Color::from_rgb(0.3, 1.0, 0.3);
                            self.selected_file = None;
                            self.private_key_path = None;
                        }
                        Err(e) => {
                            self.status_message = format!("[X] Decryption failed: {}", e);
                            self.status_color = Color::from_rgb(1.0, 0.3, 0.3);
                        }
                    }
                }
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        // Header with logo
        let header = column![
            text("[#] DEADBOLT")
                .size(32)
                .style(Color::from_rgb(0.4, 0.8, 1.0)),
            text("Post-Quantum File Encryption")
                .size(13)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
        ]
        .spacing(5)
        .align_items(Alignment::Center);

        // Status bar
        let status_bar = container(
            text(&self.status_message)
                .size(12)
                .style(self.status_color)
        )
        .padding(10)
        .width(Length::Fill)
        .center_x();

        // Navigation buttons
        let nav_buttons = row![
            button("[-] Home")
                .padding([8, 15])
                .on_press(Message::ShowHome),
            button("[+] Keygen")
                .padding([8, 15])
                .on_press(Message::ShowKeygen),
            button("[#] Encrypt")
                .padding([8, 15])
                .on_press(Message::ShowEncrypt),
            button("[*] Decrypt")
                .padding([8, 15])
                .on_press(Message::ShowDecrypt),
        ]
        .spacing(8)
        .align_items(Alignment::Center);

        // Main content area based on mode
        let main_content = match self.current_mode {
            Mode::Home => self.view_home(),
            Mode::Keygen => self.view_keygen(),
            Mode::Encrypt => self.view_encrypt(),
            Mode::Decrypt => self.view_decrypt(),
        };

        // Complete layout
        let content = column![
            header,
            Space::with_height(Length::Fixed(15.0)),
            nav_buttons,
            Space::with_height(Length::Fixed(10.0)),
            status_bar,
            Space::with_height(Length::Fixed(15.0)),
            main_content,
        ]
        .spacing(0)
        .padding(20)
        .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .into()
    }

    fn theme(&self) -> Theme {
        Theme::custom(
            "Deadbolt".to_string(),
            Palette {
                background: Color::from_rgb(0.15, 0.16, 0.20),    // Yumuşak koyu gri-mavi
                text: Color::from_rgb(0.9, 0.9, 0.9),
                primary: Color::from_rgb(0.4, 0.6, 0.9),
                success: Color::from_rgb(0.3, 0.8, 0.5),
                danger: Color::from_rgb(0.9, 0.3, 0.3),
            }
        )
    }
}

impl DeadboltGUI {
    fn view_home(&self) -> Element<'_, Message> {
        column![
            text("[Q] Quantum-Safe Cryptography")
                .size(20)
                .style(Color::from_rgb(0.8, 0.8, 0.8)),
            Space::with_height(Length::Fixed(10.0)),
            text("Powered by NIST-standardized Kyber-1024")
                .size(13)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(20.0)),
            
            container(column![
                text("[+] Generate Keypair")
                    .size(15)
                    .style(Color::from_rgb(0.5, 0.7, 1.0)),
                text("Create quantum-resistant key pair")
                    .size(11)
                    .style(Color::from_rgb(0.5, 0.5, 0.5)),
            ].spacing(5))
            .padding(15)
            .width(Length::Fixed(350.0)),
            
            Space::with_height(Length::Fixed(10.0)),
            
            container(column![
                text("[#] Encrypt Files")
                    .size(15)
                    .style(Color::from_rgb(0.3, 0.8, 0.5)),
                text("Protect files with hybrid encryption")
                    .size(11)
                    .style(Color::from_rgb(0.5, 0.5, 0.5)),
            ].spacing(5))
            .padding(15)
            .width(Length::Fixed(350.0)),
            
            Space::with_height(Length::Fixed(10.0)),
            
            container(column![
                text("[*] Decrypt Files")
                    .size(15)
                    .style(Color::from_rgb(1.0, 0.7, 0.3)),
                text("Recover encrypted files safely")
                    .size(11)
                    .style(Color::from_rgb(0.5, 0.5, 0.5)),
            ].spacing(5))
            .padding(15)
            .width(Length::Fixed(350.0)),
        ]
        .spacing(0)
        .align_items(Alignment::Center)
        .into()
    }

    fn view_keygen(&self) -> Element<'_, Message> {
        column![
            text("[+] Generate Quantum-Safe Keypair")
                .size(20)
                .style(Color::from_rgb(0.5, 0.7, 1.0)),
            Space::with_height(Length::Fixed(15.0)),
            text("This will create two files:")
                .size(13)
                .style(Color::from_rgb(0.7, 0.7, 0.7)),
            text("[^] id_quantum.pub - Share with others")
                .size(12)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            text("[!] id_quantum.priv - Keep secret!")
                .size(12)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(20.0)),
            button("[Q] Generate Kyber-1024 Keypair")
                .padding([15, 30])
                .on_press(Message::GenerateKeypair),
            Space::with_height(Length::Fixed(15.0)),
            text("Uses NIST FIPS 203 (ML-KEM) standard")
                .size(11)
                .style(Color::from_rgb(0.5, 0.5, 0.5)),
        ]
        .spacing(5)
        .align_items(Alignment::Center)
        .into()
    }

    fn view_encrypt(&self) -> Element<'_, Message> {
        let file_status = if let Some(path) = &self.selected_file {
            format!("[x] {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("File selected"))
        } else {
            "[ ] No file selected".to_string()
        };

        let key_status = if let Some(path) = &self.public_key_path {
            format!("[x] {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("Key selected"))
        } else {
            "[ ] No key selected".to_string()
        };

        let can_encrypt = self.selected_file.is_some() && self.public_key_path.is_some();

        let content = column![
            text("[#] Encrypt File")
                .size(20)
                .style(Color::from_rgb(0.3, 0.8, 0.5)),
            Space::with_height(Length::Fixed(20.0)),
            
            // File selection
            button("[>] Select File to Encrypt")
                .padding([12, 25])
                .on_press(Message::SelectFileToEncrypt),
            text(file_status)
                .size(11)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(15.0)),
            
            // Public key selection
            button("[+] Select Recipient's Public Key")
                .padding([12, 25])
                .on_press(Message::SelectPublicKey),
            text(key_status)
                .size(11)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(20.0)),
        ]
        .spacing(5)
        .align_items(Alignment::Center);

        // Encrypt button or warning message
        let encrypt_action: Element<Message> = if can_encrypt {
            button("[>>] ENCRYPT NOW")
                .padding([15, 35])
                .on_press(Message::EncryptFile)
                .into()
        } else {
            text("Select both file and key to encrypt")
                .size(12)
                .style(Color::from_rgb(0.7, 0.5, 0.5))
                .into()
        };

        column![
            content,
            encrypt_action,
            Space::with_height(Length::Fixed(10.0)),
            text("Creates .deadbolt encrypted file")
                .size(11)
                .style(Color::from_rgb(0.5, 0.5, 0.5)),
        ]
        .spacing(5)
        .align_items(Alignment::Center)
        .into()
    }

    fn view_decrypt(&self) -> Element<'_, Message> {
        let file_status = if let Some(path) = &self.selected_file {
            format!("[x] {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("File selected"))
        } else {
            "[ ] No encrypted file selected".to_string()
        };

        let key_status = if let Some(path) = &self.private_key_path {
            format!("[x] {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("Key selected"))
        } else {
            "[ ] No private key selected".to_string()
        };

        let can_decrypt = self.selected_file.is_some() && self.private_key_path.is_some();

        let content = column![
            text("[*] Decrypt File")
                .size(20)
                .style(Color::from_rgb(1.0, 0.7, 0.3)),
            Space::with_height(Length::Fixed(20.0)),
            
            // Encrypted file selection
            button("[#] Select Encrypted File (.deadbolt)")
                .padding([12, 25])
                .on_press(Message::SelectFileToDecrypt),
            text(file_status)
                .size(11)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(15.0)),
            
            // Private key selection
            button("[+] Select Your Private Key")
                .padding([12, 25])
                .on_press(Message::SelectPrivateKey),
            text(key_status)
                .size(11)
                .style(Color::from_rgb(0.6, 0.6, 0.6)),
            Space::with_height(Length::Fixed(20.0)),
        ]
        .spacing(5)
        .align_items(Alignment::Center);

        // Decrypt button or warning message
        let decrypt_action: Element<Message> = if can_decrypt {
            button("[*] DECRYPT NOW")
                .padding([15, 35])
                .on_press(Message::DecryptFile)
                .into()
        } else {
            text("Select both encrypted file and private key")
                .size(12)
                .style(Color::from_rgb(0.7, 0.5, 0.5))
                .into()
        };

        column![
            content,
            decrypt_action,
            Space::with_height(Length::Fixed(10.0)),
            text("Recovers original file")
                .size(11)
                .style(Color::from_rgb(0.5, 0.5, 0.5)),
        ]
        .spacing(5)
        .align_items(Alignment::Center)
        .into()
    }
}

pub fn run_gui() -> iced::Result {
    DeadboltGUI::run(Settings {
        window: iced::window::Settings {
            size: Size::new(550.0, 650.0),
            resizable: false,
            ..Default::default()
        },
        ..Default::default()
    })
}
