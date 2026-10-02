//! A fake network device: an SSH server that plays one platform's
//! login banner, prompt, paging and command outputs. The driver is
//! tested against it in CI without any hardware.
//!
//! Behaviour modelled:
//! - password or keyboard-interactive authentication
//! - a banner and an optional delay before the first prompt (PAN-OS)
//! - an OS shell before the CLI (Junos root), left with `cli`
//! - character echo, CRLF line endings, a line before the prompt
//!   (`{master:0}` on Junos)
//! - paging: until a paging-off command arrives, long output stops at
//!   ` --More-- ` and never returns to the prompt
//! - a `hang` command that produces no output at all

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{self, Auth, Msg, Response, Server as _, Session};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Password,
    KeyboardInteractive,
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub prompt: String,
    pub shell_prompt: Option<String>,
    pub pre_prompt: String,
    pub banner: String,
    pub prompt_delay: Duration,
    pub paging_off: Vec<String>,
    pub page_lines: usize,
    pub outputs: HashMap<String, String>,
    pub password: String,
    pub auth: AuthMode,
    /// Only these algorithms are offered by the server, when set
    /// (models an older device that has nothing modern).
    pub legacy_only: bool,
}

impl Spec {
    pub fn new(prompt: &str) -> Spec {
        Spec {
            prompt: prompt.to_string(),
            shell_prompt: None,
            pre_prompt: String::new(),
            banner: String::new(),
            prompt_delay: Duration::ZERO,
            paging_off: Vec::new(),
            page_lines: 5,
            outputs: HashMap::new(),
            password: "secret".to_string(),
            auth: AuthMode::Password,
            legacy_only: false,
        }
    }

    pub fn output(mut self, command: &str, output: &str) -> Spec {
        self.outputs.insert(command.to_string(), output.to_string());
        self
    }

    pub fn paging_off(mut self, commands: &[&str]) -> Spec {
        self.paging_off = commands.iter().map(|c| c.to_string()).collect();
        self
    }
}

pub struct FakeDevice {
    pub port: u16,
    pub fingerprint: String,
    pub received: Arc<Mutex<Vec<String>>>,
}

impl FakeDevice {
    pub fn received(&self) -> Vec<String> {
        self.received.lock().unwrap().clone()
    }
}

pub async fn start(spec: Spec) -> FakeDevice {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();

    let preferred = if spec.legacy_only {
        russh::Preferred {
            kex: std::borrow::Cow::Borrowed(&[russh::kex::ECDH_SHA2_NISTP256, russh::kex::DH_G14_SHA1]),
            cipher: std::borrow::Cow::Borrowed(&[russh::cipher::AES_128_CBC, russh::cipher::TRIPLE_DES_CBC]),
            mac: std::borrow::Cow::Borrowed(&[russh::mac::HMAC_SHA1]),
            ..russh::Preferred::DEFAULT
        }
    } else {
        russh::Preferred::DEFAULT
    };
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        preferred,
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));

    let mut server = FakeServer {
        spec: Arc::new(spec),
        received: received.clone(),
    };
    tokio::spawn(async move {
        let listener = listener;
        let _ = server.run_on_socket(config, &listener).await;
    });

    FakeDevice {
        port,
        fingerprint,
        received,
    }
}

#[derive(Clone)]
struct FakeServer {
    spec: Arc<Spec>,
    received: Arc<Mutex<Vec<String>>>,
}

impl server::Server for FakeServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> ClientHandler {
        ClientHandler {
            spec: self.spec.clone(),
            received: self.received.clone(),
            line: Vec::new(),
            paging: true,
            in_shell: self.spec.shell_prompt.is_some(),
        }
    }
}

struct ClientHandler {
    spec: Arc<Spec>,
    received: Arc<Mutex<Vec<String>>>,
    line: Vec<u8>,
    paging: bool,
    in_shell: bool,
}

impl ClientHandler {
    fn prompt(&self) -> String {
        if self.in_shell {
            return self.spec.shell_prompt.clone().unwrap_or_default();
        }
        format!("{}{}", self.spec.pre_prompt, self.spec.prompt)
    }

    fn respond(&mut self, command: &str) -> String {
        let command = command.trim();
        self.received.lock().unwrap().push(command.to_string());

        if command.is_empty() {
            return self.prompt();
        }

        if self.in_shell {
            if command == "cli" {
                self.in_shell = false;
                return format!("\r\n{}", self.prompt());
            }
            return format!("sh: {command}: not found\r\n{}", self.prompt());
        }

        if self.spec.paging_off.iter().any(|c| c == command) {
            self.paging = false;
            return self.prompt();
        }

        if command == "hang" {
            return String::new();
        }

        match self.spec.outputs.get(command) {
            Some(output) => {
                let lines: Vec<&str> = output.lines().collect();
                if self.paging && lines.len() > self.spec.page_lines {
                    let page = lines[..self.spec.page_lines].join("\r\n");
                    return format!("{page}\r\n --More-- ");
                }
                format!("{}\r\n{}", lines.join("\r\n"), self.prompt())
            }
            None => format!("% Invalid input\r\n{}", self.prompt()),
        }
    }
}

impl server::Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.spec.auth == AuthMode::Password && password == self.spec.password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if self.spec.auth != AuthMode::KeyboardInteractive {
            return Ok(Auth::reject());
        }
        match response {
            None => Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![("Password: ".into(), false)].into(),
            }),
            Some(mut answers) => {
                let answer = answers.next().unwrap_or_default();
                if answer.as_ref() == self.spec.password.as_bytes() {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        tokio::time::sleep(self.spec.prompt_delay).await;
        let greeting = format!("{}{}", self.spec.banner.replace('\n', "\r\n"), self.prompt());
        session.data(channel, greeting.into_bytes())?;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        for &byte in data {
            if byte == b'\n' || byte == b'\r' {
                let command = String::from_utf8_lossy(&self.line).into_owned();
                self.line.clear();
                // Echo the line end the way a terminal does, then answer.
                let reply = format!("{command}\r\n{}", self.respond(&command));
                session.data(channel, reply.into_bytes())?;
            } else {
                self.line.push(byte);
            }
        }
        Ok(())
    }
}
