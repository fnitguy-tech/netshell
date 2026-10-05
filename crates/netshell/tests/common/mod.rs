//! A fake network device: an SSH server that plays one platform's
//! login banner, prompt, paging and command outputs. The driver is
//! tested against it in CI without any hardware.
//!
//! Behaviour modelled:
//! - password or keyboard-interactive authentication, including the
//!   awkward kinds: a one-time-code question, a question that never
//!   stops being asked, and a server that never answers at all
//! - a banner and an optional delay before the first prompt (PAN-OS),
//!   or a greeting scripted packet by packet
//! - an OS shell before the CLI (Junos root), left with `cli`
//! - user mode and `enable` with a secret (IOS, EOS)
//! - character echo (or none), CRLF line endings, a line before the
//!   prompt (`{master:0}` on Junos), a prompt split over two packets
//! - paging: until a paging-off command arrives, long output stops at
//!   ` --More-- ` and never returns to the prompt
//! - preparation commands that are accepted silently, or rejected
//! - a `hang` command that produces no output at all, and commands
//!   whose output arrives in timed pieces
//!
//! Everything the device says goes through one queue per session, and
//! one task drains it in order. So a slow answer holds back every
//! later one, the way a real single-threaded CLI does, and the tests
//! are deterministic about what arrives when.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{self, Auth, Msg, Response, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    /// Only `password` is offered.
    Password,
    /// Only `keyboard-interactive` is offered, with one hidden
    /// `Password:` question. Some Cisco images do this.
    KeyboardInteractive,
    /// Both are offered and both take the password.
    Both,
    /// Keyboard-interactive that asks for the password and a visible
    /// one-time code in the same round.
    OneTimeCode,
    /// Keyboard-interactive with one question, echo on.
    VisibleQuestion,
    /// Keyboard-interactive that asks `Password:` again every time.
    AsksForever,
    /// The handshake completes, then no auth request is ever answered.
    Stall,
}

/// Output sent in pieces: wait, then send, for each one.
pub type Chunks = Vec<(Duration, String)>;

#[derive(Clone, Debug)]
pub struct Spec {
    pub prompt: String,
    pub shell_prompt: Option<String>,
    /// The prompt before `enable`, e.g. `RTR-1>`. When set, the
    /// session starts in user mode.
    pub user_prompt: Option<String>,
    /// What `enable` asks for. `None` means `enable` just works.
    pub enable_secret: Option<String>,
    pub pre_prompt: String,
    pub banner: String,
    pub prompt_delay: Duration,
    /// Replaces the banner and first prompt with exact packets.
    pub greeting: Option<Chunks>,
    /// Send the last two characters of every prompt in a packet of
    /// their own, this long after the rest.
    pub split_prompt: Option<Duration>,
    pub echo: bool,
    pub paging_off: Vec<String>,
    /// Commands answered with `% Invalid input`, even preparation
    /// commands that are otherwise accepted.
    pub rejects: Vec<String>,
    pub page_lines: usize,
    pub outputs: HashMap<String, String>,
    /// Commands whose output arrives in timed pieces. The prompt
    /// follows the last piece.
    pub chunked: HashMap<String, Chunks>,
    pub password: String,
    pub auth: AuthMode,
    /// Only these algorithms are offered by the server, when set
    /// (models an older device that has nothing modern).
    pub legacy_only: bool,
    /// Listen here instead of on a free port, to stand in for a
    /// device that was replaced at the same address.
    pub port: Option<u16>,
}

impl Spec {
    pub fn new(prompt: &str) -> Spec {
        Spec {
            prompt: prompt.to_string(),
            shell_prompt: None,
            user_prompt: None,
            enable_secret: None,
            pre_prompt: String::new(),
            banner: String::new(),
            prompt_delay: Duration::ZERO,
            greeting: None,
            split_prompt: None,
            echo: true,
            paging_off: Vec::new(),
            rejects: Vec::new(),
            page_lines: 5,
            outputs: HashMap::new(),
            chunked: HashMap::new(),
            password: "secret".to_string(),
            auth: AuthMode::Password,
            legacy_only: false,
            port: None,
        }
    }

    pub fn output(mut self, command: &str, output: &str) -> Spec {
        self.outputs.insert(command.to_string(), output.to_string());
        self
    }

    pub fn chunked(mut self, command: &str, chunks: &[(u64, &str)]) -> Spec {
        let chunks = chunks
            .iter()
            .map(|(millis, text)| (Duration::from_millis(*millis), text.to_string()))
            .collect();
        self.chunked.insert(command.to_string(), chunks);
        self
    }

    pub fn paging_off(mut self, commands: &[&str]) -> Spec {
        self.paging_off = commands.iter().map(|c| c.to_string()).collect();
        self
    }

    pub fn rejects(mut self, commands: &[&str]) -> Spec {
        self.rejects = commands.iter().map(|c| c.to_string()).collect();
        self
    }
}

pub struct FakeDevice {
    pub port: u16,
    pub fingerprint: String,
    pub received: Arc<Mutex<Vec<String>>>,
    /// Password attempts plus keyboard-interactive logins started:
    /// what a device's lockout counter would see.
    pub auth_attempts: Arc<AtomicUsize>,
    // Each fake gets its own known-hosts file, so no test ever reads
    // or writes the real one in the developer's home directory.
    scratch: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl FakeDevice {
    pub fn received(&self) -> Vec<String> {
        self.received.lock().unwrap().clone()
    }

    pub fn auth_attempts(&self) -> usize {
        self.auth_attempts.load(Ordering::SeqCst)
    }

    /// A known-hosts path that belongs to this fake alone.
    pub fn known_hosts(&self) -> PathBuf {
        self.scratch.path().join("known_hosts")
    }

    /// Stop listening and free the port, as if the device was pulled
    /// from the rack.
    pub async fn stop(self) -> u16 {
        self.task.abort();
        let _ = self.task.await;
        self.port
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
    let methods: &[MethodKind] = match spec.auth {
        AuthMode::Password | AuthMode::Stall => &[MethodKind::Password],
        AuthMode::Both => &[MethodKind::Password, MethodKind::KeyboardInteractive],
        AuthMode::KeyboardInteractive | AuthMode::OneTimeCode | AuthMode::VisibleQuestion | AuthMode::AsksForever => {
            &[MethodKind::KeyboardInteractive]
        }
    };
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        preferred,
        methods: MethodSet::from(methods),
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", spec.port.unwrap_or(0))).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let auth_attempts = Arc::new(AtomicUsize::new(0));

    let mut server = FakeServer {
        spec: Arc::new(spec),
        received: received.clone(),
        auth_attempts: auth_attempts.clone(),
    };
    let task = tokio::spawn(async move {
        let listener = listener;
        let _ = server.run_on_socket(config, &listener).await;
    });

    FakeDevice {
        port,
        fingerprint,
        received,
        auth_attempts,
        scratch: tempfile::tempdir().unwrap(),
        task,
    }
}

#[derive(Clone)]
struct FakeServer {
    spec: Arc<Spec>,
    received: Arc<Mutex<Vec<String>>>,
    auth_attempts: Arc<AtomicUsize>,
}

impl server::Server for FakeServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> ClientHandler {
        ClientHandler {
            spec: self.spec.clone(),
            received: self.received.clone(),
            auth_attempts: self.auth_attempts.clone(),
            line: Vec::new(),
            paging: true,
            in_shell: self.spec.shell_prompt.is_some(),
            privileged: self.spec.user_prompt.is_none(),
            awaiting_enable_secret: false,
            out: None,
        }
    }
}

struct ClientHandler {
    spec: Arc<Spec>,
    received: Arc<Mutex<Vec<String>>>,
    auth_attempts: Arc<AtomicUsize>,
    line: Vec<u8>,
    paging: bool,
    in_shell: bool,
    privileged: bool,
    awaiting_enable_secret: bool,
    /// The session's output queue. See the module comment.
    out: Option<mpsc::UnboundedSender<(Duration, Vec<u8>)>>,
}

impl ClientHandler {
    fn prompt(&self) -> String {
        if self.in_shell {
            return self.spec.shell_prompt.clone().unwrap_or_default();
        }
        let prompt = match &self.spec.user_prompt {
            Some(user_prompt) if !self.privileged => user_prompt,
            _ => &self.spec.prompt,
        };
        format!("{}{}", self.spec.pre_prompt, prompt)
    }

    /// Queue text for the client, splitting a trailing prompt in two
    /// when the spec asks for that.
    fn emit(&self, delay: Duration, text: String) {
        let Some(out) = &self.out else { return };
        if text.is_empty() {
            return;
        }
        let prompt = self.prompt();
        match self.spec.split_prompt {
            Some(gap) if prompt.len() > 2 && text.ends_with(&prompt) => {
                let (head, tail) = text.split_at(text.len() - 2);
                let _ = out.send((delay, head.as_bytes().to_vec()));
                let _ = out.send((gap, tail.as_bytes().to_vec()));
            }
            _ => {
                let _ = out.send((delay, text.into_bytes()));
            }
        }
    }

    fn respond(&mut self, command: &str) -> Chunks {
        let command = command.trim();
        self.received.lock().unwrap().push(command.to_string());
        let now = |text: String| vec![(Duration::ZERO, text)];

        if command.is_empty() {
            return now(self.prompt());
        }

        if self.in_shell {
            if command == "cli" {
                self.in_shell = false;
                return now(format!("\r\n{}", self.prompt()));
            }
            return now(format!("sh: {command}: not found\r\n{}", self.prompt()));
        }

        if command == "enable" && !self.privileged {
            if self.spec.enable_secret.is_some() {
                self.awaiting_enable_secret = true;
                return now("Password: ".to_string());
            }
            self.privileged = true;
            return now(self.prompt());
        }

        if self.spec.rejects.iter().any(|c| c == command) {
            return now(format!(
                "            ^\r\n% Invalid input detected at '^' marker.\r\n{}",
                self.prompt()
            ));
        }

        if self.spec.paging_off.iter().any(|c| c == command) {
            self.paging = false;
            return now(self.prompt());
        }

        // Session setup commands print nothing when they work.
        if command.starts_with("terminal ") || command.starts_with("set cli ") {
            return now(self.prompt());
        }

        if command == "hang" {
            return Vec::new();
        }

        if let Some(chunks) = self.spec.chunked.get(command) {
            let mut chunks = chunks.clone();
            if let Some((_, last)) = chunks.last_mut() {
                last.push_str(&format!("\r\n{}", self.prompt()));
            }
            return chunks;
        }

        match self.spec.outputs.get(command) {
            Some(output) => {
                let lines: Vec<&str> = output.lines().collect();
                if self.paging && lines.len() > self.spec.page_lines {
                    let page = lines[..self.spec.page_lines].join("\r\n");
                    return now(format!("{page}\r\n --More-- "));
                }
                now(format!("{}\r\n{}", lines.join("\r\n"), self.prompt()))
            }
            None => now(format!("% Invalid input\r\n{}", self.prompt())),
        }
    }

    /// The line typed at `Password:` after `enable`. It isn't echoed
    /// and isn't logged, like the real thing.
    fn finish_enable(&mut self, typed: &str) -> String {
        self.awaiting_enable_secret = false;
        self.received.lock().unwrap().push("<enable secret>".to_string());
        if Some(typed) == self.spec.enable_secret.as_deref() {
            self.privileged = true;
            format!("\r\n{}", self.prompt())
        } else {
            format!("\r\n% Bad secrets\r\n\r\n{}", self.prompt())
        }
    }
}

impl server::Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        if self.spec.auth == AuthMode::Stall {
            std::future::pending::<()>().await;
        }
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth_attempts.fetch_add(1, Ordering::SeqCst);
        let offered = matches!(self.spec.auth, AuthMode::Password | AuthMode::Both);
        if offered && password == self.spec.password {
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
        let ask = |prompts: Vec<(&'static str, bool)>| Auth::Partial {
            name: "".into(),
            instructions: "".into(),
            prompts: prompts
                .into_iter()
                .map(|(prompt, echo)| (prompt.into(), echo))
                .collect::<Vec<_>>()
                .into(),
        };
        if response.is_none() {
            self.auth_attempts.fetch_add(1, Ordering::SeqCst);
        }

        match (self.spec.auth, response) {
            (AuthMode::KeyboardInteractive | AuthMode::Both, None) => Ok(ask(vec![("Password: ", false)])),
            (AuthMode::KeyboardInteractive | AuthMode::Both, Some(mut answers)) => {
                let answer = answers.next().unwrap_or_default();
                if answer.as_ref() == self.spec.password.as_bytes() {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
            (AuthMode::OneTimeCode, None) => Ok(ask(vec![("Password: ", false), ("Verification code: ", true)])),
            (AuthMode::VisibleQuestion, None) => Ok(ask(vec![("Verification code: ", true)])),
            (AuthMode::AsksForever, _) => Ok(ask(vec![("Password: ", false)])),
            _ => Ok(Auth::reject()),
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

        let (out, mut queue) = mpsc::unbounded_channel::<(Duration, Vec<u8>)>();
        let handle = session.handle();
        tokio::spawn(async move {
            while let Some((delay, bytes)) = queue.recv().await {
                tokio::time::sleep(delay).await;
                if handle.data(channel, bytes).await.is_err() {
                    break;
                }
            }
        });
        self.out = Some(out);

        match self.spec.greeting.clone() {
            Some(chunks) => {
                for (delay, text) in chunks {
                    self.emit(delay, text);
                }
            }
            None => {
                let greeting = format!("{}{}", self.spec.banner.replace('\n', "\r\n"), self.prompt());
                self.emit(self.spec.prompt_delay, greeting);
            }
        }
        Ok(())
    }

    async fn data(&mut self, _channel: ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        for &byte in data {
            if byte != b'\n' && byte != b'\r' {
                self.line.push(byte);
                continue;
            }
            let typed = String::from_utf8_lossy(&self.line).into_owned();
            self.line.clear();

            if self.awaiting_enable_secret {
                let reply = self.finish_enable(&typed);
                self.emit(Duration::ZERO, reply);
                continue;
            }

            // Echo the line the way a terminal does, then answer.
            let mut echo = if self.spec.echo {
                format!("{typed}\r\n")
            } else {
                String::new()
            };
            let chunks = self.respond(&typed);
            if chunks.is_empty() {
                self.emit(Duration::ZERO, echo);
                continue;
            }
            for (delay, text) in chunks {
                // The echo rides with the first piece only when that
                // piece isn't delayed: a terminal echoes at once.
                if !echo.is_empty() && !delay.is_zero() {
                    self.emit(Duration::ZERO, std::mem::take(&mut echo));
                }
                self.emit(delay, format!("{}{text}", std::mem::take(&mut echo)));
            }
        }
        Ok(())
    }
}
