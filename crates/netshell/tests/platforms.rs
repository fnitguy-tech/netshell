mod common;

use std::time::Duration;

use common::{AuthMode, Spec, start};
use netshell::{ConnectOptions, Device, Error, HostKeyPolicy, Platform};

/// The password every fake accepts unless a test says otherwise.
const PASSWORD: &str = "secret";

const RUNNING_CONFIG: &str = "\
hostname SW-1
!
interface Ethernet1
   description uplink
!
interface Ethernet2
   description server
!
router bgp 65000
   neighbor 10.0.0.1 remote-as 65001
   neighbor 10.0.0.2 remote-as 65002
!
end";

async fn connect(device: &common::FakeDevice, platform: &str) -> Device {
    Device::connect(options(device, platform)).await.unwrap()
}

fn options(device: &common::FakeDevice, platform: &str) -> ConnectOptions {
    ConnectOptions::new("127.0.0.1", "admin", PASSWORD, Platform::by_name(platform).unwrap())
        .port(device.port)
        .read_timeout(Duration::from_secs(5))
        // Never the developer's real ~/.config/netshell/known_hosts.
        .known_hosts(device.known_hosts())
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[tokio::test]
async fn arista_eos_banner_paging_and_long_output() {
    let fake = start(
        Spec::new("SW-1#")
            .output("show version", "Arista DCS-7050SX3\nSoftware image version: 4.30.1F")
            .output("show running-config", RUNNING_CONFIG)
            .paging_off(&["terminal length 0"]),
    )
    .await;
    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(device.base_prompt(), "SW-1");

    let received = fake.received();
    assert!(received.contains(&"terminal length 0".to_string()), "{received:?}");
    assert!(received.contains(&"terminal width 511".to_string()), "{received:?}");

    assert_eq!(
        device.send_command("show version").await.unwrap(),
        "Arista DCS-7050SX3\nSoftware image version: 4.30.1F"
    );
    // 12 lines with the pager at 5: only works because paging was disabled.
    assert_eq!(
        device.send_command("show running-config").await.unwrap(),
        RUNNING_CONFIG
    );
    device.disconnect().await.unwrap();
}

#[tokio::test]
async fn arista_eos_with_login_banner() {
    let mut spec = Spec::new("SW-1#").output("show hostname", "Hostname: SW-1\nFQDN:     SW-1.example.net");
    spec.banner = "Last login: Thu Oct  2 09:00:00 2026 from 10.0.0.5\n\n* Unauthorised access prohibited *\n\n".into();
    let fake = start(spec).await;

    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(device.base_prompt(), "SW-1");
    assert_eq!(
        device.send_command("show hostname").await.unwrap(),
        "Hostname: SW-1\nFQDN:     SW-1.example.net"
    );
}

#[tokio::test]
async fn cisco_ios_keyboard_interactive_auth() {
    let mut spec = Spec::new("RTR-1#")
        .output(
            "show ip interface brief",
            "Interface  IP-Address  OK? Method Status Protocol\nGi0/0  10.0.0.1  YES NVRAM up up",
        )
        .paging_off(&["terminal length 0"]);
    spec.auth = AuthMode::KeyboardInteractive;
    let fake = start(spec).await;

    let mut device = connect(&fake, "cisco_ios").await;
    assert_eq!(device.base_prompt(), "RTR-1");
    let output = device.send_command("show ip interface brief").await.unwrap();
    assert!(output.starts_with("Interface  IP-Address"), "{output}");
    assert!(output.ends_with("up up"), "{output}");
    assert!(fake.received().contains(&"terminal width 511".to_string()));
}

#[tokio::test]
async fn cisco_nxos() {
    let fake = start(
        Spec::new("NX-1# ")
            .output("show running-config", RUNNING_CONFIG)
            .paging_off(&["terminal length 0"]),
    )
    .await;
    let mut device = connect(&fake, "cisco_nxos").await;
    assert_eq!(device.base_prompt(), "NX-1");
    assert_eq!(
        device.send_command("show running-config").await.unwrap(),
        RUNNING_CONFIG
    );
}

#[tokio::test]
async fn cisco_xr_prompt_and_preparation() {
    let fake = start(
        Spec::new("RP/0/RP0/CPU0:XR-1#")
            .output("show running-config", RUNNING_CONFIG)
            .paging_off(&["terminal length 0"]),
    )
    .await;
    let mut device = connect(&fake, "cisco_xr").await;
    assert_eq!(device.base_prompt(), "RP/0/RP0/CPU0:XR-1");
    let received = fake.received();
    assert!(
        received.contains(&"terminal exec prompt no-timestamp".to_string()),
        "{received:?}"
    );
    assert!(received.contains(&"terminal width 512".to_string()), "{received:?}");
    assert_eq!(
        device.send_command("show running-config").await.unwrap(),
        RUNNING_CONFIG
    );
}

#[tokio::test]
async fn juniper_junos_root_shell_then_cli() {
    let mut spec = Spec::new("root@JUN-1> ")
        .output("show version", "Hostname: JUN-1\nModel: ex4300-48t\nJunos: 21.4R3")
        .output("show configuration", RUNNING_CONFIG)
        .paging_off(&["set cli screen-length 0"]);
    spec.shell_prompt = Some("root@JUN-1:~ # ".into());
    spec.pre_prompt = "{master:0}\r\n".into();
    spec.banner = "--- JUNOS 21.4R3 Kernel 64-bit\n".into();
    let fake = start(spec).await;

    let mut device = connect(&fake, "juniper_junos").await;
    assert_eq!(device.base_prompt(), "root@JUN-1");
    let received = fake.received();
    assert!(received.contains(&"cli".to_string()), "{received:?}");
    assert!(
        received.contains(&"set cli complete-on-space off".to_string()),
        "{received:?}"
    );

    assert_eq!(
        device.send_command("show version").await.unwrap(),
        "Hostname: JUN-1\nModel: ex4300-48t\nJunos: 21.4R3"
    );
    assert_eq!(device.send_command("show configuration").await.unwrap(), RUNNING_CONFIG);
}

#[tokio::test]
async fn juniper_junos_non_root_lands_in_cli_directly() {
    let mut spec = Spec::new("ops@JUN-1> ").output("show version", "Junos: 21.4R3");
    spec.pre_prompt = "{master:0}\r\n".into();
    let fake = start(spec).await;

    let mut device = connect(&fake, "juniper_junos").await;
    assert_eq!(device.base_prompt(), "ops@JUN-1");
    assert!(!fake.received().contains(&"cli".to_string()));
    assert_eq!(device.send_command("show version").await.unwrap(), "Junos: 21.4R3");
}

#[tokio::test]
async fn paloalto_panos_slow_prompt_ha_suffix_and_ansi() {
    let mut spec = Spec::new("admin@PA-1(active)> ")
        .output(
            "show system info",
            "\x1b[?7hhostname: PA-1\nip-address: 10.0.0.254\nsw-version: 11.1.4",
        )
        .output("show config running", RUNNING_CONFIG)
        .paging_off(&["set cli pager off"]);
    spec.prompt_delay = Duration::from_millis(1500);
    spec.banner = "\nNumber of failed attempts since last successful attempt: 0\n\n".into();
    let fake = start(spec).await;

    let mut device = connect(&fake, "paloalto_panos").await;
    assert_eq!(device.base_prompt(), "admin@PA-1");
    let received = fake.received();
    assert!(
        received.contains(&"set cli scripting-mode on".to_string()),
        "{received:?}"
    );

    assert_eq!(
        device.send_command("show system info").await.unwrap(),
        "hostname: PA-1\nip-address: 10.0.0.254\nsw-version: 11.1.4"
    );
    assert_eq!(
        device.send_command("show config running").await.unwrap(),
        RUNNING_CONFIG
    );
}

#[tokio::test]
async fn wrong_password_is_auth_failed() {
    let fake = start(Spec::new("SW-1#")).await;
    let options = ConnectOptions::new("127.0.0.1", "admin", "wrong-Pa55", Platform::arista_eos())
        .port(fake.port)
        .known_hosts(fake.known_hosts());
    match Device::connect(options).await {
        Err(error @ Error::AuthFailed { .. }) => {
            let text = error.to_string();
            assert_eq!(text, "authentication failed for admin@127.0.0.1 (tried password)");
            assert!(!format!("{error:?}").contains("wrong-Pa55"));
        }
        other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn unknown_command_output_is_returned_verbatim() {
    let fake = start(Spec::new("SW-1#")).await;
    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(device.send_command("show nonsense").await.unwrap(), "% Invalid input");
}

#[tokio::test]
async fn silent_command_times_out_with_context() {
    let fake = start(Spec::new("SW-1#")).await;
    let mut device = connect(&fake, "arista_eos").await;
    match device.send_command_timeout("hang", Duration::from_millis(500)).await {
        Err(Error::ReadTimeout {
            host, what, timeout, ..
        }) => {
            assert_eq!(host, "127.0.0.1");
            assert!(what.contains("hang"), "{what}");
            assert_eq!(timeout, Duration::from_millis(500));
        }
        other => panic!("expected ReadTimeout, got {other:?}"),
    }
}

#[tokio::test]
async fn pinned_host_key() {
    let fake = start(Spec::new("SW-1#").output("show version", "ok")).await;

    let good = options(&fake, "arista_eos").host_key(HostKeyPolicy::Sha256Fingerprint(fake.fingerprint.clone()));
    let mut device = Device::connect(good).await.unwrap();
    assert_eq!(device.send_command("show version").await.unwrap(), "ok");

    let bad = options(&fake, "arista_eos").host_key(HostKeyPolicy::Sha256Fingerprint(
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    ));
    match Device::connect(bad).await {
        Err(Error::HostKeyMismatch { actual, .. }) => assert_eq!(actual, fake.fingerprint),
        other => panic!("expected HostKeyMismatch, got {:?}", other.map(|_| ())),
    }

    // A pin is its own source of truth: nothing is written down.
    assert!(!fake.known_hosts().exists());
}

#[tokio::test]
async fn connect_refused_is_a_connect_error() {
    let options = ConnectOptions::new("127.0.0.1", "admin", "secret", Platform::arista_eos()).port(1);
    match Device::connect(options).await {
        Err(Error::Connect { port, .. }) => assert_eq!(port, 1),
        other => panic!("expected Connect, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn send_command_expect_reads_past_a_confirmation() {
    let fake = start(Spec::new("SW-1#").output("reload", "Proceed with reload? [confirm]")).await;
    let mut device = connect(&fake, "arista_eos").await;
    let raw = device
        .send_command_expect("reload", r"\[confirm\]", Duration::from_secs(2))
        .await
        .unwrap();
    assert!(raw.contains("Proceed with reload? [confirm]"), "{raw}");
}

#[tokio::test]
async fn blocking_wrapper_from_a_plain_thread() {
    let fake = start(Spec::new("SW-1#").output("show version", "ok")).await;
    let options = options(&fake, "arista_eos");

    let output = tokio::task::spawn_blocking(move || {
        let mut device = netshell::blocking::Device::connect(options).unwrap();
        let output = device.send_command("show version").unwrap();
        device.disconnect().unwrap();
        output
    })
    .await
    .unwrap();

    assert_eq!(output, "ok");
}

// ---- The command-line binary ----------------------------------------

/// Only built with the `cli` feature, like the binary itself.
#[cfg(feature = "cli")]
mod cli {
    use super::*;

    /// Run the real `netshell` binary against a fake, off the async
    /// threads. The password comes from the environment, as in a script.
    async fn run_cli(fake: &common::FakeDevice, extra: &[&str], commands: &[&str]) -> std::process::Output {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_netshell"));
        command
            .args(["--platform", "arista_eos", "--host", "127.0.0.1", "--port"])
            .arg(fake.port.to_string())
            .args(["--username", "admin", "--password-env", "NETSHELL_TEST_PASSWORD"])
            .args(extra)
            .args(commands)
            .env("NETSHELL_TEST_PASSWORD", PASSWORD)
            .env("NETSHELL_KNOWN_HOSTS", fake.known_hosts());
        tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn cli_binary_writes_capture_sections_and_json() {
        let fake = start(
            Spec::new("SW-1#")
                .output("show version", "Arista")
                .output("show hostname", "Hostname: SW-1"),
        )
        .await;
        let commands = ["show version", "show hostname"];

        let sections = run_cli(&fake, &[], &commands).await;
        assert!(
            sections.status.success(),
            "{}",
            String::from_utf8_lossy(&sections.stderr)
        );
        let text = String::from_utf8_lossy(&sections.stdout);
        assert!(text.contains("### show version ###\n"), "{text}");
        assert!(text.contains("\nArista\n"), "{text}");
        assert!(text.contains("### show hostname ###\n"), "{text}");

        let json = run_cli(&fake, &["--json"], &commands).await;
        let text = String::from_utf8_lossy(&json.stdout);
        assert!(text.contains(r#""prompt": "SW-1""#), "{text}");
        assert!(
            text.contains(r#"{"command": "show version", "output": "Arista"}"#),
            "{text}"
        );

        // No --known-hosts flag was given, so the environment variable
        // decided where the key was remembered.
        assert_eq!(
            read(&fake.known_hosts()),
            format!("127.0.0.1:{} ssh-ed25519 {}\n", fake.port, fake.fingerprint)
        );
    }

    #[tokio::test]
    async fn cli_exits_3_and_still_prints_when_a_command_fails() {
        let fake = start(Spec::new("SW-1#").output("show version", "Arista")).await;

        let run = run_cli(
            &fake,
            &["--read-timeout", "1"],
            &["show version", "hang", "show version"],
        )
        .await;
        assert_eq!(run.status.code(), Some(3));

        // The command that worked is still on stdout.
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(stdout.contains("### show version ###\n"), "{stdout}");
        assert!(stdout.contains("\nArista\n"), "{stdout}");
        assert!(stdout.contains("### hang ###\n"), "{stdout}");
        assert!(stdout.contains("COMMAND FAILED:\ntimed out after 1s"), "{stdout}");
        // After the timeout the session is out of step, so the third
        // command is refused rather than answered with the wrong text.
        assert!(
            stdout.contains("COMMAND FAILED:\nthe session to 127.0.0.1 is out of step"),
            "{stdout}"
        );

        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains("2 of 3 commands failed"), "{stderr}");
    }

    #[tokio::test]
    async fn cli_exits_1_when_it_cannot_log_in() {
        let mut spec = Spec::new("SW-1#");
        spec.password = "something-else".into();
        let fake = start(spec).await;

        let run = run_cli(&fake, &[], &["show version"]).await;
        assert_eq!(run.status.code(), Some(1));
        assert!(run.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains("authentication failed for admin@127.0.0.1"), "{stderr}");
        assert!(!stderr.contains(PASSWORD), "{stderr}");
    }

    #[tokio::test]
    async fn cli_insecure_flag_skips_the_known_hosts_file() {
        let fake = start(Spec::new("SW-1#").output("show version", "Arista")).await;
        let run = run_cli(&fake, &["--insecure-accept-any-host-key"], &["show version"]).await;
        assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
        assert!(!fake.known_hosts().exists());
    }
}

// ---- Host keys -------------------------------------------------------

#[tokio::test]
async fn first_connect_records_the_host_key_and_the_second_passes() {
    let fake = start(Spec::new("SW-1#").output("show version", "ok")).await;
    let expected = format!("127.0.0.1:{} ssh-ed25519 {}\n", fake.port, fake.fingerprint);

    // Default policy: nothing was asked for, and the key is checked.
    assert_eq!(options(&fake, "arista_eos").host_key, HostKeyPolicy::KnownHosts);
    connect(&fake, "arista_eos").await.disconnect().await.unwrap();
    assert_eq!(read(&fake.known_hosts()), expected);

    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(device.send_command("show version").await.unwrap(), "ok");
    assert_eq!(read(&fake.known_hosts()), expected, "a known host isn't written twice");
}

#[tokio::test]
async fn changed_host_key_is_refused_and_says_how_to_accept_it() {
    let scratch = tempfile::tempdir().unwrap();
    let known_hosts = scratch.path().join("known_hosts");
    let options_for = |port: u16| {
        ConnectOptions::new("127.0.0.1", "admin", PASSWORD, Platform::arista_eos())
            .port(port)
            .known_hosts(&known_hosts)
    };

    // A neighbour that must survive everything below.
    let neighbour = "192.0.2.99:22 ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8\n";
    std::fs::write(&known_hosts, neighbour).unwrap();

    let original = start(Spec::new("SW-1#")).await;
    let old_fingerprint = original.fingerprint.clone();
    Device::connect(options_for(original.port)).await.unwrap();

    // The switch is swapped: same address and port, new host key.
    let port = original.stop().await;
    let mut spec = Spec::new("SW-1#").output("show version", "ok");
    spec.port = Some(port);
    let replacement = start(spec).await;
    assert_ne!(replacement.fingerprint, old_fingerprint);

    let error = match Device::connect(options_for(port)).await {
        Err(error @ Error::HostKeyChanged { .. }) => error,
        other => panic!("expected HostKeyChanged, got {:?}", other.map(|_| ())),
    };
    assert_eq!(
        error.to_string(),
        format!(
            "the host key for 127.0.0.1:{port} changed, so netshell didn't connect.\n  \
             stored:  ssh-ed25519 {old_fingerprint} ({}, line 2)\n  \
             offered: ssh-ed25519 {}\n\
             If you replaced or re-imaged this device, remove line 2 from that file, or run netshell once with \
             --accept-new-host-key. If you didn't, stop here: something else may be answering on that address.",
            known_hosts.display(),
            replacement.fingerprint
        )
    );
    // Refusing changed nothing on disk.
    assert_eq!(
        read(&known_hosts),
        format!("{neighbour}127.0.0.1:{port} ssh-ed25519 {old_fingerprint}\n")
    );

    // Accepting the new key is an explicit choice, and replaces only
    // that one line.
    let mut device = Device::connect(options_for(port).host_key(HostKeyPolicy::ReplaceKnownHost))
        .await
        .unwrap();
    assert_eq!(device.send_command("show version").await.unwrap(), "ok");
    assert_eq!(
        read(&known_hosts),
        format!("{neighbour}127.0.0.1:{port} ssh-ed25519 {}\n", replacement.fingerprint)
    );
    Device::connect(options_for(port)).await.unwrap();
}

#[tokio::test]
async fn accept_any_is_an_explicit_choice_that_records_nothing() {
    let fake = start(Spec::new("SW-1#").output("show version", "ok")).await;
    let mut device = Device::connect(options(&fake, "arista_eos").host_key(HostKeyPolicy::AcceptAny))
        .await
        .unwrap();
    assert_eq!(device.send_command("show version").await.unwrap(), "ok");
    assert!(!fake.known_hosts().exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_connects_are_all_recorded() {
    let scratch = tempfile::tempdir().unwrap();
    let known_hosts = scratch.path().join("known_hosts");

    let mut fakes = Vec::new();
    for _ in 0..12 {
        fakes.push(start(Spec::new("SW-1#")).await);
    }

    // Twelve new devices at the same moment, one shared file.
    let connects: Vec<_> = fakes
        .iter()
        .map(|fake| {
            let options = options(fake, "arista_eos").known_hosts(&known_hosts);
            tokio::spawn(async move { Device::connect(options).await.map(|_| ()) })
        })
        .collect();
    for connect in connects {
        connect.await.unwrap().unwrap();
    }

    let mut recorded: Vec<String> = read(&known_hosts).lines().map(str::to_string).collect();
    let mut expected: Vec<String> = fakes
        .iter()
        .map(|fake| format!("127.0.0.1:{} ssh-ed25519 {}", fake.port, fake.fingerprint))
        .collect();
    recorded.sort();
    expected.sort();
    assert_eq!(recorded, expected);
}

// ---- Timeouts and answers that arrive late ---------------------------

#[tokio::test]
async fn a_read_timeout_poisons_the_session_instead_of_shifting_answers() {
    let fake = start(
        Spec::new("SW-1#")
            .output("show version", "Arista")
            .chunked("show tech-support", &[(800, "the late output")]),
    )
    .await;
    let mut device = connect(&fake, "arista_eos").await;
    assert!(!device.is_poisoned());

    let slow = device
        .send_command_timeout("show tech-support", Duration::from_millis(300))
        .await;
    assert!(matches!(slow, Err(Error::ReadTimeout { .. })), "{slow:?}");
    assert!(device.is_poisoned());

    // Wait until the late output is sitting in the channel: the exact
    // case where the old driver returned it for the next command.
    tokio::time::sleep(Duration::from_millis(800)).await;
    for attempt in [
        device.send_command("show version").await,
        device
            .send_command_expect("show version", "Arista", Duration::from_secs(1))
            .await,
        device.find_prompt().await,
    ] {
        match attempt {
            Err(error @ Error::SessionPoisoned { .. }) => assert_eq!(
                error.to_string(),
                "the session to 127.0.0.1 is out of step after a timeout, so its next answer could belong to an \
                 earlier command. Disconnect and connect again"
            ),
            other => panic!("expected SessionPoisoned, got {other:?}"),
        }
    }
    assert!(matches!(device.write("\n").await, Err(Error::SessionPoisoned { .. })));
    // Nothing more was typed at the device after the timeout.
    assert_eq!(fake.received().last().unwrap(), "show tech-support");
}

#[tokio::test]
async fn a_late_prompt_from_an_earlier_command_is_not_the_next_answer() {
    let fake = start(
        Spec::new("SW-1#")
            .output("show version", "Arista")
            .output("show hostname", "Hostname: SW-1")
            // The pattern matches in the first piece; the rest of the
            // output and its prompt arrive 400 ms later.
            .chunked(
                "show clock",
                &[(0, "Mon Oct  5 12:00:00 2026 MARK"), (400, "Timezone: UTC")],
            ),
    )
    .await;
    let mut device = connect(&fake, "arista_eos").await;

    let raw = device
        .send_command_expect("show clock", "MARK", Duration::from_secs(2))
        .await
        .unwrap();
    assert!(raw.contains("MARK"), "{raw}");

    // `Timezone: UTC` and a prompt are still on their way. They must
    // not be returned for `show version`.
    assert_eq!(device.send_command("show version").await.unwrap(), "Arista");
    assert_eq!(device.send_command("show hostname").await.unwrap(), "Hostname: SW-1");
    assert!(!device.is_poisoned());
}

#[tokio::test]
async fn a_device_that_does_not_echo_still_works_through_the_fallback() {
    let mut spec = Spec::new("SW-1#").output("show version", "Arista");
    spec.echo = false;
    let fake = start(spec).await;

    let mut device = connect(&fake, "arista_eos").await;
    let started = std::time::Instant::now();
    assert_eq!(device.send_command("show version").await.unwrap(), "Arista");
    // The answer is only accepted after 2 quiet seconds.
    assert!(started.elapsed() >= Duration::from_secs(2), "{:?}", started.elapsed());
}

#[tokio::test]
async fn a_server_that_never_answers_auth_times_out() {
    let mut spec = Spec::new("SW-1#");
    spec.auth = AuthMode::Stall;
    let fake = start(spec).await;

    let started = std::time::Instant::now();
    let options = options(&fake, "arista_eos").connect_timeout(Duration::from_millis(500));
    match Device::connect(options).await {
        Err(error @ Error::SetupTimeout { .. }) => assert_eq!(
            error.to_string(),
            "127.0.0.1 stopped answering during authentication; gave up after 500ms"
        ),
        other => panic!("expected SetupTimeout, got {:?}", other.map(|_| ())),
    }
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

// ---- Login -----------------------------------------------------------

/// What every login test checks at the end: the prompt is right and
/// answers line up with their commands.
async fn assert_in_step(device: &mut Device) {
    assert_eq!(device.base_prompt(), "SW-1");
    assert_eq!(device.send_command("show version").await.unwrap(), "Arista");
    assert_eq!(device.send_command("show hostname").await.unwrap(), "Hostname: SW-1");
    assert_eq!(device.send_command("show version").await.unwrap(), "Arista");
}

fn login_spec() -> Spec {
    Spec::new("SW-1#")
        .output("show version", "Arista")
        .output("show hostname", "Hostname: SW-1")
}

#[tokio::test]
async fn a_banner_line_ending_in_hash_is_not_the_prompt() {
    let mut spec = login_spec();
    // The banner pauses twice for longer than the 300 ms settle time,
    // and its last line ends in `#` with no newline yet. That line is
    // on screen, looking like a prompt, when the driver first asks.
    let pause = Duration::from_millis(450);
    spec.greeting = Some(vec![
        (Duration::ZERO, "Welcome to SW-1\r\n".into()),
        (pause, "# Authorised access only #".into()),
        (pause, "\r\n\r\nSW-1#".into()),
    ]);
    let fake = start(spec).await;

    let mut device = connect(&fake, "arista_eos").await;
    assert_in_step(&mut device).await;
}

#[tokio::test]
async fn a_first_prompt_just_after_the_login_timeout_does_not_shift_answers() {
    let mut spec = login_spec();
    spec.banner = "Last login: Mon Oct  5 09:00:00 2026\n".into();
    spec.prompt_delay = Duration::from_millis(1200);
    let fake = start(spec).await;

    // The device says nothing for 1.2 s; the driver waits 1 s, then
    // sends a newline. The device answers with two prompts at once.
    let platform = Platform {
        login_timeout: Duration::from_secs(1),
        ..Platform::arista_eos()
    };
    let options = ConnectOptions::new("127.0.0.1", "admin", PASSWORD, platform)
        .port(fake.port)
        .known_hosts(fake.known_hosts());
    let mut device = Device::connect(options).await.unwrap();
    assert_in_step(&mut device).await;
}

#[tokio::test]
async fn a_prompt_split_across_two_packets() {
    let mut spec = login_spec();
    spec.banner = "Welcome\n".into();
    // `SW-` then, 100 ms later, `1#`. Every prompt, not only the first.
    spec.split_prompt = Some(Duration::from_millis(100));
    let fake = start(spec).await;

    let mut device = connect(&fake, "arista_eos").await;
    assert_in_step(&mut device).await;
}

#[tokio::test]
async fn junos_chassis_cluster_status_line_is_stripped() {
    let mut spec = Spec::new("ops@SRX-1> ").output("show version", "Junos: 21.4R3");
    spec.pre_prompt = "{primary:node0}\r\n".into();
    let fake = start(spec).await;

    let mut device = connect(&fake, "juniper_junos").await;
    assert_eq!(device.base_prompt(), "ops@SRX-1");
    assert_eq!(device.send_command("show version").await.unwrap(), "Junos: 21.4R3");
}

// ---- Algorithms ------------------------------------------------------

#[tokio::test]
async fn a_legacy_only_device_needs_the_opt_in() {
    let mut spec = Spec::new("OLD-SW-1#").output("show version", "Cisco IOS 12.4");
    spec.legacy_only = true;
    let fake = start(spec).await;

    match Device::connect(options(&fake, "cisco_ios")).await {
        Err(error @ Error::NoCommonAlgorithm { .. }) => assert_eq!(
            error.to_string(),
            "127.0.0.1 and netshell share no cipher algorithm. The device offers: aes128-cbc, 3des-cbc. If those \
             are legacy algorithms, netshell leaves them off by default. Try again with --legacy-algorithms \
             (library: ConnectOptions::legacy_algorithms(true))."
        ),
        other => panic!("expected NoCommonAlgorithm, got {:?}", other.map(|_| ())),
    }

    let mut device = Device::connect(options(&fake, "cisco_ios").legacy_algorithms(true))
        .await
        .unwrap();
    assert_eq!(device.send_command("show version").await.unwrap(), "Cisco IOS 12.4");
}

// ---- Authentication --------------------------------------------------

#[tokio::test]
async fn a_bad_password_costs_one_attempt_even_when_both_methods_are_offered() {
    let mut spec = Spec::new("SW-1#").output("show version", "ok");
    spec.auth = AuthMode::Both;
    let fake = start(spec).await;

    let wrong = ConnectOptions::new("127.0.0.1", "admin", "wrong-Pa55", Platform::arista_eos())
        .port(fake.port)
        .known_hosts(fake.known_hosts());
    assert!(matches!(Device::connect(wrong).await, Err(Error::AuthFailed { .. })));
    assert_eq!(fake.auth_attempts(), 1, "a lockout counter would have seen this many");

    // And the right password still gets in, in one more attempt.
    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(device.send_command("show version").await.unwrap(), "ok");
    assert_eq!(fake.auth_attempts(), 2);
}

#[tokio::test]
async fn keyboard_interactive_refuses_anything_but_one_hidden_question() {
    let cases = [
        (
            AuthMode::OneTimeCode,
            "netshell stopped the keyboard-interactive login to 127.0.0.1: the device asked 2 questions at once. \
             It only answers one hidden password prompt, so it can't do one-time codes or multi-question logins",
        ),
        (
            AuthMode::VisibleQuestion,
            "netshell stopped the keyboard-interactive login to 127.0.0.1: the device asked \"Verification code:\" \
             with echo on, which isn't a password prompt. It only answers one hidden password prompt, so it can't \
             do one-time codes or multi-question logins",
        ),
        (
            AuthMode::AsksForever,
            "netshell stopped the keyboard-interactive login to 127.0.0.1: the device asked more than 3 times. It \
             only answers one hidden password prompt, so it can't do one-time codes or multi-question logins",
        ),
    ];
    for (mode, expected) in cases {
        let mut spec = Spec::new("SW-1#");
        spec.auth = mode;
        let fake = start(spec).await;
        match Device::connect(options(&fake, "arista_eos")).await {
            Err(error @ Error::KeyboardInteractiveRefused { .. }) => assert_eq!(error.to_string(), expected),
            other => panic!("{mode:?}: expected a refusal, got {:?}", other.map(|_| ())),
        }
        assert_eq!(fake.auth_attempts(), 1, "{mode:?}");
    }
}

// ---- Preparation commands --------------------------------------------

#[tokio::test]
async fn rejected_paging_off_fails_the_connect() {
    let fake = start(Spec::new("SW-1#").rejects(&["terminal length 0"])).await;
    match Device::connect(options(&fake, "arista_eos")).await {
        Err(error @ Error::PreparationFailed { .. }) => assert_eq!(
            error.to_string(),
            "127.0.0.1 rejected `terminal length 0`, so paging is still on and long output would stall. The \
             device said:\n            ^\n% Invalid input detected at '^' marker."
        ),
        other => panic!("expected PreparationFailed, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn rejected_width_command_is_a_warning() {
    let fake = start(
        Spec::new("SW-1#")
            .output("show version", "Arista")
            .rejects(&["terminal width 511"]),
    )
    .await;
    let mut device = connect(&fake, "arista_eos").await;
    assert_eq!(
        device.warnings(),
        ["`terminal width 511` was rejected: % Invalid input detected at '^' marker."]
    );
    assert_eq!(device.send_command("show version").await.unwrap(), "Arista");

    // A clean connect has nothing to warn about.
    let clean = start(Spec::new("SW-1#")).await;
    assert!(connect(&clean, "arista_eos").await.warnings().is_empty());
}

// ---- Enable mode -----------------------------------------------------

fn user_mode_spec() -> Spec {
    let mut spec = Spec::new("RTR-1#")
        .output("show running-config", RUNNING_CONFIG)
        .paging_off(&["terminal length 0"]);
    spec.user_prompt = Some("RTR-1>".into());
    spec.enable_secret = Some("En4ble-Pa55".into());
    spec
}

#[tokio::test]
async fn enable_secret_takes_a_user_mode_login_to_privileged_mode() {
    let fake = start(user_mode_spec()).await;
    let mut device = Device::connect(options(&fake, "cisco_ios").enable_secret("En4ble-Pa55"))
        .await
        .unwrap();

    assert_eq!(device.base_prompt(), "RTR-1");
    assert_eq!(device.find_prompt().await.unwrap(), "RTR-1#");
    assert_eq!(
        device.send_command("show running-config").await.unwrap(),
        RUNNING_CONFIG
    );
    // `enable` came before paging off, and the secret went to the
    // password prompt, not the command line.
    let received = fake.received();
    let position = |wanted: &str| received.iter().position(|line| line == wanted).unwrap();
    assert!(position("enable") < position("<enable secret>"), "{received:?}");
    assert!(
        position("<enable secret>") < position("terminal length 0"),
        "{received:?}"
    );
    assert!(
        !received.iter().any(|line| line.contains("En4ble-Pa55")),
        "{received:?}"
    );
}

#[tokio::test]
async fn user_mode_without_a_secret_is_a_clear_error() {
    let fake = start(user_mode_spec()).await;
    match Device::connect(options(&fake, "cisco_ios")).await {
        Err(error @ Error::EnableRequired { .. }) => assert_eq!(
            error.to_string(),
            "127.0.0.1 logged in at `RTR-1>`, which is user mode, and commands like `show running-config` need \
             enable mode. Give an enable secret (CLI: --enable), or allow user mode (CLI: --user-mode)"
        ),
        other => panic!("expected EnableRequired, got {:?}", other.map(|_| ())),
    }
    // Nothing was typed beyond the newlines that find the prompt.
    assert!(fake.received().iter().all(String::is_empty), "{:?}", fake.received());

    // Staying in user mode is possible, but has to be asked for.
    let device = Device::connect(options(&fake, "cisco_ios").allow_user_mode(true))
        .await
        .unwrap();
    assert_eq!(device.base_prompt(), "RTR-1");
    assert!(!fake.received().contains(&"enable".to_string()));
}

#[tokio::test]
async fn wrong_enable_secret_fails_without_leaking_it() {
    let fake = start(user_mode_spec()).await;
    match Device::connect(options(&fake, "cisco_ios").enable_secret("not-the-secret")).await {
        Err(error @ Error::EnableFailed { .. }) => {
            assert_eq!(
                error.to_string(),
                "couldn't enter enable mode on 127.0.0.1: the device didn't accept the enable secret"
            );
            assert!(!format!("{error:?}").contains("not-the-secret"));
        }
        other => panic!("expected EnableFailed, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn enable_that_asks_for_no_password_and_platforms_without_enable() {
    // Arista EOS with no enable secret set: `enable` just works.
    let mut spec = user_mode_spec();
    spec.prompt = "SW-1#".into();
    spec.user_prompt = Some("SW-1>".into());
    spec.enable_secret = None;
    let fake = start(spec).await;
    let mut device = Device::connect(options(&fake, "arista_eos").enable_secret(""))
        .await
        .unwrap();
    assert_eq!(device.find_prompt().await.unwrap(), "SW-1#");

    // Junos has no enable mode. Its `>` prompt is normal, and a secret
    // meant for the Cisco boxes in the same inventory is ignored.
    let junos = start(Spec::new("ops@JUN-1> ").output("show version", "Junos: 21.4R3")).await;
    let mut device = Device::connect(options(&junos, "juniper_junos").enable_secret("En4ble-Pa55"))
        .await
        .unwrap();
    assert_eq!(device.send_command("show version").await.unwrap(), "Junos: 21.4R3");
    assert!(!junos.received().contains(&"enable".to_string()));
}
