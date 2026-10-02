mod common;

use std::time::Duration;

use common::{AuthMode, Spec, start};
use netshell::{ConnectOptions, Device, Error, HostKeyPolicy, Platform};

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
    ConnectOptions::new("127.0.0.1", "admin", "secret", Platform::by_name(platform).unwrap())
        .port(device.port)
        .read_timeout(Duration::from_secs(5))
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
    let options = ConnectOptions::new("127.0.0.1", "admin", "wrong", Platform::arista_eos()).port(fake.port);
    match Device::connect(options).await {
        Err(Error::AuthFailed { user, .. }) => assert_eq!(user, "admin"),
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
        Err(Error::ReadTimeout { what, timeout, .. }) => {
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

#[tokio::test]
async fn cli_binary_writes_capture_sections_and_json() {
    let fake = start(
        Spec::new("SW-1#")
            .output("show version", "Arista")
            .output("show hostname", "Hostname: SW-1"),
    )
    .await;

    let port = fake.port;
    let run = move |extra: &'static [&'static str]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_netshell"));
        command
            .args(["--platform", "arista_eos", "--host", "127.0.0.1", "--port"])
            .arg(port.to_string())
            .args(["--username", "admin", "--password-env", "NETSHELL_TEST_PASSWORD"])
            .args(extra)
            .args(["show version", "show hostname"])
            .env("NETSHELL_TEST_PASSWORD", "secret");
        command.output().unwrap()
    };

    let sections = tokio::task::spawn_blocking(move || run(&[])).await.unwrap();
    assert!(
        sections.status.success(),
        "{}",
        String::from_utf8_lossy(&sections.stderr)
    );
    let text = String::from_utf8_lossy(&sections.stdout);
    assert!(text.contains("### show version ###\n"), "{text}");
    assert!(text.contains("\nArista\n"), "{text}");
    assert!(text.contains("### show hostname ###\n"), "{text}");

    let json = tokio::task::spawn_blocking(move || run(&["--json"])).await.unwrap();
    let text = String::from_utf8_lossy(&json.stdout);
    assert!(text.contains(r#""prompt": "SW-1""#), "{text}");
    assert!(
        text.contains(r#"{"command": "show version", "output": "Arista"}"#),
        "{text}"
    );
}
