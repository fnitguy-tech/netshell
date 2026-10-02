//! Port of the Python `tests/test_redact.py`, plus a differential check
//! of the whole rule set against output recorded from the original.

use std::fs;
use std::path::Path;

use mw::collect::{Connector, Session, run_collection};
use mw::inventory::{DeviceSpec, Job};
use mw::redact::{REDACTED, scrub};

const EOS_CONFIG: &str = "\
hostname SITE-A-SW-1
!
username admin privilege 15 role network-admin secret sha512 $6$abc123/def$hashhashhash
username ops secret 0 plaintextpass
username svc ssh-key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 svc@host
enable password sha512 $6$zzz$yyyy
!
tacacs-server host 10.1.1.1 key 7 1234ABCD
tacacs-server key supersecret
radius-server host 10.1.1.2 key 7 DEADBEEF
!
snmp-server community mycommunity ro
snmp-server user bob grp v3 localized 0x80001f auth sha 0xabc priv aes 0xdef
!
ntp authentication-key 1 md5 7 0A1B2C
!
key chain KC
   key 1
      key-string 7 CAFEBABE
!
interface Ethernet1
   description password reset server
   ip ospf authentication-key 7 ABCDEF
   ip ospf message-digest-key 1 md7 FEDCBA
!
interface Tunnel1
   tunnel key 1234
!
router bgp 65000
   neighbor 10.0.0.1 password 7 0822455D0A16
   neighbor 10.0.0.2 remote-as 65000
";

const PANOS_CONFIG: &str = "\
set mgt-config users admin phash $1$abcde$fghijklmnopq
set mgt-config password-complexity enabled yes
set network ike gateway GW authentication pre-shared-key key -AQ==abcdef0123456789==
set shared server-profile radius RAD server S1 secret -AQ==zzzz
set shared server-profile ldap L bind-password -AQ==yyyy
set shared certificate C private-key -AQ==xxxx
set shared certificate C public-key -AB==keepme
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string \"my community\"
set deviceconfig system snmp-setting access-setting version v3 users U authpwd -AQ==a privpwd -AQ==b
set network virtual-router default protocol bgp auth-profile AP secret -AQ==c
";

const SECRET_VALUES: [&str; 23] = [
    "$6$abc123/def$hashhashhash",
    "plaintextpass",
    "$6$zzz$yyyy",
    "1234ABCD",
    "supersecret",
    "DEADBEEF",
    "mycommunity",
    "0xabc",
    "0xdef",
    "0A1B2C",
    "CAFEBABE",
    "ABCDEF",
    "FEDCBA",
    "0822455D0A16",
    "$1$abcde$fghijklmnopq",
    "-AQ==abcdef0123456789==",
    "-AQ==zzzz",
    "-AQ==yyyy",
    "-AQ==xxxx",
    "my community",
    "-AQ==a",
    "-AQ==b",
    "-AQ==c",
];

fn both_configs() -> String {
    format!("{EOS_CONFIG}{PANOS_CONFIG}")
}

#[test]
fn every_secret_value_is_gone() {
    let cleaned = scrub(&both_configs());

    for value in SECRET_VALUES {
        assert!(!cleaned.contains(value), "{value}");
    }
}

#[test]
fn keyword_and_type_marker_survive() {
    let cleaned = scrub(&both_configs());
    let lines: Vec<&str> = cleaned.lines().collect();

    for expected in [
        format!("username admin privilege 15 role network-admin secret sha512 {REDACTED}"),
        format!("username ops secret 0 {REDACTED}"),
        format!("enable password sha512 {REDACTED}"),
        format!("tacacs-server host 10.1.1.1 key 7 {REDACTED}"),
        format!("tacacs-server key {REDACTED}"),
        format!("snmp-server community {REDACTED} ro"),
        format!("snmp-server user bob grp v3 localized 0x80001f auth sha {REDACTED} priv aes {REDACTED}"),
        format!("ntp authentication-key 1 md5 7 {REDACTED}"),
        format!("      key-string 7 {REDACTED}"),
        format!("   ip ospf authentication-key 7 {REDACTED}"),
        format!("   ip ospf message-digest-key 1 md7 {REDACTED}"),
        format!("   neighbor 10.0.0.1 password 7 {REDACTED}"),
        format!("set mgt-config users admin phash {REDACTED}"),
        format!("set network ike gateway GW authentication pre-shared-key key {REDACTED}"),
        format!("set shared server-profile ldap L bind-password {REDACTED}"),
        format!("set shared certificate C private-key {REDACTED}"),
        format!("set deviceconfig system snmp-setting access-setting version v2c snmp-community-string {REDACTED}"),
        format!(
            "set deviceconfig system snmp-setting access-setting version v3 users U authpwd {REDACTED} privpwd {REDACTED}"
        ),
    ] {
        assert!(lines.contains(&expected.as_str()), "missing: {expected}\n{cleaned}");
    }
}

#[test]
fn non_secret_lines_untouched() {
    let cleaned = scrub(&both_configs());
    let lines: Vec<&str> = cleaned.lines().collect();

    // Public keys, GRE tunnel keys, peers without passwords and config
    // keywords that merely contain the word "password" are not secrets.
    for expected in [
        "username svc ssh-key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 svc@host",
        "   tunnel key 1234",
        "   neighbor 10.0.0.2 remote-as 65000",
        "set mgt-config password-complexity enabled yes",
        "set shared certificate C public-key -AB==keepme",
        // Free text is left alone by the keyword rules.
        "   description password reset server",
        "hostname SITE-A-SW-1",
    ] {
        assert!(lines.contains(&expected), "missing: {expected}\n{cleaned}");
    }
}

#[test]
fn show_output_without_secrets_is_unchanged() {
    let bgp_summary = "  Neighbor        V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State  PfxRcd PfxAcc\n  10.118.9.3      4  65000          1234      1230    0    0 01:02:03 Estab  3      3\n";

    assert_eq!(scrub(bgp_summary), bgp_summary);
    assert_eq!(scrub(""), "");
}

#[test]
fn scrub_is_idempotent() {
    let once = scrub(&both_configs());

    assert_eq!(scrub(&once), once);
}

#[test]
fn section_headers_survive() {
    let capture = format!("### show running-config ###\n{}\n{EOS_CONFIG}", "-".repeat(80));

    assert!(scrub(&capture).starts_with(&format!("### show running-config ###\n{}\n", "-".repeat(80))));
}

/// Every line of the corpus scrubs to exactly what the Python
/// `redact.scrub` produced for it (recorded in `fixtures_collect/`).
/// The corpus is the two configs above, a set of edge cases around the
/// lookahead guards, and every bundled demo capture.
#[test]
fn matches_the_python_output_line_for_line() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures_collect");
    let corpus = fs::read_to_string(dir.join("redact_corpus.txt")).unwrap();
    let expected = fs::read_to_string(dir.join("redact_expected.txt")).unwrap();

    let corpus_lines: Vec<&str> = corpus.split('\n').collect();
    let expected_lines: Vec<&str> = expected.split('\n').collect();
    assert_eq!(corpus_lines.len(), expected_lines.len());

    for (input, want) in corpus_lines.iter().zip(&expected_lines) {
        assert_eq!(&scrub(input), want, "input: {input:?}");
    }

    assert_eq!(scrub(&corpus), expected);
    assert_ne!(corpus, expected, "the corpus should contain secrets");
}

struct FakeSession;

impl Session for FakeSession {
    fn hostname(&mut self) -> anyhow::Result<String> {
        mw::collect::get_hostname(self, "arista_eos", "192.0.2.1")
    }

    fn send_command(&mut self, command: &str) -> anyhow::Result<String> {
        if command == "show hostname" {
            return Ok("Hostname: SITE-A-SW-1".to_string());
        }
        Ok(EOS_CONFIG.to_string())
    }

    fn disconnect(self: Box<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}

struct FakeConnector;

impl Connector for FakeConnector {
    fn connect(&self, _device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        Ok(Box::new(FakeSession))
    }
}

fn run(dir: &Path, redact_secrets: bool) -> String {
    let jobs = vec![Job {
        device: DeviceSpec {
            device_type: "arista_eos".to_string(),
            host: "192.0.2.1".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
        },
        commands: vec!["show running-config".to_string()],
    }];

    let (folder, _zip_name) = run_collection(
        &jobs,
        "precheck",
        dir,
        "2026-01-01_00-00",
        redact_secrets,
        &FakeConnector,
    )
    .unwrap();

    fs::read_to_string(folder.join("SITE-A-SW-1.txt")).unwrap()
}

#[test]
fn collection_redacts_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let capture = run(tmp.path(), true);

    assert!(capture.contains("Secrets: redacted"));
    assert!(capture.contains("### show running-config ###"));
    for value in &SECRET_VALUES[..14] {
        assert!(!capture.contains(value), "{value}");
    }
    assert!(capture.contains(&format!("neighbor 10.0.0.1 password 7 {REDACTED}")));
}

#[test]
fn collection_is_verbatim_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let capture = run(tmp.path(), false);

    assert!(!capture.contains("Secrets: redacted"));
    assert!(capture.contains("$6$abc123/def$hashhashhash"));
}
