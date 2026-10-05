//! Port of the Python `tests/test_redact.py`, plus a differential check
//! of the whole rule set against output recorded from the original.

use std::fs;
use std::path::Path;

use mw_check::collect::{Connector, Session, run_collection};
use mw_check::inventory::{DeviceSpec, Job};
use mw_check::redact::{REDACTED, scrub};

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
        mw_check::collect::get_hostname(self, "arista_eos", "192.0.2.1")
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
        device: DeviceSpec::new("arista_eos", "192.0.2.1", "u", "p"),
        commands: vec!["show running-config".to_string()],
    }];

    let folder = run_collection(
        &jobs,
        "precheck",
        dir,
        "2026-01-01_00-00",
        redact_secrets,
        &FakeConnector,
    )
    .unwrap()
    .folder;

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

// --- the rules added for the review ------------------------------------
//
// One example per rule: (input, the secret that must be gone, what the
// line must read afterwards). Every value is made up. Each secret is
// unique so "not in the output" can't pass by luck. Same cases as
// CORPUS in the Python tests/test_redact.py.
const CORPUS: &[(&str, &str, &str)] = &[
    // Arista type 8a (AES-256-GCM) on password, secret, and key
    (
        "   neighbor 10.0.0.3 password 8a Zm9vYmFyQkdQOGE=",
        "Zm9vYmFyQkdQOGE=",
        "   neighbor 10.0.0.3 password 8a <REDACTED>",
    ),
    (
        "username eng secret 8a c2VjcmV0OGFibG9i",
        "c2VjcmV0OGFibG9i",
        "username eng secret 8a <REDACTED>",
    ),
    (
        "tacacs-server host 10.1.1.9 key 8a a2V5OGFibG9iMDE=",
        "a2V5OGFibG9iMDE=",
        "tacacs-server host 10.1.1.9 key 8a <REDACTED>",
    ),
    // Plain, untyped secrets
    (
        "      key-string PlainChainKey1",
        "PlainChainKey1",
        "      key-string <REDACTED>",
    ),
    (
        "   ip ospf authentication-key PlainOspf2",
        "PlainOspf2",
        "   ip ospf authentication-key <REDACTED>",
    ),
    (
        "crypto isakmp key PlainIsakmp3 address 192.0.2.1",
        "PlainIsakmp3",
        "crypto isakmp key <REDACTED> address 192.0.2.1",
    ),
    (
        "crypto isakmp key 6 TypedIsakmp4 address 192.0.2.2",
        "TypedIsakmp4",
        "crypto isakmp key 6 <REDACTED> address 192.0.2.2",
    ),
    (" pre-shared-key PlainPsk5", "PlainPsk5", " pre-shared-key <REDACTED>"),
    (
        " pre-shared-key 0 TypedPsk6",
        "TypedPsk6",
        " pre-shared-key 0 <REDACTED>",
    ),
    (
        "  pre-shared-key local 6 LocalPsk7",
        "LocalPsk7",
        "  pre-shared-key local 6 <REDACTED>",
    ),
    // SNMP
    (
        "snmp-server host 10.0.0.9 version 2c TrapComm8",
        "TrapComm8",
        "snmp-server host 10.0.0.9 version 2c <REDACTED>",
    ),
    (
        "snmp-server host 10.0.0.9 vrf MGMT traps version 2c TrapComm9 udp-port 162",
        "TrapComm9",
        "snmp-server host 10.0.0.9 vrf MGMT traps version 2c <REDACTED> udp-port 162",
    ),
    (
        "snmp-server host 10.0.0.9 OldComm10",
        "OldComm10",
        "snmp-server host 10.0.0.9 <REDACTED>",
    ),
    (
        "snmp-server community ReadComm11 RO",
        "ReadComm11",
        "snmp-server community <REDACTED> RO",
    ),
    // NTP
    (
        "ntp authentication-key 5 md5 PlainNtp12",
        "PlainNtp12",
        "ntp authentication-key 5 md5 <REDACTED>",
    ),
    (
        "ntp authentication-key 6 md5 7 TypedNtp13",
        "TypedNtp13",
        "ntp authentication-key 6 md5 7 <REDACTED>",
    ),
    // OSPF / IS-IS / BGP / HSRP / VRRP
    (
        " ip ospf message-digest-key 1 md5 PlainMd14",
        "PlainMd14",
        " ip ospf message-digest-key 1 md5 <REDACTED>",
    ),
    (
        " ip ospf message-digest-key 2 md5 7 TypedMd15",
        "TypedMd15",
        " ip ospf message-digest-key 2 md5 7 <REDACTED>",
    ),
    (
        " neighbor 192.0.2.7 password PlainBgp16",
        "PlainBgp16",
        " neighbor 192.0.2.7 password <REDACTED>",
    ),
    (
        " isis password PlainIsis17 level-2",
        "PlainIsis17",
        " isis password <REDACTED> level-2",
    ),
    (
        "   isis authentication key 7 TypedIsis18",
        "TypedIsis18",
        "   isis authentication key 7 <REDACTED>",
    ),
    (
        " standby 10 authentication PlainHsrp19",
        "PlainHsrp19",
        " standby 10 authentication <REDACTED>",
    ),
    (
        " standby 11 authentication text TextHsrp20",
        "TextHsrp20",
        " standby 11 authentication text <REDACTED>",
    ),
    (
        " standby 12 authentication md5 key-string 7 Md5Hsrp21",
        "Md5Hsrp21",
        " standby 12 authentication md5 key-string 7 <REDACTED>",
    ),
    (
        " vrrp 20 authentication text TextVrrp22",
        "TextVrrp22",
        " vrrp 20 authentication text <REDACTED>",
    ),
    (
        " vrrp 21 authentication PlainVrrp23",
        "PlainVrrp23",
        " vrrp 21 authentication <REDACTED>",
    ),
    // Junos
    (
        "            secret \"$9$JunosRad24abc\"; ## SECRET-DATA",
        "JunosRad24abc",
        "            secret <REDACTED>; ## SECRET-DATA",
    ),
    (
        "    authentication-key \"$9$JunosBgp25abc\";",
        "JunosBgp25abc",
        "    authentication-key <REDACTED>;",
    ),
    (
        "        pre-shared-key ascii-text \"$9$JunosPsk26abc\";",
        "JunosPsk26abc",
        "        pre-shared-key ascii-text <REDACTED>;",
    ),
    (
        "            encrypted-password \"$6$JunosUser27$abcdefghijk\";",
        "JunosUser27",
        "            encrypted-password <REDACTED>;",
    ),
    // PAN-OS XML
    (
        "<snmp-community-string>XmlComm28</snmp-community-string>",
        "XmlComm28",
        "<snmp-community-string><REDACTED></snmp-community-string>",
    ),
    (
        "      <phash>$1$XmlHash29$abcdefgh</phash>",
        "XmlHash29",
        "      <phash><REDACTED></phash>",
    ),
    (
        "<password>XmlPass30</password>",
        "XmlPass30",
        "<password><REDACTED></password>",
    ),
    (
        "<pre-shared-key><key>-AQ==XmlKey31abc=</key></pre-shared-key>",
        "XmlKey31abc",
        "<pre-shared-key><key><REDACTED></key></pre-shared-key>",
    ),
    (
        "<secret>XmlSecret32</secret>",
        "XmlSecret32",
        "<secret><REDACTED></secret>",
    ),
    (
        "<pre-shared-key>XmlPsk33</pre-shared-key>",
        "XmlPsk33",
        "<pre-shared-key><REDACTED></pre-shared-key>",
    ),
    // PAN-OS set format
    (
        "set deviceconfig system snmp-setting access-setting version v2c snmp-community-string SetComm34",
        "SetComm34",
        "set deviceconfig system snmp-setting access-setting version v2c snmp-community-string <REDACTED>",
    ),
    (
        "set mgt-config users ops phash $1$SetHash35$abcdefgh",
        "SetHash35",
        "set mgt-config users ops phash <REDACTED>",
    ),
    (
        "set shared local-user-database user u1 password SetPass36",
        "SetPass36",
        "set shared local-user-database user u1 password <REDACTED>",
    ),
];

// IOS / IOS-XE block form: the key sits on its own line under the header.
const IOS_XE_BLOCKS: &str = "\
tacacs server TAC-1
 address ipv4 192.0.2.40
 key 7 BlockTac37
!
tacacs server TAC-2
 address ipv4 192.0.2.41
 key BlockTac38
radius server RAD-1
 address ipv4 192.0.2.50 auth-port 1812 acct-port 1813
 key 6 BlockRad39
 key 0 BlockRad40
!
key chain KC
 key 1
  key-string 7 ChainKey41
interface Tunnel1
 tunnel key 4242
";

const PEM_KEY_BODY: [&str; 2] = [
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7fakekeyline1",
    "q8wFakeKeyLine2Zm9vYmFyYmF6cXV4Y29ycmVjdGhvcnNlYmF0dGVyeXN0YXBs",
];

fn pem_text() -> String {
    [
        "crypto key export:",
        "-----BEGIN RSA PRIVATE KEY-----",
        PEM_KEY_BODY[0],
        PEM_KEY_BODY[1],
        "-----END RSA PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "MIIDdzCCAl+gAwIBAgIEPublicCertLineStays",
        "-----END CERTIFICATE-----",
        "after the key",
    ]
    .join("\n")
}

#[test]
fn corpus_rules() {
    for (line, secret, expected) in CORPUS {
        let cleaned = scrub(line);

        assert!(!cleaned.contains(secret), "{line}");
        assert_eq!(&cleaned, expected, "{line}");
        // Idempotent: a second run changes nothing.
        assert_eq!(scrub(&cleaned), cleaned, "{line}");
    }
}

#[test]
fn no_corpus_secret_survives_together() {
    let lines: Vec<&str> = CORPUS.iter().map(|(line, _, _)| *line).collect();
    let text = format!("{}\n{IOS_XE_BLOCKS}{}", lines.join("\n"), pem_text());
    let cleaned = scrub(&text);

    for (_, secret, _) in CORPUS {
        assert!(!cleaned.contains(secret), "{secret}");
    }

    for secret in ["BlockTac37", "BlockTac38", "BlockRad39", "BlockRad40", "ChainKey41"]
        .iter()
        .chain(PEM_KEY_BODY.iter())
    {
        assert!(!cleaned.contains(secret), "{secret}");
    }

    assert_eq!(scrub(&cleaned), cleaned);
}

#[test]
fn ios_xe_server_block_keys_are_redacted_and_key_numbers_are_not() {
    let scrubbed = scrub(IOS_XE_BLOCKS);
    let cleaned: Vec<&str> = scrubbed.lines().collect();

    assert!(cleaned.contains(&" key 7 <REDACTED>"));
    assert!(cleaned.contains(&" key <REDACTED>"));
    assert!(cleaned.contains(&" key 6 <REDACTED>"));
    assert!(cleaned.contains(&" key 0 <REDACTED>"));
    // Outside a server block, a bare "key N" is a key number or a GRE
    // tunnel key, and both must survive.
    assert!(cleaned.contains(&" key 1"));
    assert!(cleaned.contains(&" tunnel key 4242"));
    assert!(cleaned.contains(&" address ipv4 192.0.2.40"));
}

#[test]
fn pem_private_key_block_is_redacted_and_certificate_is_kept() {
    let scrubbed = scrub(&pem_text());

    assert_eq!(
        scrubbed.lines().collect::<Vec<_>>(),
        [
            "crypto key export:",
            "-----BEGIN RSA PRIVATE KEY-----",
            REDACTED,
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "MIIDdzCCAl+gAwIBAgIEPublicCertLineStays",
            "-----END CERTIFICATE-----",
            "after the key",
        ]
    );
}

#[test]
fn pem_private_key_inside_a_quoted_value_or_on_one_line() {
    let quoted = "set shared certificate C private-key \"-----BEGIN PRIVATE KEY-----\nQuotedKeyBody42\n-----END PRIVATE KEY-----\"\nnext";
    let cleaned = scrub(quoted);

    assert!(!cleaned.contains("QuotedKeyBody42"));
    assert!(cleaned.ends_with("\nnext"));
    assert_eq!(scrub(&cleaned), cleaned);

    let one_line = "key: -----BEGIN EC PRIVATE KEY-----OneLineBody43-----END EC PRIVATE KEY----- done";
    assert_eq!(
        scrub(one_line),
        "key: -----BEGIN EC PRIVATE KEY-----<REDACTED>-----END EC PRIVATE KEY----- done"
    );
}

#[test]
fn a_cut_off_pem_key_is_redacted_to_the_end() {
    let cleaned = scrub("-----BEGIN OPENSSH PRIVATE KEY-----\nCutOffBody44\nCutOffBody45");

    assert!(!cleaned.contains("CutOffBody"));
}

#[test]
fn lookalikes_are_left_alone() {
    for line in [
        " vrrp 10 authentication md5 key-chain VRRP-CHAIN",
        " standby 10 authentication md5 key-chain HSRP-CHAIN",
        "snmp-server host 10.0.0.9 version 3 priv snmpuser",
        "   authentication-key-chain BGP-CHAIN;",
        "crypto isakmp policy 10",
        " authentication pre-share",
        "<public-key>AAAAB3NzaC1yc2EAAAADAQAB</public-key>",
    ] {
        assert_eq!(scrub(line), line, "{line}");
    }
}

/// The secrets that need the lines around them (IOS-XE server blocks
/// and PEM private keys), scrubbed as one text, against what the Python
/// `redact.scrub` wrote for the same text. A second run changes nothing.
#[test]
fn block_rules_match_the_python_output() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures_collect");
    let corpus = fs::read_to_string(dir.join("redact_blocks_corpus.txt")).unwrap();
    let expected = fs::read_to_string(dir.join("redact_blocks_expected.txt")).unwrap();

    let cleaned = scrub(&corpus);
    assert_eq!(cleaned, expected);
    assert_eq!(scrub(&cleaned), cleaned);
    assert_ne!(corpus, expected, "the corpus should contain secrets");
}

/// The whole single-line corpus, scrubbed twice: the second run must
/// change nothing.
#[test]
fn the_python_corpus_is_idempotent() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures_collect");
    let expected = fs::read_to_string(dir.join("redact_expected.txt")).unwrap();

    assert_eq!(scrub(&expected), expected);
}
