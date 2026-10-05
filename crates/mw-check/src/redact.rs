//! Strip passwords, hashes, and other secrets from captured output.
//! Port of the Python `redact.py`: same rules, same `<REDACTED>` marker.
//!
//! Off by default. `mw before` / `mw after` enable it with `-r`, and
//! the collector then runs every command's output through [`scrub`]
//! before it is written to disk, so the capture files, the zips, and
//! every report built from them never contain a credential.
//!
//! Each rule keeps the keyword and any type marker (`secret sha512`,
//! `password 7`, `phash`) and replaces only the value with
//! `<REDACTED>`. The line stays recognisable in a diff: a password that
//! was added, moved, or removed is still visible as a change; only its
//! value is gone. A password that was merely rotated to a different
//! value is invisible after redaction. That's the trade-off the flag
//! makes.
//!
//! The rules are written for the platforms the inventory ships with
//! (Arista EOS and PAN-OS set-format config) plus the common IOS /
//! IOS-XE, NX-OS, Junos, and PAN-OS XML forms. Catch-alls run last
//! regardless of keyword: anything that looks like a crypt(3) hash
//! (`$6$...`, `$1$...`), a Junos or IOS `$9$` / `$8$` value, or a
//! PAN-OS encrypted blob (`-AQ==...`).
//!
//! Most rules look at one line. Two things need more than one, and
//! [`scrub`] handles them before the line rules run:
//!
//! - A PEM private key runs over many lines. The BEGIN and END lines
//!   stay and everything between them becomes one `<REDACTED>` line.
//! - IOS-XE puts a server's key on its own line under a header, where a
//!   bare `key 7 ...` looks just like a key-chain key number:
//!
//!   ```text
//!   radius server RAD-1
//!    address ipv4 192.0.2.50 auth-port 1812 acct-port 1813
//!    key 7 <REDACTED>
//!   ```
//!
//!   So that line is only redacted inside a `tacacs server NAME` or
//!   `radius server NAME` block.
//!
//! Running [`scrub`] on its own output changes nothing. Every rule
//! refuses a value that is already `<REDACTED>`.
//!
//! # Why fancy-regex
//!
//! The Python rules guard each value with negative lookaheads, and the
//! XML rule uses a backreference. The `regex` crate has neither.
//! `fancy-regex` has both and backtracks the way Python's `re` does,
//! so each pattern below is the Python pattern, character for
//! character. That keeps the two tools' output identical without a
//! hand-written copy of the matching logic.

use std::sync::LazyLock;

use fancy_regex::Regex as Fancy;
use regex::Regex;

pub const REDACTED: &str = "<REDACTED>";

// Type markers that may sit between the keyword and the value and are
// kept so the line still says what kind of secret it carried:
// 0/5/7/8/9 (IOS/EOS encryption types), 3/4 (NX-OS and old IOS), 6 (IOS
// AES), 8a (EOS AES-256-GCM: "password 8a <blob>"), sha512/sha256/md5
// (EOS hashed), md7 (EOS encrypted MD5 key), encrypted/clear (IOS-XR).
// "8a" has to come before "8": tried the other way round, "8" would
// never match in front of the "a" and the blob would be left behind
// with only the "8a" marker redacted.
const TYPE_WORDS: &str = r"(?:0|3|4|5|6|7|8a|8|9|sha512|sha256|sha|md5|md7|encrypted|clear)";

/// `(?:TYPE_WORDS\s+)?`: an optional type marker.
fn type_marker() -> String {
    format!(r"(?:{TYPE_WORDS}\s+)?")
}

/// One value: a quoted string (PAN-OS set-format quotes values that
/// contain spaces) or a run of non-space characters. Never a type
/// marker that is followed by more text, and never a value an earlier
/// pass already redacted, so overlapping rules and repeated runs are
/// idempotent (`secret sha512 <REDACTED>` must not become
/// `secret <REDACTED> <REDACTED>`).
fn value() -> String {
    format!(r#"(?!<REDACTED>)(?!{TYPE_WORDS}\s)("[^"]*"|'[^']*'|\S+)"#)
}

/// Free-text lines are left to the catch-alls only, so "description
/// password reset server" is not mangled by the keyword rules.
static FREE_TEXT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:description|comment|banner)\b").unwrap());

/// One rule: a pattern and what each match becomes (`${1}` is the kept
/// prefix, up to and including the type marker).
pub struct Rule {
    pattern: Fancy,
    replacement: &'static str,
}

impl Rule {
    fn new(pattern: &str, replacement: &'static str) -> Rule {
        Rule {
            pattern: Fancy::new(pattern).unwrap_or_else(|error| panic!("redaction rule {pattern:?}: {error}")),
            replacement,
        }
    }

    /// `pattern.sub(replacement, line)`.
    ///
    /// fancy-regex gives up on a line that needs too much backtracking.
    /// No real config line gets near that limit. If one ever does, the
    /// whole line is redacted: losing a line of evidence is better than
    /// writing a secret to disk.
    pub fn apply(&self, line: &str) -> String {
        match self.pattern.try_replacen(line, 0, self.replacement) {
            Ok(replaced) => replaced.into_owned(),
            Err(_) => REDACTED.to_string(),
        }
    }
}

const KEEP_PREFIX: &str = "${1}<REDACTED>";

/// The keyword rules, in the order the Python runs them.
pub static KEYWORD_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let type_marker = type_marker();
    let value = value();

    vec![
        // Arista EOS / IOS-style, and Junos (the value may be quoted):
        //   username admin secret sha512 $6$...   enable password sha512 ...
        //   neighbor 10.0.0.1 password 7 ...      enable secret 5 $1$...
        //   neighbor 10.0.0.1 password 8a ...     isis password ...   area-password ...
        //   secret "$9$..."; (Junos)              encrypted-password "$6$..."; (Junos)
        Rule::new(
            &format!(r"(\b(?:bind-)?(?:secret|password)\s+{type_marker}){value}"),
            KEEP_PREFIX,
        ),
        //   ntp authentication-key 1 md5 7 ...   ip ospf message-digest-key 1 md7 ...
        //   ntp authentication-key 1 md5 <plain>
        // Runs before the plain authentication-key rule below, which
        // would otherwise take the key number "1" for the secret.
        Rule::new(
            &format!(
                r"(\b(?:message-digest-key|authentication-key)\s+\d+\s+(?:md5|md7|sha\S*)\s+{type_marker}){value}"
            ),
            KEEP_PREFIX,
        ),
        // Keywords that always introduce a secret, with or without a
        // type marker:
        //   key-string 7 ...            key-string <plain>            (key chains)
        //   ip ospf authentication-key 7 ...   ip ospf authentication-key <plain>
        //   authentication-key "$9$...";       (Junos)
        //   crypto isakmp key 0 ... address 192.0.2.1    crypto isakmp key <plain> address ...
        //   pre-shared-key <plain>      pre-shared-key local 0 ...    (IOS IKEv2 keyring)
        //   pre-shared-key ascii-text "$9$...";          (Junos)
        //   pre-shared-key key -AQ==...                  (PAN-OS set format)
        //   isis authentication key <plain>    authentication text <plain>   (HSRP/VRRP, NX-OS)
        Rule::new(
            &format!(
                concat!(
                    r"(\b(?:key-string|shared-key|authentication-key|isakmp\s+key|authentication\s+key",
                    r"|authentication\s+text|pre-shared-key)\s+",
                    r"(?:(?:key|local|remote|ascii-text|hexadecimal|hex)\s+)?",
                    // Never take the key number or one of the words
                    // above for the secret. Without this, a second run
                    // would back up and redact "key" in
                    // "pre-shared-key key <REDACTED>".
                    r"(?!\d+\s+(?:md5|md7|sha\S*)\s)(?!(?:key|local|remote|ascii-text|hexadecimal|hex)\s)",
                    "{type_marker}){value}"
                ),
                type_marker = type_marker,
                value = value
            ),
            KEEP_PREFIX,
        ),
        // A bare "key" is a secret only when a type marker follows it:
        //   tacacs-server host 10.0.0.1 key 7 ...   key 8a ...
        // Without one it is a key-chain key number ("key 1") or a GRE
        // tunnel key ("tunnel key 1234"), and those stay.
        Rule::new(&format!(r"(\bkey\s+(?:0|6|7|8a|8)\s+){value}"), KEEP_PREFIX),
        //   tacacs-server key <plain>   radius-server host 10.0.0.1 key <plain>
        //   server-private 10.0.0.1 key <plain>   (IOS "aaa group server" block)
        Rule::new(
            &format!(r"(\b(?:tacacs-server|radius-server|server-private)\b.*?\bkey\s+{type_marker}){value}"),
            KEEP_PREFIX,
        ),
        //   snmp-server community <string> ro
        Rule::new(&format!(r"(\bsnmp-server\s+community\s+){value}"), KEEP_PREFIX),
        //   snmp-server host 10.0.0.9 version 2c <community>
        //   snmp-server host 10.0.0.9 vrf MGMT traps version 2c <community> udp-port 162
        // v1 and v2c only: after "version 3" comes a user name, not a secret.
        Rule::new(
            &format!(r"(\bsnmp-server\s+host\s+.*?\bversion\s+(?:1|2c)\s+){value}"),
            KEEP_PREFIX,
        ),
        //   snmp-server host 10.0.0.9 <community>      snmp-server host 10.0.0.9 traps <community>
        // The older form with no "version". Skipped when the next word
        // is an option, so the line above keeps its job.
        Rule::new(
            &format!(
                concat!(
                    r"(\bsnmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?)",
                    r"(?!(?:vrf|use-vrf|traps|informs|version|udp-port|source-interface|filter-vrf)\b)",
                    "{value}"
                ),
                value = value
            ),
            KEEP_PREFIX,
        ),
        //   snmp-server user bob grp v3 auth sha <key> priv aes <key>
        Rule::new(
            &format!(
                r"(\b(?:auth|priv)\s+(?:md5|sha|sha224|sha256|sha384|sha512|des|3des|aes|aes128|aes192|aes256)\s+){value}"
            ),
            KEEP_PREFIX,
        ),
        // HSRP / VRRP plain-text authentication:
        //   standby 10 authentication <plain>      standby 10 authentication text <plain>
        //   vrrp 10 authentication text <plain>    vrrp 10 peer authentication <plain>  (EOS)
        // "md5 key-string ..." is left for the key-string rule, and
        // "md5 key-chain NAME" names a chain, which is not a secret.
        Rule::new(
            &format!(
                concat!(
                    r"(\b(?:standby|vrrp)\s+\d+\s+(?:peer\s+)?authentication\s+(?:text\s+)?)",
                    r"(?!(?:md5|ietf-md5|key-chain|key-string|text)\b)",
                    "{type_marker}{value}"
                ),
                type_marker = type_marker,
                value = value
            ),
            KEEP_PREFIX,
        ),
        // PAN-OS set-format config:
        //   set mgt-config users admin phash $1$...
        //   set network ike gateway GW authentication pre-shared-key key -AQ==...
        //   set shared server-profile radius R server S secret -AQ==...   (secret: rule above)
        //   set shared certificate C private-key -AQ==...
        //   set deviceconfig system snmp-setting ... snmp-community-string public
        //   set deviceconfig system snmp-setting ... v3 users U authpwd -AQ==... privpwd -AQ==...
        Rule::new(
            &format!(
                concat!(
                    r"(\b(?:phash|private-key|authpwd|privpwd|passphrase|api-key",
                    r"|snmp-community-string|community-string|client-secret|collector-secret|shared-secret",
                    r"|master-key|auth-key|license-key)\s+)",
                    "{value}"
                ),
                value = value
            ),
            KEEP_PREFIX,
        ),
        // PAN-OS XML config (the default output format, and what an export holds):
        //   <phash>$1$...</phash>      <snmp-community-string>public</snmp-community-string>
        //   <pre-shared-key><key>-AQ==...</key></pre-shared-key>      <secret>-AQ==...</secret>
        // The value may not contain "<", so a second run sees
        // <REDACTED> between the tags and leaves it alone.
        Rule::new(
            concat!(
                r"(<(snmp-community-string|community-string|phash|password|bind-password|key|secret|pre-shared-key",
                r"|private-key|authpwd|privpwd|passphrase|api-key|auth-key)>)[^<]+(?=</\2>)"
            ),
            KEEP_PREFIX,
        ),
    ]
});

/// Run on every line, keyword or not.
pub static CATCHALL_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        //   crypt(3)-style hashes: $1$ (MD5), $5$/$6$ (SHA-256/512), $2a$/$2b$/$2y$ (bcrypt)
        Rule::new(r"\$(?:1|2[abxy]?|5|6)\$[^\s$]+(?:\$\S+)?", REDACTED),
        //   Junos "$9$..." (reversible) and "$8$..." (AES), IOS type 8/9
        //   and "$14$" hashes. Junos quotes the value and ends the line
        //   with ";", so the match stops at a quote or semicolon and
        //   leaves them.
        Rule::new(r#"\$(?:8|9|14)\$[^\s";<]+"#, REDACTED),
        //   PAN-OS encrypted values (base64 blobs that always start with -AQ==)
        Rule::new(r"-AQ==[^\s<]*", REDACTED),
        //   A whole PEM private key that sits on one line
        Rule::new(
            r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
            "${1}<REDACTED>${2}",
        ),
    ]
});

// A PEM private key block: OpenSSH, RSA, EC, PKCS#8, encrypted or not.
// Only labels that say PRIVATE KEY. A certificate is public and stays;
// a private key pasted inside a certificate bundle is still caught,
// because the rule goes by the key's own BEGIN line wherever it sits.
static PEM_KEY_BEGIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap());
static PEM_KEY_END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-----END [A-Z0-9 ]*PRIVATE KEY-----").unwrap());

// IOS-XE server blocks whose indented "key" line is a secret.
static KEY_BLOCK_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(\s*)(?:tacacs|radius)\s+server\s+\S+").unwrap());
static KEY_BLOCK_LINE: LazyLock<Rule> =
    LazyLock::new(|| Rule::new(&format!(r"^(\s+key\s+{}){}", type_marker(), value()), KEEP_PREFIX));

/// One line with every secret value replaced by `<REDACTED>`.
pub fn scrub_line(line: &str) -> String {
    let mut line = line.to_string();

    if !FREE_TEXT_LINE.is_match(&line) {
        for rule in KEYWORD_RULES.iter() {
            line = rule.apply(&line);
        }
    }

    for rule in CATCHALL_RULES.iter() {
        line = rule.apply(&line);
    }

    line
}

/// Text with every secret value replaced by `<REDACTED>`; idempotent.
///
/// A line that is already clean comes back unchanged, so scrubbing
/// never disturbs the `### <command> ###` section headers the compare
/// modules parse.
///
/// Mostly line by line. Two kinds of secret need the lines around them
/// (see the module docs): PEM private key blocks, and the `key` line
/// inside an IOS-XE `tacacs server` / `radius server` block.
pub fn scrub(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    let mut cleaned: Vec<String> = Vec::new();
    let mut in_pem_key = false;
    // Indent of the "tacacs server" / "radius server" header we are
    // under, or None. The block ends at the first line indented no
    // deeper than its header.
    let mut key_block_indent: Option<usize> = None;

    for line in text.split('\n') {
        if in_pem_key {
            if let Some(end) = PEM_KEY_END.find(line) {
                in_pem_key = false;
                // Keep the END marker and whatever follows it (a
                // closing quote), drop any key material in front of it.
                cleaned.push(scrub_line(&line[end.start()..]));
            }

            continue;
        }

        if let Some(begin) = PEM_KEY_BEGIN.find(line)
            && PEM_KEY_END.find_at(line, begin.end()).is_none()
        {
            in_pem_key = true;
            // The BEGIN line is kept as it is, minus anything after the
            // marker. The keyword rules are skipped for it: they would
            // read the marker itself as a value and mangle it.
            cleaned.push(line[..begin.end()].to_string());
            cleaned.push(REDACTED.to_string());
            continue;
        }

        let mut line = line.to_string();

        if let Some(block_indent) = key_block_indent {
            let indent = line.chars().count() - line.trim_start().chars().count();

            if !line.trim().is_empty() && indent > block_indent {
                line = KEY_BLOCK_LINE.apply(&line);
            } else {
                key_block_indent = None;
            }
        }

        if let Some(block) = KEY_BLOCK_START.captures(&line) {
            key_block_indent = Some(block[1].chars().count());
        }

        cleaned.push(scrub_line(&line));
    }

    cleaned.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_marker_is_kept_and_not_doubled() {
        assert_eq!(
            scrub_line("username ops secret sha512 abc"),
            "username ops secret sha512 <REDACTED>"
        );
        assert_eq!(
            scrub_line("username ops secret sha512 <REDACTED>"),
            "username ops secret sha512 <REDACTED>"
        );
        // A type word with nothing after it is the value.
        assert_eq!(scrub_line("enable secret sha512"), "enable secret <REDACTED>");
    }

    #[test]
    fn lazy_rule_skips_past_an_already_redacted_key() {
        let line = "radius-server host 10.1.1.2 key 7 <REDACTED> auth-port 1812 key later";
        assert_eq!(
            scrub_line(line),
            "radius-server host 10.1.1.2 key 7 <REDACTED> auth-port 1812 key <REDACTED>"
        );
        let once = scrub_line("tacacs-server key supersecret");
        assert_eq!(scrub_line(&once), once);
    }

    #[test]
    fn quoted_values_are_one_value() {
        assert_eq!(
            scrub_line("snmp-community-string \"my community\" ro"),
            "snmp-community-string <REDACTED> ro"
        );
    }

    #[test]
    fn free_text_still_gets_the_catchalls() {
        assert_eq!(
            scrub_line("   description password reset server"),
            "   description password reset server"
        );
        assert_eq!(
            scrub_line("   description hash $6$abc$def"),
            "   description hash <REDACTED>"
        );
    }
}
