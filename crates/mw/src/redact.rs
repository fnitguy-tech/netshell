//! Strip passwords, hashes and other secrets from captured output.
//! Port of the Python `redact.py`: same rules, same `<REDACTED>` marker.
//!
//! Off by default. `mw before` / `post` enable it with
//! `-r`, and the collector then runs every command's
//! output through [`scrub`] before it is written to disk, so the
//! capture files, the zips and every report built from them never
//! contain a credential.
//!
//! Each rule keeps the keyword and any type marker (`secret sha512`,
//! `password 7`, `phash`) and replaces only the value with
//! `<REDACTED>`. The line stays recognisable in a diff: a password that
//! was added, moved or removed is still visible as a change; only its
//! value is gone. A password that was merely rotated to a different
//! value is invisible after redaction - that is the trade-off the flag
//! makes.
//!
//! The rules are written for the platforms the inventory ships with
//! (Arista EOS and PAN-OS set-format config) plus the common IOS-style
//! forms, and two catch-alls run last regardless of keyword: anything
//! that looks like a crypt(3) hash (`$6$...`, `$1$...`) and anything
//! that looks like a PAN-OS encrypted blob (`-AQ==...`).
//!
//! The Python rules guard the value with two negative lookaheads,
//! which the `regex` crate does not support. Each keyword rule is
//! therefore compiled without them and the guard is applied by hand at
//! the value position, backtracking the way the Python engine would
//! (see [`KeywordRule::apply`]).

use std::sync::LazyLock;

use regex::{Captures, Regex};

pub const REDACTED: &str = "<REDACTED>";

// Type markers that may sit between the keyword and the value and are
// kept so the line still says what kind of secret it carried:
// 0/5/7/8/9 (IOS/EOS encryption types), 6 (IOS AES), sha512/sha256/md5
// (EOS hashed), md7 (EOS encrypted MD5 key).
const TYPE_WORDS: &str = r"(?:0|5|6|7|8|9|sha512|sha256|sha|md5|md7)";

// One value: a quoted string (PAN-OS set-format quotes values that
// contain spaces) or a run of non-space characters. Never a type marker
// that is followed by more text, and never a value an earlier pass
// already redacted, so overlapping rules and repeated runs are
// idempotent ("secret sha512 <REDACTED>" must not become
// "secret <REDACTED> <REDACTED>"). The two "never" clauses are the
// Python lookaheads, checked by `value_allowed` instead.
const VALUE: &str = r#"("[^"]*"|'[^']*'|\S+)"#;

/// The Python `(?!<REDACTED>)(?!TYPE_WORDS\s)` lookaheads, applied to
/// the text from the value position onwards.
fn value_allowed(rest: &str) -> bool {
    static TYPE_AHEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^{TYPE_WORDS}\s")).unwrap());
    !rest.starts_with(REDACTED) && !TYPE_AHEAD.is_match(rest)
}

/// Free-text lines are left to the catch-alls only, so "description
/// password reset server" is not mangled by the keyword rules.
static FREE_TEXT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:description|comment|banner)\b").unwrap());

/// One keyword rule: `pattern` is `(prefix)VALUE`, where group 1 is
/// everything up to and including the type marker and group 2 the
/// value. The replacement keeps group 1 and drops the value.
pub struct KeywordRule {
    pattern: Regex,
    /// For a rule whose prefix contains a lazy `.*?`: the part after it,
    /// so the lazy match can be extended past a value the guard rejects
    /// the way a backtracking engine would.
    tail: Option<Regex>,
}

impl KeywordRule {
    fn new(prefix: &str) -> KeywordRule {
        KeywordRule {
            pattern: Regex::new(&format!("({prefix}){VALUE}")).unwrap(),
            tail: None,
        }
    }

    fn with_lazy_tail(prefix: &str, tail: &str) -> KeywordRule {
        KeywordRule {
            pattern: Regex::new(&format!("({prefix}){VALUE}")).unwrap(),
            tail: Some(Regex::new(&format!("({tail}){VALUE}")).unwrap()),
        }
    }

    /// `pattern.sub(r"\1<REDACTED>", line)` with the value guard.
    ///
    /// Scans like Python's `re.sub`: a match whose value fails the
    /// guard is not a match at all, and the search resumes one
    /// character later. The optional type marker never offers an
    /// alternative match at the same start (if the value after the
    /// marker is rejected, the marker itself is rejected as a value
    /// too), so this is exact for every rule but the one with a lazy
    /// `.*?`, whose extension is replayed through `tail`.
    pub fn apply(&self, line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut copied = 0;
        let mut search_from = 0;

        while search_from <= line.len() {
            let Some(caps) = self.pattern.captures_at(line, search_from) else {
                break;
            };
            let start = caps.get(0).unwrap().start();

            match self.accept(line, &caps) {
                Some((end, prefix_end)) => {
                    out.push_str(&line[copied..prefix_end]);
                    out.push_str(REDACTED);
                    copied = end;
                    search_from = end;
                }
                None => {
                    search_from = start + line[start..].chars().next().map_or(1, char::len_utf8);
                }
            }
        }

        out.push_str(&line[copied..]);
        out
    }

    /// `(match end, end of the kept prefix)` for an accepted match at
    /// the start of `caps`, trying the lazy extension when there is one.
    fn accept(&self, line: &str, caps: &Captures) -> Option<(usize, usize)> {
        let whole = caps.get(0).unwrap();
        let value = caps.get(2).unwrap();

        if value_allowed(&line[value.start()..]) {
            return Some((whole.end(), value.start()));
        }

        let tail = self.tail.as_ref()?;
        let prefix = caps.get(1).unwrap();
        // The lazy `.*?` grows one character at a time and the tail is
        // retried at each position, so the next candidate is the next
        // tail match after the one just rejected.
        let mut from = prefix.start() + 1;

        while from <= line.len() {
            let tail_caps = tail.captures_at(line, from)?;
            let tail_match = tail_caps.get(0).unwrap();
            let tail_value = tail_caps.get(2).unwrap();

            if value_allowed(&line[tail_value.start()..]) {
                return Some((tail_match.end(), tail_value.start()));
            }

            from = tail_match.start() + 1;
        }

        None
    }
}

/// The keyword rules, in the order the Python runs them.
pub static KEYWORD_RULES: LazyLock<Vec<KeywordRule>> = LazyLock::new(|| {
    let type_marker = format!(r"(?:{TYPE_WORDS}\s+)?");

    vec![
        // Arista EOS / IOS-style:
        //   username admin secret sha512 $6$...   enable password sha512 ...
        //   neighbor 10.0.0.1 password 7 ...      enable secret 5 $1$...
        KeywordRule::new(&format!(r"\b(?:bind-)?(?:secret|password)\s+{type_marker}")),
        //   tacacs-server host 10.0.0.1 key 7 ...   radius-server key 7 ...
        //   key-string 7 ... (key chains)            shared-key 7 ... (IPsec)
        //   ip ospf authentication-key 7 ...         isakmp key 0 ... (IOS)
        KeywordRule::new(
            r"\b(?:key-string|shared-key|pre-shared-key\s+key|authentication-key|authentication\s+text|isakmp\s+key|key)\s+(?:[0678]\s+)",
        ),
        //   ntp authentication-key 1 md5 7 ...   ip ospf message-digest-key 1 md7 ...
        KeywordRule::new(r"\b(?:message-digest-key|authentication-key)\s+\d+\s+(?:md5|md7|sha\S*)\s+(?:[07]\s+)?"),
        //   tacacs-server key <plain>   radius-server host 10.0.0.1 key <plain>
        KeywordRule::with_lazy_tail(
            r"\b(?:tacacs-server|radius-server)\b.*?\bkey\s+(?:[07]\s+)?",
            r"\bkey\s+(?:[07]\s+)?",
        ),
        //   snmp-server community <string> ro
        KeywordRule::new(r"\bsnmp-server\s+community\s+"),
        //   snmp-server user bob grp v3 auth sha <key> priv aes <key>
        KeywordRule::new(
            r"\b(?:auth|priv)\s+(?:md5|sha|sha224|sha256|sha384|sha512|des|3des|aes|aes128|aes192|aes256)\s+",
        ),
        // PAN-OS set-format config:
        //   set mgt-config users admin phash $1$...
        //   set network ike gateway GW authentication pre-shared-key key -AQ==...
        //   set shared server-profile radius R server S secret -AQ==...   (secret: rule above)
        //   set shared certificate C private-key -AQ==...
        //   set deviceconfig system snmp-setting ... snmp-community-string public
        //   set deviceconfig system snmp-setting ... v3 users U authpwd -AQ==... privpwd -AQ==...
        KeywordRule::new(
            r"\b(?:phash|pre-shared-key\s+key|private-key|authpwd|privpwd|passphrase|api-key|snmp-community-string|community-string|client-secret|collector-secret|shared-secret|master-key|auth-key|license-key)\s+",
        ),
    ]
});

/// Run on every line, keyword or not.
pub static CATCHALL_RULES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        //   crypt(3)-style hashes: $1$ (MD5), $5$/$6$ (SHA-256/512), $2a$/$2b$/$2y$ (bcrypt)
        Regex::new(r"\$(?:1|2[abxy]?|5|6)\$[^\s$]+(?:\$\S+)?").unwrap(),
        //   PAN-OS encrypted values (base64 blobs that always start with -AQ==)
        Regex::new(r"-AQ==\S*").unwrap(),
    ]
});

/// One line with every secret value replaced by `<REDACTED>`.
pub fn scrub_line(line: &str) -> String {
    let mut line = line.to_string();

    if !FREE_TEXT_LINE.is_match(&line) {
        for rule in KEYWORD_RULES.iter() {
            line = rule.apply(&line);
        }
    }

    for pattern in CATCHALL_RULES.iter() {
        line = pattern.replace_all(&line, REDACTED).into_owned();
    }

    line
}

/// Text with every secret value replaced by `<REDACTED>`; idempotent.
///
/// Works line by line; a line that is already clean comes back
/// unchanged, so scrubbing is idempotent and never disturbs the
/// `### <command> ###` section headers the compare modules parse.
pub fn scrub(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    text.split('\n').map(scrub_line).collect::<Vec<_>>().join("\n")
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
