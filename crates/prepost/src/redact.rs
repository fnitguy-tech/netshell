//! Strip passwords, hashes and other secrets from captured output.
//! Port of the Python `redact.py`: same rules, same `<REDACTED>` marker.

pub const REDACTED: &str = "<REDACTED>";

/// One line with every secret value replaced by `<REDACTED>`.
pub fn scrub_line(line: &str) -> String {
    let _ = line;
    todo!("port of redact.scrub_line()")
}

/// Text with every secret value replaced by `<REDACTED>`; idempotent.
pub fn scrub(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    text.split('\n').map(scrub_line).collect::<Vec<_>>().join("\n")
}
