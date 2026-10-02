//! The capture file format.
//!
//! One text file per device per run:
//!
//! ```text
//! Hostname: SITE-A-SW-1
//! IP Address: 192.0.2.1
//! Generated: 2026-04-14 08:48:02.123456
//! Secrets: redacted              (only with --redact-secrets)
//! ================================================================================
//!
//!
//! ### show version ###
//! --------------------------------------------------------------------------------
//! <raw output>
//! ```
//!
//! Both compare views parse the `### command ###` headers to diff
//! command by command. Everything before the first header is the
//! `HEADER` section. The format is shared with the Python tool, so
//! captures from either can be compared by the other.

use std::fs;
use std::io;
use std::path::Path;

use indexmap::IndexMap;
use regex::Regex;

/// The pseudo-command holding the lines before the first section header.
pub const HEADER: &str = "HEADER";

/// `### command ###` section headers, in file order.
pub type Sections = IndexMap<String, Vec<String>>;

/// Split a capture file into `{command: [raw lines]}` (no filtering).
pub fn parse_sections(path: &Path) -> io::Result<Sections> {
    let bytes = fs::read(path)?;
    Ok(parse_sections_str(&String::from_utf8_lossy(&bytes)))
}

/// [`parse_sections`] on text already in memory.
pub fn parse_sections_str(text: &str) -> Sections {
    let mut sections = Sections::new();
    let mut current = HEADER.to_string();
    sections.insert(current.clone(), Vec::new());

    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.starts_with("### ") && line.ends_with(" ###") {
            current = line.replace("###", "").trim().to_string();
            sections.entry(current.clone()).or_default();
        } else {
            sections
                .get_mut(&current)
                .expect("current section exists")
                .push(line.to_string());
        }
    }

    // A file read with split('\n') yields one trailing empty string
    // after the final newline; Python's line iteration does not.
    if text.ends_with('\n')
        && let Some(lines) = sections.get_mut(&current)
        && lines.last().is_some_and(|l| l.is_empty())
    {
        lines.pop();
    }

    sections
}

/// The section header line for a command, as written to a capture.
pub fn section_header(command: &str) -> String {
    format!("### {command} ###")
}

/// Make a string usable as an HTML anchor id.
pub fn safe_id(value: &str) -> String {
    let re = Regex::new(r"[^a-z0-9]+").unwrap();
    re.replace_all(&value.to_lowercase(), "-").trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_section_headers() {
        let text = "Hostname: SW-1\n====\n\n\n### show version ###\n----\nArista\n\n\n### show ip bgp summary ###\n----\nrow\n";
        let sections = parse_sections_str(text);
        assert_eq!(
            sections.keys().collect::<Vec<_>>(),
            ["HEADER", "show version", "show ip bgp summary"]
        );
        assert_eq!(sections["HEADER"], vec!["Hostname: SW-1", "====", "", ""]);
        assert_eq!(sections["show version"], vec!["----", "Arista", "", ""]);
        assert_eq!(sections["show ip bgp summary"], vec!["----", "row"]);
    }

    #[test]
    fn safe_ids() {
        assert_eq!(safe_id("SITE-A-SW-1"), "site-a-sw-1");
        assert_eq!(safe_id("admin@PA-1 (active)"), "admin-pa-1-active");
    }
}
