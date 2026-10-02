//! Expected BGP prefix deltas for one change.
//!
//! Every prefix-count change used to carry the same hedge ("this may be
//! expected when routing policy ... change"), and a caveat on
//! everything is a caveat on nothing. An expectations file states, per
//! device and peer, what the change was supposed to do to the prefix
//! count; the HTML report then rates a matching delta Stable ("as
//! planned"), a delta that differs from or has no expectation
//! Attention, and an expected change that did not happen Attention
//! too. The hedge text survives only when no expectations file is in
//! play at all.
//!
//! File: `reports/<TICKET>/expectations.yml` by default, or
//! `-e` on `prepost report`. Schema:
//!
//! ```yaml
//! ticket: NET-123                 # optional; must match when present
//! expectations:
//!   - device: SITE-A-SW-2         # capture hostname, case-insensitive
//!     peer: 10.0.0.1              # neighbor IP or description column
//!     expected_delta: +3          # change in prefixes received, or
//!   - device: SITE-A-SW-1
//!     peer: ISP-B
//!     expected_prefixes: 815      # absolute prefixes received after
//!     note: full table minus bogons   # optional, shown in the finding
//! ```

use std::fs;
use std::path::Path;

use serde_yaml::Value;

use crate::analysis::BgpPeer;

/// The bundled example, in the prepost sources, cited when the file a
/// report asked for does not exist.
pub const EXAMPLE_EXPECTATIONS: &str = "fixtures/NET-DEMO/expectations.yml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// Change in prefixes received.
    Delta(i64),
    /// Absolute prefixes received after the change.
    Prefixes(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub device: String,
    pub peer: String,
    pub expected: Expected,
    pub note: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ExpectationsError(pub String);

/// The text form of a YAML scalar, as Python's `str()` would show it.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => serde_yaml::to_string(other).unwrap_or_default().trim_end().to_string(),
    }
}

/// Python truthiness of a YAML value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Sequence(items) => !items.is_empty(),
        Value::Mapping(map) => !map.is_empty(),
        Value::Tagged(tagged) => truthy(&tagged.value),
    }
}

/// Python's `int(str(value).strip())` for the values YAML can hand us:
/// an integer, or a string holding one with an optional sign.
fn integer_of(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => {
            let text = text.trim();
            let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            text.parse().ok()
        }
        _ => None,
    }
}

/// Parse and validate an expectations file.
pub fn load_expectations(path: &Path, ticket: Option<&str>) -> Result<Vec<Expectation>, ExpectationsError> {
    let shown = path.display();

    if !path.exists() {
        return Err(ExpectationsError(format!(
            "Expectations file not found: {shown}\nSee {EXAMPLE_EXPECTATIONS} in the prepost sources for the format."
        )));
    }

    let text = fs::read_to_string(path).map_err(|error| ExpectationsError(format!("{shown}: {error}")))?;
    let data: Value = serde_yaml::from_str(&text).map_err(|error| ExpectationsError(format!("{shown}: {error}")))?;

    let entries_value = match &data {
        Value::Mapping(_) => data.get("expectations").and_then(Value::as_sequence),
        _ => None,
    };
    let Some(raw_entries) = entries_value else {
        return Err(ExpectationsError(format!(
            "{shown}: expected a top-level 'expectations' list."
        )));
    };

    if let Some(ticket) = ticket.filter(|ticket| !ticket.is_empty())
        && let Some(file_ticket) = data.get("ticket").filter(|value| truthy(value))
    {
        let file_ticket = scalar_text(file_ticket);
        if file_ticket.trim().to_uppercase() != ticket.trim().to_uppercase() {
            return Err(ExpectationsError(format!(
                "{shown}: file is for ticket {file_ticket}, this report is for {ticket}."
            )));
        }
    }

    let mut entries = Vec::new();

    for (index, entry) in raw_entries.iter().enumerate() {
        let label = format!("expectations[{index}]");

        let Value::Mapping(entry) = entry else {
            return Err(ExpectationsError(format!("{shown}: {label} must be a mapping.")));
        };

        let mut names = Vec::new();
        for key in ["device", "peer"] {
            match entry.get(key).and_then(Value::as_str) {
                Some(value) if !value.trim().is_empty() => names.push(value.trim().to_string()),
                _ => return Err(ExpectationsError(format!("{shown}: {label} is missing '{key}'."))),
            }
        }

        let has_delta = entry.contains_key("expected_delta");
        let has_total = entry.contains_key("expected_prefixes");

        if has_delta == has_total {
            return Err(ExpectationsError(format!(
                "{shown}: {label} needs exactly one of 'expected_delta' or 'expected_prefixes'."
            )));
        }

        let value_key = if has_delta {
            "expected_delta"
        } else {
            "expected_prefixes"
        };
        let value = &entry[value_key];

        // YAML reads "+3" as the int 3, "3" as 3; a quoted "+3" arrives
        // as a string and is accepted too. Booleans are not integers.
        let value = match value {
            Value::Number(_) | Value::String(_) => integer_of(value),
            _ => None,
        };
        let Some(value) = value else {
            return Err(ExpectationsError(format!(
                "{shown}: {label}: '{value_key}' must be an integer."
            )));
        };

        let note = match entry.get("note") {
            None | Some(Value::Null) => String::new(),
            Some(note) => scalar_text(note).trim().to_string(),
        };

        let peer = names.pop().expect("peer validated");
        let device = names.pop().expect("device validated");

        entries.push(Expectation {
            device,
            peer,
            expected: if has_delta {
                Expected::Delta(value)
            } else {
                Expected::Prefixes(value)
            },
            note,
        });
    }

    Ok(entries)
}

/// The entries for one capture hostname (case-insensitive).
pub fn for_device<'a>(expectations: &'a [Expectation], hostname: &str) -> Vec<&'a Expectation> {
    expectations
        .iter()
        .filter(|e| e.device.eq_ignore_ascii_case(hostname))
        .collect()
}

/// The first entry naming this peer by description or IP.
pub fn match_peer<'a>(expectations: &'a [Expectation], peer: &BgpPeer) -> Option<&'a Expectation> {
    expectations
        .iter()
        .find(|e| e.peer.eq_ignore_ascii_case(&peer.name) || e.peer.eq_ignore_ascii_case(&peer.ip))
}

/// Human form of what an entry expects: "a change of +3" or "815 prefixes received".
pub fn describe(entry: &Expectation) -> String {
    match entry.expected {
        Expected::Delta(delta) => format!("a change of {delta:+}"),
        Expected::Prefixes(total) => format!("{total} prefixes received"),
    }
}
