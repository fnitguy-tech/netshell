//! BGP-relevant lines that changed in the running config.

use crate::capture::Sections;

use super::finding::{DiffKind, DiffLine};
use crate::difflib::ndiff;

/// Keywords that make a config line BGP-relevant, on the line itself or
/// on the block header an indented change sits under.
pub const BGP_CONFIG_KEYWORDS: &[&str] = &[
    "router bgp",
    "protocol bgp",
    "neighbor",
    "peer-group",
    "peer group",
    "route-map",
    "prefix-list",
    "access-list",
    "access-group",
    "community",
    "send-community",
    "set community",
    "match community",
    "redist",
    "aggregate-address",
    "valid-networks",
    "auth-profile",
    "used-by",
    "bfd",
    "link-state",
    "shutdown",
    "no shutdown",
];

/// The running config lines of a capture: EOS/IOS `show running-config`
/// followed by PAN-OS `show config running`, whichever are present.
fn config_lines(sections: &Sections) -> Vec<String> {
    ["show running-config", "show config running"]
        .iter()
        .filter_map(|command| sections.get(*command))
        .flatten()
        .cloned()
        .collect()
}

/// Whether any BGP keyword appears in the lowercased text.
fn mentions_bgp(lowered: &str) -> bool {
    BGP_CONFIG_KEYWORDS.iter().any(|keyword| lowered.contains(keyword))
}

/// A block header: a non-blank line that starts in column one.
fn is_block_header(text: &str) -> bool {
    !text.trim().is_empty() && !text.starts_with(char::is_whitespace)
}

/// Which side(s) of the diff a line belongs to, for header tracking.
#[derive(Clone, Copy)]
enum Side {
    Removed,
    Added,
}

/// ndiff-style lines: removed, added, and context for the block header
/// an indented change sits under.
///
/// The header ("ip prefix-list ISP-OUT", "router bgp 64500") is what
/// makes an indented "seq 40 permit ..." line BGP-relevant, and what
/// makes it readable.
pub fn bgp_config_changes(pre: &Sections, post: &Sections) -> Vec<DiffLine> {
    let pre_lines = config_lines(pre);
    let post_lines = config_lines(post);

    // The diff interleaves the two sides, so each side keeps its own
    // notion of "the block this line is under": a removed line belongs
    // to the precheck's last header, an added line to the postcheck's.
    let mut headers = [String::new(), String::new()];
    let mut emitted_header: Option<String> = None;
    let mut important = Vec::new();

    let mut visit = |text: &str, side: Option<Side>| {
        if is_block_header(text) {
            match side {
                None => {
                    headers[0] = text.to_string();
                    headers[1] = text.to_string();
                }
                Some(Side::Removed) => headers[0] = text.to_string(),
                Some(Side::Added) => headers[1] = text.to_string(),
            }
        }

        let Some(side) = side else {
            return;
        };

        let content = text.trim().to_lowercase();
        let indented = text.starts_with(char::is_whitespace);
        let block_header = match side {
            Side::Removed => headers[0].clone(),
            Side::Added => headers[1].clone(),
        };
        let in_relevant_block = indented && mentions_bgp(&block_header.to_lowercase());

        if mentions_bgp(&content) || in_relevant_block {
            if indented && emitted_header.as_deref() != Some(block_header.as_str()) {
                important.push(DiffLine::context(block_header.clone()));
                emitted_header = Some(block_header);
            } else if !indented {
                // A changed header line is its own context for what follows.
                emitted_header = Some(text.to_string());
            }

            important.push(DiffLine {
                kind: match side {
                    Side::Removed => DiffKind::Removed,
                    Side::Added => DiffKind::Added,
                },
                text: text.to_string(),
            });
        }
    };

    // ndiff interleaves the two sides; "? " hint lines are never produced.
    for line in ndiff(&pre_lines, &post_lines) {
        if let Some(text) = line.strip_prefix("- ") {
            visit(text, Some(Side::Removed));
        } else if let Some(text) = line.strip_prefix("+ ") {
            visit(text, Some(Side::Added));
        } else if let Some(text) = line.strip_prefix("  ") {
            visit(text, None);
        }
    }

    important
}

/// Added/removed lines only; block-header context lines do not count.
pub fn count_config_changes(changes: &[DiffLine]) -> usize {
    changes
        .iter()
        .filter(|line| !matches!(line.kind, DiffKind::Context))
        .count()
}
