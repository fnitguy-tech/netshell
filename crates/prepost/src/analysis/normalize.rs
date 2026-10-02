//! The HTML report's normalization: looser than the text diff's on
//! purpose, so the collapsible raw-diff evidence sections read
//! naturally. Port of `htmlreport.clean_line_for_compare` and
//! `normalized_section`.

/// Normalize one line for diffing, or `None` to drop it as noise.
pub fn clean_line_for_compare(command: &str, line: &str) -> Option<String> {
    let _ = (command, line);
    todo!("port of htmlreport.clean_line_for_compare()")
}

/// A section's lines, normalized and with noise dropped.
pub fn normalized_section(command: &str, lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| clean_line_for_compare(command, line))
        .collect()
}
