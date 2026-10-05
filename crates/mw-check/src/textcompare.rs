//! Quick plain-text pre/post comparison: the fast on-call view written
//! at the end of a postcheck run. One `.txt` diffing the latest
//! precheck against the latest postcheck, command by command, with
//! expected churn filtered out. Port of the Python `textcompare.py`.
//! The HTML report (`report`) is the richer, shareable artifact.
//!
//! Normalization is the heart of it: counters, uptimes, ARP/MAC age
//! timers, BGP message counts and content-version lines change on every
//! capture and would bury real findings, so they are stripped or
//! collapsed before diffing. Each command's rule keeps the
//! operationally meaningful columns (e.g. a BGP peer's state and prefix
//! counts survive; its up/down timer does not). That is the right call
//! for a diff, where the timer differs on every capture; the
//! interpreted HTML report reads the same column, because an
//! uptime that went backwards is the only trace a session that reset
//! and recovered leaves in that table.
//!
//! The per-command diff is a line-for-line port of Python's
//! `difflib.ndiff` (the `SequenceMatcher` longest-block algorithm with
//! its junk heuristics, and `Differ`'s similar-line synchronisation), so
//! the `-`/`+` lines come out in the order the Python tool writes them.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::capture::{self, Sections};
pub use crate::difflib::ndiff;
use crate::layout::{TicketDirs, display_path_from, find_latest_folder};
use crate::vpn::{normalize_vpn_line, vpn_commands};

/// Commands captured for evidence but too volatile to ever diff
/// meaningfully (per-lane optics readings drift constantly).
pub const SKIP_COMPARE_COMMANDS: &[&str] = &["show interfaces transceiver"];

/// Lines that change on every capture regardless of command.
pub const NOISY_STARTS: &[&str] = &[
    "Generated:",
    "Uptime:",
    "Free memory:",
    "Last table change time",
    "Number of table inserts",
    "Number of table deletes",
    "time:",
    "uptime:",
    "url-filtering-version:",
    "Last update age:",
    "Update messages:",
    "Total messages:",
    "Flap counts:",
    "lifetime remain:",
    "Bytes received",
    "Bytes sent",
    "Packets received",
    "Packets sent",
];

/// Config output is compared verbatim: every character matters.
const CONFIG_COMMANDS: &[&str] = &["show running-config", "show config running"];

/// EOS route-map / prefix-list listings carry per-entry hit counters.
const POLICY_COMMANDS: &[&str] = &["show route-map", "show ip prefix-list"];

/// `show routing protocol bgp peer` fields that move on every capture.
const BGP_PEER_NOISE: &[&str] = &[
    "Peer status:",
    "Update messages:",
    "Total messages:",
    "Last update age:",
    "Flap counts:",
];

/// `show system info` fields that move on their own: content/AV/threat
/// package versions auto-update on their own schedule, not
/// maintenance-window findings.
const SYSTEM_INFO_NOISE: &[&str] = &[
    "time:",
    "uptime:",
    "url-filtering-version:",
    "global-protect-client-package-version:",
    "global-protect-clientless-vpn-version:",
    "app-version:",
    "av-version:",
    "threat-version:",
    "wildfire-version:",
];

/// Trailing "x:y:z ago" age column.
static AGE_CLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+\d+:\d+:\d+ ago$").unwrap());

/// Trailing "N days, ... ago" age column.
static AGE_DAYS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+\d+ days?,.*ago$").unwrap());

/// "Match clauses hit: N" / "Set clauses hit: N" counter lines.
static CLAUSES_HIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*(Match|Set)?\s*clauses? hit").unwrap());

/// Trailing "( N matches )" / "( N hits )" on a route-map entry.
static HIT_COUNT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s*\(\s*\d+\s+(matches|hits)\s*\)$").unwrap());

/// An ARP entry age at the start of a token.
static ARP_AGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+:\d+:\d+").unwrap());

/// `" ".join(parts)`.
fn join(parts: &[&str]) -> String {
    parts.join(" ")
}

/// Python's `str.isdigit()` for the ASCII output a device produces.
fn is_digit_token(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| c.is_ascii_digit())
}

/// Normalize one line for the text diff, or `None` to drop it.
pub fn normalize_line(command: &str, line: &str) -> Option<String> {
    let line = line.trim_end_matches('\n');

    if SKIP_COMPARE_COMMANDS.contains(&command) {
        return None;
    }

    // Config output is compared verbatim - every character matters.
    if CONFIG_COMMANDS.contains(&command) {
        return Some(line.to_string());
    }

    if NOISY_STARTS.iter().any(|item| line.trim().starts_with(item)) {
        return None;
    }

    // Strip trailing "x:y:z ago" / "N days, ... ago" age columns.
    let line = AGE_CLOCK.replace_all(line, "");
    let line = AGE_DAYS.replace_all(&line, "");
    let line: &str = &line;

    if vpn_commands().contains(&command) {
        return normalize_vpn_line(command, line);
    }

    // EOS route-map / prefix-list listings carry per-entry hit counters;
    // the entries themselves are the point, so drop the counter line.
    if POLICY_COMMANDS.contains(&command) {
        if CLAUSES_HIT.is_match(line.trim()) {
            return None;
        }

        return Some(HIT_COUNT.replace_all(line, "").into_owned());
    }

    if command == "show ip bgp summary" {
        // Keep peer identity + state/prefixes, drop the Up/Down timer
        // and message counters between them.
        let parts: Vec<&str> = line.split_whitespace().collect();
        let head = &parts[..parts.len().min(3)];

        if let Some(estab_index) = parts.iter().position(|p| *p == "Estab") {
            return Some(join(&[head, &parts[estab_index..]].concat()));
        }

        if let Some(idle_index) = parts.iter().position(|p| *p == "Idle(Admin)") {
            return Some(join(&[head, &parts[idle_index..]].concat()));
        }

        return Some(line.to_string());
    }

    if command == "show ip ospf neighbor" {
        // Column 5 is the dead-timer countdown - always different.
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 8 {
            return Some(join(&[&parts[0..5], &parts[6..]].concat()));
        }

        return Some(line.to_string());
    }

    if command == "show ip arp" {
        // Column 1 is the entry age.
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 4 && ARP_AGE.is_match(parts[1]) {
            return Some(join(&[&parts[0..1], &parts[2..]].concat()));
        }

        return Some(line.to_string());
    }

    if command == "show mac address-table" {
        let line = AGE_CLOCK.replace_all(line, "");
        let line = AGE_DAYS.replace_all(&line, "");
        return Some(line.into_owned());
    }

    if command == "show routing route" {
        // PAN-OS route age is a bare integer column; drop all-digit
        // tokens so only destination/nexthop/flags are compared.
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 5 {
            let kept: Vec<&str> = parts.into_iter().filter(|p| !is_digit_token(p)).collect();
            return Some(join(&kept));
        }

        return Some(line.to_string());
    }

    if command == "show routing protocol bgp peer" {
        let stripped = line.trim();

        if BGP_PEER_NOISE.iter().any(|item| stripped.starts_with(item)) {
            // "Peer status: Established, for 123456 secs" - keep the
            // state, drop the ever-growing duration.
            if stripped.starts_with("Peer status:") {
                return Some(stripped.split(',').next().unwrap_or(stripped).to_string());
            }

            return None;
        }

        return Some(line.to_string());
    }

    if command == "show routing protocol ospf neighbor" {
        if line.trim().starts_with("lifetime remain:") {
            return None;
        }

        return Some(line.to_string());
    }

    if command == "show system info" {
        let stripped = line.trim();

        if SYSTEM_INFO_NOISE.iter().any(|item| stripped.starts_with(item)) {
            return None;
        }

        return Some(line.to_string());
    }

    Some(line.to_string())
}

/// Split a capture file into `{command: [normalized lines]}`: the raw
/// sections of [`capture::parse_sections`] with [`normalize_line`]
/// applied and dropped lines removed.
pub fn parse_sections(path: &Path) -> io::Result<Sections> {
    Ok(normalize_sections(capture::parse_sections(path)?))
}

/// [`parse_sections`] on sections already split.
pub fn normalize_sections(raw: Sections) -> Sections {
    raw.into_iter()
        .map(|(command, lines)| {
            let kept = lines.iter().filter_map(|line| normalize_line(&command, line)).collect();
            (command, kept)
        })
        .collect()
}

// ---------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------

const RULE_EQUALS: &str = "================================================================================";
const RULE_DASHES: &str = capture::SECTION_RULE;

/// The whole text report for one precheck folder against one postcheck
/// folder: the header, any warnings, the file summary, the devices that
/// couldn't be verified, and one section per common device with each
/// changed command's `-`/`+` lines.
///
/// `root` is what the two folder paths are shown relative to.
///
/// A device that failed or went missing has nothing to diff. It's
/// listed up top instead, so it can't hide behind "No meaningful
/// changes detected.":
///
/// ```text
/// ACTION REQUIRED: 1 device(s) could not be verified
/// --------------------------------------------------------------------------------
/// ! SW-1 (10.0.0.5): Device unreachable after the change
///     Before: Captured. After: Failed.
///     Evidence: 10.0.0.5_FAILED.txt in the postcheck folder
///     | could not connect to 10.0.0.5:22: Connection refused (os error 111)
/// ```
pub fn compare_folders(
    root: &Path,
    ticket: &str,
    precheck_folder: &Path,
    postcheck_folder: &Path,
) -> anyhow::Result<String> {
    let pre_files = capture::capture_files(precheck_folder)?;
    let post_files = capture::capture_files(postcheck_folder)?;

    // common_files are captured in both runs.
    let (common_files, problems) = capture::device_problems(precheck_folder, postcheck_folder)?;
    let (warnings, _notes) = capture::baseline_warnings(precheck_folder, postcheck_folder);

    let pre_set: HashSet<&String> = pre_files.iter().collect();
    let post_set: HashSet<&String> = post_files.iter().collect();

    // The listings are sorted, so these are too.
    let missing_post: Vec<&String> = pre_files.iter().filter(|name| !post_set.contains(name)).collect();
    let new_post: Vec<&String> = post_files.iter().filter(|name| !pre_set.contains(name)).collect();

    let mut report = String::new();
    report.push_str("Pre/Post Maintenance Comparison Report\n");
    report.push_str(RULE_EQUALS);
    report.push_str("\n\n");
    writeln!(report, "Ticket:           {ticket}")?;
    writeln!(report, "Precheck Folder:  {}", display_path_from(root, precheck_folder))?;
    writeln!(
        report,
        "Postcheck Folder: {}",
        display_path_from(root, postcheck_folder)
    )?;
    report.push('\n');

    for warning in &warnings {
        writeln!(report, "WARNING: {warning}\n")?;
    }

    report.push_str("File Summary\n");
    report.push_str(RULE_DASHES);
    report.push('\n');
    writeln!(report, "Common files: {}", common_files.len())?;
    writeln!(report, "Missing in postcheck: {}", missing_post.len())?;
    writeln!(report, "New in postcheck: {}", new_post.len())?;
    report.push('\n');

    if !missing_post.is_empty() {
        report.push_str("Missing in Postcheck:\n");
        for file_name in &missing_post {
            writeln!(report, "- {file_name}")?;
        }
        report.push('\n');
    }

    if !new_post.is_empty() {
        report.push_str("New in Postcheck:\n");
        for file_name in &new_post {
            writeln!(report, "+ {file_name}")?;
        }
        report.push('\n');
    }

    if !problems.is_empty() {
        writeln!(
            report,
            "ACTION REQUIRED: {} device(s) could not be verified",
            problems.len()
        )?;
        report.push_str(RULE_DASHES);
        report.push('\n');

        for problem in &problems {
            writeln!(report, "! {}: {}", problem.label(), problem.title)?;
            writeln!(report, "    Before: {}. After: {}.", problem.before, problem.after)?;
            writeln!(report, "    Evidence: {}", problem.evidence)?;
            for line in &problem.detail {
                writeln!(report, "    | {line}")?;
            }
        }

        report.push('\n');
    }

    for file_name in &common_files {
        let pre_sections = parse_sections(&precheck_folder.join(file_name))?;
        let post_sections = parse_sections(&postcheck_folder.join(file_name))?;

        let mut all_commands: Vec<&String> = pre_sections.keys().chain(post_sections.keys()).collect();
        all_commands.sort_unstable();
        all_commands.dedup();

        report.push('\n');
        report.push_str(RULE_EQUALS);
        report.push('\n');
        writeln!(report, "Device/File: {file_name}")?;
        report.push_str(RULE_EQUALS);
        report.push('\n');

        let mut device_changed = false;
        let empty: Vec<String> = Vec::new();

        for command in all_commands {
            let pre_lines = pre_sections.get(command).unwrap_or(&empty);
            let post_lines = post_sections.get(command).unwrap_or(&empty);

            if pre_lines == post_lines {
                continue;
            }

            device_changed = true;

            report.push('\n');
            report.push_str(RULE_DASHES);
            report.push('\n');
            writeln!(report, "Command: {command}")?;
            report.push_str(RULE_DASHES);
            report.push('\n');
            report.push_str("Differences detected.\n\n");

            for line in ndiff(pre_lines, post_lines) {
                if line.starts_with("- ") || line.starts_with("+ ") {
                    report.push_str(&line);
                    report.push('\n');
                }
            }
        }

        if !device_changed {
            report.push_str("\nNo meaningful changes detected.\n");
        }
    }

    Ok(report)
}

/// The console lines for a pair of folders that may not be trustworthy:
/// one `WARNING:` per warning, then one `Note:` per note.
pub fn console_lines(warnings: &[String], notes: &[String]) -> Vec<String> {
    warnings
        .iter()
        .map(|warning| format!("WARNING: {warning}"))
        .chain(notes.iter().map(|note| format!("Note: {note}")))
        .collect()
}

/// The console line that names the devices with no usable capture:
///
/// ```text
/// ACTION REQUIRED: 2 device(s) could not be verified: SW-1, 10.0.0.9
/// ```
pub fn action_required_line(names: &[&str]) -> String {
    format!(
        "ACTION REQUIRED: {} device(s) could not be verified: {}",
        names.len(),
        names.join(", ")
    )
}

/// Write `Compare/compare_<run_timestamp>.txt` from the latest
/// precheck and postcheck folders, printing progress and the summary.
/// Returns the report path, or `None` when a run folder is missing.
pub fn write_compare_report(ticket: &str, dirs: &TicketDirs, run_timestamp: &str) -> anyhow::Result<Option<PathBuf>> {
    let precheck_folder = find_latest_folder(&dirs.precheck, "precheck_");
    let postcheck_folder = find_latest_folder(&dirs.postcheck, "postcheck_");

    let Some(precheck_folder) = precheck_folder else {
        println!("No precheck folder found. Skipping compare.");
        return Ok(None);
    };

    let Some(postcheck_folder) = postcheck_folder else {
        println!("No postcheck folder found. Skipping compare.");
        return Ok(None);
    };

    fs::create_dir_all(&dirs.compare)?;
    let compare_file = dirs.compare.join(format!("compare_{run_timestamp}.txt"));

    // Said on the console as well as in the report, so you see it
    // before you leave the window.
    let (_common, problems) = capture::device_problems(&precheck_folder, &postcheck_folder)?;
    let (warnings, notes) = capture::baseline_warnings(&precheck_folder, &postcheck_folder);

    for line in console_lines(&warnings, &notes) {
        println!("{line}");
    }

    let report = compare_folders(&dirs.root, ticket, &precheck_folder, &postcheck_folder)?;
    fs::write(&compare_file, report)?;

    if !problems.is_empty() {
        let names: Vec<&str> = problems.iter().map(|problem| problem.name.as_str()).collect();
        println!("{}", action_required_line(&names));
    }

    println!("Compare report created: {}", dirs.display(&compare_file));

    Ok(Some(compare_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_shape_for_an_unchanged_device() {
        let tmp = tempfile::tempdir().unwrap();
        let pre = tmp.path().join("pre");
        let post = tmp.path().join("post");
        fs::create_dir_all(&pre).unwrap();
        fs::create_dir_all(&post).unwrap();
        let capture = "Hostname: sw\nGenerated: 1\n### show version ###\n--------------------------------------------------------------------------------\nUptime: 1 day\nArista\n";
        fs::write(pre.join("sw.txt"), capture).unwrap();
        fs::write(post.join("sw.txt"), capture.replace("1 day", "2 days")).unwrap();
        fs::write(pre.join("old.txt"), "x\n").unwrap();
        fs::write(post.join("new.txt"), "y\n").unwrap();

        let report = compare_folders(tmp.path(), "NET-9", &pre, &post).unwrap();
        assert!(report.starts_with("Pre/Post Maintenance Comparison Report\n"));
        assert!(report.contains("Ticket:           NET-9\n"));
        assert!(report.contains("Common files: 1\nMissing in postcheck: 1\nNew in postcheck: 1\n\n"));
        assert!(report.contains("Missing in Postcheck:\n- old.txt\n\n"));
        assert!(report.contains("New in Postcheck:\n+ new.txt\n\n"));
        assert!(report.ends_with(
            "Device/File: sw.txt\n================================================================================\n\nNo meaningful changes detected.\n"
        ));
    }
}
