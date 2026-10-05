//! What's in a capture folder, and whether it can be trusted.
//!
//! Both reports read capture folders through this module, so they agree
//! on four things:
//!
//! 1. Where one command's output ends and the next begins.
//! 2. Which files are devices, and which devices are missing or failed.
//! 3. Whether the run that wrote a folder got to the end.
//! 4. Whether the "before" folder really is older than the "after" folder.
//!
//! One text file per device per run. The collector writes the header
//! and the two-line marker above each command; the device writes
//! everything under it:
//!
//! ```text
//! Hostname: SITE-A-SW-1
//! IP Address: 192.0.2.1
//! Generated: 2026-04-14 08:48:02.123456
//! Secrets: redacted              (only with -r / --redact)
//! ================================================================================
//!
//!
//! ### show version ###
//! --------------------------------------------------------------------------------
//! <raw output>
//! ```
//!
//! Everything before the first header is the `HEADER` section. The
//! format is shared with the Python tool (`modules/captures.py`), so
//! captures from either can be compared by the other.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::layout::safe_name;

/// The pseudo-command holding the lines before the first section header.
pub const HEADER: &str = "HEADER";

/// The dash rule the collector writes under every section header. A
/// header only counts when this exact line follows it.
pub const SECTION_RULE: &str = "--------------------------------------------------------------------------------";

/// A device the collector couldn't capture gets this file instead of
/// `<hostname>.txt`. The first line says what happened; the rest is the
/// error text.
pub const FAILED_SUFFIX: &str = "_FAILED.txt";
pub const FAILED_FIRST_LINE: &str = "FAILED TO CONNECT TO";
pub const NOT_ATTEMPTED_FIRST_LINE: &str = "NOT ATTEMPTED:";

/// Written into the run folder as the last step of a capture. A folder
/// without it was interrupted partway (Ctrl-C, a crash, a closed
/// laptop), so it's missing devices and isn't a full baseline.
pub const COMPLETE_MARKER: &str = "capture-complete.json";

pub const NEWER_BASELINE_WARNING: &str =
    "The before capture is newer than the after capture. Did you run before again by mistake?";

static RUN_STAMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2})(-\d{2})?$").unwrap());

static NOT_ID_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());

/// `### command ###` section headers, in file order.
pub type Sections = IndexMap<String, Vec<String>>;

/// Split a capture file into `{command: [raw lines]}` (no filtering).
pub fn parse_sections(path: &Path) -> io::Result<Sections> {
    let bytes = fs::read(path)?;
    Ok(parse_sections_str(&String::from_utf8_lossy(&bytes)))
}

/// [`parse_sections`] on text already in memory.
///
/// A section starts only at the exact marker the collector writes: a
/// `### command ###` line with the 80-dash rule right under it. Device
/// output can't fake that by accident. A login banner inside
/// `show running-config` like
///
/// ```text
/// ### AUTHORIZED USE ONLY ###
/// ```
///
/// used to start a new section and cut the config in two. Now it's just
/// another config line, because no dash rule follows it.
///
/// Lines above the first header land under `HEADER`. The dash rule
/// stays in the section as its first line, the way it always has, so
/// old and new captures compare the same.
pub fn parse_sections_str(text: &str) -> Sections {
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|raw| raw.strip_suffix('\r').unwrap_or(raw))
        .collect();

    // split('\n') yields one trailing empty string after the final
    // newline; Python's line iteration does not.
    if text.ends_with('\n') {
        lines.pop();
    }

    let mut sections = Sections::new();
    let mut current = HEADER.to_string();
    sections.insert(current.clone(), Vec::new());

    for (index, line) in lines.iter().enumerate() {
        let is_header =
            line.starts_with("### ") && line.ends_with(" ###") && lines.get(index + 1) == Some(&SECTION_RULE);

        if is_header {
            current = line.replace("###", "").trim().to_string();
            // A command captured twice starts over, as in the Python.
            sections.insert(current.clone(), Vec::new());
        } else {
            sections
                .get_mut(&current)
                .expect("current section exists")
                .push(line.to_string());
        }
    }

    sections
}

/// The header line for a command, as written to a capture. The
/// collector writes [`SECTION_RULE`] on the next line.
pub fn section_header(command: &str) -> String {
    format!("### {command} ###")
}

/// Make a string usable as an HTML anchor id.
pub fn safe_id(value: &str) -> String {
    NOT_ID_CHARS
        .replace_all(&value.to_lowercase(), "-")
        .trim_matches('-')
        .to_string()
}

/// The device files in a run folder, sorted. Only `.txt` files count,
/// so the completion marker is never mistaken for a device.
pub fn capture_files(folder: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();

    for entry in fs::read_dir(folder)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".txt") {
            names.push(name);
        }
    }

    names.sort_unstable();
    Ok(names)
}

pub fn is_failed(file_name: &str) -> bool {
    file_name.ends_with(FAILED_SUFFIX)
}

/// Record a device we couldn't capture; returns the file path.
///
/// `10.0.0.5` gets `10.0.0.5_FAILED.txt`. The host goes through
/// [`safe_name`], so an IPv6 address like `2001:db8::5` becomes
/// `2001_db8__5_FAILED.txt`, which Windows can hold too.
pub fn write_failed(folder: &Path, host: &str, first_line: &str, error_text: &str) -> io::Result<PathBuf> {
    let path = folder.join(format!("{}{FAILED_SUFFIX}", safe_name(host, "device")));
    fs::write(&path, format!("{first_line} {host}\n{error_text}"))?;
    Ok(path)
}

/// A file's text, split the way Python's text mode and `splitlines()`
/// do it: `\r\n` and `\r` both end a line.
fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    let bytes = fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    Ok(text.lines().map(str::to_string).collect())
}

/// `(was it attempted, [error lines])` from a `_FAILED.txt` file.
fn read_failed(path: &Path) -> io::Result<(bool, Vec<String>)> {
    let lines: Vec<String> = read_lines(path)?
        .iter()
        .map(|line| line.trim_end().to_string())
        .collect();

    let attempted = !lines
        .first()
        .is_some_and(|first| first.starts_with(NOT_ATTEMPTED_FIRST_LINE));
    let detail = lines
        .into_iter()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .collect();

    Ok((attempted, detail))
}

/// The `IP Address:` a capture file was taken from, or `""`.
fn capture_address(path: &Path) -> io::Result<String> {
    Ok(read_lines(path)?
        .iter()
        .take(5)
        .find_map(|line| line.strip_prefix("IP Address:"))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default())
}

/// One device with no usable capture on one side or both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The file that stands for the device: its capture, or its
    /// `_FAILED.txt` when it was never captured.
    pub file_name: String,
    /// The hostname, or the address when no hostname is known.
    pub name: String,
    pub address: String,
    pub title: String,
    /// `Captured`, `Not captured`, `Failed`, or `Not attempted`.
    pub before: String,
    pub after: String,
    pub summary: String,
    pub evidence: String,
    /// The error lines from the `_FAILED.txt` file.
    pub detail: Vec<String>,
}

impl Problem {
    /// `SW-1 (10.0.0.5)`, or just the name when there's no separate address.
    pub fn label(&self) -> String {
        if !self.address.is_empty() && self.address != self.name {
            format!("{} ({})", self.name, self.address)
        } else {
            self.name.clone()
        }
    }
}

/// What one `_FAILED.txt` says: `(state, what, evidence, detail)`.
fn failure(
    folder: &Path,
    failed_file: &str,
    label: &str,
) -> io::Result<(&'static str, &'static str, String, Vec<String>)> {
    let (attempted, detail) = read_failed(&folder.join(failed_file))?;
    let (state, what) = if attempted {
        ("Failed", "unreachable")
    } else {
        ("Not attempted", "not attempted")
    };
    Ok((state, what, format!("{failed_file} in the {label} folder"), detail))
}

/// Sort two run folders into devices to compare and devices to flag.
///
/// Returns `(common_files, problems)`. `common_files` are captured in
/// both runs and safe to diff. `problems` is one entry for every device
/// that isn't: unreachable, never attempted, missing, or new. Each of
/// those means "we can't say this device is fine", so the reports list
/// them first and rate them Action Required.
///
/// Example. The before folder holds `SW-1.txt`, taken from 10.0.0.5.
/// The after folder holds `10.0.0.5_FAILED.txt`. The two are matched on
/// the address and come back as one problem:
///
/// ```text
/// SW-1 (10.0.0.5): Device unreachable after the change
/// ```
///
/// with the connect error from the FAILED file as its detail.
pub fn device_problems(precheck_folder: &Path, postcheck_folder: &Path) -> io::Result<(Vec<String>, Vec<Problem>)> {
    let pre_files = capture_files(precheck_folder)?;
    let post_files = capture_files(postcheck_folder)?;

    let ok = |files: &[String]| -> Vec<String> { files.iter().filter(|name| !is_failed(name)).cloned().collect() };
    // Keyed the way write_failed() names the file, so a capture's
    // "IP Address:" line can be matched to it.
    let failed = |files: &[String]| -> BTreeMap<String, String> {
        files
            .iter()
            .filter(|name| is_failed(name))
            .map(|name| (name[..name.len() - FAILED_SUFFIX.len()].to_string(), name.clone()))
            .collect()
    };

    let pre_ok = ok(&pre_files);
    let post_ok = ok(&post_files);
    let mut pre_failed = failed(&pre_files);
    let mut post_failed = failed(&post_files);

    // The listings are sorted, so these three are too.
    let common_files: Vec<String> = pre_ok.iter().filter(|name| post_ok.contains(name)).cloned().collect();
    let only_pre: Vec<&String> = pre_ok.iter().filter(|name| !post_ok.contains(name)).collect();
    let only_post: Vec<&String> = post_ok.iter().filter(|name| !pre_ok.contains(name)).collect();

    let mut problems = Vec::new();

    for file_name in only_pre {
        let name = file_name[..file_name.len() - ".txt".len()].to_string();
        let address = capture_address(&precheck_folder.join(file_name))?;
        let failed_file = if address.is_empty() {
            None
        } else {
            post_failed.remove(&safe_name(&address, ""))
        };

        problems.push(match failed_file {
            Some(failed_file) => {
                let (state, what, evidence, detail) = failure(postcheck_folder, &failed_file, "postcheck")?;
                Problem {
                    file_name: file_name.clone(),
                    name,
                    address,
                    title: format!("Device {what} after the change"),
                    before: "Captured".to_string(),
                    after: state.to_string(),
                    summary: "This device answered before the change and didn't after. Nothing about its state \
                              after the change is known. Check that it's up and reachable, then run the postcheck \
                              again."
                        .to_string(),
                    evidence,
                    detail,
                }
            }
            None => Problem {
                file_name: file_name.clone(),
                name,
                address,
                title: "Device missing after the change".to_string(),
                before: "Captured".to_string(),
                after: "Not captured".to_string(),
                summary: "This device was captured before the change, and the after capture has no file for it \
                          at all. Check that it's still in the inventory, then run the postcheck again."
                    .to_string(),
                evidence: format!("{file_name} is in the precheck folder only"),
                detail: Vec::new(),
            },
        });
    }

    for file_name in only_post {
        let name = file_name[..file_name.len() - ".txt".len()].to_string();
        let address = capture_address(&postcheck_folder.join(file_name))?;
        let failed_file = if address.is_empty() {
            None
        } else {
            pre_failed.remove(&safe_name(&address, ""))
        };

        problems.push(match failed_file {
            Some(failed_file) => {
                let (state, what, evidence, detail) = failure(precheck_folder, &failed_file, "precheck")?;
                Problem {
                    file_name: file_name.clone(),
                    name,
                    address,
                    title: format!("Device {what} before the change"),
                    before: state.to_string(),
                    after: "Captured".to_string(),
                    summary: "This device has no before capture, so there's nothing to compare its after state \
                              against. Check it by hand."
                        .to_string(),
                    evidence,
                    detail,
                }
            }
            None => Problem {
                file_name: file_name.clone(),
                name,
                address,
                title: "Device only in the after capture".to_string(),
                before: "Not captured".to_string(),
                after: "Captured".to_string(),
                summary: "This device has no before capture, so there's nothing to compare its after state \
                          against. If it was renamed during the window, its old name is listed here as missing."
                    .to_string(),
                evidence: format!("{file_name} is in the postcheck folder only"),
                detail: Vec::new(),
            },
        });
    }

    for (host, failed_file) in &post_failed {
        let (state, what, evidence, detail) = failure(postcheck_folder, failed_file, "postcheck")?;

        problems.push(match pre_failed.remove(host) {
            Some(before_file) => {
                let (before_state, _what, before_evidence, _detail) =
                    failure(precheck_folder, &before_file, "precheck")?;
                Problem {
                    file_name: failed_file.clone(),
                    name: host.clone(),
                    address: host.clone(),
                    title: format!("Device {what} before and after the change"),
                    before: before_state.to_string(),
                    after: state.to_string(),
                    summary: "This device was never captured, so nothing about it is known. Check it by hand."
                        .to_string(),
                    evidence: format!("{before_evidence}, and {evidence}"),
                    detail,
                }
            }
            None => Problem {
                file_name: failed_file.clone(),
                name: host.clone(),
                address: host.clone(),
                title: format!("Device {what} after the change"),
                before: "Not captured".to_string(),
                after: state.to_string(),
                summary: "Nothing about this device's state after the change is known. Check that it's up and \
                          reachable, then run the postcheck again."
                    .to_string(),
                evidence,
                detail,
            },
        });
    }

    for (host, failed_file) in &pre_failed {
        let (state, what, evidence, detail) = failure(precheck_folder, failed_file, "precheck")?;
        problems.push(Problem {
            file_name: failed_file.clone(),
            name: host.clone(),
            address: host.clone(),
            title: format!("Device {what} before the change"),
            before: state.to_string(),
            after: "Not captured".to_string(),
            summary: "This device has no capture before or after the change, so nothing about it is known. \
                      Check it by hand."
                .to_string(),
            evidence,
            detail,
        });
    }

    Ok((common_files, problems))
}

/// The totals kept in the completion marker, so a reader can see what
/// "finished" meant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunCounts {
    pub devices: usize,
    pub captured: usize,
    pub incomplete: usize,
    pub failed: usize,
    pub not_attempted: usize,
}

/// Mark a run folder as finished. Called once, after the last device.
///
/// ```text
/// {
///   "phase": "precheck",
///   "finished": "2026-04-14 08:49:31",
///   "devices": 8,
///   "captured": 7,
///   "incomplete": 0,
///   "failed": 1,
///   "not_attempted": 0
/// }
/// ```
pub fn write_complete_marker(folder: &Path, phase: &str, counts: RunCounts) -> io::Result<()> {
    #[derive(serde::Serialize)]
    struct Record<'a> {
        phase: &'a str,
        finished: String,
        devices: usize,
        captured: usize,
        incomplete: usize,
        failed: usize,
        not_attempted: usize,
    }

    let record = Record {
        phase,
        finished: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        devices: counts.devices,
        captured: counts.captured,
        incomplete: counts.incomplete,
        failed: counts.failed,
        not_attempted: counts.not_attempted,
    };
    let text = serde_json::to_string_pretty(&record).map_err(io::Error::other)?;

    fs::write(folder.join(COMPLETE_MARKER), format!("{text}\n"))
}

/// The folder's own name, with any trailing slash ignored.
fn folder_name(folder: &Path) -> String {
    folder
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A run folder's timestamp to the second, as a sortable string, or
/// `None` when the name carries none. Older folders stop at the minute;
/// they're read as second 00.
///
/// `precheck_2026-04-14_08-48` gives `2026-04-14_08-48-00`.
pub fn run_stamp(folder: &Path) -> Option<String> {
    let name = folder_name(folder);
    let found = RUN_STAMP.captures(&name)?;
    Some(format!("{}{}", &found[1], found.get(2).map_or("-00", |m| m.as_str())))
}

/// Reasons not to trust this pair of folders: `(warnings, notes)`.
///
/// Warnings go at the top of both reports and on the console. Notes go
/// on the console only.
///
/// 1. The before folder is newer than the after folder. Say you ran
///    `mw before` at 08:48, made the change, then ran `mw before` again
///    at 10:40 by mistake, and `mw after` at 10:42. The comparison is
///    now "after against after" and shows no change at all. Here the
///    stamps are compared, and a before stamp later than the after
///    stamp is called out.
///
/// 2. A folder has no completion marker. If its name carries seconds
///    (`precheck_2026-04-14_08-48-05`), this version wrote it, and the
///    only way it lacks a marker is that the run was cut short. That's
///    a warning. If its name stops at the minute, an older version
///    wrote it and never wrote markers, so there's no way to tell. That
///    gets a note, and the comparison still runs.
pub fn baseline_warnings(precheck_folder: &Path, postcheck_folder: &Path) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    if let (Some(pre_stamp), Some(post_stamp)) = (run_stamp(precheck_folder), run_stamp(postcheck_folder))
        && pre_stamp > post_stamp
    {
        warnings.push(NEWER_BASELINE_WARNING.to_string());
    }

    for (label, folder) in [("before", precheck_folder), ("after", postcheck_folder)] {
        if folder.join(COMPLETE_MARKER).exists() {
            continue;
        }

        let name = folder_name(folder);
        let has_seconds = RUN_STAMP.captures(&name).is_some_and(|found| found.get(2).is_some());

        if has_seconds {
            warnings.push(format!(
                "The {label} capture ({name}) didn't finish. It was interrupted partway, so devices may be \
                 missing from it. Run it again before you trust this comparison."
            ));
        } else {
            notes.push(format!(
                "The {label} capture ({name}) has no completion marker. An older version wrote it, so there's \
                 no way to tell whether it finished."
            ));
        }
    }

    (warnings, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_section_headers() {
        let text = format!(
            "Hostname: SW-1\n====\n\n\n### show version ###\n{SECTION_RULE}\nArista\n\n\n### show ip bgp summary ###\n{SECTION_RULE}\nrow\n"
        );
        let sections = parse_sections_str(&text);
        assert_eq!(
            sections.keys().collect::<Vec<_>>(),
            ["HEADER", "show version", "show ip bgp summary"]
        );
        assert_eq!(sections["HEADER"], vec!["Hostname: SW-1", "====", "", ""]);
        assert_eq!(sections["show version"], vec![SECTION_RULE, "Arista", "", ""]);
        assert_eq!(sections["show ip bgp summary"], vec![SECTION_RULE, "row"]);
    }

    #[test]
    fn a_header_needs_the_dash_rule_right_under_it() {
        let text = format!("### show a ###\n{SECTION_RULE}\nA\n### show b ###\nnot a rule\n### show c ###");
        let sections = parse_sections_str(&text);
        assert_eq!(sections.keys().collect::<Vec<_>>(), ["HEADER", "show a"]);
        assert_eq!(
            sections["show a"],
            vec![SECTION_RULE, "A", "### show b ###", "not a rule", "### show c ###"]
        );
    }

    #[test]
    fn safe_ids() {
        assert_eq!(safe_id("SITE-A-SW-1"), "site-a-sw-1");
        assert_eq!(safe_id("admin@PA-1 (active)"), "admin-pa-1-active");
    }

    #[test]
    fn run_stamps_compare_across_the_old_and_new_formats() {
        assert_eq!(
            run_stamp(Path::new("/x/precheck_2026-04-14_08-48")).as_deref(),
            Some("2026-04-14_08-48-00")
        );
        assert_eq!(
            run_stamp(Path::new("/x/precheck_2026-04-14_08-48-05/")).as_deref(),
            Some("2026-04-14_08-48-05")
        );
        assert_eq!(run_stamp(Path::new("/x/precheck_custom")), None);

        // Same minute, old and new format: not "newer".
        let (warnings, _notes) = baseline_warnings(
            Path::new("/x/precheck_2026-04-14_08-48"),
            Path::new("/x/postcheck_2026-04-14_08-48-30"),
        );
        assert!(!warnings.iter().any(|warning| warning == NEWER_BASELINE_WARNING));
    }

    #[test]
    fn failed_files_use_safe_names() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_failed(tmp.path(), "2001:db8::5", FAILED_FIRST_LINE, "no route\n").unwrap();
        assert_eq!(path.file_name().unwrap(), "2001_db8__5_FAILED.txt");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "FAILED TO CONNECT TO 2001:db8::5\nno route\n"
        );
        assert_eq!(read_failed(&path).unwrap(), (true, vec!["no route".to_string()]));
    }
}
