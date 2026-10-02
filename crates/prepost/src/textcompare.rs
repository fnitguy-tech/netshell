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
//! interpreted HTML report reads the same column on purpose, because an
//! uptime that went backwards is the only trace a session that reset
//! and recovered leaves in that table.
//!
//! The per-command diff is a line-for-line port of Python's
//! `difflib.ndiff` (the `SequenceMatcher` longest-block algorithm with
//! its junk heuristics, and `Differ`'s similar-line synchronisation), so
//! the `-`/`+` lines come out in the order the Python tool writes them.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::hash::Hash;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::capture::{self, Sections};
use crate::layout::{TicketDirs, display_path, find_latest_folder};
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
// difflib port
// ---------------------------------------------------------------------

/// Port of `difflib.SequenceMatcher` (CPython 3.11) specialised to the
/// way `ndiff` drives it: the second sequence `b` is indexed once, and
/// every method takes the first sequence `a` as an argument, so one
/// matcher can be compared against many `a`s cheaply.
struct SequenceMatcher<'b, T> {
    b: &'b [T],
    /// `b2j`: for each non-junk, non-popular element of `b`, its
    /// indices in ascending order.
    b2j: HashMap<&'b T, Vec<usize>>,
    /// Elements of `b` the junk predicate rejected.
    bjunk: HashSet<&'b T>,
    /// Multiset of `b` for `quick_ratio`.
    fullbcount: HashMap<&'b T, usize>,
}

/// `(i, j, size)`: `a[i..i + size] == b[j..j + size]`.
type Block = (usize, usize, usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    Replace,
    Delete,
    Insert,
    Equal,
}

/// `(tag, i1, i2, j1, j2)` as `get_opcodes` returns it.
type Opcode = (Tag, usize, usize, usize, usize);

/// `difflib._calculate_ratio`.
fn calculate_ratio(matches: usize, length: usize) -> f64 {
    if length > 0 {
        return 2.0 * matches as f64 / length as f64;
    }
    1.0
}

impl<'b, T: Eq + Hash> SequenceMatcher<'b, T> {
    /// `SequenceMatcher(isjunk, autojunk=True)` with `set_seq2(b)`
    /// already applied (`__chain_b`).
    fn new(is_junk: Option<fn(&T) -> bool>, b: &'b [T]) -> Self {
        let mut b2j: HashMap<&'b T, Vec<usize>> = HashMap::new();
        for (i, elt) in b.iter().enumerate() {
            b2j.entry(elt).or_default().push(i);
        }

        // Purge junk elements.
        let mut bjunk = HashSet::new();
        if let Some(is_junk) = is_junk {
            for elt in b2j.keys() {
                if is_junk(elt) {
                    bjunk.insert(*elt);
                }
            }
            for elt in &bjunk {
                b2j.remove(elt);
            }
        }

        // Purge popular elements that are not junk (autojunk): in a
        // sequence of 200+ items, anything appearing in more than 1% of
        // it is not worth anchoring a match on.
        let n = b.len();
        if n >= 200 {
            let ntest = n / 100 + 1;
            let popular: Vec<&'b T> = b2j
                .iter()
                .filter(|(_, idxs)| idxs.len() > ntest)
                .map(|(elt, _)| *elt)
                .collect();
            for elt in popular {
                b2j.remove(elt);
            }
        }

        let mut fullbcount = HashMap::new();
        for elt in b {
            *fullbcount.entry(elt).or_insert(0) += 1;
        }

        Self {
            b,
            b2j,
            bjunk,
            fullbcount,
        }
    }

    /// Longest matching block in `a[alo..ahi]` and `b[blo..bhi]`: the
    /// longest junk-free match, earliest in `a` then in `b`, extended
    /// first by matching non-junk and then by matching junk on each end.
    fn find_longest_match(&self, a: &[T], alo: usize, ahi: usize, blo: usize, bhi: usize) -> Block {
        let b = self.b;
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);

        // During an iteration of the loop, j2len[j] = length of longest
        // junk-free match ending with a[i-1] and b[j].
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, ai) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(indices) = self.b2j.get(ai) {
                for &j in indices {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = j.checked_sub(1).and_then(|prev| j2len.get(&prev)).copied().unwrap_or(0) + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }

        // Extend the best by non-junk elements on each end. "Popular"
        // non-junk elements are not in b2j, so the best match so far
        // contains no junk *or* popular elements.
        while besti > alo && bestj > blo && !self.bjunk.contains(&b[bestj - 1]) && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && !self.bjunk.contains(&b[bestj + bestsize])
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }

        // Now suck up the matching junk on each side of it too.
        while besti > alo && bestj > blo && self.bjunk.contains(&b[bestj - 1]) && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && self.bjunk.contains(&b[bestj + bestsize])
            && a[besti + bestsize] == b[bestj + bestsize]
        {
            bestsize += 1;
        }

        (besti, bestj, bestsize)
    }

    /// `get_matching_blocks`: sorted, adjacent blocks collapsed, with
    /// the `(len(a), len(b), 0)` sentinel last.
    fn matching_blocks(&self, a: &[T]) -> Vec<Block> {
        let (la, lb) = (a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks: Vec<Block> = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(a, alo, ahi, blo, bhi);
            if k > 0 {
                blocks.push((i, j, k));
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        blocks.sort_unstable();

        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut non_adjacent = Vec::new();
        for (i2, j2, k2) in blocks {
            if i1 + k1 == i2 && j1 + k1 == j2 {
                k1 += k2;
            } else {
                if k1 > 0 {
                    non_adjacent.push((i1, j1, k1));
                }
                (i1, j1, k1) = (i2, j2, k2);
            }
        }
        if k1 > 0 {
            non_adjacent.push((i1, j1, k1));
        }

        non_adjacent.push((la, lb, 0));
        non_adjacent
    }

    /// `get_opcodes`: how to turn `a` into `b`.
    fn opcodes(&self, a: &[T]) -> Vec<Opcode> {
        let (mut i, mut j) = (0, 0);
        let mut answer = Vec::new();
        for (ai, bj, size) in self.matching_blocks(a) {
            let tag = if i < ai && j < bj {
                Some(Tag::Replace)
            } else if i < ai {
                Some(Tag::Delete)
            } else if j < bj {
                Some(Tag::Insert)
            } else {
                None
            };
            if let Some(tag) = tag {
                answer.push((tag, i, ai, j, bj));
            }
            (i, j) = (ai + size, bj + size);
            if size > 0 {
                answer.push((Tag::Equal, ai, i, bj, j));
            }
        }
        answer
    }

    /// `ratio`: 2.0 * matches / (len(a) + len(b)).
    fn ratio(&self, a: &[T]) -> f64 {
        let matches: usize = self.matching_blocks(a).iter().map(|block| block.2).sum();
        calculate_ratio(matches, a.len() + self.b.len())
    }

    /// `quick_ratio`: an upper bound on `ratio` from the multiset
    /// intersection.
    fn quick_ratio(&self, a: &[T]) -> f64 {
        let mut avail: HashMap<&T, isize> = HashMap::new();
        let mut matches = 0;
        for elt in a {
            let numb = match avail.get(elt) {
                Some(n) => *n,
                None => self.fullbcount.get(elt).copied().unwrap_or(0) as isize,
            };
            avail.insert(elt, numb - 1);
            if numb > 0 {
                matches += 1;
            }
        }
        calculate_ratio(matches, a.len() + self.b.len())
    }

    /// `real_quick_ratio`: the cheapest upper bound on `ratio`.
    fn real_quick_ratio(&self, a: &[T]) -> f64 {
        let (la, lb) = (a.len(), self.b.len());
        calculate_ratio(la.min(lb), la + lb)
    }
}

/// `difflib.IS_CHARACTER_JUNK`: spaces and tabs.
fn is_character_junk(ch: &char) -> bool {
    *ch == ' ' || *ch == '\t'
}

/// `difflib.Differ` with `ndiff`'s defaults: no line junk, whitespace
/// is character junk. Emits `"- line"`, `"+ line"` and `"  line"`; the
/// `"? "` intraline hint lines are not produced because the report
/// never reads them.
struct Differ {
    out: Vec<String>,
}

impl Differ {
    fn dump(&mut self, tag: char, x: &[String], lo: usize, hi: usize) {
        for line in &x[lo..hi] {
            self.out.push(format!("{tag} {line}"));
        }
    }

    fn plain_replace(&mut self, a: &[String], alo: usize, ahi: usize, b: &[String], blo: usize, bhi: usize) {
        // Dump the shorter block first - reduces the burden on
        // short-term memory if the blocks are of very different sizes.
        if bhi - blo < ahi - alo {
            self.dump('+', b, blo, bhi);
            self.dump('-', a, alo, ahi);
        } else {
            self.dump('-', a, alo, ahi);
            self.dump('+', b, blo, bhi);
        }
    }

    /// When replacing one block of lines with another, search the
    /// blocks for *similar* lines; the best-matching pair (if any) is
    /// used as a synch point.
    fn fancy_replace(&mut self, a: &[String], alo: usize, ahi: usize, b: &[String], blo: usize, bhi: usize) {
        // Don't synch up unless the lines have a similarity score of at
        // least cutoff; best_ratio tracks the best score seen so far.
        let (mut best_ratio, cutoff) = (0.74_f64, 0.75_f64);
        let mut best: Option<(usize, usize)> = None;
        // First indices of equal lines (if any).
        let mut eq: Option<(usize, usize)> = None;

        let a_chars: Vec<Vec<char>> = a[alo..ahi].iter().map(|line| line.chars().collect()).collect();

        // Search for the pair that matches best without being identical
        // (identical lines must be junk lines, & we don't want to synch
        // up on junk - unless we have to).
        for (j, bj) in b.iter().enumerate().take(bhi).skip(blo) {
            let bj_chars: Vec<char> = bj.chars().collect();
            let cruncher = SequenceMatcher::new(Some(is_character_junk), &bj_chars);
            for (i, ai) in a_chars.iter().enumerate().map(|(offset, ai)| (alo + offset, ai)) {
                if &a[i] == bj {
                    if eq.is_none() {
                        eq = Some((i, j));
                    }
                    continue;
                }
                // Computing similarity is expensive, so use the quick
                // upper bounds first.
                if cruncher.real_quick_ratio(ai) > best_ratio && cruncher.quick_ratio(ai) > best_ratio {
                    let ratio = cruncher.ratio(ai);
                    if ratio > best_ratio {
                        best_ratio = ratio;
                        best = Some((i, j));
                    }
                }
            }
        }

        let (best_i, best_j, identical) = if best_ratio < cutoff {
            // No non-identical "pretty close" pair.
            match eq {
                // No identical pair either - treat it as a straight replace.
                None => {
                    self.plain_replace(a, alo, ahi, b, blo, bhi);
                    return;
                }
                // No close pair, but an identical pair - synch up on that.
                Some((i, j)) => (i, j, true),
            }
        } else {
            // There's a close pair, so forget the identical pair (if any).
            let (i, j) = best.expect("a ratio above the cutoff records its pair");
            (i, j, false)
        };

        // Pump out diffs from before the synch point.
        self.fancy_helper(a, alo, best_i, b, blo, best_j);

        if identical {
            self.out.push(format!("  {}", a[best_i]));
        } else {
            // The '-', '?', '+', '?' quad for the synched lines, minus
            // the '?' hints.
            self.out.push(format!("- {}", a[best_i]));
            self.out.push(format!("+ {}", b[best_j]));
        }

        // Pump out diffs from after the synch point.
        self.fancy_helper(a, best_i + 1, ahi, b, best_j + 1, bhi);
    }

    fn fancy_helper(&mut self, a: &[String], alo: usize, ahi: usize, b: &[String], blo: usize, bhi: usize) {
        if alo < ahi {
            if blo < bhi {
                self.fancy_replace(a, alo, ahi, b, blo, bhi);
            } else {
                self.dump('-', a, alo, ahi);
            }
        } else if blo < bhi {
            self.dump('+', b, blo, bhi);
        }
    }

    fn compare(mut self, a: &[String], b: &[String]) -> Vec<String> {
        let cruncher = SequenceMatcher::new(None, b);
        for (tag, alo, ahi, blo, bhi) in cruncher.opcodes(a) {
            match tag {
                Tag::Replace => self.fancy_replace(a, alo, ahi, b, blo, bhi),
                Tag::Delete => self.dump('-', a, alo, ahi),
                Tag::Insert => self.dump('+', b, blo, bhi),
                Tag::Equal => self.dump(' ', a, alo, ahi),
            }
        }
        self.out
    }
}

/// `difflib.ndiff(a, b)` without the `"? "` intraline hint lines: every
/// line of `a` and `b` comes back once, prefixed `"- "`, `"+ "` or
/// `"  "`, in the order the Python tool writes them.
pub fn ndiff(a: &[String], b: &[String]) -> Vec<String> {
    Differ { out: Vec::new() }.compare(a, b)
}

// ---------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------

const RULE_EQUALS: &str = "================================================================================";
const RULE_DASHES: &str = "--------------------------------------------------------------------------------";

/// Sorted entry names of a run folder (`sorted(os.listdir(folder))`).
fn list_folder(folder: &Path) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(folder)?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    names.sort_unstable();
    Ok(names)
}

/// The whole text report for one precheck folder against one postcheck
/// folder: the header, the file summary and one section per common
/// device with each changed command's `-`/`+` lines.
pub fn compare_folders(ticket: &str, precheck_folder: &Path, postcheck_folder: &Path) -> anyhow::Result<String> {
    let pre_files = list_folder(precheck_folder)?;
    let post_files = list_folder(postcheck_folder)?;

    let pre_set: HashSet<&String> = pre_files.iter().collect();
    let post_set: HashSet<&String> = post_files.iter().collect();

    // The listings are sorted, so these are too.
    let common_files: Vec<&String> = pre_files.iter().filter(|name| post_set.contains(name)).collect();
    let missing_post: Vec<&String> = pre_files.iter().filter(|name| !post_set.contains(name)).collect();
    let new_post: Vec<&String> = post_files.iter().filter(|name| !pre_set.contains(name)).collect();

    let mut report = String::new();
    report.push_str("Pre/Post Maintenance Comparison Report\n");
    report.push_str(RULE_EQUALS);
    report.push_str("\n\n");
    writeln!(report, "Ticket:           {ticket}")?;
    writeln!(report, "Precheck Folder:  {}", display_path(precheck_folder))?;
    writeln!(report, "Postcheck Folder: {}", display_path(postcheck_folder))?;
    report.push('\n');

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

    for file_name in common_files {
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

    let report = compare_folders(ticket, &precheck_folder, &postcheck_folder)?;
    fs::write(&compare_file, report)?;

    println!("Compare report created: {}", display_path(&compare_file));

    Ok(Some(compare_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn longest_match_prefers_earliest_and_extends_over_junk() {
        // The docstring example: without junk the whole " abcd" matches
        // at b=4; with blanks as junk the junk-free "abcd" is taken at
        // its earliest position, b=0, and cannot extend left.
        let a: Vec<char> = " abcd".chars().collect();
        let b: Vec<char> = "abcd abcd".chars().collect();
        let matcher = SequenceMatcher::new(None, &b);
        assert_eq!(matcher.find_longest_match(&a, 0, 5, 0, 9), (0, 4, 5));

        let matcher = SequenceMatcher::new(Some(is_character_junk), &b);
        assert_eq!(matcher.find_longest_match(&a, 0, 5, 0, 9), (1, 0, 4));
    }

    #[test]
    fn opcodes_match_the_docstring() {
        let a: Vec<char> = "qabxcd".chars().collect();
        let b: Vec<char> = "abycdf".chars().collect();
        let matcher = SequenceMatcher::new(None, &b);
        assert_eq!(
            matcher.opcodes(&a),
            vec![
                (Tag::Delete, 0, 1, 0, 0),
                (Tag::Equal, 1, 3, 0, 2),
                (Tag::Replace, 3, 4, 2, 3),
                (Tag::Equal, 4, 6, 3, 5),
                (Tag::Insert, 6, 6, 5, 6),
            ]
        );
    }

    #[test]
    fn ratio_matches_python() {
        let a: Vec<char> = "abcd".chars().collect();
        let b: Vec<char> = "bcde".chars().collect();
        let matcher = SequenceMatcher::new(None, &b);
        assert_eq!(matcher.ratio(&a), 0.75);
        assert_eq!(matcher.quick_ratio(&a), 0.75);
        assert_eq!(matcher.real_quick_ratio(&a), 1.0);
        assert_eq!(calculate_ratio(0, 0), 1.0);
    }

    #[test]
    fn autojunk_ignores_popular_lines() {
        // 250 lines, 50 of them "!": popular, so not anchors, yet still
        // matched by extension around the real anchors.
        let mut a = Vec::new();
        for i in 0..200 {
            a.push(format!("line {i}"));
            if i % 4 == 0 {
                a.push("!".to_string());
            }
        }
        let mut b = a.clone();
        b.insert(100, "inserted".to_string());
        let matcher = SequenceMatcher::new(None, &b);
        assert!(!matcher.b2j.contains_key(&"!".to_string()));
        assert!(matcher.b2j.contains_key(&"line 7".to_string()));
        let changes: Vec<String> = ndiff(&a, &b).into_iter().filter(|l| !l.starts_with("  ")).collect();
        assert_eq!(changes, vec!["+ inserted"]);
    }

    #[test]
    fn ndiff_synchs_on_the_closest_pair() {
        // "three"/"tree" is the only pair above the cutoff; the lines
        // before it are a plain replace, shorter block first.
        let a = lines(&["one", "two", "three"]);
        let b = lines(&["ore", "tree", "emu"]);
        assert_eq!(
            ndiff(&a, &b),
            vec!["+ ore", "- one", "- two", "- three", "+ tree", "+ emu"]
        );
    }

    #[test]
    fn plain_replace_dumps_the_shorter_block_first() {
        let a = lines(&["alpha", "beta", "gamma"]);
        let b = lines(&["zzzzz"]);
        assert_eq!(ndiff(&a, &b), vec!["+ zzzzz", "- alpha", "- beta", "- gamma"]);
        assert_eq!(ndiff(&b, &a), vec!["- zzzzz", "+ alpha", "+ beta", "+ gamma"]);
    }

    #[test]
    fn identical_pair_is_a_synch_point_when_nothing_is_close() {
        let a = lines(&["aaaa", "!", "bbbb"]);
        let b = lines(&["cccc", "!", "dddd"]);
        assert_eq!(ndiff(&a, &b), vec!["- aaaa", "+ cccc", "  !", "- bbbb", "+ dddd"]);
    }

    #[test]
    fn report_shape_for_an_unchanged_device() {
        let tmp = tempfile::tempdir().unwrap();
        let pre = tmp.path().join("pre");
        let post = tmp.path().join("post");
        fs::create_dir_all(&pre).unwrap();
        fs::create_dir_all(&post).unwrap();
        let capture = "Hostname: sw\nGenerated: 1\n### show version ###\nUptime: 1 day\nArista\n";
        fs::write(pre.join("sw.txt"), capture).unwrap();
        fs::write(post.join("sw.txt"), capture.replace("1 day", "2 days")).unwrap();
        fs::write(pre.join("old.txt"), "x\n").unwrap();
        fs::write(post.join("new.txt"), "y\n").unwrap();

        let report = compare_folders("NET-9", &pre, &post).unwrap();
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
