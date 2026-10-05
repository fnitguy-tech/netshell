//! Port of CPython 3.11 `difflib` (`SequenceMatcher` and `ndiff`).
//!
//! Every diff the Python tool shows a reader comes from `difflib.ndiff`:
//! the quick text report, the raw-diff evidence sections of the HTML
//! report, the BGP config-change context and the route-map divergence
//! detail. ndiff does not just find a minimal edit script; it pairs
//! up *similar* lines inside a replaced block and interleaves them,
//! and it prints additions before removals when fewer lines were
//! added. Reproducing that exactly is what makes the Rust reports
//! byte-identical to the Python ones, so the algorithm is ported
//! rather than approximated with a Myers diff.
//!
//! Only what `ndiff` needs is here: no `"? "` intraline hint lines
//! (nothing reads them), no `unified_diff`.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// The most line pairs the fancy replace may score for one replaced
/// block: (old lines in the block) x (new lines in the block). Above
/// it, the block is written the plain way: every `-` line, then every
/// `+` line (the shorter side goes first, which is difflib's own rule).
///
/// Why it matters: when a block of lines is replaced by another block,
/// the fancy replace scores every old line against every new line to
/// find the closest pair, lines up on it, then does the same again on
/// each side. A block of 5,000 changed lines is 25 million scores for
/// the first pass alone, and the report takes minutes.
///
/// Worked example: 200 old lines replaced by 200 new ones is 40,000
/// pairs, which is at the cap and still gets the fancy treatment. 200
/// replaced by 201 is 40,200 pairs and is written plain.
///
/// Nothing is lost above the cap. Both reports keep only the `-` and
/// `+` lines, so the same lines appear either way; only their order
/// within the block changes, from interleaved pairs to
/// removed-then-added. The largest replaced block in the bundled demo
/// is 4 pairs, so the demo report is unchanged. The Python tool has the
/// same cap with the same value (`modules/difftrim.py`).
pub const FANCY_REPLACE_MAX_PAIRS: usize = 40_000;

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
///
/// One guard on top of CPython's: a size cap on the fancy replace (see
/// [`FANCY_REPLACE_MAX_PAIRS`]).
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
        // Too big to score pair by pair: write it plain. The check sits
        // here, not in compare(), so it also covers the blocks the
        // fancy helper hands back on each side of a synch point.
        if (ahi - alo) * (bhi - blo) > FANCY_REPLACE_MAX_PAIRS {
            self.plain_replace(a, alo, ahi, b, blo, bhi);
            return;
        }

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
    let (head, tail) = trim_matching_ends(a, b);

    if head == 0 && tail == 0 {
        return Differ { out: Vec::new() }.compare(a, b);
    }

    let mut out: Vec<String> = a[..head].iter().map(|line| format!("  {line}")).collect();
    let core_a = &a[head..a.len() - tail];
    let core_b = &b[head..b.len() - tail];

    if !core_a.is_empty() || !core_b.is_empty() {
        out.extend(Differ { out: Vec::new() }.compare(core_a, core_b));
    }

    out.extend(a[a.len() - tail..].iter().map(|line| format!("  {line}")));

    out
}

/// How many lines at the start and end of `a` and `b` already match.
///
/// A firewall's `show config running` is 78,180 lines and a window changes
/// a few of them. The longest-match search gets slower than linearly as the
/// input grows, so diffing the whole file is expensive: 70% of a 1.9 second
/// Python report ran inside `find_longest_match`, on configs that were
/// identical apart from a few lines. Matching lines at the ends can't come
/// out as `- ` or `+ `, however the matcher aligns the middle, so `ndiff`
/// skips them and emits them as context.
///
/// Measured on that config: 795 ms down to 11 ms in Python.
///
/// This makes `ndiff` no longer a drop-in for CPython's on any input - it
/// decides some pairings of equal lines by position rather than by search.
/// Real captures hit that rarely and cosmetically: on the bundled demo a
/// `+ !` moved two places among the other additions in a config diff, with
/// the same lines added and removed either way. Both ports run the same
/// trim and agree line for line. See `modules/difftrim.py` in
/// prepost-check, which carries the same trim and the measurements.
fn trim_matching_ends<T: PartialEq>(a: &[T], b: &[T]) -> (usize, usize) {
    let limit = a.len().min(b.len());
    let mut head = 0;

    while head < limit && a[head] == b[head] {
        head += 1;
    }

    let mut tail = 0;

    while tail < limit - head && a[a.len() - 1 - tail] == b[b.len() - 1 - tail] {
        tail += 1;
    }

    // Don't cut inside a run of equal lines. Which copy of a repeated line
    // gets paired depends on the rest of the input, and "!" ends every block
    // in an Arista config, so cutting through a run forces a different
    // pairing. Backing up to the start of the run leaves the choice to the
    // matcher, which keeps the two ports in step.
    while head > 0 && ((head < a.len() && a[head - 1] == a[head]) || (head < b.len() && a[head - 1] == b[head])) {
        head -= 1;
    }

    while tail > 0
        && ((tail < a.len() - head && a[a.len() - 1 - tail] == a[a.len() - tail])
            || (tail < b.len() - head && b[b.len() - 1 - tail] == a[a.len() - tail]))
    {
        tail -= 1;
    }

    (head, tail)
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
}
