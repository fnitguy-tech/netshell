//! The shared finding shape and the analysis roll-up.
//!
//! Every interpreted finding (BGP peer, prefix-list entry, pair
//! divergence, interface) is one [`Finding`], so the renderer draws
//! them all the same way and the totals, attention list, impact score
//! and charts treat them alike.

use std::collections::BTreeMap;

/// How much a finding matters. Ordered: a higher variant outranks a
/// lower one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Impact {
    Stable,
    Changed,
    Attention,
    ActionRequired,
}

impl Impact {
    pub const ALL: [Impact; 4] = [
        Impact::Stable,
        Impact::Changed,
        Impact::Attention,
        Impact::ActionRequired,
    ];

    /// The label the Python report uses: "Action Required" etc.
    pub fn label(self) -> &'static str {
        match self {
            Impact::Stable => "Stable",
            Impact::Changed => "Changed",
            Impact::Attention => "Attention",
            Impact::ActionRequired => "Action Required",
        }
    }

    /// CSS class suffix: "action-required" etc.
    pub fn css(self) -> &'static str {
        match self {
            Impact::Stable => "stable",
            Impact::Changed => "changed",
            Impact::Attention => "attention",
            Impact::ActionRequired => "action-required",
        }
    }
}

/// Operational area a finding or a changed command belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Classification {
    Configuration,
    Protocol,
    Routing,
    Interface,
    Layer2,
    Firewall,
    System,
    EvidenceOnly,
}

impl Classification {
    pub const ALL: [Classification; 8] = [
        Classification::Configuration,
        Classification::Protocol,
        Classification::Routing,
        Classification::Interface,
        Classification::Layer2,
        Classification::Firewall,
        Classification::System,
        Classification::EvidenceOnly,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Classification::Configuration => "Configuration",
            Classification::Protocol => "Protocol",
            Classification::Routing => "Routing",
            Classification::Interface => "Interface",
            Classification::Layer2 => "Layer 2",
            Classification::Firewall => "Firewall",
            Classification::System => "System",
            Classification::EvidenceOnly => "Evidence only",
        }
    }
}

/// Per-classification counters, always iterated in [`Classification::ALL`] order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassificationCounts(BTreeMap<Classification, usize>);

impl ClassificationCounts {
    pub fn get(&self, key: Classification) -> usize {
        self.0.get(&key).copied().unwrap_or(0)
    }

    pub fn add(&mut self, key: Classification, count: usize) {
        *self.0.entry(key).or_default() += count;
    }

    pub fn iter(&self) -> impl Iterator<Item = (Classification, usize)> + '_ {
        Classification::ALL.iter().map(move |key| (*key, self.get(*key)))
    }

    pub fn total(&self) -> usize {
        self.0.values().sum()
    }
}

/// Per-impact counters, always iterated in [`Impact::ALL`] order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImpactCounts(BTreeMap<Impact, usize>);

impl ImpactCounts {
    pub fn get(&self, key: Impact) -> usize {
        self.0.get(&key).copied().unwrap_or(0)
    }

    pub fn add(&mut self, key: Impact, count: usize) {
        *self.0.entry(key).or_default() += count;
    }

    pub fn iter(&self) -> impl Iterator<Item = (Impact, usize)> + '_ {
        Impact::ALL.iter().map(move |key| (*key, self.get(*key)))
    }
}

/// One before/after cell in a finding's grid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub label: String,
    pub before: String,
    pub after: String,
}

impl Field {
    pub fn new(label: impl Into<String>, before: impl Into<String>, after: impl Into<String>) -> Field {
        Field {
            label: label.into(),
            before: before.into(),
            after: after.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Removed,
    /// Block-header context (`  router bgp 65000`): shown muted, never counted.
    Context,
}

/// One line of a diff, without its sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

impl DiffLine {
    pub fn added(text: impl Into<String>) -> DiffLine {
        DiffLine {
            kind: DiffKind::Added,
            text: text.into(),
        }
    }

    pub fn removed(text: impl Into<String>) -> DiffLine {
        DiffLine {
            kind: DiffKind::Removed,
            text: text.into(),
        }
    }

    pub fn context(text: impl Into<String>) -> DiffLine {
        DiffLine {
            kind: DiffKind::Context,
            text: text.into(),
        }
    }

    /// ndiff-style rendering: "- text", "+ text", "  text".
    pub fn ndiff(&self) -> String {
        let sign = match self.kind {
            DiffKind::Added => '+',
            DiffKind::Removed => '-',
            DiffKind::Context => ' ',
        };
        format!("{sign} {}", self.text)
    }
}

/// One BGP peer as parsed from a summary table (EOS/IOS) or a PAN-OS
/// peer block. Counts stay strings: that is how they are displayed,
/// and "n/a"-style values appear in real output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpPeer {
    /// Description column, or the IP when there is none.
    pub name: String,
    pub ip: String,
    pub as_number: String,
    pub state: String,
    pub prefixes_received: String,
    pub prefixes_accepted: String,
    /// The Up/Down column (`01:02:03`, `1d02h`, `never`), when captured.
    pub updown: Option<String>,
}

/// The BGP peer context a BGP finding keeps for tests and summaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpContext {
    pub peer: BgpPeer,
    pub before: Option<BgpPeer>,
    pub after: Option<BgpPeer>,
}

/// One interpreted finding of any kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub classification: Classification,
    /// "BGP", "Prefix list", "Pair symmetry", "Interface".
    pub category: String,
    pub impact: Impact,
    pub title: String,
    /// Spans shown after the title; the first is styled as the name.
    pub subject: Vec<String>,
    pub fields: Vec<Field>,
    /// "→" normally, "vs" for pair findings.
    pub arrow: String,
    pub summary: String,
    pub evidence: String,
    /// Raw diff lines shown under the finding (route-map bodies etc.).
    pub detail: Vec<DiffLine>,
    /// Pair findings: both members, first member counts it in totals.
    pub devices: Vec<String>,
    pub bgp: Option<BgpContext>,
}

impl Finding {
    /// A finding with the usual defaults: "→" arrow, no detail, not a
    /// pair finding, no BGP context.
    pub fn new(
        classification: Classification,
        category: impl Into<String>,
        impact: Impact,
        title: impl Into<String>,
    ) -> Finding {
        Finding {
            classification,
            category: category.into(),
            impact,
            title: title.into(),
            subject: Vec::new(),
            fields: Vec::new(),
            arrow: "→".to_string(),
            summary: String::new(),
            evidence: String::new(),
            detail: Vec::new(),
            devices: Vec::new(),
            bgp: None,
        }
    }
}

/// Per-device roll-up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceReport {
    pub file_name: String,
    pub hostname: String,
    pub device_id: String,
    pub findings: Vec<Finding>,
    pub config_changes: Vec<DiffLine>,
    /// Normalized added/removed lines per changed command, sorted by command.
    pub diffs: BTreeMap<String, Vec<DiffLine>>,
    pub raw_categories: ClassificationCounts,
    pub findings_count: usize,
    pub attention_count: usize,
    pub action_count: usize,
    pub changed_count: usize,
    pub stable_count: usize,
    pub impact_score: usize,
}

/// Outcomes of rating prefix deltas against an expectations file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectationTotals {
    pub as_planned: usize,
    pub differs: usize,
    pub unexplained: usize,
    pub not_met: usize,
}

/// Everything the report renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    pub common_files: Vec<String>,
    /// Sorted by action count, attention count, findings count, score; descending.
    pub device_reports: Vec<DeviceReport>,
    pub pairs: Vec<(String, String)>,
    pub pair_findings: Vec<Finding>,
    pub expectations_in_play: bool,
    pub expectation_totals: ExpectationTotals,
    pub total_findings_by_classification: ClassificationCounts,
    pub impact_totals: ImpactCounts,
    /// `impact_totals` split by where the finding came from: `window_totals`
    /// from comparing pre against post, `symmetry_totals` from comparing the
    /// two members of a pair against each other. The health verdict is graded
    /// on the window alone, because a pair-symmetry finding is a standing
    /// condition the window did not create.
    pub window_totals: ImpactCounts,
    pub symmetry_totals: ImpactCounts,
    pub devices_with_findings: usize,
}
