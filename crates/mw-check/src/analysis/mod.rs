//! Interpretation: parse the captures, produce impact-rated findings,
//! roll them up per device and network-wide.
//!
//! The pipeline mirrors the Python `htmlreport.analyze()`:
//!
//! 1. per device: BGP neighbour findings with config-change context,
//!    prefix-list findings, interface findings, and the normalized raw
//!    diff of every command;
//! 2. pair symmetry findings across each redundant pair, attributed to
//!    both members but counted once;
//! 3. counts, weighted impact score, totals and ordering.

pub mod bgp;
pub mod config;
pub mod finding;
pub mod interfaces;
pub mod normalize;
pub mod pairs;
pub mod prefix_list;
pub mod rawdiff;

use std::path::Path;

pub use finding::{
    Analysis, BgpContext, BgpPeer, Classification, ClassificationCounts, DeviceReport, DiffKind, DiffLine, Field,
    Finding, Impact, ImpactCounts,
};

/// Diff every common device file between the two run folders and roll
/// up findings and totals.
///
/// `pairs`: explicit pairs from the inventory; pairs whose hostnames
/// differ only by a trailing number are inferred anyway.
pub fn analyze(
    precheck_folder: &Path,
    postcheck_folder: &Path,
    pairs: Option<&[(String, String)]>,
) -> anyhow::Result<Analysis> {
    use std::collections::BTreeSet;

    use indexmap::IndexMap;

    use crate::capture::{self, Sections};

    fn file_names(folder: &Path) -> anyhow::Result<BTreeSet<String>> {
        let mut names = BTreeSet::new();
        for entry in std::fs::read_dir(folder)? {
            names.insert(entry?.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    let pre_files = file_names(precheck_folder)?;
    let post_files = file_names(postcheck_folder)?;
    let common_files: Vec<String> = pre_files.intersection(&post_files).cloned().collect();

    let mut total_findings_by_classification = ClassificationCounts::default();
    let mut impact_totals = ImpactCounts::default();
    let mut window_totals = ImpactCounts::default();
    let mut symmetry_totals = ImpactCounts::default();

    struct Device {
        file_name: String,
        pre: Sections,
        post: Sections,
        config_changes: Vec<DiffLine>,
        findings: Vec<Finding>,
        diffs: std::collections::BTreeMap<String, Vec<DiffLine>>,
        raw_categories: ClassificationCounts,
    }

    // Pass 1: per-device parsing and findings.
    let mut devices: IndexMap<String, Device> = IndexMap::new();

    for file_name in &common_files {
        let pre_sections = capture::parse_sections(&precheck_folder.join(file_name))?;
        let post_sections = capture::parse_sections(&postcheck_folder.join(file_name))?;

        let hostname = file_name.replace(".txt", "");
        let config_changes = config::bgp_config_changes(&pre_sections, &post_sections);
        let mut findings = bgp::bgp_neighbor_findings(&pre_sections, &post_sections, &config_changes);
        findings.extend(prefix_list::prefix_list_findings(&pre_sections, &post_sections));
        findings.extend(interfaces::interface_findings(&pre_sections, &post_sections));
        let diffs = rawdiff::raw_diffs(&pre_sections, &post_sections);
        let raw_categories = rawdiff::classify_raw_diff_commands(&diffs);

        devices.insert(
            hostname,
            Device {
                file_name: file_name.clone(),
                pre: pre_sections,
                post: post_sections,
                config_changes,
                findings,
                diffs,
                raw_categories,
            },
        );
    }

    // Pass 2: pair symmetry. Each pair finding is attributed to both
    // members (it raises both devices' attention count and impact score)
    // but counted once in the network-wide totals.
    let hostnames: Vec<String> = devices.keys().cloned().collect();
    let resolved_pairs = pairs::resolve_pairs(&hostnames, pairs);
    let mut all_pair_findings = Vec::new();

    for pair in &resolved_pairs {
        let (a, b) = pair;
        let found = pairs::pair_findings(
            pair,
            &devices[a].post,
            &devices[b].post,
            Some(&devices[a].pre),
            Some(&devices[b].pre),
        );
        all_pair_findings.extend(found.iter().cloned());
        devices[a].findings.extend(found.iter().cloned());
        devices[b].findings.extend(found);
    }

    // Pass 3: counts, scores and totals.
    let mut device_reports = Vec::new();
    let mut devices_with_findings = 0;

    for (hostname, device) in devices {
        let findings = device.findings;
        let config_changes = device.config_changes;
        let raw_categories = device.raw_categories;

        let config_change_count = config::count_config_changes(&config_changes);
        let findings_count = findings.len() + config_change_count;

        if findings_count > 0 {
            devices_with_findings += 1;
        }

        for finding in &findings {
            if finding.devices.first().is_some_and(|first| *first != hostname) {
                continue; // counted once, on the pair's first member
            }

            total_findings_by_classification.add(finding.classification, 1);
            impact_totals.add(finding.impact, 1);

            // The health verdict answers "did this window change anything". A
            // pair-symmetry finding is a standing condition that was just as
            // true before the window as after, so it is counted on its own and
            // kept out of that verdict - otherwise a maintenance that changed
            // nothing reads as 30 problems it did not cause.
            if finding.category == pairs::CATEGORY {
                symmetry_totals.add(finding.impact, 1);
            } else {
                window_totals.add(finding.impact, 1);
            }
        }

        if config_change_count > 0 {
            total_findings_by_classification.add(Classification::Configuration, config_change_count);
            impact_totals.add(Impact::Changed, config_change_count);
            window_totals.add(Impact::Changed, config_change_count);
        }

        for (category, count) in raw_categories.iter() {
            if count > 0 {
                total_findings_by_classification.add(category, count);
            }
        }

        let count_of = |impact: Impact| findings.iter().filter(|f| f.impact == impact).count();
        let attention_count = count_of(Impact::Attention);
        let action_count = count_of(Impact::ActionRequired);
        let changed_count = count_of(Impact::Changed);
        let stable_count = count_of(Impact::Stable);

        // Weighted so one action-required finding outranks any pile of
        // cosmetic churn; interface diffs weigh more than L2 noise.
        let impact_score = action_count * 10
            + attention_count * 5
            + changed_count * 2
            + config_change_count * 2
            + raw_categories.get(Classification::Interface) * 4
            + stable_count;

        device_reports.push(DeviceReport {
            file_name: device.file_name,
            device_id: capture::safe_id(&hostname),
            hostname,
            findings,
            config_changes,
            diffs: device.diffs,
            raw_categories,
            findings_count,
            attention_count,
            action_count,
            changed_count,
            stable_count,
            impact_score,
        });
    }

    // Highest action count first, then attention, findings, score; a
    // stable sort keeps file order among equals, as Python's does.
    device_reports.sort_by(|a, b| {
        (b.action_count, b.attention_count, b.findings_count, b.impact_score).cmp(&(
            a.action_count,
            a.attention_count,
            a.findings_count,
            a.impact_score,
        ))
    });

    Ok(Analysis {
        common_files,
        device_reports,
        pairs: resolved_pairs,
        pair_findings: all_pair_findings,
        total_findings_by_classification,
        impact_totals,
        window_totals,
        symmetry_totals,
        devices_with_findings,
    })
}
