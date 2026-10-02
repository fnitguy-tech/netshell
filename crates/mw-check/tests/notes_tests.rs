//! Maintenance notes.
//!
//! The report says what changed; it cannot say what you meant to do, what
//! surprised you, or what you only noticed afterwards. The notes file is
//! that account, written by hand in Markdown and rendered above the machine
//! findings.
//!
//! Two behaviours matter more than the formatting. A template nobody filled
//! in must not pass for a finished write-up, and an existing file must never
//! be overwritten by a fresh skeleton.
//!
//! Every rendering here has to match `modules/notes.py` in prepost-check
//! byte for byte, which the demo fixture checks end to end.

use mw_check::notes;

const FILLED: &str = "\
# NET-9 - Maintenance Notes

- Precheck: reports/NET-9/Precheck/precheck_2026-01-01_00-00

## What we set out to do

Add the second uplink.

## What we missed

- `seq 60` never landed on SW-2 - the inverse of the gap
  the step existed to close.
- The tool rated it **Stable**.

## Still open

- [ ] chase the cabling
- [x] re-add the entry
";

fn hosts(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_unfilled_template_renders_nothing() {
    // Six empty headings would look like a write-up.
    let template = notes::template("NET-9", "pre", "post", &hosts(&["SW-1", "SW-2"]));

    assert!(!notes::parse(&template).is_empty());
    assert!(notes::parse(&template).iter().all(|s| s.blocks.is_empty()));
    assert_eq!(notes::render_html(&template), "");
    assert_eq!(notes::open_task_count(&template), 0);
}

#[test]
fn the_template_names_the_devices_and_the_runs() {
    let template = notes::template("NET-9", "pre/run-a", "post/run-b", &hosts(&["SW-2", "SW-1"]));

    assert!(template.contains("# NET-9 - Maintenance Notes"));
    assert!(template.contains("- Precheck: pre/run-a"));
    assert!(template.contains("- Postcheck: post/run-b"));
    // Sorted, and counted, so a missing device is obvious at a glance.
    assert!(template.contains("- Devices (2): SW-1, SW-2"));

    for (heading, _prompt) in notes::TEMPLATE_SECTIONS {
        assert!(template.contains(&format!("## {heading}")));
    }
}

#[test]
fn write_template_never_overwrites_existing_notes() {
    // Half-finished notes are more use than a fresh skeleton.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("deeper").join("notes.md");
    let mine = "# mine\n\n## What we missed\n\nthe cable.\n";

    assert!(notes::write_template(&path, "NET-9", "pre", "post", &hosts(&["SW-1"])).unwrap());
    std::fs::write(&path, mine).unwrap();

    assert!(!notes::write_template(&path, "NET-9", "pre", "post", &hosts(&["SW-1"])).unwrap());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), mine);
}

#[test]
fn load_returns_none_when_there_is_no_file() {
    let tmp = tempfile::tempdir().unwrap();

    assert_eq!(notes::load(&tmp.path().join("absent.md")), None);
}

#[test]
fn only_sections_with_content_are_rendered() {
    let html = notes::render_html(FILLED);

    assert!(html.contains("<h3>What we set out to do</h3>"));
    assert!(html.contains("<h3>What we missed</h3>"));
    assert!(html.contains("<h3>Still open</h3>"));
    // "What actually happened" is not in FILLED at all.
    assert!(!html.contains("What actually happened"));
    // The seeded header is dropped: the report shows the runs in its own pills.
    assert!(!html.contains("Precheck: reports/NET-9"));
}

#[test]
fn a_wrapped_bullet_stays_one_bullet() {
    // Markdown writers wrap. Without continuation lines, a wrapped bullet
    // came out as a bullet plus a stray paragraph holding the rest of its
    // sentence.
    let html = notes::render_html(FILLED);

    assert!(html.contains("the inverse of the gap the step existed to close."));
    assert_eq!(html.matches("<li>").count(), 2);
    assert!(!html.contains("<p>the step existed to close"));
}

#[test]
fn checkboxes_carry_their_state_and_are_counted() {
    let html = notes::render_html(FILLED);

    assert!(html.contains("<span class=\"notes-box\">[ ]</span> chase the cabling"));
    assert!(html.contains("<span class=\"notes-box\">[x]</span> re-add the entry"));
    assert!(html.contains("notes-open") && html.contains("notes-done"));
    assert_eq!(notes::open_task_count(FILLED), 1);
}

#[test]
fn an_uppercase_x_also_counts_as_done() {
    let html = notes::render_html("## Still open\n\n- [X] done\n- [ ] not done\n");

    assert!(html.contains("<span class=\"notes-box\">[x]</span> done"));
    assert_eq!(
        notes::open_task_count("## Still open\n\n- [X] done\n- [ ] not done\n"),
        1
    );
}

#[test]
fn inline_code_and_bold_survive_escaping() {
    let html = notes::render_html(FILLED);

    assert!(html.contains("<code>seq 60</code>"));
    assert!(html.contains("<strong>Stable</strong>"));
}

#[test]
fn notes_are_escaped() {
    // The notes are a file on disk, but they still end up in a page that
    // gets attached to a ticket and opened in a browser. The payloads
    // survive as visible text, with every angle bracket escaped.
    for hostile in [
        "- <img src=x onerror=alert(1)>",
        "- [ ] <b>not bold</b> & raw",
        "<script>alert(1)</script>",
    ] {
        let html = notes::render_html(&format!("## Heading\n\n{hostile}\n"));

        for tag in ["<script", "<img", "<b>"] {
            assert!(!html.contains(tag), "{tag} reached the page from {hostile:?}");
        }

        assert!(html.contains("&lt;"));
    }
}

#[test]
fn a_heading_with_no_body_is_dropped_entirely() {
    // A hostile heading cannot reach the page on its own: a section with
    // nothing under it is left out, heading and all.
    assert_eq!(notes::render_html("## <script>alert(1)</script>\n"), "");
}

#[test]
fn prompts_and_comments_are_dropped() {
    let html = notes::render_html("## What we missed\n\n<!-- found after the fact -->\nthe cable.\n");

    assert!(!html.contains("found after the fact"));
    assert!(html.contains("<p>the cable.</p>"));
}
