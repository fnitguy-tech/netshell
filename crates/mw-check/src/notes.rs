//! Maintenance notes: the engineer's account of the window.
//!
//! The report says what changed. It cannot say why you changed it, what
//! surprised you, or what you only noticed afterwards - and that is the
//! part a reader needs most when they pick the ticket up a month later.
//!
//! So the notes are written by hand, in Markdown, and rendered into the
//! top of the HTML report above the machine findings. One file, two uses:
//! attached to the ticket inside the report, and shareable on its own.
//!
//! ```text
//! reports/<TICKET>/notes.md     (mw notes writes the template)
//! ```
//!
//! The template is seeded with what the tool already knows: the ticket, the
//! window times, and the devices it captured. That leaves only the
//! judgement to type. An empty section renders as nothing, and a template
//! with nothing filled in renders no notes block at all - the console says
//! so, so a blank skeleton can't pass for a finished write-up.
//!
//! The Markdown subset is tiny, because this has to produce byte-identical
//! HTML to `modules/notes.py` in prepost-check from the same file:
//!
//! ```text
//! ## Heading          a section heading
//! - item              a bullet
//! - [ ] item          an open checkbox
//! - [x] item          a ticked checkbox
//! `code`              inline code
//! **bold**            inline bold
//! <!-- comment -->    dropped (the template's own prompts)
//! ```
//!
//! Anything else is a paragraph. There is no nesting, no tables, and no
//! links; a line that looks like one of those is shown as written.

use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::report::escape;

/// The questions worth answering after a window, in the order a reader
/// wants them: what you meant to do, what happened, what you missed, what
/// is still open, what you would change.
pub const TEMPLATE_SECTIONS: [(&str, &str); 5] = [
    ("What we set out to do", "the change in one or two sentences, and why"),
    (
        "What actually happened",
        "deviations from the plan, surprises, anything re-run",
    ),
    (
        "What we missed",
        "found after the fact - what it was, and how it got past the checks",
    ),
    ("Still open", "one '- [ ] owner - item' per line"),
    (
        "Would do differently",
        "what to change in the MOP or the checks next time",
    ),
];

static HEADING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^##\s+(.*\S)\s*$").unwrap());
static TASK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-\s+\[([ xX])\]\s+(.*\S)\s*$").unwrap());
static BULLET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-\s+(.*\S)\s*$").unwrap());
static COMMENT_ONLY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*<!--.*-->\s*$").unwrap());
static CODE_SPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`([^`]+)`").unwrap());
static BOLD_SPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*\*([^*]+)\*\*").unwrap());

/// One list item: whether it is a checkbox, whether it is ticked, its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub task: bool,
    pub done: bool,
    pub text: String,
}

/// One block under a heading: a paragraph or a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Paragraph(String),
    List(Vec<Item>),
}

/// One section: its heading and the blocks under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub heading: String,
    pub blocks: Vec<Block>,
}

/// The seeded notes template for one ticket, as Markdown text.
pub fn template(ticket: &str, precheck_label: &str, postcheck_label: &str, hostnames: &[String]) -> String {
    let mut sorted: Vec<&String> = hostnames.iter().collect();
    sorted.sort();

    let devices = if sorted.is_empty() {
        "none captured yet".to_string()
    } else {
        sorted.iter().map(|name| name.as_str()).collect::<Vec<_>>().join(", ")
    };

    let mut lines = vec![
        format!("# {ticket} - Maintenance Notes"),
        String::new(),
        format!("- Precheck: {precheck_label}"),
        format!("- Postcheck: {postcheck_label}"),
        format!("- Devices ({}): {devices}", hostnames.len()),
        String::new(),
        "<!-- Written by hand. Delete the prompts as you answer them; a section".to_string(),
        "     left empty is left out of the report. -->".to_string(),
        String::new(),
    ];

    for (heading, prompt) in TEMPLATE_SECTIONS {
        lines.push(format!("## {heading}"));
        lines.push(String::new());
        lines.push(format!("<!-- {prompt} -->"));
        lines.push(String::new());
    }

    format!("{}\n", lines.join("\n").trim_end_matches('\n'))
}

/// Write the template, refusing to overwrite notes that already exist.
///
/// Returns `Ok(true)` when it wrote the file, `Ok(false)` when one was
/// already there. It never overwrites: half-finished notes are more use
/// than a fresh skeleton.
pub fn write_template(
    path: &Path,
    ticket: &str,
    precheck_label: &str,
    postcheck_label: &str,
    hostnames: &[String],
) -> anyhow::Result<bool> {
    if path.exists() {
        return Ok(false);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, template(ticket, precheck_label, postcheck_label, hostnames))?;

    Ok(true)
}

/// The notes file's text, or `None` when there is no file to read.
pub fn load(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// Split notes Markdown into sections, prompts dropped.
///
/// Content before the first `## ` heading is the seeded header, which the
/// report already shows in its own meta pills, so it is dropped. A heading
/// whose body is only prompts comes back with no blocks.
pub fn parse(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut heading: Option<String> = None;
    let mut blocks: Vec<Block> = Vec::new();
    let mut paragraph: Vec<String> = Vec::new();
    let mut items: Vec<Item> = Vec::new();

    fn close_paragraph(paragraph: &mut Vec<String>, blocks: &mut Vec<Block>) {
        if !paragraph.is_empty() {
            blocks.push(Block::Paragraph(paragraph.join(" ")));
            paragraph.clear();
        }
    }

    fn close_items(items: &mut Vec<Item>, blocks: &mut Vec<Block>) {
        if !items.is_empty() {
            blocks.push(Block::List(std::mem::take(items)));
        }
    }

    for raw in text.lines() {
        let line = raw.trim_end();

        if let Some(found) = HEADING.captures(line) {
            close_paragraph(&mut paragraph, &mut blocks);
            close_items(&mut items, &mut blocks);

            if let Some(previous) = heading.take() {
                sections.push(Section {
                    heading: previous,
                    blocks: std::mem::take(&mut blocks),
                });
            }

            blocks.clear();
            heading = Some(found[1].to_string());
            continue;
        }

        // The template's prompts, and any note-to-self the writer left in
        // comment form. Dropped, not rendered.
        if COMMENT_ONLY.is_match(line) || line.trim_start().starts_with("<!--") || line.trim_end().ends_with("-->") {
            continue;
        }

        if line.trim().is_empty() {
            close_paragraph(&mut paragraph, &mut blocks);
            close_items(&mut items, &mut blocks);
            continue;
        }

        if let Some(found) = TASK.captures(line) {
            close_paragraph(&mut paragraph, &mut blocks);
            items.push(Item {
                task: true,
                done: found[1].eq_ignore_ascii_case("x"),
                text: found[2].to_string(),
            });
            continue;
        }

        if let Some(found) = BULLET.captures(line) {
            close_paragraph(&mut paragraph, &mut blocks);
            items.push(Item {
                task: false,
                done: false,
                text: found[1].to_string(),
            });
            continue;
        }

        // An indented line under a list item continues it. Markdown writers
        // wrap, and without this a wrapped bullet came out as a bullet plus
        // a stray paragraph holding the rest of its sentence.
        if let Some(last) = items.last_mut()
            && line.starts_with(char::is_whitespace)
        {
            last.text = format!("{} {}", last.text, line.trim());
            continue;
        }

        close_items(&mut items, &mut blocks);
        paragraph.push(line.trim().to_string());
    }

    close_paragraph(&mut paragraph, &mut blocks);
    close_items(&mut items, &mut blocks);

    if let Some(previous) = heading {
        sections.push(Section {
            heading: previous,
            blocks,
        });
    }

    sections
}

/// Escape one line, then re-apply the two inline spans we support.
pub fn inline_html(text: &str) -> String {
    let escaped = escape(text);
    let with_code = CODE_SPAN.replace_all(&escaped, "<code>$1</code>");

    BOLD_SPAN.replace_all(&with_code, "<strong>$1</strong>").into_owned()
}

/// The notes as an HTML block, or `""` when nothing has been filled in.
pub fn render_html(text: &str) -> String {
    let sections: Vec<Section> = parse(text).into_iter().filter(|s| !s.blocks.is_empty()).collect();

    if sections.is_empty() {
        return String::new();
    }

    let mut parts = vec![
        "<div id=\"maintenance-notes\" class=\"notes-card\">".to_string(),
        "        <h2>Maintenance Notes</h2>".to_string(),
    ];

    for section in &sections {
        parts.push(format!("        <h3>{}</h3>", inline_html(&section.heading)));

        for block in &section.blocks {
            match block {
                Block::Paragraph(body) => parts.push(format!("        <p>{}</p>", inline_html(body))),
                Block::List(entries) => {
                    parts.push("        <ul class=\"notes-list\">".to_string());

                    for item in entries {
                        if item.task {
                            let box_text = if item.done { "[x]" } else { "[ ]" };
                            let state = if item.done { "done" } else { "open" };
                            parts.push(format!(
                                "            <li class=\"notes-task notes-{state}\">\
                                 <span class=\"notes-box\">{box_text}</span> {}</li>",
                                inline_html(&item.text)
                            ));
                        } else {
                            parts.push(format!("            <li>{}</li>", inline_html(&item.text)));
                        }
                    }

                    parts.push("        </ul>".to_string());
                }
            }
        }
    }

    parts.push("    </div>".to_string());

    parts.join("\n")
}

/// How many `- [ ]` items are still open, for the report's summary.
pub fn open_task_count(text: &str) -> usize {
    parse(text)
        .iter()
        .flat_map(|section| &section.blocks)
        .filter_map(|block| match block {
            Block::List(items) => Some(items),
            Block::Paragraph(_) => None,
        })
        .flatten()
        .filter(|item| item.task && !item.done)
        .count()
}
