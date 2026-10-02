"""Markdown report writer - collects per-target result dicts (returned
by each role's run()) and writes them as a table under reports/."""
from pathlib import Path


def write_report(name, rows, columns):
    out = Path("reports") / f"{name}.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [f"# {name}", ""]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("|" + "|".join(["---"] * len(columns)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in columns) + " |")

    out.write_text("\n".join(lines) + "\n")
    return out
