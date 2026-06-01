"""Mirror source-of-truth ADRs from /adr into the Starlight docs tree.

ADRs in `/adr` are the single source of truth; the docs site shows a read-only
mirror. This script copies each `adr/*.md` into `docs/src/content/docs/adrs/`,
prepends Starlight frontmatter (title, description) derived from the ADR's
first H1 and first non-empty paragraph, and applies two AppSec-reader
ergonomics:

1. The body below the metadata header collapses into a `<details>` element so
   the ADR list page shows context-only by default.
2. EARS invariant references like ``E3`` or ``E12`` link to the canonical
   anchors on `/concepts/ears-invariants/` so a reader can pull the normative
   text without leaving the page.

Run via ``mise run docs:sync``. Idempotent.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADR_SRC = REPO_ROOT / "adr"
DOCS_DEST = REPO_ROOT / "docs" / "src" / "content" / "docs" / "adrs"
EARS_HREF_BASE = "/agentic-security-lab/concepts/ears-invariants/"

_H1 = re.compile(r"^#\s+(.*)$", re.MULTILINE)
# Matches `E1` through `E19` standalone (not inside a code span and not inside
# an existing link). Word boundaries on both sides; allow trailing punctuation.
_EARS_REF = re.compile(r"(?<![\w/#])(E(?:[1-9]|1[0-9]))(?![\w/])")
# Sections we want to fold into the collapsible body. Anything before the first
# such heading stays visible on the page (status, date, deciders, context).
_FOLD_HEADINGS = ("## Decision", "## Alternatives Considered", "## Rationale", "## Consequences")


def _yaml_escape(value: str) -> str:
    """Quote a scalar for a YAML frontmatter value."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def extract_title(body: str, fallback: str) -> str:
    """Return the first H1 heading text, or a fallback derived from the filename."""
    match = _H1.search(body)
    return match.group(1).strip() if match else fallback


def extract_description(body: str, title: str) -> str:
    """Return the first non-empty, non-heading, non-metadata line as a description."""
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith(">"):
            continue
        return line
    return f"Architecture Decision Record: {title}"


def build_frontmatter(title: str, description: str) -> str:
    """Build a Starlight YAML frontmatter block."""
    return f"---\ntitle: {_yaml_escape(title)}\ndescription: {_yaml_escape(description)}\n---\n\n"


def link_ears_refs(body: str) -> str:
    """Rewrite ``E12`` style references to anchor links on the EARS page.

    Skips matches inside fenced code blocks and inline code, and skips matches
    that are already inside a Markdown link target.
    """

    out: list[str] = []
    in_fence = False
    for raw in body.splitlines(keepends=True):
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            out.append(raw)
            continue
        if in_fence:
            out.append(raw)
            continue
        # Protect inline code spans by splitting on backticks; only rewrite even-indexed segments.
        parts = raw.split("`")
        for i in range(0, len(parts), 2):
            parts[i] = _EARS_REF.sub(
                lambda m: f"[{m.group(1)}]({EARS_HREF_BASE}#{m.group(1).lower()})",
                parts[i],
            )
        out.append("`".join(parts))
    return "".join(out)


def collapse_decision_body(body: str) -> str:
    """Wrap Decision/Alternatives/Rationale/Consequences in a `<details>` block.

    Anything before the first folded heading stays visible. ADRs without those
    headings are returned unchanged.
    """

    fold_idx: int | None = None
    for heading in _FOLD_HEADINGS:
        idx = body.find(f"\n{heading}")
        if idx != -1 and (fold_idx is None or idx < fold_idx):
            fold_idx = idx

    if fold_idx is None:
        return body

    head = body[: fold_idx + 1]  # include the leading newline
    tail = body[fold_idx + 1 :]
    return (
        f"{head}\n"
        '<details>\n<summary>Decision, alternatives, rationale, consequences</summary>\n\n'
        f"{tail}\n\n</details>\n"
    )


def transform(body: str) -> str:
    """Apply EARS linking + decision collapse. Order matters: link first."""
    return collapse_decision_body(link_ears_refs(body))


def sync() -> int:
    """Copy every ADR into the docs tree with prepended frontmatter. Returns count."""
    if not ADR_SRC.is_dir():
        raise SystemExit(f"ADR source directory not found: {ADR_SRC}")

    DOCS_DEST.mkdir(parents=True, exist_ok=True)

    count = 0
    for adr_path in sorted(ADR_SRC.glob("*.md")):
        body = adr_path.read_text(encoding="utf-8")
        fallback = adr_path.stem.replace("-", " ").title()
        title = extract_title(body, fallback)
        description = extract_description(body, title)
        rendered = build_frontmatter(title, description) + transform(body)
        (DOCS_DEST / adr_path.name).write_text(rendered, encoding="utf-8")
        count += 1

    print(f"Synced {count} ADR(s) -> {DOCS_DEST}")
    return count


if __name__ == "__main__":
    sync()
