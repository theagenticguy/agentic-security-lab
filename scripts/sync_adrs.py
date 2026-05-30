"""Mirror source-of-truth ADRs from /adr into the Starlight docs tree.

ADRs in `/adr` are the single source of truth; the docs site shows a read-only mirror.
This script copies each `adr/*.md` into `docs/src/content/docs/adrs/`, prepending
Starlight frontmatter (title, description) derived from the ADR's first H1 and first
non-empty paragraph. Run via `mise run docs:sync`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADR_SRC = REPO_ROOT / "adr"
DOCS_DEST = REPO_ROOT / "docs" / "src" / "content" / "docs" / "adrs"

_H1 = re.compile(r"^#\s+(.*)$", re.MULTILINE)


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
        out = build_frontmatter(title, description) + body
        (DOCS_DEST / adr_path.name).write_text(out, encoding="utf-8")
        count += 1

    print(f"Synced {count} ADR(s) -> {DOCS_DEST}")
    return count


if __name__ == "__main__":
    sync()
