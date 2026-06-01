# INTENTIONALLY VULNERABLE — honey-bug canary (CWE-22). Do not deploy.
"""Report download with a planted path traversal (distinct from tiny-repo)."""

from __future__ import annotations

import pathlib

REPORT_ROOT = pathlib.Path("/var/reports")


def export_report(filename: str) -> bytes:
    # CWE-22: untrusted `filename` joined to the root with no containment check,
    # so `../../etc/passwd` escapes REPORT_ROOT.
    target = REPORT_ROOT / filename
    return target.read_bytes()
