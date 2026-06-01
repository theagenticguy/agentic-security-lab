# INTENTIONALLY VULNERABLE — fixture for asec-pr-reviewer end-to-end tests. Do not deploy.
"""File download endpoint (Flask-style). Contains a deliberate CWE-22 path traversal."""

from __future__ import annotations

import os

from flask import Flask, request

app = Flask(__name__)

BASE = "/srv/files"


@app.route("/download")
def download() -> bytes:
    requested = request.args["p"]
    # CWE-22: `requested` is joined onto BASE with no normalization or
    # containment check, so `../../etc/passwd` escapes the base directory.
    path = os.path.join(BASE, requested)
    with open(path, "rb") as handle:
        return handle.read()
