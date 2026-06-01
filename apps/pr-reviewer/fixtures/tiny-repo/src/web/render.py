# INTENTIONALLY VULNERABLE — fixture for asec-pr-reviewer end-to-end tests. Do not deploy.
"""Search-results renderer (Flask-style). Contains a deliberate CWE-79 XSS."""

from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def render_results() -> str:
    # CWE-79: the `q` query parameter is reflected into HTML without escaping.
    return f"<div>{request.args['q']}</div>"
