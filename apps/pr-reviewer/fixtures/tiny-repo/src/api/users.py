# INTENTIONALLY VULNERABLE — fixture for asec-pr-reviewer end-to-end tests. Do not deploy.
"""User lookup API (Flask-style). Contains a deliberate CWE-89 SQL injection."""

from __future__ import annotations

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def find_user() -> str:
    name = request.args["name"]
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # CWE-89: untrusted `name` interpolated straight into the SQL text.
    cursor.execute(f"SELECT * FROM users WHERE name='{name}'")
    rows = cursor.fetchall()
    return str(rows)
