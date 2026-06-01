# INTENTIONALLY VULNERABLE — honey-bug canary (CWE-89). Do not deploy.
"""Order lookup endpoint with a planted SQL injection (distinct from tiny-repo)."""

from __future__ import annotations

import psycopg2  # type: ignore[import-untyped]
from bottle import request, route  # type: ignore[import-untyped]


@route("/orders")
def lookup_orders() -> str:
    order_ref = request.query.ref
    conn = psycopg2.connect("dbname=shop")
    cur = conn.cursor()
    # CWE-89: untrusted `order_ref` concatenated into SQL, not bound to a placeholder.
    cur.execute("SELECT * FROM orders WHERE ref = '" + order_ref + "'")
    return str(cur.fetchall())
