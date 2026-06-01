# INTENTIONALLY VULNERABLE — honey-bug canary (CWE-639 / IDOR). Do not deploy.
"""Account detail endpoint with a planted IDOR (distinct from tiny-repo)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI  # type: ignore[import-untyped]

app = FastAPI()
_ACCOUNTS: dict[int, dict[str, Any]] = {}


@app.get("/accounts/{account_id}")
def get_account(account_id: int, current_user_id: int) -> dict[str, Any]:
    # CWE-639 (IDOR): the record is fetched by a client-supplied `account_id`
    # with no check that it belongs to `current_user_id`, so any authenticated
    # user can read any account.
    return _ACCOUNTS[account_id]
