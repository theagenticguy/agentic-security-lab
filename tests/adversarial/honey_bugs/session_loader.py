# INTENTIONALLY VULNERABLE — honey-bug canary (CWE-502). Do not deploy.
"""Session restore with a planted insecure deserialization (distinct from tiny-repo)."""

from __future__ import annotations

import base64
import pickle
from typing import Any


def load_session(cookie_value: str) -> Any:
    raw = base64.b64decode(cookie_value)
    # CWE-502: untrusted, attacker-controlled cookie passed straight to pickle.loads,
    # enabling arbitrary object construction / RCE.
    return pickle.loads(raw)
