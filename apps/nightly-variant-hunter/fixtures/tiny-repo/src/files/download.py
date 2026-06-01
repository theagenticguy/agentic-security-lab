"""Unrelated file -- no SQLi shape here, the hunter should not flag it."""

import os

BASE = "/srv/files"


def safe_read(name):
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE):
        raise ValueError("path escapes base")
    with open(path, encoding="utf-8") as handle:
        return handle.read()
