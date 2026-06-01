"""Make the CDK app importable from tests.

The CDK app runs as ``python app.py`` from ``infra/cdk`` (see cdk.json), so the
``stacks`` package is top-level there. When pytest collects from the repo root,
this conftest puts ``infra/cdk`` on ``sys.path`` so ``from stacks... import`` works.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CDK_ROOT = Path(__file__).resolve().parent
if str(_CDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_CDK_ROOT))
