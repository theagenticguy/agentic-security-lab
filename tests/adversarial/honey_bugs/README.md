# Honey-bug regression set

Five intentionally-vulnerable source files, one per focus CWE. Each is a *planted*
bug the orchestrator must always detect: the adversarial-CI gate fails if recall
drops below 5/5 (catches Opus/skill regressions, per whitepaper §16).

These snippets are deliberately **distinct** from
`apps/pr-reviewer/fixtures/tiny-repo/` so the agent cannot pass by memorizing the
demo corpus — different frameworks, different sink shapes, different variable names.

| File | CWE | Vulnerability |
| --- | --- | --- |
| `order_lookup.py` | CWE-89 | SQL injection via `%`-formatted query |
| `comment_view.py` | CWE-79 | Reflected XSS in a Django `HttpResponse` |
| `report_export.py` | CWE-22 | Path traversal joining user input to a base dir |
| `session_loader.py` | CWE-502 | Insecure deserialization (`pickle.loads` on a cookie) |
| `account_api.py` | CWE-639 | IDOR — object fetched by client-supplied id, no owner check |

Not deployable. Test fixture data, not substrate code (excluded from bandit + pyright).
