# Contributing

## Branch naming

Use a typed prefix matching the change kind:

| Prefix      | Use for                                  |
| ----------- | ---------------------------------------- |
| `feat/`     | new capability                           |
| `fix/`      | bug fix                                  |
| `docs/`     | documentation only                       |
| `ci/`       | CI / workflow / tooling changes          |
| `refactor/` | behavior-preserving restructuring        |
| `security/` | hardening, dependency, or disclosure fix |
| `infra/`    | CDK / infrastructure changes             |

Example: `feat/asec-sandbox-docker-runtime`.

## Conventional commits (enforced)

Commit messages MUST follow [Conventional Commits](https://www.conventionalcommits.org/).
This is enforced locally by the `commit-msg` lefthook running `cz check`, and in CI.

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `ci`, `refactor`, `test`, `chore`, `perf`, `build`,
`security`. Scope is usually the package, e.g. `feat(asec-memory): add SQLite ledger`.

Versioning and `CHANGELOG.md` are driven from commit history by commitizen
(`mise run release:bump`).

## Pull requests

- Keep PRs scoped to one branch-prefix concern.
- Fill out the PR template (summary, EARS invariants touched, test plan).
- All CI gates (`lint`, `typecheck`, `test`, security scans, CDK Nag) must be green.
- Reference the ADR(s) your change implements or amends.

## ADR process

Architectural decisions live in `/adr` as the single source of truth (mirrored
read-only into the docs site via `scripts/sync_adrs.py`).

1. Copy `adr/0000-template.md` to `adr/NNNN-short-title.md` (next sequential number).
2. Fill in Status (`Proposed` -> `Accepted` / `Rejected` / `Superseded`), Context,
   Decision, Alternatives Considered, Rationale, and Consequences.
3. Open the ADR in the same PR as (or just ahead of) the code that implements it.
4. Never edit an `Accepted` ADR's decision; supersede it with a new ADR instead.
