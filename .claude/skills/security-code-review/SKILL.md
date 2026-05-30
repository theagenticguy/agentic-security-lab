---
name: security-code-review
description: Review a git diff for vulnerabilities by running Semgrep and CodeQL, then
  emit structured findings. Use when the user asks for a security review of a diff/PR.
allowed-tools: Bash(semgrep *) Bash(codeql *) Bash(git diff *) Read Grep
disable-model-invocation: true
context: fork
agent: general-purpose
---

## Diff under review
!`git diff --merge-base origin/main`

## Task
1. Run `semgrep --config auto --sarif -o /tmp/semgrep.sarif $(git diff --name-only --merge-base origin/main)`.
2. If a CodeQL DB exists at .codeql/db, run `codeql database analyze .codeql/db --format sarifv2.1.0 -o /tmp/codeql.sarif <suite>`.
3. Merge SARIF; keep only findings on changed lines.
4. Emit one block per finding: file:line, CWE, severity (CRITICAL/HIGH/MED/LOW),
   evidence snippet, fix. End with a markdown summary table and a PASS/FAIL gate
   (FAIL if any CRITICAL/HIGH).
Do not modify source files. Report only.
