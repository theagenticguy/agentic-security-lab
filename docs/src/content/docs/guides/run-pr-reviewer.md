---
title: Run the PR reviewer
description: Walk through the one end-to-end app over a tiny diff corpus.
---

:::caution[Work in progress]
This guide is a placeholder. The PR-reviewer E2E loop lands on Day 3 of the bootstrap;
this page will document the full walkthrough once the wiring is in place.
:::

## What it will cover

- Loading the tiny-repo fixture and its hand-written `threat-model.yaml`
- The five named functions read top-to-bottom: `load_target` → `build_threat_model` →
  `run_review` → `score_and_store` → `report`
- Inspecting the emitted `findings.sarif` and the hash-chained WORM audit line
- Reading the Engineering report (markdown table + PASS/FAIL gate)

## Run it today

```bash
uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

See [Getting started](/agentic-security-lab/guides/getting-started/) for setup.
