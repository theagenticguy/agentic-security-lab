---
title: Run the pull-request reviewer
description: Walk through the one end-to-end app over a tiny diff corpus.
sidebar:
  badge:
    text: Roadmap
    variant: caution
  order: 99
---

:::caution[Roadmap page]
This page is a roadmap stub. The pull-request reviewer end-to-end loop is the
v1 milestone; once it lands, this page will document the full walkthrough.
For now the run-it-today block below is the canonical command.
:::

## Run it today

```bash
uv run pr-reviewer review ./apps/pr-reviewer/fixtures/tiny-repo
```

See [Getting started](/agentic-security-lab/guides/getting-started/) for setup.

## What it will cover when complete

- Loading the tiny-repo fixture and its hand-written `threat-model.yaml`.
- The five named functions read top-to-bottom: `load_target` →
  `build_threat_model` → `run_review` → `score_and_store` → `report`.
- Inspecting the emitted `findings.sarif` and the hash-chained Write-Once-Read-Many
  (WORM) audit-log line.
- Reading the engineering report (markdown table plus PASS/FAIL gate).
