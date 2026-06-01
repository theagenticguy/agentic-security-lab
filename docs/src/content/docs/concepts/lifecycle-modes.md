---
title: Lifecycle modes
description: The five lifecycle modes the substrate is designed for. v1 implements only the pull-request mode.
sidebar:
  order: 3
---

The full design plans for five lifecycle modes. v1 implements **only the
pull-request mode** end-to-end; the other four are designed-for, not built.
Adding a mode is new orchestration wiring on the same six packages, not new
isolation, ledger, or audit primitives.

| Mode | Trigger | Scope | v1 status |
|---|---|---|---|
| Onboarding | New repo connected | Full-repo baseline threat model + first-pass findings | Designed, not built |
| **Pull request** | PR opened or updated | Review changed lines only; gate on CRITICAL or HIGH | **v1 — built** |
| Nightly | Cron | Full-repo re-scan + variant analysis on prior hits | Designed, not built |
| Release | Tag push | Supply-chain + Software Bill of Materials (SBOM) + dependency-audit gate | Designed, not built |
| Incident | Manual or alert-driven | Forensic log analysis + targeted hypothesis loop | Designed, not built |

:::note
v1 wires one mode (pull-request review) end-to-end against a small fixture
corpus. It exercises every package boundary once, against a known input, so the
isolation, ledger, and audit-log behavior is testable. It is not a production
review service.
:::
