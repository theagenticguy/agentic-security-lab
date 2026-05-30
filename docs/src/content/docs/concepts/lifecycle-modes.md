---
title: Lifecycle modes
description: The five lifecycle modes the substrate is designed for — v1 ships PR-only.
---

The full whitepaper envisions five lifecycle modes for the agent. The v1 substrate is
built so all five can be layered on later, but **v1 implements the PR mode only**. The
other modes are designed-for, not built.

| Mode | Trigger | Scope | v1 status |
|---|---|---|---|
| Onboarding | New repo connected | Full-repo baseline threat model + findings sweep | Designed, not built |
| **PR** | Pull request opened/updated | Review changed lines only; gate on CRITICAL/HIGH | **v1 — built** |
| Nightly | Cron | Full-repo re-scan + variant analysis on prior hits | Designed, not built |
| Release | Tag push | Supply-chain + SBOM + dependency audit gate | Designed, not built |
| Incident | Manual / alert | Forensic log analysis + targeted hypothesis loop | Designed, not built |

:::note
v1 wires exactly one mode end-to-end (PR) over a tiny committed fixture corpus. The
point of v1 is to prove the loop *topology* and the trust primitives, not to cover every
mode. Modes share the same six-package substrate; adding a mode is new orchestration
wiring, not new primitives.
:::
