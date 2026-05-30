# ADR-001: Adopt the Claude Agent SDK on Bedrock

- **Status:** Accepted
- **Date:** 2026-05-30
- **Deciders:** AI Engineering NAMER

## Context

The substrate needs an agent runtime that can drive a Claude Opus 4.8 model to read code
semantically, run sandboxed experiments, and verify hypotheses in a loop. That runtime
must support hooks (for the deny-by-default PreToolUse permission gate, E7/E8), skill
loading, and subagent fan-out, while running against Amazon Bedrock for the
`global.anthropic.claude-opus-4-8` inference profile. We must pick the runtime layer the
orchestrator (`asec-core`) builds on, and do so without leaking provider SDK types
throughout the codebase.

## Decision

We will adopt the **Claude Agent SDK (Python)** as the v1 agent runtime, configured to run
against **Amazon Bedrock** with **Claude Opus 4.8** (`global.anthropic.claude-opus-4-8`)
as the default model. The concrete `ClaudeAgentRuntime` adapter wraps `ClaudeSDKClient`
and is the only v1 implementation of the `AgentRuntime` Protocol defined in `asec-core`.

## Alternatives Considered

- **Strands Agents SDK** — AWS-native agent framework with a clean Bedrock story. Rejected
  for v1: weaker first-class hook/skill ergonomics than the Claude Agent SDK, and a less
  direct path from existing Claude Code authoring experience. Kept as the designed-for swap
  target behind the `AgentRuntime` Protocol (see ADR-002).
- **Direct boto3 Bedrock Converse API** — maximal control, minimal dependency surface.
  Rejected: we would have to re-implement the hook lifecycle, skill loading, streaming
  normalization, and subagent orchestration by hand — exactly the value the Agent SDK
  already provides.

## Rationale

The Claude Agent SDK gives us the richest hook and skill model of the options, which the
substrate's permission gate (E7/E8) and audit logging (E12) depend on directly. Its
ergonomics map cleanly onto the team's existing Claude Code authoring experience, lowering
adoption cost. Running it on Bedrock satisfies the deployment and governance constraints
while keeping the default model on the required Opus 4.8 inference profile.

## Consequences

### Positive

- We get a standard, well-supported SDK with hooks, skills, streaming, and subagent
  primitives out of the box — no bespoke agent loop to maintain.
- Authoring skills and hooks mirrors the team's Claude Code workflow.

### Negative

- Vendor coupling to the Claude Agent SDK surface. **Mitigated** by the `AgentRuntime`
  Protocol seam (ADR-002): the orchestrator depends only on the Protocol, so a future
  `StrandsRuntime` can satisfy the same shape without inheritance coupling. Split trigger:
  a second runtime consumer (e.g. a non-Claude provider) appears.
