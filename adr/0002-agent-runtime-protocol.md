# ADR-002: `AgentRuntime` Protocol + adapter (runtime swap)

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

ADR-001 commits the substrate to the Claude Agent SDK as the v1 runtime, but explicitly
defers other providers behind a seam. We need that seam to be concrete: the orchestrator
(`asec-core`) must drive querying, hook registration (E16), and subagent fan-out (E15)
without ever importing `claude-agent-sdk` types or shapes. The question this ADR answers is
*what shape* the runtime boundary takes so a future provider is a swap, not a rewrite.

## Decision

We will define **`AgentRuntime` as a `typing.Protocol`** in `asec-core` with three members:
`query(prompt, *, options) -> AsyncIterator[RuntimeMessage]`, `register_hook(event, hook)`,
and `async spawn_subagents(specs)`. The sole v1 implementation is **`ClaudeAgentRuntime`**,
which lazy-imports the SDK inside its methods and normalizes every SDK stream message into a
frozen, provider-neutral `RuntimeMessage`. Future candidates — `OpenAIAgentsRuntime`,
`DeepAgentsRuntime`, `OpenCodeRuntime` — are deferred until a real second consumer appears;
each satisfies the same Protocol without inheritance.

## Alternatives Considered

- **A bare `make_options()` function** the orchestrator calls directly. Rejected: it leaks
  `ClaudeAgentOptions` and other SDK types up into the orchestrator, defeating the seam.
- **An abstract base class with `ClaudeAgentRuntime(AgentRuntime)` inheritance.** Rejected:
  ABC inheritance couples every adapter to our base, forces an import edge, and gains
  nothing over structural typing — `@runtime_checkable` Protocols give us `isinstance`
  checks in tests without the coupling.

## Rationale

A structural Protocol enforces the `apps -> packages -> asec-core` dependency direction with
zero inheritance edges: adapters live in their own packages and depend only on the Protocol.
`RuntimeMessage` keeps the orchestrator provider-pure, so the hook lifecycle (E16) and
subagent dispatch (E15) are testable against a fake runtime.

## Consequences

### Positive

- A new runtime is a new file implementing one Protocol — no orchestrator changes.
- The substrate is testable against an in-memory fake `AgentRuntime`.

### Negative

- Every adapter must do its own SDK-to-`RuntimeMessage` normalization. **Mitigated** by
  keeping `RuntimeMessage` small and discriminated by `kind`. Split trigger: a second
  runtime consumer lands and we extract a shared normalization helper.
