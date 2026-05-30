# Track A: Claude Agent SDK (Python)

Technical reference for building agentic security-review systems on the Claude Agent SDK (Python). Grounded in https://docs.claude.com/en/api/agent-sdk/python and https://github.com/anthropics/claude-agent-sdk-python. Install: `pip install claude-agent-sdk` (requires the Claude Code CLI on PATH).

## query() vs ClaudeSDKClient

`query()` is a stateless async generator: one prompt in, a stream of messages out. Use it for single-shot scans, CI gates, or fan-out workers where each call is independent.

```python
from claude_agent_sdk import query, ClaudeAgentOptions
async for msg in query(prompt="Audit auth.py for IDOR", options=ClaudeAgentOptions(model="opus")):
    print(msg)
```

`ClaudeSDKClient` is a stateful, bidirectional session: persistent context across turns, mid-stream interrupts, and dynamic tool/hook wiring. Use it for interactive triage, multi-turn hypothesis refinement, or any workflow that resumes/forks sessions.

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
async with ClaudeSDKClient(options=ClaudeAgentOptions(allowed_tools=["Read","Grep"])) as client:
    await client.query("Find injection sinks")
    async for msg in client.receive_response(): print(msg)
```

## ClaudeAgentOptions for security work

Key fields:

- **`system_prompt`** — `str | SystemPromptPreset | SystemPromptFile`. Inject the review rubric/threat model.
- **`model`** / **`fallback_model`** — model ID or alias (`"opus"`).
- **`permission_mode`** — `Literal["default","acceptEdits","plan","bypassPermissions","dontAsk","auto"]`. The 6 modes: `default`, `acceptEdits`, `plan` (read-only — ideal for non-destructive audit passes), `bypassPermissions` (sandbox only), `dontAsk`, `auto`.
- **`allowed_tools`** / **`disallowed_tools`** — for security work, restrict to `["Read","Grep","Glob"]` plus your MCP tools.
- **`hooks`** — `dict[HookEvent, list[HookMatcher]]` for deterministic policy enforcement.
- **`agents`** — `dict[str, AgentDefinition]`, programmatic subagents.
- **`output_format`** — JSON-schema structured output; pin findings to a fixed shape.
- **`max_budget_usd`** — `float`; stops the query when estimated cost is hit.

## The 10 hook events

`PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `PreCompact`, `Notification`, `SubagentStart`, `PermissionRequest`.

A `PreToolUse` hook that blocks edits to files listed in `threat-model.yaml`:

```python
import yaml
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

PROTECTED = set(yaml.safe_load(open("threat-model.yaml")).get("protected_files", []))

async def gate_edit(input_data, tool_use_id, context):
    path = input_data["tool_input"].get("file_path", "")
    if any(path.endswith(p) for p in PROTECTED):
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"{path} is threat-model protected"}}
    return {}

options = ClaudeAgentOptions(
    allowed_tools=["Edit"],
    hooks={"PreToolUse": [HookMatcher(matcher="Edit", hooks=[gate_edit])]},
)
```

## Programmatic subagents (AgentDefinition)

```python
from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition

CWES = ["CWE-89 SQLi", "CWE-79 XSS", "CWE-22 Path Traversal"]
agents = {
    f"worker-{i}": AgentDefinition(
        description=f"Hunts {c}",
        prompt=f"You are a security reviewer. Find only {c}. Report file:line + severity.",
        tools=["Read", "Grep", "Glob"], model="opus", permissionMode="plan",
    ) for i, c in enumerate(CWES)
}
opts = ClaudeAgentOptions(
    agents=agents,
    system_prompt="Dispatch one subagent per CWE in parallel, then merge findings.",
)
async for msg in query(prompt="Review ./src; one subagent per CWE.", options=opts):
    print(msg)
```

## SDK MCP servers via @tool

```python
from claude_agent_sdk import tool, create_sdk_mcp_server, ClaudeAgentOptions

@tool("run_fuzzer", "Fuzz a target function", {"target": str, "iterations": int})
async def run_fuzzer(args):
    crashes = my_fuzz_harness(args["target"], args.get("iterations", 1000))
    return {"content": [{"type": "text",
            "text": f"{len(crashes)} crashes in {args['target']}: {crashes[:5]}"}]}

fuzz_server = create_sdk_mcp_server(name="fuzz", version="1.0.0", tools=[run_fuzzer])
options = ClaudeAgentOptions(
    mcp_servers={"fuzz": fuzz_server},
    allowed_tools=["mcp__fuzz__run_fuzzer"],
)
```

## Bedrock backend

```bash
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
export ANTHROPIC_DEFAULT_OPUS_MODEL='global.anthropic.claude-opus-4-8'
```

`global.` prefix for global inference profiles, `us.` for US cross-region. IAM needs `bedrock:InvokeModel(WithResponseStream)` plus inference-profile read actions.

## Session resume and fork

```python
opts = ClaudeAgentOptions(resume="<session-id>")                    # continue same session
opts = ClaudeAgentOptions(resume="<session-id>", fork_session=True) # branch new session
```

Fork is the right primitive for **parallel hypothesis testing**: replay an audit session to its branch point, then fork N children to chase competing exploit theories concurrently. Each fork mutates its own transcript.

## SessionStore + checkpointing

`session_store` accepts a `SessionStore` protocol implementation (`append`, `load`, `list_sessions`, `delete`) that mirrors transcript entries to durable storage — DynamoDB, S3, Postgres. `enable_file_checkpointing=True` snapshots files the agent edits, enabling rollback of bad automated remediation.

## CLAUDE_CODE_ENABLE_TASKS=1

Set when the orchestrator must expose visible, persistent multi-step task state across a long review.
