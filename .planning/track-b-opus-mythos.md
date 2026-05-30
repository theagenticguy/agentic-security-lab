# Track B: Opus 4.8 + Mythos + Computer Use

*All figures attributed to Anthropic published sources, retrieved 2026-05-29. Items not independently reproduced are flagged.*

## 1. Opus 4.8 verified facts

As published by Anthropic:

- **Announced:** May 28, 2026 (https://www.anthropic.com/news/claude-opus-4-8).
- **Pricing per 1M tokens** (claude.com pricing): input **$5**, output **$25**, 5-min cache write **$6.25**, 1-hour cache write **$10**, cache hit/read **$0.50**. Batch: $2.50 in / $12.50 out. Fast mode: $10 in / $50 out.
- **Context window:** 1M tokens (200k on Microsoft Foundry). **Max output:** 128k tokens synchronous; up to 300k via the `output-300k-2026-03-24` batch beta.
- **Knowledge cutoff:** Jan 2026. Uses a new tokenizer (Opus 4.7+), which can consume up to ~35% more tokens per fixed text.
- **Thinking mode:** the models-overview table lists Opus 4.8 with *adaptive thinking = Yes, extended thinking = No*; `effort` defaults to `high`.

**Headline benchmarks:** the announcement post text I retrieved does **not** inline SWE-bench Verified, SWE-bench Pro, GPQA Diamond, or AIME figures — it references the System Card for them. I therefore do not have verified exact percentages for those four and decline to fabricate them. The one quantified security benchmark Anthropic states publicly (Glasswing page) is **CyberGym: Mythos Preview 83.1% vs Opus 4.6 66.6%**.

## 2. Mythos availability quote

From the Opus 4.8 announcement (https://www.anthropic.com/news/claude-opus-4-8):

> "We're making swift progress on developing these safeguards and expect to be able to bring Mythos-class models to all our customers in the coming weeks."

## 3. Glasswing / Mythos claims

Stated on https://www.anthropic.com/glasswing:

- **CyberGym 83.1%** (Mythos Preview) — published figure.
- **12 founding partners:** AWS, Anthropic, Apple, Broadcom, Cisco, CrowdStrike, Google, JPMorganChase, Linux Foundation, Microsoft, NVIDIA, Palo Alto Networks; plus **"over 40 additional organizations"** with extended access.
- Mythos Preview on Bedrock is **invitation-only**, regional, `us-east-1` only, requiring an allowlisted dedicated AWS account (model id `anthropic.claude-mythos-preview`).

The zero-day discovery claims (next section) are vendor statements, not independently verified here.

## 4. Computer use API

Beta header **`computer-use-2025-11-24`** (Opus 4.8/4.7/4.6, Sonnet 4.6, Opus 4.5). Three tools are typically supplied together: **`computer_20251124`** (adds `zoom` with `enable_zoom: true`), **`text_editor_20250728`** (name `str_replace_based_edit_tool`), **`bash_20250124`**.

The agent loop: send request → Claude returns `stop_reason: tool_use` with an action (`screenshot`, `left_click`, `type`, `key`, `scroll`, etc.) → your app executes it in a sandboxed VM/container → you append a `tool_result` (base64 PNG screenshot) → repeat until Claude stops requesting tools.

```python
for _ in range(max_iterations):
    resp = client.beta.messages.create(
        model="claude-opus-4-8", max_tokens=4096,
        messages=messages, tools=TOOLS,
        betas=["computer-use-2025-11-24"])
    messages.append({"role": "assistant", "content": resp.content})
    results = process_tool_calls(resp)   # run actions, capture screenshot
    if not results: break
    messages.append({"role": "user", "content": results})
```

**Cost/latency order of magnitude:** each screenshot ≈ 1,000–1,800 input tokens; tool definition 735 tokens; computer-use system overhead 466–499 tokens. Anthropic flags latency as too slow for real-time human use — target async/background automation. Opus 4.8 supports up to 2576px long-edge with 1:1 coordinates (no scaling).

## 5. Extended thinking

Per the models table, Opus 4.8 uses **adaptive thinking** (the `effort` param, default `high`), not the classic `thinking.type=enabled` / `budget_tokens` of Sonnet/Haiku 4.x. On thinking-enabled models the pattern is `thinking={"type": "enabled", "budget_tokens": N}`; minimum **1024**, with **16k+** appropriate for deep security audits where multi-step reasoning over a large diff matters. For Opus 4.8 security review, set `effort` explicitly (`high`/`max`) rather than a token budget.

## 6. Bedrock invocation

Two surfaces exist:

- **Cross-region inference profiles (used by Claude Code / Agent SDK):** `global.anthropic.claude-opus-4-8` (global, no premium) and `us.anthropic.claude-opus-4-8` (US, +10%).
- **New Mantle Messages endpoint** (`/anthropic/v1/messages`): model id `anthropic.claude-opus-4-8`.

Open to all Bedrock customers; global endpoint across the listed regions (us-east-1/2, us-west-2, eu-*, ap-*, etc.). Point the Agent SDK at Bedrock with:

```bash
export CLAUDE_CODE_USE_BEDROCK=1
export ANTHROPIC_MODEL="global.anthropic.claude-opus-4-8"
export AWS_REGION="us-east-1"
# plus AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
```

Default quota 2M input TPM (raise to 4M without Anthropic approval). Mythos Preview requires a separate allowlisted account, `us-east-1` only.

## 7. Cost reality check

**Assumptions:** ~5M input tokens (50K-LoC repo + prompts), ~200k output tokens (findings), Opus 4.8 standard global pricing, no caching.

- Input: 5M × $5/1M = **$25.00**
- Output: 200k × $25/1M = **$5.00**
- **Total ≈ $30** per full pass (order of magnitude: tens of dollars).

With prompt caching on the code corpus (cache hits at $0.50/1M), repeat passes drop input cost ~10x to a few dollars. Batch API would halve a one-shot run to ~$15. Tokenizer overhead (~35%) and agentic re-reads can push a real audit to the low-hundreds of dollars.

## 8. Stated by Anthropic, not independently reproduced

From https://www.anthropic.com/glasswing, attributed to Anthropic, **not** verified in this research:

- "thousands of zero-day vulnerabilities… in every major operating system and every major web browser."
- A **27-year-old** vulnerability in **OpenBSD**.
- A **16-year-old** vulnerability in **FFmpeg**, in a line automated tools had hit ~5 million times without catching it.
- Autonomously found and **chained Linux kernel vulnerabilities** to escalate from ordinary user to full machine control.
- CyberGym **83.1%** (benchmark figure, not an external reproduction).
