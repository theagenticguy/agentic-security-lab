"""Bedrock smoke test for the v1 model id.

Goal: cheapest possible InvokeModel against the Opus 4.8 global inference
profile, to prove the substrate has Bedrock access before Day 3 wires the
real orchestrator. ~5 input tokens, ~5 output tokens.

Usage: AWS_PROFILE=lalsaado-handson uv run python scripts/bedrock_smoke.py
"""

from __future__ import annotations

import json
import os
import sys

import boto3

MODEL_ID = os.environ.get("ANTHROPIC_MODEL", "global.anthropic.claude-opus-4-8")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def main() -> int:
    client = boto3.client("bedrock-runtime", region_name=REGION)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
    }
    resp = client.invoke_model(modelId=MODEL_ID, body=json.dumps(body))
    payload = json.loads(resp["body"].read())
    text = payload["content"][0]["text"].strip()
    usage = payload.get("usage") or {}
    print(f"model_id      = {MODEL_ID}")
    print(f"region        = {REGION}")
    print(f"reply         = {text!r}")
    print(f"input_tokens  = {usage.get('input_tokens')}")
    print(f"output_tokens = {usage.get('output_tokens')}")
    return 0 if "OK" in text.upper() else 1


if __name__ == "__main__":
    sys.exit(main())
