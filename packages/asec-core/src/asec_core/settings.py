"""Runtime configuration (E19).

`Settings` is a frozen `BaseSettings` value object: the orchestrator reads provider,
model, region, budget cap, and permission mode from the environment once at startup,
then treats the result as immutable for the lifetime of a review run.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PermissionMode = Literal[
    "plan", "default", "acceptEdits", "bypassPermissions", "dontAsk", "auto"
]


class Settings(BaseSettings):
    """Frozen runtime configuration sourced from the environment (E19).

    Mirrors the Claude Agent SDK's Bedrock contract: `CLAUDE_CODE_USE_BEDROCK` selects
    the backend, `ANTHROPIC_MODEL` / `ANTHROPIC_DEFAULT_OPUS_MODEL` pins the model id,
    and `AWS_REGION` targets the inference profile. `max_budget_usd` is the hard cost cap
    enforced by `GovernanceGate` before every tool call.
    """

    model_config = SettingsConfigDict(frozen=True, extra="ignore")

    bedrock_use: bool = Field(
        default=False, validation_alias="CLAUDE_CODE_USE_BEDROCK"
    )
    model_id: str = Field(
        default="global.anthropic.claude-opus-4-8",
        validation_alias=AliasChoices(
            "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL"
        ),
    )
    aws_region: str = Field(default="us-east-1", validation_alias="AWS_REGION")
    max_budget_usd: float = Field(default=5.0, validation_alias="ASEC_MAX_BUDGET_USD")
    permission_mode: PermissionMode = Field(
        default="plan", validation_alias="ASEC_PERMISSION_MODE"
    )
