"""Pydantic v2 value objects for the Phase-Zero threat-model artifact."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AssetClass = Literal["PII", "PHI", "FINANCIAL", "SECRET", "MODEL", "EMBEDDING", "OTHER"]
Weight = Literal["HIGH", "MED", "LOW"]
Stride = Literal["S", "T", "R", "I", "D", "E"]
NodeKind = Literal["AND", "OR", "LEAF"]


class Asset(BaseModel):
    """A thing worth protecting, classified and weighted."""

    model_config = ConfigDict(frozen=True)

    id: str
    asset_class: AssetClass = Field(alias="class")
    weight: Weight
    description: str


class Threat(BaseModel):
    """A STRIDE threat against a single architecture element."""

    model_config = ConfigDict(frozen=True)

    id: str
    element_id: str
    stride: Stride
    description: str
    likelihood: Weight
    impact: Weight
    mitigation: str | None = None
    owner: str | None = None


class AttackTreeNode(BaseModel):
    """A node in an attack tree: a goal decomposed by AND/OR, or a leaf."""

    model_config = ConfigDict(frozen=True)

    goal: str
    kind: NodeKind
    children: tuple[AttackTreeNode, ...] = ()


class ThreatModel(BaseModel):
    """The complete threat-model artifact for a target."""

    model_config = ConfigDict(frozen=True)

    version: int
    generated_by: str
    generated_at: datetime
    assets: tuple[Asset, ...] = ()
    threats: tuple[Threat, ...] = ()
    attack_trees: tuple[AttackTreeNode, ...] = ()
