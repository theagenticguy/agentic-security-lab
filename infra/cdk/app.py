"""CDK app entrypoint: synthesize the substrate stack with CDK Nag aspects applied."""

from __future__ import annotations

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from stacks.substrate import AsecSubstrateStack

app = cdk.App()

# DynamoDB TableV2 with a customer-managed KMS key requires a region-aware
# stack; region-agnostic synth fails with ReplicaSpecificationCannotRenderedRegion.
# Day 4 will load env from a settings file; for now pin to us-east-1 (the
# Bedrock Opus 4.8 home region used by the orchestrator).
AsecSubstrateStack(
    app,
    "AsecSubstrateStack",
    env=cdk.Environment(region="us-east-1"),
)

# CDK Nag: enforce AWS Solutions security/compliance rules across the whole app.
# Encryption and public-access findings may never be suppressed (CI assert).
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()
