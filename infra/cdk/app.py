"""CDK app entrypoint: synthesize the substrate stack with CDK Nag aspects applied."""

from __future__ import annotations

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from stacks.sandbox_host import SandboxHostStack
from stacks.substrate import AsecSubstrateStack

app = cdk.App()

# DynamoDB TableV2 with a customer-managed KMS key requires a region-aware
# stack; region-agnostic synth fails with ReplicaSpecificationCannotRenderedRegion.
# Day 4 will load env from a settings file; for now pin to us-east-1 (the
# Bedrock Opus 4.8 home region used by the orchestrator).
env = cdk.Environment(region="us-east-1")

substrate = AsecSubstrateStack(app, "AsecSubstrateStack", env=env)

# Sandbox host consumes the substrate VPC, scoped Bedrock role, CMK, and the
# Bedrock interface-endpoint SG (egress target). See ADR-0009 / Track G.
SandboxHostStack(
    app,
    "SandboxHostStack",
    env=env,
    vpc=substrate.vpc,
    bedrock_role=substrate.bedrock_role,
    kms_key=substrate.kms_key,
    bedrock_endpoint_sg=substrate.endpoint_security_group,
)

# CDK Nag: enforce AWS Solutions security/compliance rules across the whole app.
# Encryption and public-access findings may never be suppressed (CI assert).
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()
