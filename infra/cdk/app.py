"""CDK app entrypoint: synthesize the substrate stack with CDK Nag aspects applied."""

from __future__ import annotations

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from stacks.substrate import AsecSubstrateStack

app = cdk.App()

AsecSubstrateStack(app, "AsecSubstrateStack")

# CDK Nag: enforce AWS Solutions security/compliance rules across the whole app.
# Encryption and public-access findings may never be suppressed (CI assert).
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()
