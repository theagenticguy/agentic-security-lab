"""Synth-time assertions for the substrate + sandbox-host stacks.

These run offline via ``aws_cdk.assertions.Template`` against a synthesized
``cdk.App()`` — no AWS credentials needed. They lock the security-critical
shape of the stacks (no NAT, scoped IAM, WORM bucket, IMDSv2, no ingress).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

# Make the `stacks` package importable when pytest collects from the repo root.
_CDK_DIR = Path(__file__).resolve().parents[1]
if str(_CDK_DIR) not in sys.path:
    sys.path.insert(0, str(_CDK_DIR))

from stacks.sandbox_host import SandboxHostStack  # noqa: E402
from stacks.substrate import AsecSubstrateStack  # noqa: E402


@pytest.fixture(scope="module")
def templates() -> tuple[Template, Template]:
    """Synthesize both stacks from a single app, then derive both templates.

    The stacks share one ``cdk.App`` because the sandbox host consumes substrate
    cross-stack exports. ``Template.from_stack`` is called only after the whole
    tree is built, so the construct tree is never modified post-synth.
    """
    app = cdk.App()
    env = cdk.Environment(region="us-east-1")
    substrate = AsecSubstrateStack(app, "AsecSubstrateStack", env=env)
    sandbox = SandboxHostStack(
        app,
        "SandboxHostStack",
        env=env,
        vpc=substrate.vpc,
        bedrock_role=substrate.bedrock_role,
        kms_key=substrate.kms_key,
        bedrock_endpoint_sg=substrate.endpoint_security_group,
    )
    assembly = app.synth()
    return (
        Template.from_json(assembly.get_stack_by_name(substrate.stack_name).template),
        Template.from_json(assembly.get_stack_by_name(sandbox.stack_name).template),
    )


@pytest.fixture(scope="module")
def substrate_tmpl(templates: tuple[Template, Template]) -> Template:
    return templates[0]


@pytest.fixture(scope="module")
def sandbox_tmpl(templates: tuple[Template, Template]) -> Template:
    return templates[1]


# --------------------------------------------------------------------------- #
# SubstrateStack
# --------------------------------------------------------------------------- #


def test_vpc_has_no_nat_gateways(substrate_tmpl: Template) -> None:
    """No NAT gateways: egress is only via VPC endpoints."""
    substrate_tmpl.resource_count_is("AWS::EC2::NatGateway", 0)


def test_gateway_endpoints_exist(substrate_tmpl: Template) -> None:
    gateways = [
        ep
        for ep in substrate_tmpl.find_resources("AWS::EC2::VPCEndpoint").values()
        if ep["Properties"].get("VpcEndpointType", "Gateway") == "Gateway"
    ]
    blob = json.dumps(gateways).lower()
    assert "s3" in blob
    assert "dynamodb" in blob


def test_interface_endpoints_exist(substrate_tmpl: Template) -> None:
    endpoints = substrate_tmpl.find_resources("AWS::EC2::VPCEndpoint")
    blob = json.dumps(endpoints).lower()
    for svc in ("bedrock-runtime", "kms", "logs", "sts"):
        assert svc in blob, f"missing interface endpoint for {svc}"


def test_interface_endpoints_have_private_dns(substrate_tmpl: Template) -> None:
    iface = [
        ep
        for ep in substrate_tmpl.find_resources("AWS::EC2::VPCEndpoint").values()
        if ep["Properties"].get("VpcEndpointType") == "Interface"
    ]
    assert iface, "expected interface endpoints"
    assert all(ep["Properties"].get("PrivateDnsEnabled") is True for ep in iface)


def test_bedrock_invoke_not_resource_wildcard(substrate_tmpl: Template) -> None:
    """No `Resource: "*"` paired with bedrock:InvokeModel on the agent role policy."""
    policies = substrate_tmpl.find_resources("AWS::IAM::Policy")
    found_invoke = False
    for pol in policies.values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if any(a == "bedrock:InvokeModel" for a in actions):
                found_invoke = True
                assert stmt.get("Resource") != "*", "InvokeModel must be ARN-scoped"
                res = stmt["Resource"]
                res = [res] if not isinstance(res, list) else res
                assert "*" not in res
    assert found_invoke, "expected a bedrock:InvokeModel statement"


def test_explicit_s3_delete_deny(substrate_tmpl: Template) -> None:
    policies = substrate_tmpl.find_resources("AWS::IAM::Policy")
    blob = json.dumps(list(policies.values()))
    assert '"s3:DeleteObject"' in blob
    # The delete statement must be a Deny.
    found_deny = False
    for pol in policies.values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            actions = stmt.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if any("s3:DeleteObject" in a for a in actions):
                assert stmt["Effect"] == "Deny"
                found_deny = True
    assert found_deny


def test_ddb_leading_keys_condition(substrate_tmpl: Template) -> None:
    blob = json.dumps(list(substrate_tmpl.find_resources("AWS::IAM::Policy").values()))
    assert "dynamodb:LeadingKeys" in blob
    assert "FINDING#" in blob and "SESSION#" in blob and "LEDGER#" in blob


def test_audit_bucket_object_lock(substrate_tmpl: Template) -> None:
    substrate_tmpl.has_resource_properties(
        "AWS::S3::Bucket",
        {"ObjectLockEnabled": True},
    )


def test_ddb_cmk_encryption(substrate_tmpl: Template) -> None:
    substrate_tmpl.has_resource_properties(
        "AWS::DynamoDB::GlobalTable",
        Match.object_like(
            {"SSESpecification": Match.object_like({"SSEEnabled": True, "SSEType": "KMS"})}
        ),
    )


def test_ddb_gsi1_on_status(substrate_tmpl: Template) -> None:
    blob = json.dumps(list(substrate_tmpl.find_resources("AWS::DynamoDB::GlobalTable").values()))
    assert "GSI1" in blob
    assert "status" in blob


# --------------------------------------------------------------------------- #
# SandboxHostStack
# --------------------------------------------------------------------------- #


def test_instance_type_is_c7g_metal(sandbox_tmpl: Template) -> None:
    # The instance is launched from the launch template, which carries the type.
    sandbox_tmpl.has_resource_properties(
        "AWS::EC2::LaunchTemplate",
        Match.object_like({"LaunchTemplateData": Match.object_like({"InstanceType": "c7g.metal"})}),
    )


def test_sandbox_sg_has_no_ingress(sandbox_tmpl: Template) -> None:
    sgs = sandbox_tmpl.find_resources("AWS::EC2::SecurityGroup")
    for sg in sgs.values():
        ingress = sg["Properties"].get("SecurityGroupIngress", [])
        assert ingress == [], "sandbox host SG must have no ingress"


def test_imdsv2_enforced(sandbox_tmpl: Template) -> None:
    sandbox_tmpl.has_resource_properties(
        "AWS::EC2::LaunchTemplate",
        Match.object_like(
            {
                "LaunchTemplateData": Match.object_like(
                    {"MetadataOptions": Match.object_like({"HttpTokens": "required"})}
                )
            }
        ),
    )


def test_root_volume_gp3_encrypted_iops(sandbox_tmpl: Template) -> None:
    sandbox_tmpl.has_resource_properties(
        "AWS::EC2::LaunchTemplate",
        Match.object_like(
            {
                "LaunchTemplateData": Match.object_like(
                    {
                        "BlockDeviceMappings": Match.array_with(
                            [
                                Match.object_like(
                                    {
                                        "Ebs": Match.object_like(
                                            {
                                                "VolumeType": "gp3",
                                                "Encrypted": True,
                                                "Iops": 6000,
                                                "Throughput": 250,
                                            }
                                        )
                                    }
                                )
                            ]
                        )
                    }
                )
            }
        ),
    )
