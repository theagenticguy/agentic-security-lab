"""AsecSubstrateStack — the single v1 substrate stack (split later).

Day-1 scope: KMS key, S3 audit bucket (Object Lock), DynamoDB findings ledger. The VPC +
interface/gateway endpoints and the scoped Bedrock IAM role are Day-4 hardening (see the
TODO markers below). Constructs follow PLAN section 7.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from cdk_nag import NagSuppressions
from constructs import Construct

# Bedrock Opus 4.8 model identifiers (see mise.toml / track-b-opus-mythos.md).
# Global cross-region inference profile used by the Agent SDK / Claude Code, plus
# the underlying foundation model. IAM is scoped to the ARNs built from these.
OPUS_INFERENCE_PROFILE_ID = "global.anthropic.claude-opus-4-8"
OPUS_FOUNDATION_MODEL_ID = "anthropic.claude-opus-4-8"

# Single-table partition-key prefixes (ADR-004). DDB access is constrained to these
# leading keys so the Bedrock role can only touch findings/session/ledger rows.
LEDGER_PK_PREFIXES = ("FINDING#", "SESSION#", "LEDGER#")


class AsecSubstrateStack(Stack):
    """KMS + WORM audit bucket + single-table findings ledger for the substrate.

    Day-4 additions: an isolated (no-NAT) VPC with Bedrock/KMS/Logs/STS interface
    endpoints + S3/DynamoDB gateway endpoints, and a least-privilege Bedrock IAM
    role with an explicit permissions boundary. The VPC, Bedrock role, KMS key,
    audit bucket, and findings ledger are exposed as stack attributes so
    ``SandboxHostStack`` can consume them.
    """

    def __init__(self, scope: Construct, id: str, **kwargs: object) -> None:
        super().__init__(scope, id, **kwargs)

        # KMS CMK shared by S3 + DynamoDB; rotation on (never suppress encryption rules).
        key = kms.Key(self, "AsecKey", enable_key_rotation=True)

        # S3 audit bucket — WORM via Object Lock, SSE-KMS, TLS-only, versioned, private.
        self.audit_bucket = s3.Bucket(
            self,
            "AuditBucket",
            object_lock_enabled=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )
        # AwsSolutions-S1: server-access logs disabled. This *is* the audit bucket
        # (WORM, Object Lock, hash-chained JSONL — see ADR-005). Adding S3 server
        # access logs to itself would be circular; per-request CloudTrail Data
        # Events on this bucket are the right Day-4 control. See
        # cdk-nag-suppressions.md for the audit trail.
        NagSuppressions.add_resource_suppressions(
            self.audit_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": (
                        "Bucket is itself the WORM audit log; per-request CloudTrail "
                        "Data Events (Day-4) cover access logging. ADR-005."
                    ),
                }
            ],
        )

        # DynamoDB findings ledger — single-table, on-demand, PITR, CMK, full streams.
        self.findings_ledger = dynamodb.TableV2(
            self,
            "FindingsLedger",
            partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            billing=dynamodb.Billing.on_demand(),
            encryption=dynamodb.TableEncryptionV2.customer_managed_key(key),
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            dynamo_stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            # GSI1 on `status` for FP-suppression / triage queries. Schema frozen
            # per ADR-004 (single-table design); the GSI partition key is `status`.
            global_secondary_indexes=[
                dynamodb.GlobalSecondaryIndexPropsV2(
                    index_name="GSI1",
                    partition_key=dynamodb.Attribute(
                        name="status", type=dynamodb.AttributeType.STRING
                    ),
                )
            ],
        )

        self.kms_key = key

        # --- VPC: 2 isolated AZs, no NAT (no egress except via VPC endpoints) ---
        self.vpc = ec2.Vpc(
            self,
            "AsecVpc",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                )
            ],
            # VPC Flow Logs to CloudWatch (CMK-encrypted) for network forensics
            # (AwsSolutions-VPC7) — the audit trail wants per-flow records even
            # though there is no NAT egress.
            flow_logs={
                "AllTraffic": ec2.FlowLogOptions(
                    destination=ec2.FlowLogDestination.to_cloud_watch_logs(),
                    traffic_type=ec2.FlowLogTrafficType.ALL,
                )
            },
        )

        # SG for the interface endpoints: allow 443 from the isolated subnet CIDRs.
        endpoint_sg = ec2.SecurityGroup(
            self,
            "EndpointSg",
            vpc=self.vpc,
            description="HTTPS from isolated subnets to interface VPC endpoints",
            allow_all_outbound=False,
        )
        for subnet in self.vpc.isolated_subnets:
            endpoint_sg.add_ingress_rule(
                peer=ec2.Peer.ipv4(subnet.ipv4_cidr_block),
                connection=ec2.Port.tcp(443),
                description="HTTPS from isolated subnet",
            )
        self.endpoint_security_group = endpoint_sg
        # AwsSolutions-EC23 cannot statically evaluate the ingress CIDR because it is
        # an intrinsic ref to the VPC's per-subnet CidrBlock (a CloudFormation token,
        # not a literal). The rule is satisfied by construction: ingress is 443 from
        # the isolated subnet CIDRs only (never 0.0.0.0/0). ADR-0009.
        NagSuppressions.add_resource_suppressions(
            endpoint_sg,
            [
                {
                    "id": "CdkNagValidationFailure",
                    "reason": (
                        "EC23 ingress CIDR is an intrinsic ref to the isolated subnet "
                        "CidrBlock (a token), so the rule cannot statically evaluate "
                        "it. Ingress is restricted to 443 from the isolated subnets "
                        "by construction — never an open CIDR. ADR-0009."
                    ),
                }
            ],
        )

        # Interface endpoints (private DNS on) — Bedrock runtime + KMS + Logs + STS.
        for name, svc in (
            ("BedrockRuntime", ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME),
            ("Kms", ec2.InterfaceVpcEndpointAwsService.KMS),
            ("Logs", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS),
            ("Sts", ec2.InterfaceVpcEndpointAwsService.STS),
        ):
            self.vpc.add_interface_endpoint(
                f"{name}Endpoint",
                service=svc,
                private_dns_enabled=True,
                security_groups=[endpoint_sg],
            )

        # Gateway endpoints — S3 + DynamoDB (no SG, route-table based).
        self.vpc.add_gateway_endpoint(
            "S3GatewayEndpoint", service=ec2.GatewayVpcEndpointAwsService.S3
        )
        self.vpc.add_gateway_endpoint(
            "DynamoDbGatewayEndpoint", service=ec2.GatewayVpcEndpointAwsService.DYNAMODB
        )

        # --- Bedrock IAM role with explicit permissions boundary ---
        # Permissions boundary: the union ceiling of everything the role may ever do.
        # Even if an inline policy is broadened by mistake, effective perms stay capped.
        boundary = iam.ManagedPolicy(
            self,
            "BedrockRoleBoundary",
            statements=[
                iam.PolicyStatement(
                    sid="BedrockInvokeCeiling",
                    actions=[
                        "bedrock:InvokeModel",
                        "bedrock:InvokeModelWithResponseStream",
                        "bedrock:GetInferenceProfile",
                    ],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="DataPlaneCeiling",
                    actions=[
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:Query",
                        "dynamodb:BatchGetItem",
                        "dynamodb:BatchWriteItem",
                        "s3:PutObject",
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=["*"],
                ),
            ],
        )

        # Opus 4.8 inference-profile + foundation-model ARNs, built per region/account.
        inference_profile_arn = cdk.Arn.format(
            cdk.ArnComponents(
                service="bedrock",
                resource="inference-profile",
                resource_name=OPUS_INFERENCE_PROFILE_ID,
            ),
            self,
        )
        foundation_model_arn = cdk.Arn.format(
            cdk.ArnComponents(
                service="bedrock",
                region="",  # foundation-model ARNs are region-agnostic, account-less
                account="",
                resource="foundation-model",
                resource_name=OPUS_FOUNDATION_MODEL_ID,
            ),
            self,
        )

        bedrock_role = iam.Role(
            self,
            "BedrockAgentRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            permissions_boundary=boundary,
            description="Least-privilege role for the sandbox host to invoke Opus 4.8",
        )

        # Bedrock invoke + inference-profile read, scoped to the Opus 4.8 ARNs only.
        bedrock_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeOpus",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:GetInferenceProfile",
                ],
                resources=[inference_profile_arn, foundation_model_arn],
            )
        )

        # DDB read/write constrained to the substrate-owned leading keys (ADR-004).
        bedrock_role.add_to_policy(
            iam.PolicyStatement(
                sid="LedgerReadWrite",
                actions=[
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:Query",
                    "dynamodb:BatchGetItem",
                    "dynamodb:BatchWriteItem",
                ],
                resources=[
                    self.findings_ledger.table_arn,
                    f"{self.findings_ledger.table_arn}/index/*",
                ],
                conditions={
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": [f"{prefix}*" for prefix in LEDGER_PK_PREFIXES]
                    }
                },
            )
        )

        # Audit bucket: PutObject only — never delete (WORM). Explicit Deny is belt
        # and suspenders on top of Object Lock + the put-only grant.
        bedrock_role.add_to_policy(
            iam.PolicyStatement(
                sid="AuditPutOnly",
                actions=["s3:PutObject"],
                resources=[self.audit_bucket.arn_for_objects("*")],
            )
        )
        bedrock_role.add_to_policy(
            iam.PolicyStatement(
                sid="DenyAuditDelete",
                effect=iam.Effect.DENY,
                actions=["s3:DeleteObject", "s3:DeleteObjectVersion"],
                resources=[
                    self.audit_bucket.bucket_arn,
                    self.audit_bucket.arn_for_objects("*"),
                ],
            )
        )

        # KMS: only the data-plane actions on the substrate CMK.
        bedrock_role.add_to_policy(
            iam.PolicyStatement(
                sid="CmkDataKeys",
                actions=["kms:Encrypt", "kms:GenerateDataKey", "kms:Decrypt"],
                resources=[key.key_arn],
            )
        )

        self.bedrock_role = bedrock_role

        # --- CDK Nag suppressions for the IAM least-privilege wildcards ---
        # These are *resource-path* wildcards (DDB index ARNs, S3 object keys), not
        # blanket `Resource:"*"`, and the permissions-boundary ceiling is *meant* to
        # be broad (it caps, never grants). Each is documented in
        # cdk-nag-suppressions.md with the ADR pointer.
        NagSuppressions.add_resource_suppressions(
            boundary,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "This is a permissions BOUNDARY (a ceiling, not a grant). A "
                        "boundary is intentionally broad on resources: it only caps "
                        "what attached roles can ever do; the actual grants on "
                        "BedrockAgentRole are ARN-scoped to the Opus 4.8 model, the "
                        "ledger table, the audit bucket, and the CMK. ADR-0009."
                    ),
                    "appliesTo": ["Resource::*"],
                },
            ],
        )
        NagSuppressions.add_resource_suppressions(
            bedrock_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "DDB Query/BatchGet must reach the table's GSIs; the index "
                        "wildcard is scoped to this table's ARN + '/index/*' and is "
                        "the AWS-documented least-privilege shape for index access. "
                        "Row access is further constrained by dynamodb:LeadingKeys. "
                        "ADR-0004 / ADR-0009."
                    ),
                    "appliesTo": [
                        "Resource::<FindingsLedgerA5506F25.Arn>/index/*",
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Audit PutObject must target arbitrary object keys under the "
                        "WORM bucket; the wildcard is scoped to this bucket's object "
                        "namespace ('<bucket-arn>/*') with PutObject only and an "
                        "explicit Deny on DeleteObject*. ADR-0005 / ADR-0009."
                    ),
                    "appliesTo": [
                        "Resource::<AuditBucketB01E0AE8.Arn>/*",
                    ],
                },
            ],
            apply_to_children=True,
        )
