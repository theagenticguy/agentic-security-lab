"""AsecSubstrateStack — the single v1 substrate stack (split later).

Day-1 scope: KMS key, S3 audit bucket (Object Lock), DynamoDB findings ledger. The VPC +
interface/gateway endpoints and the scoped Bedrock IAM role are Day-4 hardening (see the
TODO markers below). Constructs follow PLAN section 7.
"""

from __future__ import annotations

from aws_cdk import Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from constructs import Construct


class AsecSubstrateStack(Stack):
    """KMS + WORM audit bucket + single-table findings ledger for the substrate."""

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
        )

        self.kms_key = key

        # TODO(day-4): VPC (2 AZ, isolated subnets).
        # TODO(day-4): interface endpoint BEDROCK_RUNTIME + gateway endpoints S3/DYNAMODB.
        # TODO(day-4): scoped Bedrock IAM role (InvokeModel* + inference-profile read,
        #              ledger RW, audit-bucket put-only / no delete).
        # TODO(day-4): GSI1 on `status` for FP-suppression queries (freeze in ADR-004).
