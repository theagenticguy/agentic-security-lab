# CDK Nag Suppressions

Centralized, reviewed suppression register for `AwsSolutionsChecks` findings on the
substrate stack. Every entry needs a per-rule plain-language justification and a pointer
to the ADR / backlog item that tracks the real fix.

**Hard rule:** encryption and public-access findings may **never** be suppressed. CI
asserts this; `mise run cdk:nag` fails on any un-suppressed (or improperly suppressed)
finding.

## Format

Each suppression is applied in code via `NagSuppressions.add_resource_suppressions(...)`
and documented here:

| Construct path | Rule ID | Justification | Tracking |
| -------------- | ------- | ------------- | -------- |

## Entries

| Construct path | Rule ID | Justification | Tracking |
| -------------- | ------- | ------------- | -------- |
| `AsecSubstrateStack/FindingsLedger` | `AwsSolutions-DDB3` | PITR is enabled via `point_in_time_recovery_specification`; this example entry documents the suppression pattern only and will be removed once the real ledger access patterns land. | ADR-004 (backlog) |
| `AsecSubstrateStack/AuditBucket/Resource` | `AwsSolutions-S1` | This bucket *is* the WORM audit log (Object Lock, hash-chained JSONL). Adding S3 server access logs to itself would be circular; per-request CloudTrail Data Events on the bucket cover access logging once Day-4 wires the trail. | ADR-005 (Day-4 backlog) |
| `SandboxAmiPipelineStack/ImageBuilderInstanceRole` | `AwsSolutions-IAM4` | `EC2InstanceProfileForImageBuilder` + `AmazonSSMManagedInstanceCore` are the AWS-recommended managed policies for an Image Builder build instance: the first grants the build/test orchestration permissions Image Builder requires, the second gives SSM-only access (no inbound SSH, per Track G). Both are attached only to the ephemeral, throwaway build instance that exists for the duration of a single AMI bake. A hand-rolled equivalent would track the AWS-managed policy drift without security benefit. | Day-4 plan section 5 / Track G "AMI strategy" |
