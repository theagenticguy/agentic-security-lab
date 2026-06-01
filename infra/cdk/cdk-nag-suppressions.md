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
| `SandboxHostStack/SandboxInstanceRole` | `AwsSolutions-IAM4` | `AmazonSSMManagedInstanceCore` is the AWS-recommended baseline managed policy for SSM access without inbound SSH; preferred over a hand-rolled equivalent. The Bedrock data-plane perms remain on the separately-scoped substrate Bedrock role (no `Resource:"*"`). | ADR-0009 |
| `SandboxHostStack/SandboxHost` | `AwsSolutions-EC28` | Detailed monitoring is unnecessary for a single ephemeral v1 sandbox host; CloudWatch basic metrics + SSM session telemetry suffice. Revisit if a fleet lands. | ADR-0009 |
| `SandboxHostStack/SandboxHost` + `SandboxLaunchTemplate` | `AwsSolutions-EC29` | Sandbox host is cattle: recreated from the baked AMI with no durable state (scratch is tmpfs/overlayfs; audit flushes to S3 Object Lock before any stop). Termination protection would fight the destroy/recreate model. | ADR-0009 |
| `AsecSubstrateStack/BedrockRoleBoundary` | `AwsSolutions-IAM5` (`Resource::*`) | This is a permissions *boundary* (a ceiling, not a grant): broad resources are correct because it only caps what attached roles may ever do. Actual grants on `BedrockAgentRole` are ARN-scoped to the Opus 4.8 model, the ledger, the audit bucket, and the CMK. | ADR-0009 |
| `AsecSubstrateStack/BedrockAgentRole/DefaultPolicy` | `AwsSolutions-IAM5` (`<ledger>/index/*`) | DDB Query/BatchGet must reach the table's GSIs; the wildcard is scoped to this table ARN + `/index/*` (the AWS-documented least-privilege shape) and rows are further constrained by `dynamodb:LeadingKeys`. No `Resource:"*"`. | ADR-0004, ADR-0009 |
| `AsecSubstrateStack/BedrockAgentRole/DefaultPolicy` | `AwsSolutions-IAM5` (`<audit-bucket>/*`) | Audit `PutObject` targets arbitrary object keys under the WORM bucket; the wildcard is scoped to that bucket's object namespace with PutObject only + an explicit Deny on `DeleteObject*`. No `Resource:"*"`. | ADR-0005, ADR-0009 |
| `SandboxHostStack/SandboxInstanceRole` (above) | — | — | — |
| `AsecSubstrateStack/EndpointSg` | `CdkNagValidationFailure` (EC23) | The endpoint SG ingress CIDR is an intrinsic ref to the isolated subnet `CidrBlock` (a CloudFormation token), so EC23 cannot statically evaluate it. By construction ingress is 443 from the isolated subnets only — never an open CIDR. | ADR-0009 |

**Never suppressed (CI-asserted):** encryption (root EBS gp3 SSE-KMS on the substrate CMK; DDB CMK; S3 SSE-KMS) and public-access (`BLOCK_ALL`, no SG ingress, IMDSv2 enforced). IAM5 on the Bedrock `InvokeModel*` wildcard is *not* suppressed because the action wildcard is scoped to the Opus 4.8 inference-profile + foundation-model ARNs (no `Resource:"*"`), which is exactly the least-privilege shape CDK Nag IAM5 wants — `test_synth.py` asserts this.
