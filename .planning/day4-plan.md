# Day 4 Plan — Infra Substrate + Sandbox Hardening

> Day 4 from PLAN.md §10: real `DockerSandbox`, real CDK substrate (VPC + endpoints + IAM + sandbox host), CDK Nag. Track G decides the EC2/gVisor/storage specifics; this plan wires them.

## 1. End-state of Day 4

`apps/pr-reviewer` runs its E2E loop against a real `DockerSandbox` (`--network=none`, `--cap-drop=ALL`, read-only root, non-root UID) instead of `LocalSandbox`; `mise run cdk:synth` emits two stacks (`AsecSubstrateStack` + `SandboxHostStack`) that pass CDK Nag with only documented suppressions. Deployable: the substrate VPC/endpoints/KMS/S3-Object-Lock/DDB/IAM and the `c7g.metal` sandbox host AMI pipeline. Behind feature flags: `kind="gvisor"` (`--runtime=runsc`, soft-falls to runc only when `allow_fallback=True`), the `EgressProxy` allowlist sidecar (off unless `egress_allowlist` non-empty), and live KVM platform (`c7g.metal` keeps `/dev/kvm`, but systrap runs day one).

## 2. Real DockerSandbox impl (`asec-sandbox`)

Replace the `NotImplementedError` stub in `sandbox.py`. Use **`python-on-whales`** (typed CLI wrapper — keeps us on the docker CLI so `--runtime=runsc`, rootless, and seccomp profiles pass through verbatim; the low-level `docker` SDK does not cleanly expose `--runtime`). Add `python-on-whales` to `asec-sandbox/pyproject.toml` via `uv add --package asec-sandbox`.

`start()` builds the run args from `SandboxSpec`:

- `--cap-drop=ALL`, `--security-opt no-new-privileges`, `--security-opt seccomp=<default.json>`, `--read-only`, `--user 10001:10001`.
- tmpfs for `/tmp` and `/work/.scratch` (rw,nosuid,nodev,size from `mem_limit_mib`); honor `spec.tmpfs_paths`.
- Resource caps: `--cpus`, `--memory`, `--pids-limit` from spec.
- `--network=none` default. If `spec.network == "allowlist"`: start an `EgressProxy` (§3), then `--network=container:<proxy_id>` so the agent shares the proxy netns (whitepaper §07 pattern).
- `--runtime=runsc` when `spec.kind == "gvisor"` **and** runsc is registered. Probe via `docker.system.info()` runtimes (or `docker info --format '{{json .Runtimes}}'`). If runsc absent: raise unless `allow_fallback=True`, then `--runtime=runc` with a `structlog.warning`. Add `allow_fallback: bool = False` to `SandboxSpec`.
- Bind-mount target repo read-only at `/work` (`spec.mounts`, default `read_only=True`); refuse any rw mount outside `/work/.scratch`.
- Long-lived container: `sleep infinity` entrypoint; `exec()` = `docker.container.execute(...)`; `collect_artifacts()` = `docker cp`/`exec cat` from `/work/.scratch` (never bind-mount PoCs out — whitepaper §07); `teardown()` = force-remove container + stop proxy.

Fold `GVisorSandbox` into `DockerSandbox` (gVisor is a runtime flag, not a separate class) — keep the `GVisorSandbox` name as a thin subclass that defaults `kind="gvisor"` for back-compat.

**Image strategy:** thin `packages/asec-sandbox/Dockerfile.sandbox` (FROM `python:3.13-slim`, non-root user 10001, scanner binaries, no shell egress tools) built locally for tests; the baked AMI (§5) ships the same image pre-pulled. Default image tag in `SandboxSpec.image: str = "asec-sandbox:dev"`.

**Tests** — `packages/asec-sandbox/tests/test_docker.py`: auto-probe Docker (`shutil.which("docker")` + `docker info`) → set `DOCKER_AVAILABLE`; `@pytest.mark.skipif` integration tests (real run: `--network=none` blocks egress, read-only root rejects writes, non-root UID, runsc-vs-runc fallback). When unavailable, mock `python_on_whales.docker` and assert the **arg vector** carries every hardening flag (this is the CI-portable contract test).

## 3. EgressProxy primitive (`asec-sandbox`)

New `packages/asec-sandbox/src/asec_sandbox/egress.py`:

- `EgressProxySpec(BaseModel, frozen=True)`: `image: str = "asec-tinyproxy:dev"`, `allowlist: tuple[tuple[str, int], ...]` (host, port), `bind_port: int = 8888`. Validator: non-empty allowlist, ports 1–65535.
- `EgressProxy.start()`: render deny-default tinyproxy config (`FilterDefaultDeny Yes`, `Filter` file built from allowlist as anchored regexes — whitepaper §07), launch the sidecar on the asec-managed network, return its container id for `--network=container:` joining. `stop()`: force-remove.
- Asec-managed Docker network `asec-internal` created with `--internal` (no internet route / no gateway) — the proxy is the **only** egress path; ensure-exists idempotent helper.
- Default allowlist for v1: `bedrock-runtime.us-east-1.amazonaws.com:443` and the configured git remote host (matches Track G SG egress).

**Tests** — `test_egress.py`: spec validation (empty allowlist rejects, bad port rejects), rendered tinyproxy config golden-string assertion, start/stop lifecycle with mocked `docker`.

## 4. CDK substrate stack — real this time

Update `infra/cdk/stacks/substrate.py` (resolve the four `TODO(day-4)` markers):

- **VPC**: `ec2.Vpc` with 2 isolated subnets (`SubnetType.PRIVATE_ISOLATED`) across 2 AZs, **no NAT** (`nat_gateways=0`).
- **Interface endpoints**: `BEDROCK_RUNTIME`, `KMS`, `LOGS`, `STS` (`InterfaceVpcEndpointAwsService`, private-DNS on, SG allowing 443 from the isolated subnets).
- **Gateway endpoints**: `S3`, `DYNAMODB`.
- **Bedrock IAM role** with explicit `PermissionsBoundary`: `bedrock:InvokeModel*` + `bedrock:GetInferenceProfile` scoped to the Opus 4.8 inference-profile + foundation-model ARNs; DDB RW constrained by `dynamodb:LeadingKeys` condition on PK/SK prefixes; audit-bucket `s3:PutObject` only (explicit `Deny` on `s3:DeleteObject*`); KMS `Encrypt`/`GenerateDataKey`/`Decrypt` on the CMK only.
- Existing KMS key + audit bucket + DDB ledger stay; add GSI1 on `status` (frozen per ADR-004). Keep the existing `AwsSolutions-S1` suppression.

**New `infra/cdk/stacks/sandbox_host.py` — `SandboxHostStack`** (consumes substrate VPC/role via props):

- Instance: Track G v1 default `c7g.metal` (Graviton3, 64 vCPU/128 GiB) — `ec2.InstanceType("c7g.metal")`; expose as a stack prop so dev can flip to `c7g.16xlarge`.
- AMI: AL2023 (`MachineImage.latest_amazon_linux2023(cpu_type=ARM_64)`) with cloud-init (`user_data`) installing Docker + runsc (`--platform=systrap`) + tinyproxy; pre-pull `Dockerfile.sandbox` image. Day-4 path = cloud-init; §5 supersedes with a baked AMI.
- Root EBS: gp3, 100 GiB, 6000 IOPS / 250 MiB/s, encrypted with the substrate CMK (Track G §"v1 default").
- Instance store: `c7g.metal` has none → sandbox scratch is tmpfs + overlayfs on gp3 (Track G). Ship the mdadm RAID0 cloud-init unit **disabled/guarded** ("assemble only if instance-store NVMe present") so the `i7ie.metal-24xl` upgrade is a prop flip, not a rewrite.
- Security group: **no ingress** (SSM-only access, no SSH); egress restricted to 443 to the Bedrock endpoint SG + the git remote CIDR.
- IAM instance profile assumes the substrate Bedrock role (SSM managed policy for access).

`app.py`: instantiate both stacks (`us-east-1`), pass substrate VPC/role/CMK into `SandboxHostStack`.

**CDK Nag**: handle new findings deliberately. Expected: `EC2*` (detailed monitoring, IMDSv2 — enforce IMDSv2 rather than suppress), `IAM5` on any wildcard action (justify `InvokeModel*` scoped to the model ARN). Encryption + public-access stay non-suppressible (CI assert). Document every new suppression in `infra/cdk/cdk-nag-suppressions.md` with rationale + ADR pointer.

## 5. AMI strategy

**Recommend (a): EC2 Image Builder pipeline as a CDK construct** (`infra/cdk/stacks/ami_pipeline.py`), per Track G §"Sandbox host AMI strategy". Rationale: stays inside the existing CDK + CDK Nag IaC gate (CONSTRAINTS.md), produces dated/signed/scannable AMIs, and lets the rebuild pipeline embed the Track-C scanner components on a weekly + critical-CVE cadence — no parallel Packer toolchain to govern. **(c) cloud-init-only is the Day-4 fallback** shipped in `SandboxHostStack` so the host is launchable before the pipeline lands; the baked-AMI id, once produced, is fed back as a `SandboxHostStack` prop. Packer-in-`infra/packer/` is explicitly rejected (second pipeline to secure).

## 6. ADR-0009

`adr/0009-gvisor-ec2-storage.md` — gVisor (`runsc --platform=systrap` on Nitro; KVM reserved for measured bare-metal wins; ptrace rejected as deprecated), EC2 (`c7g.metal` v1 default keeping `/dev/kvm` optional; `c7g.16xlarge` dev tier), storage (gp3 root + tmpfs/overlayfs scratch; instance-store RAID0 only on i7ie upgrade; durable audit on io2/S3 Object Lock — never let an audit segment live only on ephemeral instance store). Authored in parallel under the ADR-backfill task; this plan records the decisions it captures.

## 7. Tests

- New `infra/cdk/tests/test_synth.py` using `aws_cdk.assertions.Template`: VPC has 0 NAT gateways; S3 + DynamoDB gateway endpoints exist; `BEDROCK_RUNTIME`/`KMS`/`LOGS`/`STS` interface endpoints exist; Bedrock IAM policy is scoped (no `Resource: "*"` on InvokeModel, explicit `s3:DeleteObject` Deny); audit bucket has `ObjectLockEnabled`; DDB has CMK encryption (`SSESpecification` + KMS); `SandboxHostStack` instance type == `c7g.metal`, IMDSv2 enforced, SG has no ingress.
- `asec-sandbox`: `test_docker.py` + `test_egress.py` per §2/§3.
- Add `infra/cdk` to dev/test path so `mise run test` collects the synth tests.

## 8. Branching + parallelism

- `day4/sandbox-impl` — real `DockerSandbox` + `EgressProxy` + `Dockerfile.sandbox` + tests.
- `day4/cdk-stacks` — `substrate.py` updates + `sandbox_host.py` + `test_synth.py` + Nag suppressions.
- `day4/ami-pipeline` — `ami_pipeline.py` Image Builder construct (cloud-init fallback already in the cdk-stacks branch).

**Merge order:** `sandbox-impl` first (unblocks `asec-sandbox` + the pr-reviewer DI swap); `cdk-stacks` + `ami-pipeline` in parallel; integration branch last (wire `apps/pr-reviewer` to `DockerSandbox`, run E2E + `cdk:nag`).

## 9. Acceptance criteria (all `mise` tasks exit 0)

Day 3 set — `mise run lint`, `typecheck`, `test`, `security:scan`, `security:gitleaks`, `cdk:synth` — **plus** `mise run cdk:nag` validating both stacks with only documented suppressions (un-suppressed finding = non-zero = blocker, per PLAN §7). The pr-reviewer E2E test passes with `DockerSandbox` (Docker auto-probed; mocked in CI).

## 10. Risks (top 5)

1. **Bedrock VPC endpoint quirks** — interface endpoint must use private DNS and the SG must allow 443 from isolated subnets, or `InvokeModel` times out with no NAT. Mitigation: synth-assert the endpoint + SG; live smoke from the host before declaring done.
2. **Image Builder vs cloud-init complexity** — Image Builder is slower to iterate. Mitigation: ship cloud-init in `SandboxHostStack` day one; Image Builder lands behind it and feeds back the AMI id.
3. **gVisor on `c7g.metal` (arm64)** — runsc systrap on Graviton must be verified; some seccomp/syscall paths differ from x86. Mitigation: runtime-probe + `allow_fallback`; integration test asserts runsc actually engaged.
4. **IAM least-privilege drift** — `InvokeModel*` wildcard and DDB `LeadingKeys` are easy to over-broaden. Mitigation: `test_synth.py` asserts no `Resource:"*"` on sensitive actions + explicit delete Deny; CDK Nag IAM5 reviewed not blanket-suppressed.
5. **Instance-store ephemerality vs WORM durability** — an audit segment left only on tmpfs/instance store is lost on stop. Mitigation: scratch on ephemeral, audit buffer on gp3, sealed segments flushed to S3 Object Lock before any stop; never `/etc/fstab` the scratch array.
