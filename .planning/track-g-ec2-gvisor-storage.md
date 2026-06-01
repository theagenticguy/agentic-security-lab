# Track G: EC2, gVisor, Storage

Substrate decisions for a sandboxed agent host on EC2, as of May 2026. Prices are us-east-1 on-demand Linux, pulled from the AWS Price List API (offer version `20260529053858`).

## gVisor isolation platforms

The prompt's framing is one generation behind. **`ptrace` is no longer the default and is deprecated** — `systrap` replaced it as the gVisor default in mid-2023 and ptrace "is expected to eventually be removed entirely" ([gvisor.dev/docs/architecture_guide/platforms](https://gvisor.dev/docs/architecture_guide/platforms/)). The real trade is three-way:

- **systrap (default).** Intercepts syscalls via seccomp `SECCOMP_RET_TRAP` → `SIGSYS`. Far faster than ptrace, needs no virtualization extensions, works on any VM. This is the correct default for EC2.
- **KVM.** Best raw performance on bare metal; uses virtualization extensions and needs access to KVM (`/dev/kvm`). gVisor docs state that inside a nested VM, "systrap will often provide better performance... due to the overhead of nested virtualization."
- **ptrace.** Deprecated, slowest (high context-switch overhead). Do not adopt.

**Decision:** Run `runsc --platform=systrap` on standard Nitro VMs for v1. Reserve `--platform=kvm` only for a bare-metal host where you have measured a syscall-bound win. The KVM-on-EC2 story is gated entirely on `/dev/kvm`, covered next.

## EC2 instance families exposing /dev/kvm (May 2026)

**Nested virtualization on Nitro non-metal types still did NOT land** as of May 2026. The Nitro hypervisor does not pass virtualization extensions to guests; `/dev/kvm` is exposed only on **bare-metal (`.metal`) instances**, where there is no hypervisor between you and the silicon. Confirm on a host with `ls -la /dev/kvm` and `grep -E 'vmx|svm' /proc/cpuinfo`. This is unchanged from prior years — do not design around guest-level KVM on non-metal.

All families below were confirmed to exist in the us-east-1 price list (none fabricated):

| Instance | vCPU / Mem | /dev/kvm | $/hr (us-east-1) | Note |
|---|---|---|---|---|
| c7g.metal | 64 / 128 GiB | Yes | $2.32 | Graviton3, smallest true metal |
| c8g.metal-24xl | 96 / 192 GiB | Yes | $3.83 | Graviton4, current gen |
| m7g.metal | 64 / 256 GiB | Yes | $2.61 | Graviton3, balanced |
| m8g.metal-24xl | 96 / 384 GiB | Yes | $4.31 | Graviton4 |
| c7i.metal-24xl | 96 / 192 GiB | Yes | $4.28 | Intel SPR |
| c7i.metal-48xl | 192 / 384 GiB | Yes | $8.57 | Intel, large |
| m7i.metal-24xl | 96 / 384 GiB | Yes | $4.84 | Intel |
| r7i.metal-24xl | 96 / 768 GiB | Yes | $6.35 | Intel, mem-heavy |
| r7g.metal | 64 / 512 GiB | Yes | $3.43 | Graviton3, mem-heavy |
| i7ie.metal-24xl | 96 / 768 GiB | Yes | $12.48 | 8 × 7.5 TB NVMe |
| i7ie.metal-48xl | 192 / 1536 GiB | Yes | $24.95 | 16 × 7.5 TB NVMe (120 TB) |

Non-metal sizes for the "smaller dev" tier (no `/dev/kvm`, but systrap doesn't need it): c7g.16xlarge $2.32, m7g.16xlarge $2.61, c7i.12xlarge $2.14, m7i.12xlarge $2.42. i7ie sizing confirmed from [aws.amazon.com/ec2/instance-types/i7ie](https://aws.amazon.com/ec2/instance-types/i7ie/): i7ie.6xlarge = 24 vCPU / 192 GiB / 2 × 7.5 TB NVMe.

**v1 default + dev alternative:** Default to a **Graviton bare-metal** host so KVM stays an option without re-architecting — **c8g.metal-24xl** ($3.83/hr, 96 vCPU) if you want current-gen headroom, or **c7g.metal** ($2.32/hr, 64 vCPU) as the cheapest true-metal entry. Smaller dev alternative: **c7g.16xlarge** (non-metal, $2.32/hr, systrap only). Mac metal is irrelevant to this Linux host workload.

## Storage tiers for the sandbox host

- **Root EBS — gp3 vs io2 Block Express.** gp3: up to 80,000 IOPS, 2,000 MiB/s, 1 GiB–64 TiB; baseline 3,000 IOPS / 125 MiB/s free, the rest provisioned independently of size. io2 Block Express: up to 256,000 IOPS, 4,000 MiB/s, **sub-500-microsecond average latency for 16 KiB I/O**, 99.999% durability ([EBS volume types](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html)). For a host root + audit-log buffer, **gp3 is the default** — the host OS and a buffered append log do not need io2's latency floor. Reserve io2 BX for the durable WORM audit volume where you want max durability and (optionally) multi-attach.
- **Instance store NVMe** (i7ie / im4gn / x2idn). Hardware XTS-AES-256 encrypted, keys destroyed on stop/terminate. **Ephemeral: data survives reboot but is lost on stop, hibernate, or terminate** ([SSD instance store](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html)). Stripe with RAID0 for aggregate throughput. This is the right home for sandbox tmpfs/overlayfs scratch — ephemerality is a *feature* for throwaway sandboxes.
- **Scratch vs durable ratio.** Put 100% of sandbox overlay/scratch on instance-store RAID0 (or tmpfs for the smallest sandboxes). Keep host OS + the audit-log *buffer* on durable gp3, and flush sealed audit segments to the io2/S3 Object Lock WORM tier. Rule of thumb: scratch sized to (concurrent sandboxes × per-sandbox overlay budget); durable sized to OS + a few hours of audit buffer.
- **FSx.** Reach for **FSx for Lustre** only when multiple hosts need a *shared* high-throughput scratch pool (sub-ms, GB/s, hundreds of clients) — e.g., a fleet doing shared corpus fuzzing. **FSx for OpenZFS** when you want shared NFS scratch with snapshots/clones and POSIX semantics at lower scale. Single-host v1 needs neither; instance store + gp3 covers it.

## EBS advanced configuration

- **Volume initialization.** **Empty volumes are fully performant immediately — no warm-up needed** ([Initialize EBS volumes](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-initialize.html)). Initialization only matters for volumes *restored from snapshot*. The old `dd`/`fio` pre-warm is now superseded by **EBS Provisioned Rate for Volume Initialization** (100–300 MiB/s, all volume types and instance types) for predictable restore times. **Fast Snapshot Restore (FSR)** gives full performance instantly at creation but is pricier and per-AZ; use it only for snapshot-backed boot volumes that must be hot on first I/O. For a fresh sandbox host built from a baked AMI, neither is needed for scratch; consider FSR or a provisioned init rate only for the audit volume if it is snapshot-restored. Note: gp3 throughput is provisioned at create time, not warmed.
- **Multi-attach (io2 only).** gp3 does not support it. io2 supports multi-attach + NVMe reservations. Worth it only if a *separate* reader (audit shipper / verifier) must read the same volume concurrently with the writer host; it needs a cluster-aware filesystem and is overkill for v1's single writer. Default: single-attach io2/gp3 + ship to S3.
- **Encryption.** Use a **customer-managed KMS CMK** (not the AWS-managed `aws/ebs` key) so you control rotation, grants, and audit via CloudTrail. Enable account-level **EBS encryption by default**. For the S3 Object Lock audit bucket, use SSE-KMS with **S3 Bucket Keys enabled** to cut KMS request volume/cost on high-write logs.
- **Snapshot lifecycle (DLM).** Use **Data Lifecycle Manager** to schedule snapshots of the WORM audit volume (e.g., hourly→daily→weekly retention) with copy-to-second-region for the audit trail. Tag-targeted policy keeps it declarative in CDK.
- **TRIM cadence.** On EBS, rely on the periodic `fstrim.timer` (weekly) — fine for the host root. `blkdiscard` is for wiping a whole device before reuse. `nvme set-feature` is for low-level tuning and generally not needed on Nitro EBS.

## Instance store NVMe handling

- **Namespaces per family.** i7ie exposes one NVMe device per physical SSD: i7ie.6xlarge = **2 × 7.5 TB**, i7ie.12xlarge = 4, i7ie.24xlarge/metal-24xl = 8, i7ie.48xlarge/metal-48xl = 16 (≈120 TB total). i4i exposes 1–8 AWS Nitro SSDs by size (i4i.4xlarge ≈ 1 × 3.75 TB). Enumerate at boot with `lsblk`/`nvme list` rather than hard-coding device names — Nitro assigns `/dev/nvmeXn1` non-deterministically.
- **RAID0 vs LVM.** Use **mdadm RAID0** across all instance-store devices for the simplest, lowest-overhead stripe and predictable aggregate throughput (multiple GB/s on i7ie-class hardware); LVM striping is equivalent but adds a layer you don't need for pure scratch. Leave ~10% unpartitioned for SSD over-provisioning (AWS-recommended to curb write amplification).
- **Boot-time bring-up.** A `systemd` unit (or cloud-init `bootcmd`) that: discovers instance-store devices, assembles `/dev/md0` RAID0, makes a filesystem, mounts at `/scratch`. Because the array is rebuilt every boot, do **not** persist it in `/etc/fstab` by UUID. TRIM-supported instance-store volumes are pre-trimmed before allocation and ship unformatted; **skip TRIM during the initial mkfs** for faster bring-up, then let weekly `fstrim` run.
- **The trade.** Instance store is ephemeral by design — perfect for sandboxes that are destroyed/recreated, fatal for the Day-2 WORM audit. So: **scratch on instance store, audit on durable EBS → S3 Object Lock.** Never let an audit segment exist *only* on instance store across a stop.

## Sandbox host AMI strategy

- **OS choice (gVisor support, May 2026).** **AL2023** is the v1 pick: ships current Nitro/NVMe drivers, Docker available, clean `runsc` install, AWS-native patch cadence. **Ubuntu 24.04** is the close second (broadest gVisor docs/community, `linux-aws` kernel has NVMe built in). **Bottlerocket** is excellent for hardened, immutable, container-only hosts but its locked-down model and orchestrator-centric design make the runsc + tinyproxy sidecar + custom RAID bring-up harder to layer in for v1 — defer it. All three expose instance-store NVMe per AWS docs.
- **Bake the AMI.** Pre-install: Docker + `runsc` (gVisor) wired as a runtime with `--platform=systrap`, the tinyproxy egress sidecar from Track C §7, the systemd RAID0 bring-up unit, NVMe tooling, and the agent base image. This makes host launch fast and reproducible.
- **Builder: Packer-via-CDK.** Given the repo is CDK Python with CDK Nag (CONSTRAINTS.md), define an **`AmiImagePipeline`** using EC2 Image Builder in CDK for v1 — it stays inside the existing IaC/Nag gate and produces dated, signed, scannable AMIs without a separate Packer toolchain. (Plain Packer is fine as a fallback but adds a parallel pipeline to govern.)
- **Update cadence + IAM.** Rebuild the AMI on a scheduled Image Builder pipeline (e.g., weekly + on critical CVE) with an embedded component that runs the Track C scanners. IAM baseline: instance profile scoped to Bedrock invoke for the target model, S3 PutObject to the Object Lock audit bucket only, KMS decrypt on the EBS CMK, SSM for access (no inbound SSH). No `iam:*`, no broad S3.

## Concrete v1 default for the lab

- **Instance:** `c7g.metal` (Graviton3, 64 vCPU / 128 GiB). Bare metal keeps `/dev/kvm` available so the KVM platform is a config flip, not a migration — but run **systrap** day one.
- **Root EBS:** gp3, 100 GiB, 6,000 IOPS / 250 MiB/s provisioned, encrypted with a customer KMS CMK, holds OS + audit-log buffer.
- **Instance store:** none on c7g.metal — provision sandbox scratch as **tmpfs** (sized to RAM budget) plus overlayfs on the gp3 root for larger scratch. (If scratch volume grows, switch the host to **i7ie.metal-24xl** and RAID0 its 8 × 7.5 TB NVMe — note the jump to $12.48/hr.)
- **Durable audit:** separate io2 Block Express volume (or direct stream to S3 Object Lock) with DLM snapshots + cross-region copy.
- **gVisor platform:** `runsc --platform=systrap`.
- **Cost:** **$2.32/hr** compute + ~$0.01/hr gp3 ≈ **$2.33/hr**. At **4 h/day** → ~$9.32/day → **~$280/month**. The cheaper dev alternative `c7g.16xlarge` (non-metal, systrap only) is the same $2.32/hr but drop it to spot or stop-when-idle to cut the run rate further.
