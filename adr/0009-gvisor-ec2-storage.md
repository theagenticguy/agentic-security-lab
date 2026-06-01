# ADR-009: gVisor platform + EC2 instance type + storage tiers

- **Status:** Accepted
- **Date:** 2026-06-01
- **Deciders:** AI Engineering NAMER

## Context

ADR-003 puts the sandbox behind a `Sandbox` Protocol and names gVisor `runsc` as the v1
isolation runtime. That decision only lands if the *host* is right: the gVisor platform, the
EC2 instance type, and the storage layout for scratch versus durable audit all have to be
chosen against current (May 2026) AWS reality. This ADR records those substrate decisions,
synthesized from `.planning/track-g-ec2-gvisor-storage.md` (prices: us-east-1 on-demand
Linux, AWS Price List offer `20260529053858`). It answers: which gVisor platform, which
instance, which volumes, and where the WORM audit lives.

## Decision

**gVisor platform.** Run **`runsc --platform=systrap`** as the v1 default. Per
[gvisor.dev platforms docs](https://gvisor.dev/docs/architecture_guide/platforms/), `ptrace`
is no longer the default and is deprecated ("expected to eventually be removed entirely") — do
not adopt it. systrap intercepts syscalls via seccomp `SECCOMP_RET_TRAP`, needs no
virtualization extensions, and runs on any Nitro VM. Reserve **`--platform=kvm`** only for a
bare-metal host where we have *measured* a syscall-bound win; inside nested virt, systrap
typically beats KVM anyway.

**Instance.** Default to **`c7g.metal`** (Graviton3, 64 vCPU / 128 GiB, $2.32/hr). Bare metal
keeps **`/dev/kvm` exposed** so the KVM platform is a config flip, not a migration — confirm
with `ls -la /dev/kvm` + `grep -E 'vmx|svm' /proc/cpuinfo`. Nested virtualization on Nitro
*non-metal* still has not landed as of May 2026, so guest-level KVM is metal-only. The
smaller-dev tier is **`c7g.16xlarge`** (non-metal, same $2.32/hr, systrap only, no `/dev/kvm`).

**Storage.** Root **EBS gp3, 100 GiB, 6,000 IOPS / 250 MiB/s, encrypted with a
customer-managed KMS CMK** (not `aws/ebs`), holding OS + the audit-log *buffer*. `c7g.metal`
ships **no instance store**, so sandbox scratch is **tmpfs** (RAM-budgeted) plus **overlayfs
on the gp3 root**. Instance-store **RAID0 (mdadm)** applies only on an **`i7ie` upgrade**
(e.g. `i7ie.metal-24xl`, 8 × 7.5 TB NVMe, $12.48/hr) if scratch outgrows RAM — assembled at
boot by a systemd unit, never persisted in `/etc/fstab`, since instance store is wiped on
stop/terminate. **Durable audit goes to a separate io2 Block Express volume and/or S3 Object
Lock — never on ephemeral instance store**; an audit segment must never exist *only* on
instance store across a stop. Use DLM for snapshot lifecycle with cross-region copy, and
account-level EBS encryption-by-default.

## Alternatives Considered

- **x86 `.metal` (e.g. `c7i.metal-24xl`, $4.28/hr).** Rejected for v1: Graviton bare metal is
  cheaper and exposes `/dev/kvm` just the same; the workload is provider-neutral Linux.
- **Nested virt on a Nitro non-metal type.** Rejected: it has not landed as of May 2026 — the
  Nitro hypervisor does not pass virtualization extensions to guests, so `/dev/kvm` is
  metal-only. Designing around guest KVM on non-metal would be designing around a feature that
  does not exist.
- **Pure tmpfs for everything, including audit.** Rejected: tmpfs and instance store are
  ephemeral — correct for throwaway scratch, fatal for the WORM audit (ADR-005), which needs
  durability and S3 Object Lock.

## Rationale

systrap is the correct default because it is the fastest non-deprecated platform that needs no
special hardware; choosing Graviton bare metal keeps the KVM option open as a config flip
without committing to its overhead. The storage split — ephemeral scratch on tmpfs/overlayfs,
durable audit on gp3-buffer → io2 / S3 Object Lock — matches each tier's durability needs to
its purpose, per Track G. The `c7g.metal` default lands at **~$2.33/hr** (compute + gp3),
roughly **$280/month** at 4 h/day.

## Consequences

### Positive

- Strong syscall isolation (gVisor systrap) on a host where KVM is one config flip away.
- Scratch is fast and free-to-discard (tmpfs/overlayfs); durable audit is provably retained.
- Cost is bounded and predictable; the dev tier matches the metal default's hourly rate.

### Negative

- `c7g.metal` has no instance store, so large scratch needs a host-class change (to `i7ie`,
  ~5× the hourly cost) rather than a cheap volume add. **Mitigated** by sizing tmpfs to the
  RAM budget and using overlayfs on gp3 first. Split trigger: concurrent sandboxes exhaust RAM
  + gp3 scratch, justifying the i7ie RAID0 upgrade.
- ARM64 (Graviton) requires multi-arch agent base images. **Mitigated** by baking an arm64
  AMI via EC2 Image Builder. Split trigger: a tool with no arm64 build forces an x86 metal
  host.
