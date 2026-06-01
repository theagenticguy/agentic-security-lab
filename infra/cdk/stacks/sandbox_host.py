"""SandboxHostStack — the EC2 host that runs the gVisor Docker sandbox.

Track G v1 default: a Graviton3 bare-metal ``c7g.metal`` (64 vCPU / 128 GiB) so
``/dev/kvm`` stays available as a config flip, while ``runsc --platform=systrap``
runs day one. AL2023 (arm64) AMI, hardened via cloud-init (Docker + runsc +
tinyproxy), gp3 root encrypted with the substrate CMK, no ingress (SSM-only),
egress restricted to the Bedrock interface-endpoint SG + GitHub codeload, and
IMDSv2 enforced via a launch template. See ADR-0009.
"""

from __future__ import annotations

from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from cdk_nag import NagSuppressions
from constructs import Construct

# Pre-pulled sandbox image (placeholder reference; the baked AMI of §5 supersedes
# the cloud-init pull). Matches packages/asec-sandbox/Dockerfile.sandbox.
SANDBOX_IMAGE = "asec-sandbox:dev"

# gVisor release to install via cloud-init. The baked AMI (§5) replaces this.
GVISOR_URL = "https://storage.googleapis.com/gvisor/releases/release/latest/arm64"

# codeload.github.com egress for `git clone` of the target repo. v1 uses a
# hardcoded CIDR; the better path is to resolve GitHub's published meta ranges
# (https://api.github.com/meta -> .git) at deploy time and emit a rule per CIDR,
# or front the clone through the tinyproxy allowlist sidecar (Track C §7).
GITHUB_CODELOAD_CIDR = "140.82.112.0/20"


class SandboxHostStack(Stack):
    """EC2 sandbox host consuming the substrate VPC, Bedrock role, and CMK."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        vpc: ec2.IVpc,
        bedrock_role: iam.IRole,
        kms_key: kms.IKey,
        bedrock_endpoint_sg: ec2.ISecurityGroup,
        instance_type: ec2.InstanceType | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        # Track G v1 default; dev flips to ec2.InstanceType("c7g.16xlarge").
        instance_type = instance_type or ec2.InstanceType("c7g.metal")

        # AL2023 on arm64 (Graviton). Ships current Nitro/NVMe drivers + Docker.
        ami = ec2.MachineImage.latest_amazon_linux2023(cpu_type=ec2.AmazonLinuxCpuType.ARM_64)

        # cloud-init: Docker + runsc (systrap) + tinyproxy, pre-pull the sandbox image,
        # and a guarded mdadm RAID0 unit (disabled-by-default; only runs when
        # instance-store NVMe is present, e.g. on an i7ie.metal-24xl upgrade).
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "set -euxo pipefail",
            # --- Docker ---
            "dnf install -y docker",
            "systemctl enable --now docker",
            # --- gVisor (runsc) ---
            f"ARCH=$(uname -m); URL={GVISOR_URL}",
            "for f in runsc containerd-shim-runsc-v1; do "
            '  curl -fsSL "${URL}/${f}" -o "/usr/local/bin/${f}"; '
            '  curl -fsSL "${URL}/${f}.sha512" -o "/tmp/${f}.sha512"; '
            "done",
            "chmod 0755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1",
            # Register runsc as a Docker runtime with the systrap platform (Track G).
            "/usr/local/bin/runsc --platform=systrap install",
            "systemctl restart docker",
            # --- tinyproxy (egress allowlist sidecar host pkg) ---
            "dnf install -y tinyproxy || true",
            # --- pre-pull the sandbox image (placeholder; baked AMI supersedes) ---
            f"docker pull {SANDBOX_IMAGE} || true",
            # --- instance-store RAID0 bring-up: DISABLED BY DEFAULT, guarded ---
            # Only assembles /dev/md0 when instance-store NVMe is present. c7g.metal
            # has none, so this is a no-op; the i7ie.metal-24xl upgrade is a prop
            # flip, not a rewrite. The array is rebuilt every boot (never /etc/fstab).
            "ENABLE_INSTANCE_STORE_RAID=${ENABLE_INSTANCE_STORE_RAID:-false}",
            'STORE_DEVS=$(nvme list 2>/dev/null | awk "/Instance Storage/ {print \\$1}" || true)',
            'if [ "$ENABLE_INSTANCE_STORE_RAID" = "true" ] && [ -n "$STORE_DEVS" ]; then '
            "  dnf install -y mdadm; "
            "  N=$(echo $STORE_DEVS | wc -w); "
            "  mdadm --create /dev/md0 --level=0 --raid-devices=$N $STORE_DEVS; "
            "  mkfs.xfs -K /dev/md0; "  # -K skips TRIM: instance store is pre-trimmed
            "  mkdir -p /scratch; mount /dev/md0 /scratch; "
            "fi",
        )

        # Root EBS: gp3, 100 GiB, 6000 IOPS / 250 MiB/s, encrypted with the CMK.
        root_volume = ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=ec2.BlockDeviceVolume.ebs(
                volume_size=100,
                volume_type=ec2.EbsDeviceVolumeType.GP3,
                iops=6000,
                throughput=250,
                encrypted=True,
                kms_key=kms_key,
            ),
        )

        # Security group: NO ingress (SSM-only access, no SSH). Egress only to 443
        # on the Bedrock endpoint SG + GitHub codeload.
        sg = ec2.SecurityGroup(
            self,
            "SandboxHostSg",
            vpc=vpc,
            description="Sandbox host: no ingress; egress to Bedrock endpoints + GitHub",
            allow_all_outbound=False,
        )
        sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(bedrock_endpoint_sg.security_group_id),
            connection=ec2.Port.tcp(443),
            description="HTTPS to Bedrock/KMS/Logs/STS interface endpoints",
        )
        sg.add_egress_rule(
            peer=ec2.Peer.ipv4(GITHUB_CODELOAD_CIDR),
            connection=ec2.Port.tcp(443),
            description="HTTPS to codeload.github.com for git clone (v1 hardcoded CIDR)",
        )

        # Instance profile: assume the substrate Bedrock role + SSM core (no SSH).
        # The substrate Bedrock role already trusts ec2.amazonaws.com, so the host's
        # instance role only needs sts:AssumeRole permission (granted below).
        instance_role = iam.Role(
            self,
            "SandboxInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
            ],
        )
        instance_role.add_to_policy(
            iam.PolicyStatement(
                sid="AssumeBedrockRole",
                actions=["sts:AssumeRole"],
                resources=[bedrock_role.role_arn],
            )
        )

        # Launch template is the authoritative config: it carries the AMI, instance
        # type, IAM role, SG, user-data, the gp3 root volume (throughput=250 is only
        # honored on a launch-template block device, not on a bare ec2.Instance), and
        # IMDSv2 enforcement (HttpTokens=required). The instance is launched from it.
        launch_template = ec2.LaunchTemplate(
            self,
            "SandboxLaunchTemplate",
            instance_type=instance_type,
            machine_image=ami,
            role=instance_role,
            security_group=sg,
            user_data=user_data,
            block_devices=[root_volume],
            require_imdsv2=True,
        )
        self.launch_template = launch_template

        # Wire the launch template into a concrete instance (ec2.Instance does not
        # accept a launch template, so drop to CfnInstance and reference it by id).
        subnet = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED).subnet_ids[0]
        self.instance = ec2.CfnInstance(
            self,
            "SandboxHost",
            launch_template=ec2.CfnInstance.LaunchTemplateSpecificationProperty(
                launch_template_id=launch_template.launch_template_id,
                version=launch_template.latest_version_number,
            ),
            subnet_id=subnet,
        )
        self.security_group = sg
        self.instance_type = instance_type

        # CDK Nag suppressions — see infra/cdk/cdk-nag-suppressions.md + ADR-0009.
        NagSuppressions.add_resource_suppressions(
            instance_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "AmazonSSMManagedInstanceCore is the AWS-recommended baseline "
                        "for SSM access without inbound SSH; preferred over a hand-rolled "
                        "SSM policy. ADR-0009."
                    ),
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSSMManagedInstanceCore"
                    ],
                },
            ],
        )
        for target in (launch_template, self.instance):
            NagSuppressions.add_resource_suppressions(
                target,
                [
                    {
                        "id": "AwsSolutions-EC28",
                        "reason": (
                            "Detailed monitoring is unnecessary for a single ephemeral "
                            "v1 sandbox host; CloudWatch basic metrics + SSM suffice. "
                            "ADR-0009."
                        ),
                    },
                    {
                        "id": "AwsSolutions-EC29",
                        "reason": (
                            "Sandbox host is cattle, not a pet: it is recreated from "
                            "the baked AMI and holds no durable state (scratch is "
                            "tmpfs/overlay; audit flushes to S3 Object Lock). "
                            "Termination protection would impede the destroy/recreate "
                            "model. ADR-0009."
                        ),
                    },
                ],
                apply_to_children=True,
            )
