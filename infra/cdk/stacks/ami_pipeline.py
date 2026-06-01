"""SandboxAmiPipelineStack — EC2 Image Builder pipeline for the sandbox host AMI.

Bakes the runsc (gVisor) + Docker + tinyproxy host image on top of AL2023 arm64,
per Day-4 plan section 5 and Track G ("Sandbox host AMI strategy"). Staying inside
CDK + CDK Nag keeps the AMI build under the same IaC/Nag governance as the rest of
the substrate (CONSTRAINTS.md) and produces dated, scannable AMIs without a parallel
Packer toolchain.

This stack deploys independently of ``SandboxHostStack``. Once a pipeline run has
produced an AMI, its id is fed back into ``SandboxHostStack`` as a stack prop (the
Day-4 fallback is the cloud-init path already shipped in that stack).
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_imagebuilder as imagebuilder
from cdk_nag import NagSuppressions
from constructs import Construct

# Component build scripts live next to the CDK app so they are reviewed + versioned
# alongside the stack that references them.
_COMPONENTS_DIR = Path(__file__).resolve().parent.parent / "components"

# Parent (base) image: AWS-managed AL2023 arm64 Image Builder image ARN. The
# ``x.x.x`` suffix always resolves to the latest semantic version of the base image.
_PARENT_IMAGE = "arn:aws:imagebuilder:us-east-1:aws:image/amazon-linux-2023-arm64-x86/x.x.x"

# Distribution / build region for v1 (single AMI, us-east-1 — Bedrock Opus home region).
_TARGET_REGION = "us-east-1"

# Build instance type — small, cheap, arm64 to match the baked image arch.
_BUILD_INSTANCE_TYPE = "t4g.medium"

# Placeholder ECR ref for the canonical asec sandbox image pre-pulled into the AMI.
# Replaced with the real repository URI once Track-C publishes it.
_SANDBOX_IMAGE_REF = "{{ACCOUNT_ID}}.dkr.ecr.us-east-1.amazonaws.com/asec-sandbox:canonical"


def _shell_component_data(name: str, description: str, script_path: Path) -> str:
    """Wrap a build ``.sh`` script in an Image Builder component document (YAML).

    Image Builder components are YAML documents with phases/steps; we run the
    pinned script verbatim as a single ``ExecuteBash`` step so the reviewed
    ``components/*.sh`` file is the single source of truth.
    """
    script = script_path.read_text(encoding="utf-8")
    # Indent the script under the YAML block scalar (8 spaces to sit under `commands:`).
    indented = "\n".join(f"        {line}" if line else "" for line in script.splitlines())
    return (
        f"name: {name}\n"
        f"description: {description}\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        f"      - name: {name.replace('-', '_')}\n"
        "        action: ExecuteBash\n"
        "        inputs:\n"
        "          commands:\n"
        "            - |\n"
        f"{indented}\n"
    )


def _prebake_component_data(image_ref: str) -> str:
    """Inline component that pre-pulls the canonical sandbox image into the AMI."""
    return (
        "name: prebake-sandbox-image\n"
        "description: Pre-pull the canonical asec sandbox container image.\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: prebake_sandbox_image\n"
        "        action: ExecuteBash\n"
        "        inputs:\n"
        "          commands:\n"
        "            - |\n"
        "              set -euo pipefail\n"
        f"              echo '[prebake] pulling {image_ref}'\n"
        # Placeholder ECR ref; replaced once Track-C publishes the real repo URI.
        # Soft-fail on the placeholder so AMI builds succeed before the image exists,
        # and warn loudly so the gap is visible in build logs.
        f"              docker pull '{image_ref}' || "
        "echo '[prebake] WARNING: placeholder image ref not pulled; wire real ECR URI'\n"
    )


class SandboxAmiPipelineStack(Stack):
    """EC2 Image Builder pipeline that bakes the hardened sandbox host AMI."""

    # Component version. Bump on any change to a component document / script.
    COMPONENT_VERSION = "1.0.0"
    RECIPE_VERSION = "1.0.0"

    def __init__(self, scope: Construct, id: str, **kwargs: object) -> None:
        super().__init__(scope, id, **kwargs)

        # --- Components -------------------------------------------------------
        # Five components: four script-backed (docker, runsc, tinyproxy, harden)
        # plus the inline prebake step.
        shell_specs = [
            ("install-docker", "Install the Docker engine (AL2023 arm64).", "install-docker.sh"),
            (
                "install-runsc",
                "Install + register gVisor runsc (pinned, sha-verified, systrap).",
                "install-runsc.sh",
            ),
            (
                "install-tinyproxy",
                "Install tinyproxy for the egress allowlist sidecar.",
                "install-tinyproxy.sh",
            ),
            (
                "harden-host",
                "CIS hardening: SSM-only access, IMDSv2, sysctl/module lockdown.",
                "harden-host.sh",
            ),
        ]

        self.components: list[imagebuilder.CfnComponent] = []
        for name, description, filename in shell_specs:
            component = imagebuilder.CfnComponent(
                self,
                f"Component{name.title().replace('-', '')}",
                name=f"asec-{name}",
                platform="Linux",
                version=self.COMPONENT_VERSION,
                description=description,
                supported_os_versions=["Amazon Linux 2023"],
                data=_shell_component_data(name, description, _COMPONENTS_DIR / filename),
            )
            self.components.append(component)

        prebake = imagebuilder.CfnComponent(
            self,
            "ComponentPrebakeSandboxImage",
            name="asec-prebake-sandbox-image",
            platform="Linux",
            version=self.COMPONENT_VERSION,
            description="Pre-pull the canonical asec sandbox container image.",
            supported_os_versions=["Amazon Linux 2023"],
            data=_prebake_component_data(_SANDBOX_IMAGE_REF),
        )
        self.components.append(prebake)

        # --- Image recipe -----------------------------------------------------
        # Chain the components in install order on top of the AL2023 arm64 base.
        recipe_components = [
            imagebuilder.CfnImageRecipe.ComponentConfigurationProperty(component_arn=c.attr_arn)
            for c in self.components
        ]
        self.recipe = imagebuilder.CfnImageRecipe(
            self,
            "SandboxImageRecipe",
            name="asec-sandbox-host",
            version=self.RECIPE_VERSION,
            parent_image=_PARENT_IMAGE,
            components=recipe_components,
            description="AL2023 arm64 + Docker + runsc + tinyproxy, CIS-hardened.",
            block_device_mappings=[
                imagebuilder.CfnImageRecipe.InstanceBlockDeviceMappingProperty(
                    device_name="/dev/xvda",
                    ebs=imagebuilder.CfnImageRecipe.EbsInstanceBlockDeviceSpecificationProperty(
                        delete_on_termination=True,
                        encrypted=True,
                        volume_size=30,
                        volume_type="gp3",
                    ),
                )
            ],
        )

        # --- IAM: instance role + profile for the build instance -------------
        build_role = iam.Role(
            self,
            "ImageBuilderInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Role assumed by the Image Builder build/test instance.",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("EC2InstanceProfileForImageBuilder"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            ],
        )
        instance_profile = iam.CfnInstanceProfile(
            self,
            "ImageBuilderInstanceProfile",
            roles=[build_role.role_name],
        )

        # --- Infrastructure configuration ------------------------------------
        # IMDSv2 enforced on the build instance (HttpTokens=required, hop limit 1).
        self.infra_config = imagebuilder.CfnInfrastructureConfiguration(
            self,
            "SandboxInfraConfig",
            name="asec-sandbox-build-infra",
            instance_profile_name=instance_profile.ref,
            instance_types=[_BUILD_INSTANCE_TYPE],
            instance_metadata_options=imagebuilder.CfnInfrastructureConfiguration.InstanceMetadataOptionsProperty(
                http_tokens="required",
                http_put_response_hop_limit=1,
            ),
            terminate_instance_on_failure=True,
        )

        # --- Distribution configuration --------------------------------------
        # Single AMI published to us-east-1 for v1.
        self.distribution_config = imagebuilder.CfnDistributionConfiguration(
            self,
            "SandboxDistributionConfig",
            name="asec-sandbox-distribution",
            distributions=[
                imagebuilder.CfnDistributionConfiguration.DistributionProperty(
                    region=_TARGET_REGION,
                    ami_distribution_configuration={
                        "Name": "asec-sandbox-host-{{ imagebuilder:buildDate }}",
                        "Description": "Hardened AL2023 arm64 sandbox host (Docker + runsc + tinyproxy).",
                    },
                )
            ],
        )

        # --- Image pipeline ---------------------------------------------------
        # Weekly cron + on-demand: the schedule rebuilds weekly (Track G cadence);
        # ad-hoc rebuilds (e.g. critical CVE) are triggered on-demand via the
        # StartImagePipelineExecution API / console against this pipeline.
        self.pipeline = imagebuilder.CfnImagePipeline(
            self,
            "SandboxImagePipeline",
            name="asec-sandbox-ami-pipeline",
            image_recipe_arn=self.recipe.attr_arn,
            infrastructure_configuration_arn=self.infra_config.attr_arn,
            distribution_configuration_arn=self.distribution_config.attr_arn,
            description="Weekly rebuild of the hardened sandbox host AMI.",
            status="ENABLED",
            schedule=imagebuilder.CfnImagePipeline.ScheduleProperty(
                # Weekly, Sunday 06:00 UTC.
                schedule_expression="cron(0 6 ? * sun *)",
                pipeline_execution_start_condition="EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE",
            ),
            image_tests_configuration=imagebuilder.CfnImagePipeline.ImageTestsConfigurationProperty(
                image_tests_enabled=True,
                timeout_minutes=90,
            ),
        )

        # --- Output: latest AMI id export ------------------------------------
        # SandboxHostStack consumes this once a build has run. The pipeline emits
        # the produced image; we expose the recipe/pipeline ARNs and reserve the
        # AMI-id export name so the host stack can Fn::ImportValue it.
        cdk.CfnOutput(
            self,
            "SandboxAmiPipelineArn",
            value=self.pipeline.attr_arn,
            description="ARN of the sandbox AMI Image Builder pipeline.",
            export_name="AsecSandboxAmiPipelineArn",
        )
        # Reserved export consumed by SandboxHostStack. Populated from the latest
        # pipeline output AMI id (resolved out-of-band after the first build) and
        # surfaced as a stack prop, per the Day-4 plan (no live wiring yet).
        cdk.CfnOutput(
            self,
            "SandboxAmiId",
            value="ami-pending-first-pipeline-run",
            description=(
                "Latest baked sandbox AMI id. Placeholder until the first pipeline "
                "run; then fed to SandboxHostStack as a prop (Day-4 plan section 5)."
            ),
            export_name="AsecSandboxAmiId",
        )

        # --- CDK Nag suppressions --------------------------------------------
        # Image Builder service requires the AWS-managed instance-profile policy;
        # documented in cdk-nag-suppressions.md.
        NagSuppressions.add_resource_suppressions(
            build_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "EC2InstanceProfileForImageBuilder and AmazonSSMManagedInstanceCore "
                        "are the AWS-recommended managed policies for an Image Builder build "
                        "instance (build orchestration + SSM-only access, no inbound SSH). "
                        "Scoped to the ephemeral build instance only. See "
                        "cdk-nag-suppressions.md."
                    ),
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/EC2InstanceProfileForImageBuilder",
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSSMManagedInstanceCore",
                    ],
                }
            ],
        )
