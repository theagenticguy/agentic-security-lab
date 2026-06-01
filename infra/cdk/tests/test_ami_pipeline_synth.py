"""Synth-time assertions for SandboxAmiPipelineStack (EC2 Image Builder)."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk.assertions import Match, Template
from stacks.ami_pipeline import SandboxAmiPipelineStack


def _template() -> Template:
    app = cdk.App()
    stack = SandboxAmiPipelineStack(
        app, "SandboxAmiPipelineStack", env=cdk.Environment(region="us-east-1")
    )
    return Template.from_stack(stack)


def test_five_components_exist() -> None:
    """Four script-backed components + the inline prebake step = five total."""
    _template().resource_count_is("AWS::ImageBuilder::Component", 5)


def test_expected_component_names() -> None:
    template = _template()
    names = {
        props["Properties"]["Name"]
        for props in template.find_resources("AWS::ImageBuilder::Component").values()
    }
    assert names == {
        "asec-install-docker",
        "asec-install-runsc",
        "asec-install-tinyproxy",
        "asec-harden-host",
        "asec-prebake-sandbox-image",
    }


def test_recipe_references_all_components() -> None:
    """The image recipe chains exactly the five components."""
    template = _template()
    recipes = template.find_resources("AWS::ImageBuilder::ImageRecipe")
    assert len(recipes) == 1
    (recipe,) = recipes.values()
    components = recipe["Properties"]["Components"]
    assert len(components) == 5
    # Each entry must reference a component ARN (Fn::GetAtt -> Arn).
    for entry in components:
        assert "ComponentArn" in entry


def test_recipe_parent_image_is_al2023_arm64() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ImageBuilder::ImageRecipe",
        {"ParentImage": Match.string_like_regexp(r"amazon-linux-2023-arm64-x86")},
    )


def test_pipeline_has_schedule_expression() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ImageBuilder::ImagePipeline",
        {"Schedule": {"ScheduleExpression": Match.string_like_regexp(r"^cron\(")}},
    )


def test_distribution_targets_us_east_1() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ImageBuilder::DistributionConfiguration",
        {"Distributions": Match.array_with([Match.object_like({"Region": "us-east-1"})])},
    )


def test_build_instance_type_is_set() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ImageBuilder::InfrastructureConfiguration",
        {"InstanceTypes": ["t4g.medium"]},
    )


def test_build_instance_enforces_imdsv2() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ImageBuilder::InfrastructureConfiguration",
        {"InstanceMetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1}},
    )


def test_ami_id_export_reserved_for_host_stack() -> None:
    template = _template()
    template.has_output(
        "SandboxAmiId",
        {"Export": {"Name": "AsecSandboxAmiId"}},
    )
