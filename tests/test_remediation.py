import json
import subprocess
import sys

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from decay_tracker.remediation.actions import (
    DisableS3StaticWebsite,
    QuarantinePublicS3Bucket,
    ReleaseUnassociatedElasticIP,
    RemediationError,
)
from decay_tracker.remediation.executor import execute_plan
from decay_tracker.remediation.output import render_python_script
from decay_tracker.remediation.owner_resolution import resolve_owner
from decay_tracker.remediation.planner import plan_remediation


def _asset(asset_type, identifier, **overrides):
    data = {
        "asset_type": asset_type,
        "identifier": identifier,
        "decay_band": "HIGH",
        "decay_score": 60,
        "region": "us-east-1",
        "account_id": "123456789012",
        "owner_tag": None,
        "tags": {},
        "raw": {},
        "risk_factors": ["fixture risk"],
        "publicly_accessible": False,
        "probe_detail": "",
    }
    data.update(overrides)
    return data


def test_planner_only_selects_high_and_critical_assets_and_maps_safe_actions():
    assets = [
        _asset("s3_bucket", "public-bucket", publicly_accessible=True),
        _asset("s3_bucket", "website-bucket", raw={"website_enabled": True}),
        _asset("elastic_ip", "198.51.100.9", raw={"allocation_id": "eipalloc-demo", "associated": False}),
        _asset("ec2_instance", "i-demo"),
        _asset("s3_bucket", "medium-bucket", decay_band="MEDIUM", decay_score=35),
    ]

    plan = plan_remediation(assets)
    action_ids = [item["action_id"] for item in plan["actions"]]

    assert plan["summary"]["high_or_critical_assets"] == 4
    assert "quarantine_public_s3_bucket" in action_ids
    assert "disable_s3_static_website" in action_ids
    assert "release_unassociated_elastic_ip" in action_ids
    assert action_ids.count("flag_for_manual_review") == 1
    assert all(item["resource_id"] != "medium-bucket" for item in plan["actions"])
    assert plan["summary"]["irreversible_actions"] == 1


def test_planner_does_not_release_eip_when_association_is_uncertain():
    asset = _asset(
        "elastic_ip",
        "198.51.100.9",
        raw={"allocation_id": "eipalloc-demo"},
        probe_detail="Association details were unavailable",
    )
    plan = plan_remediation([asset])
    assert plan["actions"][0]["action_id"] == "flag_for_manual_review"


def test_owner_tag_wins_without_cloudtrail_lookup():
    class NeverCallCloudTrail:
        def lookup_events(self, **_kwargs):
            raise AssertionError("CloudTrail must not run when an owner tag exists")

    owner = resolve_owner(
        _asset("s3_bucket", "tagged-bucket", owner_tag="platform-team"),
        cloudtrail_client=NeverCallCloudTrail(),
    )
    assert owner == {"owner": "platform-team", "source": "tag", "evidence": "owner_tag"}


def test_cloudtrail_fallback_matches_resource_and_returns_principal():
    class FakeCloudTrail:
        def lookup_events(self, **kwargs):
            assert kwargs["LookupAttributes"][0]["AttributeValue"] == "CreateBucket"
            return {
                "Events": [{
                    "EventId": "event-1",
                    "Resources": [{"ResourceName": "northstar-assets"}],
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/demo-owner"},
                        "requestParameters": {"bucketName": "northstar-assets"},
                    }),
                }]
            }

    owner = resolve_owner(
        _asset("s3_bucket", "northstar-assets"),
        cloudtrail_client=FakeCloudTrail(),
    )
    assert owner["owner"] == "arn:aws:iam::123456789012:user/demo-owner"
    assert owner["source"] == "cloudtrail"
    assert "event-1" in owner["evidence"]


@mock_aws
def test_quarantine_s3_bucket_and_undo_restores_previous_configuration():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cast-remediation-test-bucket")
    previous = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    s3.put_public_access_block(
        Bucket="cast-remediation-test-bucket",
        PublicAccessBlockConfiguration=previous,
    )

    action = QuarantinePublicS3Bucket("cast-remediation-test-bucket")
    record = action.execute(session)
    current = s3.get_public_access_block(Bucket="cast-remediation-test-bucket")["PublicAccessBlockConfiguration"]
    assert all(current.values())

    action.undo(session, record)
    restored = s3.get_public_access_block(Bucket="cast-remediation-test-bucket")["PublicAccessBlockConfiguration"]
    assert restored == previous


@mock_aws
def test_quarantine_undo_removes_block_if_none_existed_before():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cast-no-pab-bucket")
    action = QuarantinePublicS3Bucket("cast-no-pab-bucket")
    record = action.execute(session)
    action.undo(session, record)

    with pytest.raises(ClientError) as error:
        s3.get_public_access_block(Bucket="cast-no-pab-bucket")
    assert error.value.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration"


@mock_aws
def test_disable_website_and_undo_restores_configuration():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cast-website-test-bucket")
    config = {"IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "error.html"}}
    s3.put_bucket_website(Bucket="cast-website-test-bucket", WebsiteConfiguration=config)

    action = DisableS3StaticWebsite("cast-website-test-bucket")
    record = action.execute(session)
    with pytest.raises(ClientError):
        s3.get_bucket_website(Bucket="cast-website-test-bucket")

    action.undo(session, record)
    assert s3.get_bucket_website(Bucket="cast-website-test-bucket")["IndexDocument"] == config["IndexDocument"]


@mock_aws
def test_eip_release_rechecks_association_and_refuses_to_release_attached_address():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    instance = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro"
    )["Instances"][0]["InstanceId"]
    address = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(InstanceId=instance, AllocationId=address["AllocationId"])

    action = ReleaseUnassociatedElasticIP(address["AllocationId"], address["PublicIp"], "us-east-1")
    with pytest.raises(RemediationError, match="now associated"):
        action.execute(session)
    current = ec2.describe_addresses(AllocationIds=[address["AllocationId"]])["Addresses"]
    assert current and current[0].get("AssociationId")


@mock_aws
def test_eip_release_works_only_after_live_check_confirms_unassociated():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    address = ec2.allocate_address(Domain="vpc")
    action = ReleaseUnassociatedElasticIP(address["AllocationId"], address["PublicIp"], "us-east-1")
    result = action.execute(session)
    assert result["reversible"] is False
    assert "another AWS customer" in result["note"]
    with pytest.raises(ClientError):
        ec2.describe_addresses(AllocationIds=[address["AllocationId"]])


def test_generated_script_dry_runs_in_subprocess_and_guards_execute_without_yes(tmp_path):
    plan = plan_remediation([_asset("ec2_instance", "i-manual-review")])
    script = tmp_path / "remediate.py"
    script.write_text(render_python_script(plan), encoding="utf-8")

    dry_run = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert dry_run.returncode == 0, dry_run.stderr
    output = json.loads(dry_run.stdout)
    assert output["mode"] == "dry_run"
    assert output["results"][0]["status"] == "manual_review_required"

    unsafe = subprocess.run(
        [sys.executable, str(script), "--execute"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert unsafe.returncode == 2
    assert "requires --yes" in unsafe.stderr

    yes_only = subprocess.run(
        [sys.executable, str(script), "--yes"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert yes_only.returncode == 2
    assert "only valid together" in yes_only.stderr


def test_executor_dry_run_lists_calls_without_requiring_session():
    plan = plan_remediation([_asset("s3_bucket", "public-bucket", publicly_accessible=True)])
    result = execute_plan(plan)
    assert result["mode"] == "dry_run"
    assert result["success"] is True
    assert result["results"][0]["status"] == "dry_run"
    assert result["results"][0]["planned_calls"][0]["operation"] == "get_public_access_block"


def test_unowned_resources_are_not_assigned_a_guessed_owner():
    owner = resolve_owner(_asset("s3_bucket", "unowned-bucket"))
    assert owner["owner"] is None
    assert owner["source"] == "unresolved"
