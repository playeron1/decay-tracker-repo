import boto3
import pytest
from moto import mock_aws

from decay_tracker.models import Reachability
from decay_tracker.scanners.s3_scanner import S3Scanner


@mock_aws
def test_detects_public_bucket():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-forgotten-bucket")
    s3.put_bucket_acl(
        Bucket="public-forgotten-bucket",
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ],
            "Owner": {"ID": "owner"},
        },
    )

    assets = list(S3Scanner(session).scan())
    assert len(assets) == 1
    assert assets[0].publicly_accessible is True


@mock_aws
def test_private_bucket_not_flagged_public():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="private-bucket")

    assets = list(S3Scanner(session).scan())
    assert len(assets) == 1
    assert assets[0].publicly_accessible is False


@mock_aws
def test_bucket_tags_map_to_owner_project():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="tagged-bucket")
    s3.put_bucket_tagging(
        Bucket="tagged-bucket",
        Tagging={"TagSet": [{"Key": "Owner", "Value": "alice"}, {"Key": "Project", "Value": "payments"}]},
    )

    assets = list(S3Scanner(session).scan())
    asset = assets[0]
    assert asset.owner_tag == "alice"
    assert asset.project_tag == "payments"


@mock_aws
def test_website_enabled_bucket_marked_responsive_or_error():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="website-bucket")
    s3.put_bucket_website(
        Bucket="website-bucket",
        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}},
    )

    assets = list(S3Scanner(session).scan())
    asset = assets[0]
    assert asset.raw["website_enabled"] is True
    assert asset.reachability in (Reachability.RESPONSIVE, Reachability.RESPONSIVE_ERROR)
