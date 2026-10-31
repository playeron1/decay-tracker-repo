#!/usr/bin/env python3
"""Generates a sample decay_report.html using mocked AWS resources.

Useful for:
  - CI smoke-testing the full pipeline without real credentials
  - letting someone see what the dashboard looks like before pointing
    the tool at a real account
"""
from __future__ import annotations

import boto3
from moto import mock_aws

from decay_tracker.report.html_report import generate_html_report
from decay_tracker.scanners.ec2_scanner import Ec2Scanner
from decay_tracker.scanners.s3_scanner import S3Scanner
from decay_tracker.scoring.engine import score_assets


def build_demo_environment(session) -> None:
    s3 = session.client("s3")

    # A forgotten public bucket with an old, unmodified object - zombie prototype.
    s3.create_bucket(Bucket="2021-marketing-launch-assets")
    s3.put_bucket_acl(
        Bucket="2021-marketing-launch-assets",
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ],
            "Owner": {"ID": "demo-owner"},
        },
    )

    # A well-maintained, tagged, private bucket.
    s3.create_bucket(Bucket="prod-payments-data")
    s3.put_object(Bucket="prod-payments-data", Key="active.txt", Body=b"active")
    s3.put_bucket_tagging(
        Bucket="prod-payments-data",
        Tagging={"TagSet": [{"Key": "Owner", "Value": "payments-team"}, {"Key": "Project", "Value": "payments"}]},
    )

    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    stopped_id = resp["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[stopped_id])

    # Unassociated Elastic IP - allocated years ago, never released.
    ec2.allocate_address(Domain="vpc")


def main() -> None:
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        build_demo_environment(session)

        assets = []
        assets.extend(S3Scanner(session).scan())
        assets.extend(Ec2Scanner(session, "us-east-1").scan())
        assets = score_assets(assets)

        path = generate_html_report(assets, "decay_report.html")
        print(f"Demo dashboard written to {path} ({len(assets)} assets)")


if __name__ == "__main__":
    main()
