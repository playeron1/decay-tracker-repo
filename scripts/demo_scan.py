#!/usr/bin/env python3
"""Generates a realistic sample decay_report.html using mocked AWS resources.

This simulates a company's AWS account that has accumulated a few years of
abandoned projects, so the dashboard has a convincing mix of CRITICAL / HIGH
/ MEDIUM / LOW findings to demo or present - no real AWS account needed.

Run:
    python scripts/demo_scan.py
Then open decay_report.html in a browser.

For a second run that demonstrates the trend/diff feature:
    python scripts/demo_scan.py --second-run
    decay-tracker diff --history-dir .decay_tracker/history
"""
from __future__ import annotations

import argparse

import boto3
from moto import mock_aws

from decay_tracker.report.html_report import generate_html_report
from decay_tracker.scanners.ec2_scanner import Ec2Scanner
from decay_tracker.scanners.elb_scanner import ElbScanner
from decay_tracker.scanners.s3_scanner import S3Scanner
from decay_tracker.scoring.engine import score_assets
from decay_tracker.storage.history import ScanHistory


def build_demo_environment(session, worsen: bool = False) -> None:
    """Populates mocked AWS with a believable 'company that's been around
    a few years' mix of resources: some actively maintained, several
    forgotten. `worsen=True` adds an extra zombie, for the --second-run
    diff demo."""
    s3 = session.client("s3")
    ec2 = session.client("ec2", region_name="us-east-1")

    # --- CRITICAL: forgotten public bucket from a dead 2021 marketing campaign ---
    s3.create_bucket(Bucket="2021-product-launch-static-assets")
    s3.put_bucket_acl(
        Bucket="2021-product-launch-static-assets",
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
    s3.put_bucket_website(
        Bucket="2021-product-launch-static-assets",
        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}},
    )

    # --- CRITICAL: intern hackathon bucket, public, no tags, no owner ---
    s3.create_bucket(Bucket="hackathon-demo-uploads-bucket")
    s3.put_bucket_acl(
        Bucket="hackathon-demo-uploads-bucket",
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

    # --- LOW: actively maintained, tagged, private production bucket ---
    s3.create_bucket(Bucket="prod-payments-ledger")
    s3.put_object(Bucket="prod-payments-ledger", Key="latest-batch.json", Body=b"{}")
    s3.put_bucket_tagging(
        Bucket="prod-payments-ledger",
        Tagging={"TagSet": [{"Key": "Owner", "Value": "payments-team"}, {"Key": "Project", "Value": "payments"}]},
    )

    # --- MEDIUM: private bucket but untagged (governance gap, not exposed) ---
    s3.create_bucket(Bucket="internal-backups-untagged")

    # --- HIGH: stopped EC2 instance, never terminated (classic orphan VM) ---
    stopped = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    stopped_id = stopped["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[stopped_id])

    # --- LOW: actively running, tagged, owned instance ---
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Owner", "Value": "platform-team"}, {"Key": "Project", "Value": "api-gateway"}],
            }
        ],
    )

    # --- HIGH: unassociated Elastic IP, allocated years ago and forgotten ---
    ec2.allocate_address(Domain="vpc")

    if worsen:
        # Simulate a NEW zombie appearing since the last scan, for the
        # diff/trend demo: another abandoned public bucket.
        s3.create_bucket(Bucket="2024-staging-leftover-bucket")
        s3.put_bucket_acl(
            Bucket="2024-staging-leftover-bucket",
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
        ec2.allocate_address(Domain="vpc")  # a second forgotten EIP


def _print_summary(assets) -> None:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in assets:
        counts[a.decay_band] += 1
    print(f"  CRITICAL={counts['CRITICAL']}  HIGH={counts['HIGH']}  MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}")
    for a in assets:
        if a.decay_band in ("CRITICAL", "HIGH"):
            print(f"    [{a.decay_band:8s}] {a.asset_type.value:15s} {a.identifier} (score {a.decay_score:.0f})")


def _scan_all(session) -> list:
    assets = []
    assets.extend(S3Scanner(session).scan())
    assets.extend(Ec2Scanner(session, "us-east-1").scan())
    assets.extend(ElbScanner(session, "us-east-1").scan())
    return score_assets(assets)


def run_demo(second_run: bool = False) -> None:
    history = ScanHistory(".decay_tracker/history")

    # Single shared mock_aws() context so resource IDs stay stable across
    # both "runs" - this makes the diff output tell a clean story (exactly
    # the 2 new zombies added by worsen=True) instead of moto generating
    # fresh random IDs each time mock_aws() is re-entered.
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        build_demo_environment(session, worsen=False)

        assets = _scan_all(session)
        path = generate_html_report(assets, "decay_report.html")
        history.save(assets, run_label="demo-run-1")
        print(f"Dashboard written to {path} ({len(assets)} assets)")
        _print_summary(assets)

        if second_run:
            build_demo_environment(session, worsen=True)  # adds 2 more zombies on top

            assets = _scan_all(session)
            path = generate_html_report(assets, "decay_report.html")
            history.save(assets, run_label="demo-run-2")
            print(f"\nSecond run written to {path} ({len(assets)} assets)")
            _print_summary(assets)

    if second_run:
        print("\nRun `decay-tracker diff --history-dir .decay_tracker/history` to see the trend between runs.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--second-run", action="store_true", help="Also run a second scan with a new zombie added, to demo the diff/trend feature")
    args = parser.parse_args()
    run_demo(second_run=args.second_run)
