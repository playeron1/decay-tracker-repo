"""Thin wrapper around boto3 session creation.

Centralized so CLI flags (profile, region) and credential handling are
consistent across all scanners, and so tests can inject a fake session.
"""
from __future__ import annotations


def get_session(profile: str | None = None, region: str | None = None):
    import boto3

    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def get_account_id(session) -> str | None:
    try:
        sts = session.client("sts")
        return sts.get_caller_identity()["Account"]
    except Exception:
        return None


def all_regions(session, service: str = "ec2") -> list[str]:
    """Enumerate enabled regions. Falls back to a static common list if
    the DescribeRegions call isn't permitted."""
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    except Exception:
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-southeast-2",
        ]
