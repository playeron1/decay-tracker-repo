"""Core data model.

Every scanner (DNS, S3, EC2/EIP, ELB, Route53, ...) normalizes what it
finds into an `Asset`. Scoring and reporting are written once against
this shape and don't know or care which AWS service an asset came from.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE = "ec2_instance"
    ELASTIC_IP = "elastic_ip"
    LOAD_BALANCER = "load_balancer"
    DNS_RECORD = "dns_record"
    SECURITY_GROUP = "security_group"
    IAM_ROLE = "iam_role"
    SNAPSHOT = "snapshot"


class Reachability(str, Enum):
    """What we actually observed when we poked the asset."""
    RESPONSIVE = "responsive"        # resolves/responds, actively serving something
    RESPONSIVE_ERROR = "responsive_error"  # resolves/responds but errors (e.g. S3 403/404, dangling CNAME)
    UNREACHABLE = "unreachable"      # does not resolve / times out
    UNKNOWN = "unknown"              # couldn't test (no network perm, skipped, etc.)


@dataclass
class Evidence:
    """One timestamped observation supporting a signal (for audit trail)."""
    source: str                      # e.g. "cloudtrail", "s3:GetBucketLocation", "dns:A"
    detail: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Asset:
    asset_type: AssetType
    identifier: str                  # ARN, bucket name, FQDN, instance ID, etc.
    region: str | None = None
    account_id: str | None = None

    # Lifecycle signals (None = unknown, not "zero")
    created_at: datetime | None = None
    last_activity_at: datetime | None = None       # last known touch (CloudTrail, last-modified, etc.)
    last_cost_at: datetime | None = None            # last seen in Cost Explorer / billing

    # Ownership / governance signals
    owner_tag: str | None = None
    project_tag: str | None = None
    has_termination_protection: bool = False
    tags: dict[str, str] = field(default_factory=dict)

    # Live probe result
    reachability: Reachability = Reachability.UNKNOWN
    probe_detail: str | None = None                 # e.g. "HTTP 200", "NXDOMAIN", "dangling CNAME -> s3"
    publicly_accessible: bool = False

    # Raw provider metadata, kept for the report / debugging
    raw: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    # Filled in by the scoring engine, not scanners
    decay_score: float | None = None
    decay_band: str | None = None
    risk_factors: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable ID for dedup / diffing across scan runs."""
        raw = f"{self.asset_type.value}:{self.account_id}:{self.region}:{self.identifier}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def add_evidence(self, source: str, detail: str) -> None:
        self.evidence.append(Evidence(source=source, detail=detail))

    def days_since(self, when: datetime | None) -> float | None:
        if when is None:
            return None
        now = datetime.now(timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (now - when).total_seconds() / 86400.0
