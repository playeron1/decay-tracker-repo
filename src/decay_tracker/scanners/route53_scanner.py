"""Route53 scanner.

Enumerates all hosted zones and record sets, and specifically flags
CNAME/ALIAS records pointing at AWS-managed endpoint patterns (S3,
ELB, CloudFront) so they can be cross-checked for dangling references.
This is the AWS-side feed for DnsScanner: run this first to get a
hostname list pulled directly from your account rather than guessed.
"""
from __future__ import annotations

from collections.abc import Iterable

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scanners.base import Scanner
from decay_tracker.scanners.dns_scanner import _looks_like_cloud_endpoint

RISKY_TYPES = {"CNAME", "A", "AAAA"}


class Route53Scanner(Scanner):
    name = "route53"

    def __init__(self, session, account_id: str | None = None):
        self.session = session
        self.account_id = account_id
        self.r53 = session.client("route53")

    def list_hostnames(self) -> list[str]:
        """Convenience method: flat list of record names to feed DnsScanner."""
        names = []
        for asset in self.scan():
            names.append(asset.identifier)
        return names

    def scan(self) -> Iterable[Asset]:
        try:
            zones = self.r53.list_hosted_zones()["HostedZones"]
        except Exception as e:
            raise RuntimeError(f"Failed to list Route53 hosted zones: {e}") from e

        for zone in zones:
            zone_id = zone["Id"]
            zone_name = zone["Name"]
            try:
                paginator = self.r53.get_paginator("list_resource_record_sets")
                for page in paginator.paginate(HostedZoneId=zone_id):
                    for record in page.get("ResourceRecordSets", []):
                        rtype = record.get("Type")
                        if rtype not in RISKY_TYPES:
                            continue
                        name = record["Name"].rstrip(".")

                        target = None
                        is_alias = "AliasTarget" in record
                        if is_alias:
                            target = record["AliasTarget"]["DNSName"].rstrip(".")
                        elif record.get("ResourceRecords"):
                            target = record["ResourceRecords"][0].get("Value")

                        dangling_pattern = _looks_like_cloud_endpoint(target) if target else None

                        asset = Asset(
                            asset_type=AssetType.DNS_RECORD,
                            identifier=name,
                            account_id=self.account_id,
                            reachability=Reachability.UNKNOWN,  # live-checked by DnsScanner
                            probe_detail=f"{rtype} record in zone {zone_name}"
                            + (f" -> {target}" if target else ""),
                            publicly_accessible=True,  # all public Route53 records are internet-facing by default
                            raw={
                                "zone_id": zone_id,
                                "zone_name": zone_name,
                                "record_type": rtype,
                                "target": target,
                                "is_alias": is_alias,
                            },
                        )
                        asset.add_evidence(
                            "route53:list_resource_record_sets",
                            f"{rtype} -> {target or '(no target)'} in {zone_name}",
                        )
                        if dangling_pattern:
                            asset.add_evidence(
                                "route53:dangling-pattern",
                                f"Target matches AWS-managed endpoint pattern '{dangling_pattern}' "
                                f"- cross-check live resolution for takeover risk",
                            )
                        yield asset
            except Exception as e:
                # Don't let one bad zone kill the whole scan
                err_asset = Asset(
                    asset_type=AssetType.DNS_RECORD,
                    identifier=zone_name,
                    account_id=self.account_id,
                    reachability=Reachability.UNKNOWN,
                    probe_detail=f"Failed to enumerate records: {e}",
                )
                err_asset.add_evidence("route53:error", str(e))
                yield err_asset
