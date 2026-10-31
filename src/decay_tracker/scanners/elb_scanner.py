"""Load balancer scanner (ALB/NLB via elbv2, classic ELB via elb).

A load balancer with zero healthy targets behind it is a very common
zombie pattern: the app died, nobody tore down the LB, and its DNS name
(or a custom CNAME pointing at it) is still live and publicly resolvable.
"""
from __future__ import annotations

from collections.abc import Iterable

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scanners.base import Scanner


class ElbScanner(Scanner):
    name = "elb"

    def __init__(self, session, region: str, account_id: str | None = None):
        self.session = session
        self.region = region
        self.account_id = account_id
        self.elbv2 = session.client("elbv2", region_name=region)

    def _target_health_summary(self, lb_arn: str) -> tuple[int, int]:
        """Returns (healthy_count, total_count) across all target groups."""
        healthy, total = 0, 0
        try:
            tgs = self.elbv2.describe_target_groups(LoadBalancerArn=lb_arn)["TargetGroups"]
            for tg in tgs:
                health = self.elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                for t in health.get("TargetHealthDescriptions", []):
                    total += 1
                    if t.get("TargetHealth", {}).get("State") == "healthy":
                        healthy += 1
        except Exception:
            pass
        return healthy, total

    def scan(self) -> Iterable[Asset]:
        try:
            paginator = self.elbv2.get_paginator("describe_load_balancers")
        except Exception as e:
            raise RuntimeError(f"Failed to describe load balancers in {self.region}: {e}") from e

        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                arn = lb["LoadBalancerArn"]
                dns_name = lb["DNSName"]
                scheme = lb.get("Scheme", "unknown")
                created_at = lb.get("CreatedTime")
                is_internet_facing = scheme == "internet-facing"

                healthy, total = self._target_health_summary(arn)

                try:
                    tags_resp = self.elbv2.describe_tags(ResourceArns=[arn])
                    tag_descs = tags_resp.get("TagDescriptions", [])
                    tags = {t["Key"]: t["Value"] for t in (tag_descs[0]["Tags"] if tag_descs else [])}
                except Exception:
                    tags = {}

                if total == 0:
                    reachability = Reachability.RESPONSIVE_ERROR
                    detail = "No target groups/targets registered - LB is live but serves nothing"
                elif healthy == 0:
                    reachability = Reachability.RESPONSIVE_ERROR
                    detail = f"0/{total} targets healthy - LB live but backend is dead"
                else:
                    reachability = Reachability.RESPONSIVE
                    detail = f"{healthy}/{total} targets healthy"

                asset = Asset(
                    asset_type=AssetType.LOAD_BALANCER,
                    identifier=dns_name,
                    region=self.region,
                    account_id=self.account_id,
                    created_at=created_at,
                    owner_tag=tags.get("Owner") or tags.get("owner"),
                    project_tag=tags.get("Project") or tags.get("project"),
                    tags=tags,
                    reachability=reachability,
                    probe_detail=f"{scheme}; {detail}",
                    publicly_accessible=is_internet_facing,
                    raw={"arn": arn, "type": lb.get("Type"), "scheme": scheme},
                )
                asset.add_evidence("elbv2:describe_load_balancers", f"Scheme: {scheme}, created {created_at}")
                asset.add_evidence("elbv2:target-health", detail)
                yield asset
