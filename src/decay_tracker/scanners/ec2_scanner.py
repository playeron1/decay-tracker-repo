"""EC2 instance + Elastic IP scanner.

Orphaned VMs: stopped-but-never-terminated instances that still have
public IPs / security groups wide open. Elastic IPs that are allocated
but not attached to anything are a classic forgotten-cost + sometimes
forgotten-DNS-target case (an EIP can still be referenced by stale DNS
after the instance behind it is gone, though once released AWS can
reassign it to someone else - a real takeover vector).
"""
from __future__ import annotations

from collections.abc import Iterable

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scanners.base import Scanner


def _open_to_world(sg_permissions: list[dict]) -> bool:
    for perm in sg_permissions:
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True
        for ipv6_range in perm.get("Ipv6Ranges", []):
            if ipv6_range.get("CidrIpv6") == "::/0":
                return True
    return False


class Ec2Scanner(Scanner):
    name = "ec2"

    def __init__(self, session, region: str, account_id: str | None = None):
        self.session = session
        self.region = region
        self.account_id = account_id
        self.ec2 = session.client("ec2", region_name=region)

    def _security_groups_open(self, group_ids: list[str]) -> bool:
        if not group_ids:
            return False
        try:
            resp = self.ec2.describe_security_groups(GroupIds=group_ids)
            for sg in resp.get("SecurityGroups", []):
                if _open_to_world(sg.get("IpPermissions", [])):
                    return True
        except Exception:
            pass
        return False

    def scan_instances(self) -> Iterable[Asset]:
        try:
            paginator = self.ec2.get_paginator("describe_instances")
        except Exception as e:
            raise RuntimeError(f"Failed to describe EC2 instances in {self.region}: {e}") from e

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    state = inst["State"]["Name"]
                    if state == "terminated":
                        continue

                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    sg_open = self._security_groups_open(sg_ids)
                    public_ip = inst.get("PublicIpAddress")
                    launch_time = inst.get("LaunchTime")

                    reachability = Reachability.UNKNOWN
                    detail_bits = [f"State: {state}"]
                    publicly_accessible = bool(public_ip) and sg_open

                    if state == "running" and public_ip:
                        reachability = Reachability.RESPONSIVE if sg_open else Reachability.RESPONSIVE_ERROR
                        detail_bits.append(f"Public IP {public_ip}")
                    elif state == "stopped":
                        reachability = Reachability.UNREACHABLE
                        detail_bits.append("Stopped (not terminated) - classic orphan pattern")

                    if sg_open:
                        detail_bits.append("Security group open to 0.0.0.0/0")

                    asset = Asset(
                        asset_type=AssetType.EC2_INSTANCE,
                        identifier=inst["InstanceId"],
                        region=self.region,
                        account_id=self.account_id,
                        created_at=launch_time,
                        last_activity_at=launch_time if state == "running" else None,
                        owner_tag=tags.get("Owner") or tags.get("owner"),
                        project_tag=tags.get("Project") or tags.get("project"),
                        tags=tags,
                        reachability=reachability,
                        probe_detail="; ".join(detail_bits),
                        publicly_accessible=publicly_accessible,
                        raw={"instance_type": inst.get("InstanceType"), "state": state},
                    )
                    asset.add_evidence("ec2:describe_instances", "; ".join(detail_bits))
                    if sg_ids:
                        asset.add_evidence(
                            "ec2:security-groups",
                            f"{'Open to internet' if sg_open else 'Not publicly open'} "
                            f"({len(sg_ids)} group(s) attached)",
                        )
                    yield asset

    def scan_elastic_ips(self) -> Iterable[Asset]:
        try:
            resp = self.ec2.describe_addresses()
        except Exception as e:
            raise RuntimeError(f"Failed to describe Elastic IPs in {self.region}: {e}") from e

        for addr in resp.get("Addresses", []):
            tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
            instance_id = addr.get("InstanceId")
            associated = bool(instance_id)

            asset = Asset(
                asset_type=AssetType.ELASTIC_IP,
                identifier=addr.get("PublicIp", addr.get("AllocationId", "unknown")),
                region=self.region,
                account_id=self.account_id,
                owner_tag=tags.get("Owner") or tags.get("owner"),
                project_tag=tags.get("Project") or tags.get("project"),
                tags=tags,
                reachability=Reachability.UNKNOWN if associated else Reachability.UNREACHABLE,
                probe_detail=(
                    f"Associated with {instance_id}" if associated
                    else "Allocated but NOT associated with any resource - pure cost/stale-DNS risk"
                ),
                publicly_accessible=True,
                raw={"allocation_id": addr.get("AllocationId")},
            )
            asset.add_evidence(
                "ec2:describe_addresses",
                "Unassociated Elastic IP" if not associated else f"Associated with {instance_id}",
            )
            yield asset

    def scan(self) -> Iterable[Asset]:
        yield from self.scan_instances()
        yield from self.scan_elastic_ips()
