"""DNS scanner.

Checks a list of hostnames (typically pulled from Route53 zones, but can
be any list) for:
  - whether they still resolve at all
  - whether a CNAME points at an AWS-managed endpoint (S3 website, ELB,
    CloudFront, API Gateway) that itself no longer exists -> classic
    "dangling DNS" subdomain-takeover setup
  - basic HTTP reachability on resolving hosts

This is intentionally dependency-light (stdlib socket + optional
`requests`) so it works even in network-restricted environments; AWS-side
record enumeration (Route53) lives in route53_scanner.py and feeds this.
"""
from __future__ import annotations

import socket
from collections.abc import Iterable

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scanners.base import Scanner

# Known patterns of AWS-managed endpoints that are common dangling-DNS targets.
# If a CNAME points here but resolution/HTTP fails, it's a strong signal
# the backing resource (bucket, distribution, ELB) was deleted while the
# DNS record was left behind - a classic subdomain-takeover setup.
DANGLING_PATTERNS = [
    ".s3-website",
    ".s3.amazonaws.com",
    ".s3.",
    ".elb.amazonaws.com",
    ".cloudfront.net",
    ".execute-api.",
    ".herokuapp.com",
    ".github.io",
    ".azurewebsites.net",
]


def _looks_like_cloud_endpoint(cname_target: str) -> str | None:
    target = cname_target.lower()
    for pattern in DANGLING_PATTERNS:
        if pattern in target:
            return pattern
    return None


class DnsScanner(Scanner):
    name = "dns"

    def __init__(self, hostnames: list[str], http_timeout: float = 5.0, probe_http: bool = True):
        self.hostnames = hostnames
        self.http_timeout = http_timeout
        self.probe_http = probe_http

    def _resolve(self, hostname: str) -> tuple[Reachability, str, str | None]:
        """Returns (reachability, detail, cname_target_if_any)."""
        try:
            # getaddrinfo also tells us if it's resolving via CNAME chain;
            # for explicit CNAME target we fall back to a light manual lookup.
            infos = socket.getaddrinfo(hostname, None)
            ips = sorted({i[4][0] for i in infos})
            cname_target = self._cname_target(hostname)
            return Reachability.RESPONSIVE, f"Resolves to {', '.join(ips)}", cname_target
        except socket.gaierror:
            cname_target = self._cname_target(hostname)
            if cname_target:
                return (
                    Reachability.RESPONSIVE_ERROR,
                    f"NXDOMAIN but CNAME chain exists -> {cname_target}",
                    cname_target,
                )
            return Reachability.UNREACHABLE, "NXDOMAIN / does not resolve", None
        except TimeoutError:
            return Reachability.UNKNOWN, "DNS lookup timed out", None

    @staticmethod
    def _cname_target(hostname: str) -> str | None:
        try:
            import dns.resolver  # dnspython, optional dependency

            answer = dns.resolver.resolve(hostname, "CNAME")
            return str(answer[0].target).rstrip(".")
        except Exception:
            return None

    def _probe_http(self, hostname: str) -> str:
        if not self.probe_http:
            return "HTTP probe skipped"
        try:
            import requests

            resp = requests.get(
                f"https://{hostname}", timeout=self.http_timeout, allow_redirects=True
            )
            return f"HTTP {resp.status_code}"
        except Exception:
            try:
                import requests

                resp = requests.get(
                    f"http://{hostname}", timeout=self.http_timeout, allow_redirects=True
                )
                return f"HTTP {resp.status_code} (plain http)"
            except Exception as e:
                return f"HTTP probe failed: {type(e).__name__}"

    def scan(self) -> Iterable[Asset]:
        for hostname in self.hostnames:
            reachability, detail, cname_target = self._resolve(hostname)

            http_detail = None
            publicly_accessible = False
            if reachability == Reachability.RESPONSIVE:
                http_detail = self._probe_http(hostname)
                publicly_accessible = http_detail.startswith("HTTP") and "failed" not in http_detail

            asset = Asset(
                asset_type=AssetType.DNS_RECORD,
                identifier=hostname,
                reachability=reachability,
                probe_detail=f"{detail}" + (f" | {http_detail}" if http_detail else ""),
                publicly_accessible=publicly_accessible,
                last_activity_at=None,  # DNS has no inherent activity signal; left for enrichment
            )
            asset.add_evidence("dns:resolve", detail)
            if http_detail:
                asset.add_evidence("http:probe", http_detail)

            if cname_target:
                dangling_pattern = _looks_like_cloud_endpoint(cname_target)
                if dangling_pattern and reachability != Reachability.RESPONSIVE:
                    asset.add_evidence(
                        "dns:dangling-check",
                        f"CNAME targets cloud endpoint pattern '{dangling_pattern}' "
                        f"but does not resolve cleanly - likely dangling / takeover risk",
                    )
                asset.raw["cname_target"] = cname_target

            yield asset
