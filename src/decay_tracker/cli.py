"""Command-line entry point.

Usage:
    decay-tracker scan --region us-east-1 --profile default
    decay-tracker scan --all-regions --dns-zones            # pull hostnames from Route53
    decay-tracker scan --hostnames old-project.example.com,staging.example.com
    decay-tracker report decay_report.html
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from decay_tracker.aws_session import all_regions, get_account_id, get_session
from decay_tracker.models import Asset
from decay_tracker.report.html_report import generate_html_report
from decay_tracker.scanners.dns_scanner import DnsScanner
from decay_tracker.scanners.ec2_scanner import Ec2Scanner
from decay_tracker.scanners.elb_scanner import ElbScanner
from decay_tracker.scanners.route53_scanner import Route53Scanner
from decay_tracker.scanners.s3_scanner import S3Scanner
from decay_tracker.scoring.engine import score_assets
from decay_tracker.storage.history import ScanHistory


def _run_scan(args) -> list[Asset]:
    session = get_session(profile=args.profile, region=args.region)
    account_id = get_account_id(session)
    assets: list[Asset] = []

    regions = all_regions(session) if args.all_regions else [args.region or session.region_name or "us-east-1"]

    if not args.skip_s3:
        print("Scanning S3 buckets (global)...", file=sys.stderr)
        try:
            assets.extend(S3Scanner(session, account_id=account_id).scan())
        except Exception as e:
            print(f"  ! S3 scan failed: {e}", file=sys.stderr)

    if not args.skip_route53:
        print("Scanning Route53 hosted zones...", file=sys.stderr)
        try:
            r53 = Route53Scanner(session, account_id=account_id)
            r53_assets = list(r53.scan())
            assets.extend(r53_assets)
            discovered_hostnames = [a.identifier for a in r53_assets]
        except Exception as e:
            print(f"  ! Route53 scan failed: {e}", file=sys.stderr)
            discovered_hostnames = []
    else:
        discovered_hostnames = []

    hostnames = list(args.hostnames or [])
    if args.dns_zones:
        hostnames.extend(discovered_hostnames)
    if hostnames:
        print(f"Live-checking {len(hostnames)} DNS hostname(s)...", file=sys.stderr)
        try:
            assets.extend(DnsScanner(hostnames, probe_http=not args.no_http_probe).scan())
        except Exception as e:
            print(f"  ! DNS live-check failed: {e}", file=sys.stderr)

    if not args.skip_ec2:
        for region in regions:
            print(f"Scanning EC2 + Elastic IPs in {region}...", file=sys.stderr)
            try:
                assets.extend(Ec2Scanner(session, region, account_id=account_id).scan())
            except Exception as e:
                print(f"  ! EC2 scan failed in {region}: {e}", file=sys.stderr)

    if not args.skip_elb:
        for region in regions:
            print(f"Scanning load balancers in {region}...", file=sys.stderr)
            try:
                assets.extend(ElbScanner(session, region, account_id=account_id).scan())
            except Exception as e:
                print(f"  ! ELB scan failed in {region}: {e}", file=sys.stderr)

    return score_assets(assets)


def _write_json(assets: list[Asset], path: str) -> None:
    from decay_tracker.storage.history import _serialize_asset

    Path(path).write_text(json.dumps([_serialize_asset(a) for a in assets], indent=2, default=str))


def _write_csv(assets: list[Asset], path: str) -> None:
    fields = [
        "decay_band", "decay_score", "asset_type", "identifier", "region",
        "reachability", "publicly_accessible", "owner_tag", "project_tag", "probe_detail",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in assets:
            writer.writerow({
                "decay_band": a.decay_band,
                "decay_score": a.decay_score,
                "asset_type": a.asset_type.value,
                "identifier": a.identifier,
                "region": a.region,
                "reachability": a.reachability.value,
                "publicly_accessible": a.publicly_accessible,
                "owner_tag": a.owner_tag,
                "project_tag": a.project_tag,
                "probe_detail": a.probe_detail,
            })


def cmd_scan(args) -> int:
    assets = _run_scan(args)

    if not assets:
        print("No assets discovered. Check credentials/permissions and scanner flags.", file=sys.stderr)
        return 1

    history = ScanHistory(args.history_dir)
    history.save(assets, run_label=args.label)

    if args.json:
        _write_json(assets, args.json)
        print(f"Wrote JSON: {args.json}")
    if args.csv:
        _write_csv(assets, args.csv)
        print(f"Wrote CSV: {args.csv}")
    if args.html:
        path = generate_html_report(assets, args.html)
        print(f"Wrote HTML dashboard: {path}")

    critical = [a for a in assets if a.decay_band == "CRITICAL"]
    high = [a for a in assets if a.decay_band == "HIGH"]
    print(f"\nScanned {len(assets)} asset(s): {len(critical)} CRITICAL, {len(high)} HIGH")
    for a in critical[:10]:
        print(f"  [CRITICAL] {a.asset_type.value}: {a.identifier} (score {a.decay_score:.0f})")

    if args.fail_on_critical and critical:
        return 2
    return 0


def cmd_diff(args) -> int:
    history = ScanHistory(args.history_dir)
    diff = history.diff_last_two()
    if diff is None:
        print("Need at least two scan runs in history to diff.", file=sys.stderr)
        return 1
    print(json.dumps(diff, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="decay-tracker", description="Attack-surface decay tracker for abandoned cloud resources")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a scan and score discovered assets")
    scan.add_argument("--profile", help="AWS profile name")
    scan.add_argument("--region", help="Single AWS region (default: session default)")
    scan.add_argument("--all-regions", action="store_true", help="Scan EC2/ELB across all enabled regions")
    scan.add_argument("--hostnames", type=lambda s: s.split(","), help="Comma-separated hostnames to live-check")
    scan.add_argument("--dns-zones", action="store_true", help="Also live-check every hostname found in Route53")
    scan.add_argument("--no-http-probe", action="store_true", help="Skip HTTP probing, DNS resolution only")
    scan.add_argument("--skip-s3", action="store_true")
    scan.add_argument("--skip-ec2", action="store_true")
    scan.add_argument("--skip-elb", action="store_true")
    scan.add_argument("--skip-route53", action="store_true")
    scan.add_argument("--json", help="Write JSON output to this path")
    scan.add_argument("--csv", help="Write CSV output to this path")
    scan.add_argument("--html", default="decay_report.html", help="Write HTML dashboard to this path")
    scan.add_argument("--history-dir", default=".decay_tracker/history", help="Where scan history is stored")
    scan.add_argument("--label", help="Label for this run in history")
    scan.add_argument("--fail-on-critical", action="store_true", help="Exit non-zero if any CRITICAL asset found (for CI)")
    scan.set_defaults(func=cmd_scan)

    diff = sub.add_parser("diff", help="Diff the two most recent scan runs")
    diff.add_argument("--history-dir", default=".decay_tracker/history")
    diff.set_defaults(func=cmd_diff)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
