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
from decay_tracker.remediation import output as remediation_output
from decay_tracker.remediation.executor import execute_plan
from decay_tracker.remediation.planner import plan_remediation
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


def _load_remediation_assets(path: str) -> list[dict]:
    """Load a scan JSON list or a ScanHistory snapshot."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("assets")
    if not isinstance(payload, list):
        raise ValueError("Scan JSON must be an asset list or an object containing an 'assets' list.")
    return payload


def cmd_remediate(args) -> int:
    """Create a conservative plan; AWS writes require both explicit flags."""
    if args.execute and not args.yes:
        print("Refusing to execute: pass both --execute and --yes.", file=sys.stderr)
        return 2
    if args.yes and not args.execute:
        print("--yes is only valid together with --execute.", file=sys.stderr)
        return 2
    try:
        assets = _load_remediation_assets(args.from_json)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Could not load scan JSON: {error}", file=sys.stderr)
        return 1
    if not assets:
        print("The scan file contains no assets.", file=sys.stderr)
        return 1

    session = None
    cloudtrail_factory = None
    if args.execute or not args.no_cloudtrail_lookup:
        session = get_session(profile=args.profile, region=args.region)
        if not args.no_cloudtrail_lookup:
            def cloudtrail_factory(region):
                return session.client(
                    "cloudtrail",
                    region_name=region or args.region or session.region_name or "us-east-1",
                )

    plan = plan_remediation(assets, cloudtrail_client=cloudtrail_factory)
    remediation_output.write_json(plan, args.output_json)
    remediation_output.write_markdown(plan, args.output_md)
    remediation_output.write_python_script(plan, args.output_script)

    print(remediation_output.render_markdown(plan))
    print(f"Plan JSON: {args.output_json}")
    print(f"Plan Markdown: {args.output_md}")
    print(f"Runnable script: {args.output_script}")
    if args.execute:
        planned_accounts = [str(value) for value in plan.get("account_ids", []) if value]
        if len(planned_accounts) != 1:
            print(
                "Refusing live execution: the scan must contain exactly one recorded AWS account ID.",
                file=sys.stderr,
            )
            return 4
        actual_account_id = get_account_id(session)
        if not actual_account_id or actual_account_id != planned_accounts[0]:
            print(
                "Refusing live execution: the active AWS credentials do not match the scan account "
                f"(scan={planned_accounts[0]}, active={actual_account_id or 'unavailable'}).",
                file=sys.stderr,
            )
            return 4
        print(
            "\nEXPLICIT AWS MODIFICATION MODE: --execute --yes supplied and the AWS account matches. "
            "Review the plan and irreversible actions before running."
        )
        print(f"Verified AWS account: {actual_account_id}")

    result = execute_plan(plan, session=session, execute=args.execute)
    remediation_output.write_json(result, args.results_json)
    print("\nExecution preview/result:")
    print(json.dumps(result, indent=2, default=str))
    if args.execute and result.get("undo_records"):
        remediation_output.write_json(result["undo_records"], args.undo_file)
        print(f"Reversible-action undo records: {args.undo_file}")
    print(f"Execution result JSON: {args.results_json}")
    return 3 if not result.get("success", True) else 0


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

    remediate = sub.add_parser(
        "remediate",
        help="Plan safe fixes for HIGH/CRITICAL assets; execution is always opt-in",
    )
    remediate.add_argument("--from-json", required=True, help="Scan JSON file (asset list or history snapshot)")
    remediate.add_argument("--profile", help="AWS profile name used for CloudTrail lookup and explicit execution")
    remediate.add_argument("--region", help="Default AWS region")
    remediate.add_argument("--no-cloudtrail-lookup", action="store_true", help="Use tags only for owner resolution")
    mode = remediate.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Preview only; this is the default")
    mode.add_argument("--execute", action="store_true", help="Perform AWS changes; requires --yes as well")
    remediate.add_argument("--yes", action="store_true", help="Confirm the AWS changes when used with --execute")
    remediate.add_argument("--output-json", default="remediation_plan.json", help="Write the generated plan as JSON")
    remediate.add_argument("--output-md", default="remediation_plan.md", help="Write the generated plan as Markdown")
    remediate.add_argument("--output-script", default="remediate.py", help="Write a standalone dry-run-by-default Python runner")
    remediate.add_argument("--results-json", default="remediation_result.json", help="Write the dry-run or execution results")
    remediate.add_argument("--undo-file", default="remediation_undo.json", help="Write undo records for successful reversible changes")
    remediate.set_defaults(func=cmd_remediate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
