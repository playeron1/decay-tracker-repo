"""JSON, Markdown and runnable Python output for remediation plans."""
from __future__ import annotations

import base64
import json
from pathlib import Path


def write_json(plan: dict, path: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(plan, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    return target


def render_markdown(plan: dict) -> str:
    summary = plan.get("summary", {})
    lines = [
        "# Remediation plan",
        "",
        f"Generated: {plan.get('generated_at', 'unknown')}",
        f"Account(s): {', '.join(plan.get('account_ids') or []) or 'not recorded'}",
        "",
        "> DRY RUN BY DEFAULT. This plan does not change AWS resources. Execution requires both --execute and --yes.",
        "> Releasing an Elastic IP is irreversible. Confirm DNS dependencies and service ownership first.",
        "",
        "## Summary",
        "",
        f"- HIGH/CRITICAL assets: {summary.get('high_or_critical_assets', 0)}",
        f"- Planned actions: {summary.get('planned_actions', 0)}",
        f"- Reversible actions: {summary.get('reversible_actions', 0)}",
        f"- Irreversible actions: {summary.get('irreversible_actions', 0)}",
        f"- Manual review items: {summary.get('manual_review_items', 0)}",
        "",
        "## Actions",
        "",
    ]
    if not plan.get("actions"):
        lines.append("No HIGH or CRITICAL assets required a remediation plan.")
    for index, item in enumerate(plan.get("actions", []), start=1):
        owner = item.get("likely_owner") or "Unknown"
        lines.extend([
            f"### {index}. {item.get('name', item.get('action_id'))}",
            "",
            f"- Resource: {item.get('resource_type')} / {item.get('resource_id')}",
            f"- Severity: **{item.get('decay_band')}** (score {item.get('decay_score')})",
            f"- Likely owner: {owner} (source: {item.get('owner_source')})",
            f"- Reversible: {'yes' if item.get('reversible') else 'no'}",
            f"- Rationale: {item.get('description')}",
        ])
        if item.get("owner_evidence"):
            lines.append(f"- Owner evidence: {item['owner_evidence']}")
        calls = item.get("aws_calls") or []
        if calls:
            lines.append("- Planned AWS API calls:")
            for call in calls:
                lines.append(
                    f"  - {call['service']}.{call['operation']} — "
                    f"{json.dumps(call.get('parameters', {}), sort_keys=True)}"
                )
        else:
            lines.append("- Planned AWS API calls: none (manual review only)")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_markdown(plan: dict, path: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(plan), encoding="utf-8")
    return target


def render_python_script(plan: dict) -> str:
    """Return a standalone plan runner with safely JSON-encoded plan data."""
    payload = base64.b64encode(
        json.dumps(plan, separators=(",", ":"), default=str).encode("utf-8")
    ).decode("ascii")
    return f'''#!/usr/bin/env python3
"""Generated CAST remediation runner. Dry-run unless --execute --yes is supplied."""
import argparse
import base64
import json
from pathlib import Path

from decay_tracker.aws_session import get_account_id, get_session
from decay_tracker.remediation.executor import execute_plan

PLAN = json.loads(base64.b64decode("{payload}").decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Execute the embedded CAST remediation plan")
    parser.add_argument("--execute", action="store_true", help="Perform AWS writes (requires --yes)")
    parser.add_argument("--yes", action="store_true", help="Confirm the AWS modifications")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="Default AWS region")
    parser.add_argument("--undo-file", default="remediation_undo.json", help="Where to save reversible undo records")
    args = parser.parse_args()
    if args.execute and not args.yes:
        parser.error("--execute requires --yes")
    if args.yes and not args.execute:
        parser.error("--yes is only valid together with --execute")
    session = get_session(profile=args.profile, region=args.region) if args.execute else None
    if args.execute:
        planned_accounts = [str(value) for value in PLAN.get("account_ids", []) if value]
        if len(planned_accounts) != 1:
            parser.error("live execution requires exactly one recorded scan account ID")
        actual_account_id = get_account_id(session)
        if not actual_account_id or actual_account_id != planned_accounts[0]:
            parser.error("active AWS account does not match the scan account; refusing to execute")
    result = execute_plan(PLAN, session, execute=args.execute)
    print(json.dumps(result, indent=2, default=str))
    if result.get("undo_records"):
        Path(args.undo_file).write_text(
            json.dumps(result["undo_records"], indent=2, default=str),
            encoding="utf-8",
        )
        print("Undo records written to:", args.undo_file)
    return 1 if not result.get("success", True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_python_script(plan: dict, path: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_python_script(plan), encoding="utf-8")
    target.chmod(0o755)
    return target
