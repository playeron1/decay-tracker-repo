"""Dry-run and opt-in execution for remediation plans."""
from __future__ import annotations

from decay_tracker.remediation.actions import FlagForManualReview, action_from_plan


def execute_plan(plan: dict, session=None, *, execute: bool = False) -> dict:
    """Execute a plan or return a no-write preview."""
    results = []
    undo_records = []
    for item in plan.get("actions", []):
        action = action_from_plan(item)
        if isinstance(action, FlagForManualReview):
            results.append({
                "plan_item_id": item.get("plan_item_id"),
                "action_id": action.action_id,
                "status": "manual_review_required",
                "description": action.describe(),
                "planned_calls": [],
            })
            continue
        if not execute:
            results.append({
                "plan_item_id": item.get("plan_item_id"),
                "action_id": action.action_id,
                "status": "dry_run",
                "description": action.describe(),
                "planned_calls": action.aws_calls(),
            })
            continue
        if session is None:
            raise ValueError("An AWS session is required when execute=True")
        try:
            undo_record = action.execute(session)
            results.append({
                "plan_item_id": item.get("plan_item_id"),
                "action_id": action.action_id,
                "status": "executed",
                "undo_record": undo_record,
            })
            if undo_record.get("reversible"):
                undo_records.append(undo_record)
        except Exception as error:
            results.append({
                "plan_item_id": item.get("plan_item_id"),
                "action_id": action.action_id,
                "status": "failed",
                "error": str(error),
            })
            # Stop at the first failed write; earlier undo records are retained.
            break

    failed = any(item["status"] == "failed" for item in results)
    return {
        "mode": "execute" if execute else "dry_run",
        "success": not failed,
        "results": results,
        "undo_records": undo_records,
    }
