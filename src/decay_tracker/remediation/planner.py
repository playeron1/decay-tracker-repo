"""Conservative remediation planning for scored cloud assets."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from decay_tracker.remediation.actions import (
    DisableS3StaticWebsite,
    FlagForManualReview,
    QuarantinePublicS3Bucket,
    ReleaseUnassociatedElasticIP,
)
from decay_tracker.remediation.owner_resolution import resolve_owner


def _value(asset: Any, key: str, default=None):
    if isinstance(asset, dict):
        return asset.get(key, default)
    return getattr(asset, key, default)


def _normal_asset_type(asset_type: Any) -> str:
    return str(getattr(asset_type, "value", asset_type or "unknown"))


def _is_unassociated_eip(asset: Any, raw: dict[str, Any]) -> bool:
    if raw.get("associated") is False:
        return True
    if (
        raw.get("associated") is True
        or raw.get("association_id")
        or raw.get("instance_id")
        or raw.get("network_interface_id")
    ):
        return False
    detail = str(_value(asset, "probe_detail", "")).lower()
    return "not associated" in detail or "unassociated" in detail


def _eligible_band(asset: Any) -> str | None:
    band = _value(asset, "decay_band")
    if band:
        normalized = str(band).upper()
        return normalized if normalized in {"HIGH", "CRITICAL"} else None
    score = _value(asset, "decay_score")
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return None
    if numeric >= 75:
        return "CRITICAL"
    if numeric >= 50:
        return "HIGH"
    return None


def _actions_for(asset: Any) -> list[Any]:
    resource_type = _normal_asset_type(_value(asset, "asset_type"))
    resource_id = str(_value(asset, "identifier", "unknown"))
    region = _value(asset, "region")
    raw = _value(asset, "raw", {}) or {}
    raw = raw if isinstance(raw, dict) else {}
    actions = []

    if resource_type == "s3_bucket":
        if bool(_value(asset, "publicly_accessible", False)):
            actions.append(QuarantinePublicS3Bucket(resource_id, region))
        if raw.get("website_enabled") is True:
            actions.append(DisableS3StaticWebsite(resource_id, region))
        if not actions:
            actions.append(FlagForManualReview(
                resource_type,
                resource_id,
                "High decay score without a confirmed public bucket or website condition; verify lifecycle and owner before changing access.",
                region,
            ))
        return actions

    if resource_type == "elastic_ip":
        allocation_id = raw.get("allocation_id")
        if allocation_id and _is_unassociated_eip(asset, raw):
            return [ReleaseUnassociatedElasticIP(allocation_id, resource_id, region)]
        return [FlagForManualReview(
            resource_type,
            resource_id,
            "The scan snapshot does not prove that this Elastic IP is unassociated; re-check ownership and association.",
            region,
        )]

    return [FlagForManualReview(
        resource_type,
        resource_id,
        "No automatic action is configured for this resource type. Confirm owner, dependencies and decommission approval manually.",
        region,
    )]


def plan_remediation(assets: list[Any], cloudtrail_client=None) -> dict[str, Any]:
    """Build a plan from HIGH/CRITICAL assets; no AWS writes are performed."""
    actions: list[dict[str, Any]] = []
    eligible_assets = 0
    for asset in assets:
        band = _eligible_band(asset)
        if band is None:
            continue
        eligible_assets += 1
        owner = resolve_owner(asset, cloudtrail_client=cloudtrail_client)
        score = _value(asset, "decay_score")
        resource_type = _normal_asset_type(_value(asset, "asset_type"))
        resource_id = str(_value(asset, "identifier", "unknown"))
        for action in _actions_for(asset):
            item = action.to_dict()
            item.update({
                "plan_item_id": f"{resource_type}:{resource_id}:{action.action_id}",
                "decay_band": band,
                "decay_score": score,
                "likely_owner": owner["owner"],
                "owner_source": owner["source"],
                "owner_evidence": owner["evidence"],
                "risk_factors": list(_value(asset, "risk_factors", []) or []),
            })
            actions.append(item)

    counts = {
        "high_or_critical_assets": eligible_assets,
        "planned_actions": len(actions),
        "reversible_actions": sum(1 for item in actions if item["reversible"]),
        "irreversible_actions": sum(
            1 for item in actions
            if not item["reversible"] and item["action_id"] != "flag_for_manual_review"
        ),
        "manual_review_items": sum(
            1 for item in actions if item["action_id"] == "flag_for_manual_review"
        ),
    }
    account_ids = sorted({
        str(_value(asset, "account_id"))
        for asset in assets if _value(asset, "account_id")
    })
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_ids": account_ids,
        "dry_run_default": True,
        "selection_rule": "Only HIGH and CRITICAL assets are planned. Lower bands are excluded.",
        "summary": counts,
        "actions": actions,
    }
