"""Resolve likely asset owners from tags, then CloudTrail management events."""
from __future__ import annotations

import json
from typing import Any

OWNER_TAG_KEYS = (
    "Owner", "owner", "owner_email", "OwnerEmail",
    "CreatedBy", "created_by", "Team", "team",
)
EVENTS_BY_TYPE = {
    "s3_bucket": ("CreateBucket",),
    "ec2_instance": ("RunInstances",),
    "elastic_ip": ("AllocateAddress",),
}


def _asset_value(asset: Any, key: str, default=None):
    if isinstance(asset, dict):
        return asset.get(key, default)
    return getattr(asset, key, default)


def _matches_identifier(value: Any, identifiers: set[str]) -> bool:
    if isinstance(value, dict):
        return any(_matches_identifier(item, identifiers) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_matches_identifier(item, identifiers) for item in value)
    if value is None:
        return False
    candidate = str(value).strip()
    if candidate in identifiers:
        return True
    return any(
        candidate.endswith("/" + identifier) or candidate.endswith(":" + identifier)
        for identifier in identifiers
    )


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("CloudTrailEvent")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _principal(event_payload: dict[str, Any]) -> str | None:
    identity = event_payload.get("userIdentity") or {}
    session_context = identity.get("sessionContext") or {}
    issuer = session_context.get("sessionIssuer") or {}
    candidates = (
        identity.get("userName"),
        issuer.get("userName"),
        identity.get("arn"),
        issuer.get("arn"),
        identity.get("principalId"),
    )
    return next((str(value) for value in candidates if value), None)


def _cloudtrail_client_for_region(client_or_factory, region: str | None):
    if callable(client_or_factory) and not hasattr(client_or_factory, "lookup_events"):
        return client_or_factory(region)
    return client_or_factory


def resolve_owner(asset: Any, cloudtrail_client=None) -> dict[str, str | None]:
    """Resolve a probable owner; return Unknown instead of fabricating attribution."""
    owner_tag = _asset_value(asset, "owner_tag")
    tags = _asset_value(asset, "tags", {}) or {}
    if owner_tag:
        return {"owner": str(owner_tag), "source": "tag", "evidence": "owner_tag"}
    if isinstance(tags, dict):
        for key in OWNER_TAG_KEYS:
            if tags.get(key):
                return {"owner": str(tags[key]), "source": "tag", "evidence": f"tag:{key}"}

    resource_type = _asset_value(asset, "asset_type", "unknown")
    resource_type = getattr(resource_type, "value", resource_type)
    resource_id = str(_asset_value(asset, "identifier", ""))
    raw = _asset_value(asset, "raw", {}) or {}
    region = _asset_value(asset, "region")
    identifiers = {resource_id}
    if isinstance(raw, dict):
        identifiers.update(
            str(raw[key])
            for key in ("allocation_id", "public_ip", "instance_id")
            if raw.get(key)
        )

    if cloudtrail_client is not None and resource_id:
        try:
            client = _cloudtrail_client_for_region(cloudtrail_client, region)
            for event_name in EVENTS_BY_TYPE.get(str(resource_type), ()):
                response = client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    MaxResults=50,
                )
                for event in response.get("Events", []):
                    payload = _event_payload(event)
                    if not (
                        _matches_identifier(event.get("Resources", []) or [], identifiers)
                        or _matches_identifier(payload.get("requestParameters", {}), identifiers)
                        or _matches_identifier(payload.get("responseElements", {}), identifiers)
                    ):
                        continue
                    principal = _principal(payload)
                    if principal:
                        event_id = event.get("EventId") or event_name
                        return {
                            "owner": principal,
                            "source": "cloudtrail",
                            "evidence": f"{event_name} event {event_id}",
                        }
        except Exception:
            # Permission and retention gaps remain unresolved, never a false match.
            pass

    return {
        "owner": None,
        "source": "unresolved",
        "evidence": "No owner tag or matching CloudTrail creation event was found",
    }
