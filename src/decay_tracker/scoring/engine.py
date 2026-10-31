"""Decay scoring engine.

The central idea: age alone isn't dangerous. A 4-year-old S3 bucket that's
still actively used isn't a zombie. The dangerous combination is:

    reachable from the outside  +  no recent activity  +  no clear owner

This module turns those signals into a 0-100 decay score and a band
(LOW / MEDIUM / HIGH / CRITICAL) that tells you how urgently to look at it.

Design choices (documented so scores are explainable, not a black box):
  - Reachability is a *gate*, not just a weight: an asset nobody can reach
    from outside is lower priority no matter how stale it looks internally.
  - Missing data is treated as a risk signal, not scored as neutral/zero.
    An asset with no owner tag and no activity timestamp is *more*
    suspicious than one we have full history for, because the absence of
    metadata is itself what lets zombies hide.
  - Every point added to the score is recorded in `risk_factors` so a
    human can see exactly why something scored the way it did.
"""
from __future__ import annotations

from dataclasses import dataclass

from decay_tracker.models import Asset, Reachability

# Tunable thresholds (days) - how long is "stale" for each signal.
STALE_ACTIVITY_DAYS = 90
VERY_STALE_ACTIVITY_DAYS = 365
STALE_COST_DAYS = 60
OLD_ASSET_DAYS = 180


@dataclass
class ScoreBreakdown:
    total: float
    factors: list[str]
    band: str


def _band_for(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def score_asset(asset: Asset) -> ScoreBreakdown:
    """Compute a 0-100 decay/risk score for a single asset.

    Returns a breakdown; caller (or this function) writes it back onto
    the asset so reporting can use asset.decay_score / .decay_band.
    """
    points = 0.0
    factors: list[str] = []

    # --- 1. Reachability: is this actually an entry point right now? ---
    if asset.reachability == Reachability.RESPONSIVE:
        points += 30
        factors.append("Actively responds to external probes (+30)")
    elif asset.reachability == Reachability.RESPONSIVE_ERROR:
        # Dangling DNS / misconfigured-but-live is often the WORST case:
        # e.g. a CNAME pointing at a deleted S3 bucket/EIP that an attacker
        # can re-register (subdomain takeover). Score it highest.
        points += 35
        factors.append(
            "Resolves/responds but errors - possible dangling reference "
            "or takeover risk (+35)"
        )
    elif asset.reachability == Reachability.UNREACHABLE:
        points += 5
        factors.append("Does not currently resolve/respond (+5)")
    else:
        points += 15
        factors.append("Reachability unknown/untested (+15)")

    if asset.publicly_accessible:
        points += 15
        factors.append("Publicly accessible (+15)")

    # --- 2. Activity staleness ---
    days_inactive = asset.days_since(asset.last_activity_at)
    if days_inactive is None:
        points += 15
        factors.append("No activity history available (+15)")
    elif days_inactive >= VERY_STALE_ACTIVITY_DAYS:
        points += 20
        factors.append(f"No activity in {int(days_inactive)} days (+20)")
    elif days_inactive >= STALE_ACTIVITY_DAYS:
        points += 10
        factors.append(f"No activity in {int(days_inactive)} days (+10)")

    # --- 3. Cost staleness (nothing is paying for it = nobody's watching it) ---
    days_since_cost = asset.days_since(asset.last_cost_at)
    if days_since_cost is not None and days_since_cost >= STALE_COST_DAYS:
        points += 5
        factors.append(f"No billed cost in {int(days_since_cost)} days (+5)")

    # --- 4. Ownership / governance ---
    if not asset.owner_tag and not asset.project_tag:
        points += 15
        factors.append("No owner or project tag (+15)")
    elif not asset.owner_tag:
        points += 7
        factors.append("No owner tag (+7)")

    # --- 5. Age, as a mild amplifier only ---
    days_old = asset.days_since(asset.created_at)
    if days_old is not None and days_old >= OLD_ASSET_DAYS:
        points += 5
        factors.append(f"Asset is {int(days_old)} days old (+5)")

    # --- 6. Mitigating factor: explicit protection suggests intentional ---
    if asset.has_termination_protection:
        points -= 10
        factors.append("Has termination/deletion protection (-10, likely intentional)")

    total = max(0.0, min(100.0, points))
    return ScoreBreakdown(total=total, factors=factors, band=_band_for(total))


def score_assets(assets: list[Asset]) -> list[Asset]:
    """Score a batch in place and return it sorted by score descending."""
    for asset in assets:
        breakdown = score_asset(asset)
        asset.decay_score = breakdown.total
        asset.decay_band = breakdown.band
        asset.risk_factors = breakdown.factors
    return sorted(assets, key=lambda a: (a.decay_score or 0), reverse=True)
