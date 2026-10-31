from datetime import datetime, timedelta, timezone

import pytest

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scoring.engine import score_asset, score_assets


def _asset(**kwargs) -> Asset:
    defaults = dict(asset_type=AssetType.S3_BUCKET, identifier="test-bucket")
    defaults.update(kwargs)
    return Asset(**defaults)


def test_fresh_owned_private_asset_scores_low():
    asset = _asset(
        reachability=Reachability.UNREACHABLE,
        publicly_accessible=False,
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=1),
        owner_tag="alice",
        project_tag="payments",
    )
    result = score_asset(asset)
    assert result.band == "LOW"
    assert result.total < 25


def test_public_responsive_unowned_stale_asset_scores_critical():
    asset = _asset(
        reachability=Reachability.RESPONSIVE,
        publicly_accessible=True,
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=500),
        owner_tag=None,
        project_tag=None,
        created_at=datetime.now(timezone.utc) - timedelta(days=900),
    )
    result = score_asset(asset)
    assert result.band == "CRITICAL"
    assert result.total >= 75


def test_dangling_reference_scores_higher_than_plain_responsive():
    dangling = _asset(reachability=Reachability.RESPONSIVE_ERROR)
    live = _asset(reachability=Reachability.RESPONSIVE)
    dangling_score = score_asset(dangling).total
    live_score = score_asset(live).total
    assert dangling_score > live_score


def test_missing_activity_data_is_treated_as_risk_not_neutral():
    unknown_activity = _asset(last_activity_at=None, reachability=Reachability.UNREACHABLE)
    recent_activity = _asset(
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=1),
        reachability=Reachability.UNREACHABLE,
    )
    assert score_asset(unknown_activity).total > score_asset(recent_activity).total


def test_termination_protection_lowers_score():
    protected = _asset(reachability=Reachability.RESPONSIVE, has_termination_protection=True)
    unprotected = _asset(reachability=Reachability.RESPONSIVE, has_termination_protection=False)
    assert score_asset(protected).total < score_asset(unprotected).total


def test_score_is_bounded_0_to_100():
    extreme = _asset(
        reachability=Reachability.RESPONSIVE_ERROR,
        publicly_accessible=True,
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=5000),
        last_cost_at=datetime.now(timezone.utc) - timedelta(days=5000),
        created_at=datetime.now(timezone.utc) - timedelta(days=5000),
        owner_tag=None,
        project_tag=None,
    )
    result = score_asset(extreme)
    assert 0 <= result.total <= 100


def test_score_assets_sorts_descending_and_mutates_in_place():
    low = _asset(identifier="low", reachability=Reachability.UNREACHABLE, owner_tag="bob", last_activity_at=datetime.now(timezone.utc))
    high = _asset(identifier="high", reachability=Reachability.RESPONSIVE, publicly_accessible=True, owner_tag=None)
    results = score_assets([low, high])
    assert results[0].identifier == "high"
    assert low.decay_score is not None and low.decay_band is not None


def test_every_scored_asset_has_explainable_factors():
    asset = _asset(reachability=Reachability.RESPONSIVE)
    score_asset(asset)
    breakdown = score_asset(asset)
    assert len(breakdown.factors) > 0
    assert all(isinstance(f, str) and f for f in breakdown.factors)
