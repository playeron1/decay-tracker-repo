from datetime import datetime, timedelta, timezone

from decay_tracker.models import Asset, AssetType, Reachability


def test_fingerprint_is_stable_for_same_identity():
    a1 = Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-1", account_id="123", region="us-east-1")
    a2 = Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-1", account_id="123", region="us-east-1")
    assert a1.fingerprint == a2.fingerprint


def test_fingerprint_differs_for_different_identity():
    a1 = Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-1")
    a2 = Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-2")
    assert a1.fingerprint != a2.fingerprint


def test_days_since_handles_none():
    asset = Asset(asset_type=AssetType.S3_BUCKET, identifier="x")
    assert asset.days_since(None) is None


def test_days_since_handles_naive_datetime():
    asset = Asset(asset_type=AssetType.S3_BUCKET, identifier="x")
    naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=10)
    result = asset.days_since(naive)
    assert result is not None
    assert 9 <= result <= 11


def test_add_evidence_appends():
    asset = Asset(asset_type=AssetType.S3_BUCKET, identifier="x")
    asset.add_evidence("test-source", "test-detail")
    assert len(asset.evidence) == 1
    assert asset.evidence[0].source == "test-source"
