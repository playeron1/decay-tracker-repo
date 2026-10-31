from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scoring.engine import score_assets
from decay_tracker.storage.history import ScanHistory


def test_save_and_list_runs(tmp_path):
    history = ScanHistory(str(tmp_path))
    assets = score_assets([Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-a")])
    history.save(assets, run_label="run1")
    assert len(history.list_runs()) == 1


def test_diff_detects_new_asset(tmp_path):
    history = ScanHistory(str(tmp_path))
    first = score_assets([Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-a")])
    history.save(first, run_label="run1")

    second = score_assets([
        Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-a"),
        Asset(asset_type=AssetType.S3_BUCKET, identifier="bucket-b"),
    ])
    history.save(second, run_label="run2")

    diff = history.diff_last_two()
    assert diff is not None
    assert len(diff["new_assets"]) == 1
    assert diff["new_assets"][0]["identifier"] == "bucket-b"


def test_diff_detects_worsened_score(tmp_path):
    history = ScanHistory(str(tmp_path))

    calm = Asset(
        asset_type=AssetType.S3_BUCKET, identifier="bucket-a",
        reachability=Reachability.UNREACHABLE, owner_tag="alice",
    )
    history.save(score_assets([calm]), run_label="run1")

    risky = Asset(
        asset_type=AssetType.S3_BUCKET, identifier="bucket-a",
        reachability=Reachability.RESPONSIVE, publicly_accessible=True, owner_tag=None,
    )
    history.save(score_assets([risky]), run_label="run2")

    diff = history.diff_last_two()
    assert len(diff["worsened"]) == 1
    assert diff["worsened"][0]["identifier"] == "bucket-a"


def test_diff_returns_none_with_fewer_than_two_runs(tmp_path):
    history = ScanHistory(str(tmp_path))
    assert history.diff_last_two() is None
