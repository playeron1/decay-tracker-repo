"""Scan history storage.

A single scan is a snapshot. "Decay tracking" implies comparing snapshots
over time: is this bucket's score rising? Did a new unreachable-but-public
EIP appear since last week? This module stores each run as timestamped
JSON and provides a diff between the two most recent runs.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from decay_tracker.models import Asset


def _serialize_asset(asset: Asset) -> dict:
    d = asdict(asset)
    d["asset_type"] = asset.asset_type.value
    d["reachability"] = asset.reachability.value
    d["fingerprint"] = asset.fingerprint
    for key in ("created_at", "last_activity_at", "last_cost_at"):
        if d.get(key):
            val = getattr(asset, key)
            d[key] = val.isoformat() if hasattr(val, "isoformat") else str(val)
    for ev in d.get("evidence", []):
        if "observed_at" in ev and hasattr(ev["observed_at"], "isoformat"):
            ev["observed_at"] = ev["observed_at"].isoformat()
        elif "observed_at" in ev:
            ev["observed_at"] = str(ev["observed_at"])
    return d


class ScanHistory:
    def __init__(self, history_dir: str = ".decay_tracker/history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def save(self, assets: list[Asset], run_label: str | None = None) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        label = run_label or timestamp
        path = self.history_dir / f"{timestamp}__{label}.json"
        payload = {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "asset_count": len(assets),
            "assets": [_serialize_asset(a) for a in assets],
        }
        path.write_text(json.dumps(payload, indent=2, default=str))
        return path

    def list_runs(self) -> list[Path]:
        return sorted(self.history_dir.glob("*.json"))

    def load(self, path: Path) -> dict:
        return json.loads(path.read_text())

    def diff_last_two(self) -> dict | None:
        runs = self.list_runs()
        if len(runs) < 2:
            return None
        prev = self.load(runs[-2])
        curr = self.load(runs[-1])

        prev_by_fp = {a["fingerprint"]: a for a in prev["assets"]}
        curr_by_fp = {a["fingerprint"]: a for a in curr["assets"]}

        new_assets = [a for fp, a in curr_by_fp.items() if fp not in prev_by_fp]
        removed_assets = [a for fp, a in prev_by_fp.items() if fp not in curr_by_fp]
        worsened = []
        improved = []
        for fp, curr_a in curr_by_fp.items():
            prev_a = prev_by_fp.get(fp)
            if not prev_a:
                continue
            prev_score = prev_a.get("decay_score") or 0
            curr_score = curr_a.get("decay_score") or 0
            if curr_score - prev_score >= 10:
                worsened.append({"identifier": curr_a["identifier"], "from": prev_score, "to": curr_score})
            elif prev_score - curr_score >= 10:
                improved.append({"identifier": curr_a["identifier"], "from": prev_score, "to": curr_score})

        return {
            "previous_run": runs[-2].name,
            "current_run": runs[-1].name,
            "new_assets": new_assets,
            "removed_assets": removed_assets,
            "worsened": worsened,
            "improved": improved,
        }
