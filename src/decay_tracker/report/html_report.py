"""Static, self-contained HTML dashboard generator.

No server, no build step, no external JS - a single HTML file with
inline CSS/JS that someone can open locally or publish as a CI artifact.
Deliberately low-tech: this report needs to survive being opened on a
random analyst's laptop five years from now.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from decay_tracker.models import Asset

BAND_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#15803d",
}


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _likely_owner(asset: Asset) -> str:
    tags = asset.tags or {}
    return (
        asset.owner_tag or tags.get("Owner") or tags.get("owner")
        or tags.get("owner_email") or tags.get("Team") or tags.get("team") or "Unknown"
    )


def _suggested_fix(asset: Asset) -> str:
    """Display a suggestion only; this report never performs AWS changes."""
    if asset.decay_band not in {"HIGH", "CRITICAL"}:
        return "Monitor — below HIGH threshold"
    resource_type = getattr(asset.asset_type, "value", str(asset.asset_type))
    raw = asset.raw or {}
    if resource_type == "s3_bucket":
        suggestions = []
        if asset.publicly_accessible:
            suggestions.append("Enable S3 Block Public Access")
        if raw.get("website_enabled") is True:
            suggestions.append("Disable static website hosting")
        return " + ".join(suggestions) if suggestions else "Manual review; confirm owner and lifecycle"
    if resource_type == "elastic_ip":
        if raw.get("associated") is False and raw.get("allocation_id"):
            return "Verify DNS dependencies, then release unassociated Elastic IP (irreversible)"
        return "Manual review; association/ownership is not confirmed"
    return "Manual review; no automatic action is configured"


def _asset_row(asset: Asset) -> str:
    color = BAND_COLOR.get(asset.decay_band or "LOW", "#374151")
    factors_html = "".join(f"<li>{_esc(f)}</li>" for f in asset.risk_factors)
    tags_html = ", ".join(f"{_esc(k)}={_esc(v)}" for k, v in (asset.tags or {}).items()) or "—"
    return f"""
    <tr class="asset-row" data-band="{_esc(asset.decay_band)}" data-type="{_esc(asset.asset_type.value)}">
      <td><span class="band" style="background:{color}">{_esc(asset.decay_band)}</span></td>
      <td>{asset.decay_score:.0f}</td>
      <td>{_esc(asset.asset_type.value)}</td>
      <td class="identifier">{_esc(asset.identifier)}</td>
      <td>{_esc(asset.region or '—')}</td>
      <td>{_esc(asset.reachability.value)}</td>
      <td>{'Yes' if asset.publicly_accessible else 'No'}</td>
      <td>{_esc(_likely_owner(asset))}</td>
      <td>{_esc(_suggested_fix(asset))}</td>
      <td>
        <details>
          <summary>{len(asset.risk_factors)} factor(s)</summary>
          <ul class="factors">{factors_html}</ul>
          <div class="probe-detail">{_esc(asset.probe_detail or '')}</div>
          <div class="tags">Tags: {tags_html}</div>
        </details>
      </td>
    </tr>"""


def generate_html_report(assets: list[Asset], output_path: str = "decay_report.html") -> Path:
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in assets:
        counts[a.decay_band or "LOW"] += 1

    rows_html = "\n".join(_asset_row(a) for a in assets)

    summary_cards = "".join(
        f"""<div class="card" style="border-top-color:{BAND_COLOR[band]}">
              <div class="card-count">{counts[band]}</div>
              <div class="card-label">{band}</div>
            </div>"""
        for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Surface Decay Report</title>
<style>
  :root {{
    --bg: #0b0f14; --panel: #121821; --text: #e6edf3; --muted: #8b949e;
    --border: #2b3340;
  }}
  @media (prefers-color-scheme: light) {{
    :root:not([data-theme="dark"]) {{
      --bg: #f6f8fa; --panel: #ffffff; --text: #1f2328; --muted: #57606a;
      --border: #d0d7de;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 24px;
  }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); margin-bottom: 24px; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{
    background: var(--panel); border: 1px solid var(--border); border-top: 4px solid;
    border-radius: 8px; padding: 16px 24px; min-width: 100px;
  }}
  .card-count {{ font-size: 1.8rem; font-weight: 700; }}
  .card-label {{ color: var(--muted); font-size: 0.8rem; letter-spacing: 0.05em; }}
  .controls {{ margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .controls select, .controls input {{
    background: var(--panel); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 10px; font-size: 0.85rem;
  }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.85rem; }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  .band {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .identifier {{ font-family: ui-monospace, monospace; max-width: 320px; overflow-wrap: anywhere; }}
  details summary {{ cursor: pointer; color: var(--muted); }}
  .factors {{ margin: 8px 0 0 0; padding-left: 18px; font-size: 0.8rem; }}
  .probe-detail, .tags {{ font-size: 0.78rem; color: var(--muted); margin-top: 6px; }}
  tr.hidden {{ display: none; }}
</style>
</head>
<body>
  <h1>Attack Surface Decay Report</h1>
  <div class="subtitle">Generated {scanned_at} · {len(assets)} asset(s) scanned</div>

  <div class="summary">{summary_cards}</div>

  <div class="controls">
    <select id="bandFilter">
      <option value="">All bands</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <input id="search" type="text" placeholder="Filter by identifier, region, owner...">
  </div>

  <table>
    <thead>
      <tr>
        <th>Band</th><th>Score</th><th>Type</th><th>Identifier</th><th>Region</th>
        <th>Reachability</th><th>Public</th><th>Likely owner</th><th>Suggested fix</th><th>Why</th>
      </tr>
    </thead>
    <tbody id="rows">
      {rows_html}
    </tbody>
  </table>

<script>
  const bandFilter = document.getElementById('bandFilter');
  const search = document.getElementById('search');
  function applyFilters() {{
    const band = bandFilter.value;
    const q = search.value.toLowerCase();
    document.querySelectorAll('.asset-row').forEach(row => {{
      const matchesBand = !band || row.dataset.band === band;
      const matchesSearch = !q || row.textContent.toLowerCase().includes(q);
      row.classList.toggle('hidden', !(matchesBand && matchesSearch));
    }});
  }}
  bandFilter.addEventListener('change', applyFilters);
  search.addEventListener('input', applyFilters);
</script>
</body>
</html>"""

    path = Path(output_path)
    path.write_text(doc, encoding="utf-8")
    return path
