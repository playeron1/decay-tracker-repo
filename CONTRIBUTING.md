# Contributing

## Adding a new scanner (new resource type)

1. Create `src/decay_tracker/scanners/<name>_scanner.py`, subclass `Scanner`
   (see `scanners/base.py`).
2. Populate `Asset` fields from `models.py` — in particular, always set
   `reachability` meaningfully (don't leave it `UNKNOWN` if you can
   determine it) since it's the highest-weighted scoring signal.
3. Call `asset.add_evidence(source, detail)` for anything that informed
   your reachability/ownership judgment — this is what shows up under
   "Why" in the dashboard and is what makes scores auditable rather than
   a black box.
4. Add moto-based tests in `tests/test_<name>_scanner.py` covering at
   least: the "zombie" case and the "healthy/owned" case, so the signal
   is demonstrably distinguishable.
5. Wire it into `cli.py` (`_run_scan`) with a `--skip-<name>` flag to
   match the existing pattern.

## Changing the scoring model

Scoring changes affect what gets surfaced as CRITICAL, so:
- Keep every point addition attributed to a `factors.append(...)` string —
  no silent scoring.
- Add/update tests in `tests/test_scoring.py` demonstrating the specific
  behavior you changed (e.g. "dangling DNS now outranks plain-responsive").
- Call out threshold changes (the `STALE_*_DAYS` constants) explicitly in
  the PR description — these are environment-dependent tuning knobs, not
  universal constants, and changing the default affects everyone's reports.

## Running the suite locally before opening a PR

```bash
pip install -e ".[dev,dns]"
ruff check src tests
pytest --cov=decay_tracker
python scripts/demo_scan.py   # eyeball the dashboard still renders sanely
```

CI runs the same three steps across Python 3.10–3.12 plus a demo-dashboard
smoke test, all against moto-mocked AWS — no real credentials are ever
needed to contribute or review.

## Non-goals

- No implicit AWS mutations. Scanning and planning are read-only by default;
  every new opt-in remediation action must document API calls, preconditions,
  reversibility and undo behavior, and have mocked-AWS tests.
- No credential storage of any kind in the repo. The scheduled-scan
  workflow uses GitHub OIDC specifically to avoid long-lived keys.
