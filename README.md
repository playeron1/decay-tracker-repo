# Cloud Attack-Surface Decay Tracker

Finds "zombie" cloud assets — forgotten S3 buckets, orphaned EC2 instances,
unassociated Elastic IPs, dead-but-live load balancers, and stale/dangling
DNS records — that still resolve or respond years after a project ended,
and quietly stay reachable as unmonitored entry points.

This isn't a vulnerability scanner. It doesn't look for CVEs. It looks for
the thing that lets a forgotten asset *become* a vulnerability: something
still publicly reachable that nobody is watching anymore.

## Why "decay," not just "inventory"

A standard asset inventory tells you what exists. This tool is built around
a different question: **is this thing dying unsupervised?** The scoring
model treats the dangerous state as a *combination* of signals — reachable
from outside, no recent activity, no owner — rather than any single one.
A bucket from 2019 that's still actively used isn't a zombie. A bucket
from last month that's public, unowned, and already stale is.

Scans are also snapshotted over time (`decay-tracker diff`) so you can see
an asset's score trending upward before it becomes a CRITICAL surprise.

## What it checks

| Resource | Signals |
|---|---|
| S3 buckets | public ACL/policy, static website hosting, object activity staleness, tags |
| EC2 instances | running+public+open-SG, stopped-but-not-terminated (classic orphan) |
| Elastic IPs | allocated but unassociated (pure cost + stale-DNS-target risk) |
| Load balancers (ALB/NLB) | zero/unhealthy targets behind a still-live DNS name |
| Route53 + arbitrary hostnames | dangling CNAMEs to deleted S3/ELB/CloudFront endpoints (subdomain takeover pattern), live resolution/HTTP probing |

## Install

```bash
pip install -e ".[dns]"
```

(`dnspython` is optional but recommended — without it, CNAME-chain detection
for dangling DNS is skipped and only plain resolution is checked.)

## Usage

```bash
# Single region, everything enabled
decay-tracker scan --profile myprofile --region us-east-1

# Full account sweep + check every hostname in Route53 for live reachability
decay-tracker scan --profile myprofile --all-regions --dns-zones

# Just check a specific list of old project domains
decay-tracker scan --profile myprofile --hostnames old-demo.example.com,staging-2021.example.com

# CI gate: exit non-zero if anything scores CRITICAL
decay-tracker scan --profile myprofile --all-regions --fail-on-critical

# Compare the two most recent scans
decay-tracker diff
```

Each run writes:
- `decay_report.html` — a self-contained, filterable local dashboard (no server needed)
- optional `--json` / `--csv` exports
- a timestamped snapshot under `.decay_tracker/history/` for trend diffing

## Scoring model

Every asset gets a 0–100 score from `src/decay_tracker/scoring/engine.py`,
with every point attributed to a specific, human-readable reason (shown in
the dashboard under "Why"). Rough shape:

- **Reachability is weighted highest**, and a *resolving-but-erroring* state
  (e.g. a CNAME pointing at a deleted bucket) scores higher than either
  fully-live or fully-dead — that's the subdomain-takeover-prone state.
- **Missing metadata counts as risk, not neutral.** No activity history and
  no owner tag isn't "unknown," it's exactly the condition that lets zombies
  hide. Treating it as zero would undercount the real risk.
- **Age is a minor amplifier only** — old-but-owned-and-active assets should
  not dominate the top of the list.
- Explicit termination/deletion protection slightly *lowers* the score —
  it's a signal someone configured this on purpose.

Bands: `LOW` (0–24), `MEDIUM` (25–49), `HIGH` (50–74), `CRITICAL` (75–100).

Thresholds live as named constants at the top of `scoring/engine.py` — tune
them for your environment rather than editing the logic inline.

## IAM permissions

The tool is read-only by design — see [`iam/decay-tracker-readonly-policy.json`](iam/decay-tracker-readonly-policy.json)
for the exact least-privilege policy. A tool meant to reduce attack surface
shouldn't expand it, so there is intentionally no write/delete capability
anywhere in this codebase — remediation (deleting/quarantining a zombie
asset) is a deliberate human action outside this tool's scope.

## Running scans on a schedule

[`\.github/workflows/scheduled-scan.yml`](.github/workflows/scheduled-scan.yml)
runs a weekly full-account scan via GitHub Actions OIDC (no long-lived AWS
keys stored in the repo), publishes the dashboard as a build artifact, and
fails the job on any CRITICAL finding. See the comments in that file and
[`iam/github-actions-trust-policy.example.json`](iam/github-actions-trust-policy.example.json)
for the one-time AWS-side setup.

## Development

```bash
pip install -e ".[dev,dns]"
pytest --cov=decay_tracker           # AWS calls are mocked via moto - no real creds needed
ruff check src tests
python scripts/demo_scan.py          # generates a sample dashboard from mocked data
```

AWS scanner tests use [`moto`](https://github.com/getmoto/moto) so the full
suite runs in CI with zero real AWS access.

## Project layout

```
src/decay_tracker/
  models.py              # shared Asset data model
  aws_session.py          # boto3 session/region helpers
  scanners/                # one file per resource type, common Scanner interface
  scoring/engine.py        # the decay scoring model
  storage/history.py       # snapshot persistence + run-to-run diffing
  report/html_report.py    # self-contained HTML dashboard generator
  cli.py                   # `decay-tracker` entry point
tests/                     # pytest + moto, mirrors src/ layout
iam/                        # least-privilege policies for running this tool
.github/workflows/          # CI + scheduled real-account scan
```

## Extending it

Adding a new resource type is one new file: subclass `Scanner`
(`scanners/base.py`), populate an `Asset`, wire it into `cli.py`. The scoring
engine and HTML report work on `Asset` and don't need to change.

## License

MIT — see [LICENSE](LICENSE).
