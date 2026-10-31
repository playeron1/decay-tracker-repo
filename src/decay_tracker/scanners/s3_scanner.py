"""S3 bucket scanner.

Finds buckets that are candidates for "forgotten but still serving":
  - still have public access (policy/ACL) despite no recent writes
  - have website hosting enabled (a common forgotten entry point)
  - no lifecycle/owner tags
  - last-modified object age used as an activity proxy (listing is capped
    to keep this cheap on large buckets)
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from decay_tracker.models import Asset, AssetType, Reachability
from decay_tracker.scanners.base import Scanner


class S3Scanner(Scanner):
    name = "s3"

    def __init__(self, session, account_id: str | None = None, sample_objects: int = 20):
        self.session = session
        self.account_id = account_id
        self.sample_objects = sample_objects
        self.s3 = session.client("s3")

    def _bucket_region(self, bucket: str) -> str | None:
        try:
            loc = self.s3.get_bucket_location(Bucket=bucket)["LocationConstraint"]
            return loc or "us-east-1"
        except Exception:
            return None

    def _last_object_activity(self, bucket: str) -> datetime | None:
        try:
            resp = self.s3.list_objects_v2(Bucket=bucket, MaxKeys=self.sample_objects)
            contents = resp.get("Contents", [])
            if not contents:
                return None
            return max(obj["LastModified"] for obj in contents)
        except Exception:
            return None

    def _is_public(self, bucket: str) -> tuple[bool, str]:
        try:
            pab = self.s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            blocked_all = all(pab.values())
            if blocked_all:
                return False, "Public access block fully enabled"
        except self.s3.exceptions.ClientError:
            pass  # no PAB config = not explicitly blocked
        except Exception:
            pass

        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    return True, f"ACL grants access to {uri.split('/')[-1]}"
        except Exception:
            pass

        try:
            policy_status = self.s3.get_bucket_policy_status(Bucket=bucket)
            if policy_status["PolicyStatus"]["IsPublic"]:
                return True, "Bucket policy marked public by AWS"
        except Exception:
            pass

        return False, "No public access detected"

    def _website_enabled(self, bucket: str) -> bool:
        try:
            self.s3.get_bucket_website(Bucket=bucket)
            return True
        except Exception:
            return False

    def _tags(self, bucket: str) -> dict[str, str]:
        try:
            resp = self.s3.get_bucket_tagging(Bucket=bucket)
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        except Exception:
            return {}

    def scan(self) -> Iterable[Asset]:
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except Exception as e:
            raise RuntimeError(f"Failed to list S3 buckets: {e}") from e

        for b in buckets:
            name = b["Name"]
            created_at = b.get("CreationDate")
            region = self._bucket_region(name)
            tags = self._tags(name)
            is_public, public_detail = self._is_public(name)
            website = self._website_enabled(name)
            last_activity = self._last_object_activity(name)

            reachability = Reachability.UNKNOWN
            probe_detail = public_detail
            if website:
                # a website-enabled bucket is a live HTTP entry point by design
                reachability = Reachability.RESPONSIVE if is_public else Reachability.RESPONSIVE_ERROR
                probe_detail = f"Static website hosting enabled; {public_detail}"
            elif is_public:
                reachability = Reachability.RESPONSIVE

            asset = Asset(
                asset_type=AssetType.S3_BUCKET,
                identifier=name,
                region=region,
                account_id=self.account_id,
                created_at=created_at,
                last_activity_at=last_activity,
                owner_tag=tags.get("Owner") or tags.get("owner"),
                project_tag=tags.get("Project") or tags.get("project"),
                tags=tags,
                reachability=reachability,
                probe_detail=probe_detail,
                publicly_accessible=is_public,
                raw={"website_enabled": website},
            )
            asset.add_evidence("s3:list_buckets", f"Created {created_at}")
            asset.add_evidence("s3:public-check", public_detail)
            if website:
                asset.add_evidence("s3:website", "Static website hosting is enabled")
            if last_activity:
                asset.add_evidence("s3:object-sample", f"Most recent sampled object modified {last_activity}")
            else:
                asset.add_evidence("s3:object-sample", "No objects found in sample (bucket may be empty)")

            yield asset
