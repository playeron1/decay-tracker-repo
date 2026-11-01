"""Explicit, auditable AWS remediation actions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class RemediationError(RuntimeError):
    """Raised when an action's safety preconditions are not met."""


class RemediationAction:
    action_id = "base"
    name = "Base remediation action"
    reversible = False

    def __init__(self, resource_type: str, resource_id: str, region: str | None = None):
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.region = region

    @property
    def parameters(self) -> dict[str, Any]:
        return {}

    def describe(self) -> str:
        return self.name

    def aws_calls(self) -> list[dict[str, Any]]:
        return []

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "parameters": self.parameters,
            "description": self.describe(),
            "reversible": self.reversible,
            "aws_calls": self.aws_calls(),
        }

    def _client(self, session, service: str):
        options = {"region_name": self.region} if self.region else {}
        return session.client(service, **options)

    def execute(self, session) -> dict[str, Any]:
        raise NotImplementedError

    def undo(self, session, record: dict[str, Any]) -> None:
        raise RemediationError(f"{self.name} does not support automatic undo")


class QuarantinePublicS3Bucket(RemediationAction):
    action_id = "quarantine_public_s3_bucket"
    name = "Quarantine public S3 bucket"
    reversible = True

    def __init__(self, bucket_name: str, region: str | None = None):
        super().__init__("s3_bucket", bucket_name, region)
        self.bucket_name = bucket_name

    @property
    def parameters(self) -> dict[str, Any]:
        return {"bucket_name": self.bucket_name}

    def describe(self) -> str:
        return (
            f"Enable all four bucket-level S3 Block Public Access controls on "
            f"{self.bucket_name}; this may interrupt intentional public access."
        )

    def aws_calls(self) -> list[dict[str, Any]]:
        return [
            {
                "service": "s3",
                "operation": "get_public_access_block",
                "parameters": {"Bucket": self.bucket_name},
                "purpose": "Capture the current setting for the undo record",
            },
            {
                "service": "s3",
                "operation": "put_public_access_block",
                "parameters": {
                    "Bucket": self.bucket_name,
                    "PublicAccessBlockConfiguration": PUBLIC_ACCESS_BLOCK,
                },
                "purpose": "Block public ACLs and public bucket policies",
            },
        ]

    def execute(self, session) -> dict[str, Any]:
        s3 = self._client(session, "s3")
        existed = True
        previous = None
        try:
            response = s3.get_public_access_block(Bucket=self.bucket_name)
            previous = response["PublicAccessBlockConfiguration"]
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code != "NoSuchPublicAccessBlockConfiguration":
                raise
            existed = False

        s3.put_public_access_block(
            Bucket=self.bucket_name,
            PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK,
        )
        return {
            "action_id": self.action_id,
            "resource_id": self.bucket_name,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "reversible": True,
            "undo": {
                "operation": "restore_s3_public_access_block",
                "bucket_name": self.bucket_name,
                "configuration_existed": existed,
                "previous_configuration": previous,
                "region": self.region,
            },
        }

    def undo(self, session, record: dict[str, Any]) -> None:
        undo = record.get("undo", record)
        s3 = self._client(session, "s3")
        if undo.get("configuration_existed"):
            s3.put_public_access_block(
                Bucket=undo["bucket_name"],
                PublicAccessBlockConfiguration=undo["previous_configuration"],
            )
        else:
            # DeletePublicAccessBlock is authorized by s3:PutBucketPublicAccessBlock.
            s3.delete_public_access_block(Bucket=undo["bucket_name"])


class DisableS3StaticWebsite(RemediationAction):
    action_id = "disable_s3_static_website"
    name = "Disable S3 static website hosting"
    reversible = True

    def __init__(self, bucket_name: str, region: str | None = None):
        super().__init__("s3_bucket", bucket_name, region)
        self.bucket_name = bucket_name

    @property
    def parameters(self) -> dict[str, Any]:
        return {"bucket_name": self.bucket_name}

    def describe(self) -> str:
        return f"Remove the static website configuration from {self.bucket_name}."

    def aws_calls(self) -> list[dict[str, Any]]:
        return [
            {
                "service": "s3",
                "operation": "get_bucket_website",
                "parameters": {"Bucket": self.bucket_name},
                "purpose": "Capture the current website configuration for undo",
            },
            {
                "service": "s3",
                "operation": "delete_bucket_website",
                "parameters": {"Bucket": self.bucket_name},
                "purpose": "Disable the bucket website endpoint",
            },
        ]

    def execute(self, session) -> dict[str, Any]:
        s3 = self._client(session, "s3")
        try:
            response = s3.get_bucket_website(Bucket=self.bucket_name)
            # ResponseMetadata is output-only and invalid in PutBucketWebsite.
            previous = {
                key: value for key, value in response.items()
                if key != "ResponseMetadata"
            }
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code == "NoSuchWebsiteConfiguration":
                raise RemediationError(
                    f"Bucket {self.bucket_name} no longer has website hosting enabled"
                ) from error
            raise

        s3.delete_bucket_website(Bucket=self.bucket_name)
        return {
            "action_id": self.action_id,
            "resource_id": self.bucket_name,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "reversible": True,
            "undo": {
                "operation": "restore_s3_website",
                "bucket_name": self.bucket_name,
                "website_configuration": previous,
                "region": self.region,
            },
        }

    def undo(self, session, record: dict[str, Any]) -> None:
        undo = record.get("undo", record)
        s3 = self._client(session, "s3")
        s3.put_bucket_website(
            Bucket=undo["bucket_name"],
            WebsiteConfiguration=undo["website_configuration"],
        )


class ReleaseUnassociatedElasticIP(RemediationAction):
    action_id = "release_unassociated_elastic_ip"
    name = "Release unassociated Elastic IP"
    reversible = False

    def __init__(
        self,
        allocation_id: str,
        public_ip: str | None = None,
        region: str | None = None,
    ):
        super().__init__("elastic_ip", public_ip or allocation_id, region)
        self.allocation_id = allocation_id
        self.public_ip = public_ip

    @property
    def parameters(self) -> dict[str, Any]:
        return {"allocation_id": self.allocation_id, "public_ip": self.public_ip}

    def describe(self) -> str:
        return (
            f"Release Elastic IP allocation {self.allocation_id} "
            f"({self.public_ip or 'public IP unknown'}). This cannot be reliably undone."
        )

    def aws_calls(self) -> list[dict[str, Any]]:
        return [
            {
                "service": "ec2",
                "operation": "describe_addresses",
                "parameters": {"AllocationIds": [self.allocation_id]},
                "purpose": "Re-check association immediately before release",
            },
            {
                "service": "ec2",
                "operation": "release_address",
                "parameters": {"AllocationId": self.allocation_id},
                "purpose": "Return the Elastic IP to the AWS address pool (irreversible)",
            },
        ]

    def execute(self, session) -> dict[str, Any]:
        ec2 = self._client(session, "ec2")
        response = ec2.describe_addresses(AllocationIds=[self.allocation_id])
        addresses = response.get("Addresses", [])
        if len(addresses) != 1:
            raise RemediationError(
                f"Allocation {self.allocation_id} was not found; refusing to release"
            )
        address = addresses[0]
        if any(
            address.get(key)
            for key in ("AssociationId", "InstanceId", "NetworkInterfaceId")
        ):
            raise RemediationError(
                f"Allocation {self.allocation_id} is now associated; refusing to release"
            )
        ec2.release_address(AllocationId=self.allocation_id)
        return {
            "action_id": self.action_id,
            "resource_id": self.resource_id,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "reversible": False,
            "undo": None,
            "note": "Released Elastic IPs may be allocated to another AWS customer.",
        }


class FlagForManualReview(RemediationAction):
    action_id = "flag_for_manual_review"
    name = "Flag for manual review"
    reversible = False

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        reason: str,
        region: str | None = None,
    ):
        super().__init__(resource_type, resource_id, region)
        self.reason = reason

    @property
    def parameters(self) -> dict[str, Any]:
        return {"reason": self.reason}

    def describe(self) -> str:
        return (
            f"No automatic change. Review {self.resource_type} "
            f"{self.resource_id}: {self.reason}"
        )


def action_from_plan(item: dict[str, Any]) -> RemediationAction:
    """Rehydrate a plan item into a known action; never evaluate plan code."""
    parameters = item.get("parameters") or {}
    action_id = item.get("action_id")
    region = item.get("region")
    if action_id == QuarantinePublicS3Bucket.action_id:
        return QuarantinePublicS3Bucket(parameters["bucket_name"], region)
    if action_id == DisableS3StaticWebsite.action_id:
        return DisableS3StaticWebsite(parameters["bucket_name"], region)
    if action_id == ReleaseUnassociatedElasticIP.action_id:
        return ReleaseUnassociatedElasticIP(
            parameters["allocation_id"], parameters.get("public_ip"), region
        )
    if action_id == FlagForManualReview.action_id:
        return FlagForManualReview(
            item["resource_type"],
            item["resource_id"],
            parameters.get("reason", "Owner verification required"),
            region,
        )
    raise RemediationError(f"Unknown remediation action: {action_id!r}")
