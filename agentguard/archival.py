"""S3/GCS audit archival — nightly export of events to immutable cloud storage.

Exports audit chain events to S3 or GCS as JSON files, organized by
date. Files are immutable once written (set via bucket lifecycle policy).

Supports:
  - AWS S3 (via boto3)
  - Google Cloud Storage (via google-cloud-storage)
  - Local filesystem (for testing)

Usage:
    from agentguard.archival import AuditArchiver

    archiver = AuditArchiver(backend="s3", bucket="my-audit-bucket")
    result = archiver.archive(store)
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentguard.event_store import EventStore
from agentguard.logging import logger


class AuditArchiver:
    """Archives audit events to immutable cloud storage.

    Attributes:
        backend: 's3' | 'gcs' | 'local'
        bucket: Bucket name (S3/GCS) or directory path (local).
        prefix: Key prefix for archived files.
    """

    def __init__(
        self,
        backend: str | None = None,
        bucket: str | None = None,
        prefix: str = "agentguard/audit",
        region: str | None = None,
    ) -> None:
        self.backend = backend or os.environ.get("AGENTGUARD_ARCHIVAL_BACKEND", "local")
        self.bucket = bucket or os.environ.get(
            "AGENTGUARD_ARCHIVAL_BUCKET", "audit-archive"
        )
        self.prefix = prefix
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    def archive(self, store: EventStore, batch_size: int = 5000) -> dict[str, Any]:
        """Archive all events from the store to cloud storage.

        Events are exported as a single JSON file per archive run,
        named by timestamp. Includes audit chain verification result.

        Args:
            store: EventStore to archive from.
            batch_size: Maximum events per archive file.

        Returns:
            Dict with status, event_count, file_key, backend.
        """
        events = store.get_events(limit=batch_size)
        if not events:
            return {
                "status": "skipped",
                "reason": "No events to archive",
                "event_count": 0,
            }

        # Include chain verification in archive
        chain_result = store.verify_chain()

        archive_data = {
            "archived_at": datetime.now(UTC).isoformat(),
            "event_count": len(events),
            "chain_verification": chain_result,
            "events": events,
        }

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S")
        file_key = f"{self.prefix}/{timestamp}.json"
        content = json.dumps(archive_data, indent=2, default=str)

        if self.backend == "s3":
            return self._upload_s3(file_key, content, len(events))
        if self.backend == "gcs":
            return self._upload_gcs(file_key, content, len(events))
        return self._save_local(file_key, content, len(events))

    def _save_local(
        self, file_key: str, content: str, event_count: int
    ) -> dict[str, Any]:
        """Save archive to local filesystem."""
        path = Path(self.bucket) / file_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        logger.bind(module="agentguard.archival").info(
            "Archived {count} events to local: {path}",
            count=event_count,
            path=str(path),
        )

        return {
            "status": "archived",
            "backend": "local",
            "event_count": event_count,
            "file_path": str(path),
        }

    def _upload_s3(
        self, file_key: str, content: str, event_count: int
    ) -> dict[str, Any]:
        """Upload archive to AWS S3."""
        try:
            import boto3

            s3 = boto3.client("s3", region_name=self.region)
            s3.put_object(
                Bucket=self.bucket,
                Key=file_key,
                Body=content.encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )

            logger.bind(module="agentguard.archival").info(
                "Archived {count} events to s3://{bucket}/{key}",
                count=event_count,
                bucket=self.bucket,
                key=file_key,
            )

            return {
                "status": "archived",
                "backend": "s3",
                "event_count": event_count,
                "bucket": self.bucket,
                "key": file_key,
            }

        except Exception as e:
            logger.opt(exception=True).warning(
                "S3 archival failed: {error}", error=str(e)
            )
            return {"status": "error", "backend": "s3", "error": str(e)}

    def _upload_gcs(
        self, file_key: str, content: str, event_count: int
    ) -> dict[str, Any]:
        """Upload archive to Google Cloud Storage."""
        try:
            from google.cloud import storage

            client = storage.Client()
            bucket = client.bucket(self.bucket)
            blob = bucket.blob(file_key)
            blob.upload_from_string(content, content_type="application/json")

            logger.bind(module="agentguard.archival").info(
                "Archived {count} events to gs://{bucket}/{key}",
                count=event_count,
                bucket=self.bucket,
                key=file_key,
            )

            return {
                "status": "archived",
                "backend": "gcs",
                "event_count": event_count,
                "bucket": self.bucket,
                "key": file_key,
            }

        except Exception as e:
            logger.opt(exception=True).warning(
                "GCS archival failed: {error}", error=str(e)
            )
            return {"status": "error", "backend": "gcs", "error": str(e)}
