"""Data retention policy for event store cleanup.

Configurable retention periods per regulation:
  - 30 days  (default / internal)
  - 90 days  (SOC2)
  - 365 days (HIPAA / ISO 27001)

Usage:
    from agentguard.compliance.retention import RetentionPolicy

    policy = RetentionPolicy(days=90)
    deleted = policy.enforce(store)
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from agentguard.event_store import EventStore
from agentguard.logging import logger

RETENTION_PRESETS = {
    "default": 30,
    "soc2": 90,
    "hipaa": 365,
    "iso27001": 365,
}


class RetentionPolicy:
    """Configurable data retention policy.

    Attributes:
        days: Number of days to retain events.
        regulation: Regulation name for logging context.
    """

    def __init__(
        self,
        days: int | None = None,
        regulation: str = "default",
    ) -> None:
        if days is not None:
            self.days = days
        else:
            self.days = RETENTION_PRESETS.get(
                regulation,
                int(os.environ.get("AGENTGUARD_RETENTION_DAYS", "90")),
            )
        self.regulation = regulation

    @property
    def cutoff_date(self) -> datetime:
        """Return the cutoff datetime — events older than this should be purged."""
        return datetime.now(UTC) - timedelta(days=self.days)

    def count_expired(self, store: EventStore) -> int:
        """Count events older than the retention period.

        Args:
            store: The EventStore to check.

        Returns:
            Number of events that would be purged.
        """
        conn = store._get_conn()
        cutoff = self.cutoff_date.isoformat()
        row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff,)
        ).fetchone()
        return row[0] if row else 0

    def enforce(self, store: EventStore, dry_run: bool = False) -> dict[str, Any]:
        """Enforce the retention policy — purge expired events.

        NOTE: This is the ONLY operation that deletes events. It should
        be run by an admin after exporting audit evidence for the period.

        Args:
            store: The EventStore to purge.
            dry_run: If True, count but don't delete.

        Returns:
            Dict with deleted_count, cutoff_date, dry_run flag.
        """
        cutoff = self.cutoff_date.isoformat()
        expired_count = self.count_expired(store)

        if dry_run or expired_count == 0:
            return {
                "deleted_count": 0,
                "would_delete": expired_count,
                "cutoff_date": cutoff,
                "retention_days": self.days,
                "regulation": self.regulation,
                "dry_run": dry_run,
            }

        conn = store._get_conn()
        conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.commit()

        logger.bind(module="agentguard.compliance.retention").info(
            "Retention enforced: deleted {count} events older than {cutoff} ({days} days, {reg})",
            count=expired_count,
            cutoff=cutoff,
            days=self.days,
            reg=self.regulation,
        )

        return {
            "deleted_count": expired_count,
            "would_delete": 0,
            "cutoff_date": cutoff,
            "retention_days": self.days,
            "regulation": self.regulation,
            "dry_run": False,
        }

    def status(self, store: EventStore) -> dict[str, Any]:
        """Return retention policy status without modifying data."""
        return {
            "retention_days": self.days,
            "regulation": self.regulation,
            "cutoff_date": self.cutoff_date.isoformat(),
            "expired_events": self.count_expired(store),
            "total_events": store.get_event_count(),
        }
