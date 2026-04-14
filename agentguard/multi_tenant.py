"""Multi-tenant organization isolation for SaaS deployment.

Each tenant (organization) gets isolated event storage, policy
configuration, and usage tracking. Tenant context is derived from
JWT claims and propagated through the request lifecycle.

Isolation model: schema-per-tenant prefix on event store tables.
In SQLite: separate database file per tenant.
In PostgreSQL: schema-per-tenant (CREATE SCHEMA tenant_xxx).

Usage:
    from agentguard.multi_tenant import TenantManager

    tm = TenantManager()
    tenant = tm.create_tenant(name="Acme Corp", admin_email="admin@acme.com")
    store = tm.get_tenant_store(tenant.tenant_id)
"""

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentguard.event_store import EventStore
from agentguard.logging import logger

# ── Models ───────────────────────────────────────────────────────────


class Tenant(BaseModel):
    """A tenant organization in the multi-tenant SaaS."""

    tenant_id: str = Field(description="Unique tenant identifier (8-char hex)")
    name: str = Field(description="Organization name")
    admin_email: str = Field(default="", description="Primary admin email")
    plan: str = Field(
        default="free", description="Billing plan: free | pro | enterprise"
    )
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    status: str = Field(default="active", description="active | suspended | deleted")
    settings: dict[str, Any] = Field(
        default_factory=lambda: {
            "policy_path": "policies/default.yaml",
            "dlp_sensitivity": "MEDIUM",
            "injection_sensitivity": "MEDIUM",
            "retention_days": 90,
            "max_events_per_day": 10000,
        }
    )


class TenantUsage(BaseModel):
    """Usage metrics for billing."""

    tenant_id: str
    period: str = Field(description="Billing period (YYYY-MM)")
    event_count: int = Field(default=0)
    api_calls: int = Field(default=0)
    storage_bytes: int = Field(default=0)
    agents_registered: int = Field(default=0)
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# ── Manager ──────────────────────────────────────────────────────────


class TenantManager:
    """Manages multi-tenant organizations, stores, and billing.

    Attributes:
        base_path: Base directory for tenant SQLite databases.
    """

    def __init__(self, base_path: str | None = None) -> None:
        self.base_path = base_path or os.environ.get(
            "AGENTGUARD_TENANT_DB_PATH", "data/tenants"
        )
        self._tenants: dict[str, Tenant] = {}
        self._stores: dict[str, EventStore] = {}
        self._usage: dict[str, TenantUsage] = {}

    def create_tenant(
        self,
        name: str,
        admin_email: str = "",
        plan: str = "free",
        settings: dict[str, Any] | None = None,
    ) -> Tenant:
        """Create a new tenant organization.

        Args:
            name: Organization name.
            admin_email: Admin email address.
            plan: Billing plan (free/pro/enterprise).
            settings: Custom tenant settings (overrides defaults).

        Returns:
            The created Tenant.
        """
        tenant_id = secrets.token_hex(4)  # 8-char hex

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            admin_email=admin_email,
            plan=plan,
        )
        if settings:
            tenant.settings.update(settings)

        self._tenants[tenant_id] = tenant

        # Initialize tenant storage
        self._init_tenant_store(tenant_id)

        # Initialize billing
        period = datetime.now(UTC).strftime("%Y-%m")
        self._usage[tenant_id] = TenantUsage(tenant_id=tenant_id, period=period)

        logger.bind(module="agentguard.multi_tenant").info(
            "Tenant created: {name} ({tenant_id}) plan={plan}",
            name=name,
            tenant_id=tenant_id,
            plan=plan,
        )

        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        return list(self._tenants.values())

    def update_tenant(self, tenant_id: str, **updates: Any) -> Tenant | None:
        """Update tenant fields."""
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return None
        for key, val in updates.items():
            if hasattr(tenant, key):
                setattr(tenant, key, val)
        return tenant

    def suspend_tenant(self, tenant_id: str) -> bool:
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return False
        tenant.status = "suspended"
        return True

    def delete_tenant(self, tenant_id: str) -> bool:
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return False
        tenant.status = "deleted"
        # Close the store
        if tenant_id in self._stores:
            self._stores[tenant_id].close()
            del self._stores[tenant_id]
        return True

    # ── Tenant Stores ────────────────────────────────────────────

    def _init_tenant_store(self, tenant_id: str) -> EventStore:
        """Create an isolated EventStore for a tenant."""
        db_dir = Path(self.base_path)
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(db_dir / f"{tenant_id}.db")
        store = EventStore(db_path=db_path)
        self._stores[tenant_id] = store
        return store

    def get_tenant_store(self, tenant_id: str) -> EventStore | None:
        """Get the isolated EventStore for a tenant."""
        if tenant_id in self._stores:
            return self._stores[tenant_id]
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            return None
        return self._init_tenant_store(tenant_id)

    # ── Billing / Usage ──────────────────────────────────────────

    def record_usage(
        self,
        tenant_id: str,
        events: int = 0,
        api_calls: int = 0,
        storage_bytes: int = 0,
    ) -> None:
        """Record usage metrics for billing."""
        usage = self._usage.get(tenant_id)
        if usage is None:
            period = datetime.now(UTC).strftime("%Y-%m")
            usage = TenantUsage(tenant_id=tenant_id, period=period)
            self._usage[tenant_id] = usage

        usage.event_count += events
        usage.api_calls += api_calls
        usage.storage_bytes += storage_bytes
        usage.last_updated = datetime.now(UTC).isoformat()

    def get_usage(self, tenant_id: str) -> TenantUsage | None:
        return self._usage.get(tenant_id)

    def get_all_usage(self) -> list[TenantUsage]:
        return list(self._usage.values())

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        return {
            "total_tenants": len(self._tenants),
            "active_tenants": sum(
                1 for t in self._tenants.values() if t.status == "active"
            ),
            "total_events": sum(u.event_count for u in self._usage.values()),
            "total_api_calls": sum(u.api_calls for u in self._usage.values()),
        }
