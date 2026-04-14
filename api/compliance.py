"""Compliance report API endpoints.

Provides auto-generated compliance reports for SOC2, HIPAA, and ISO 27001,
plus data retention policy management. Admin + auditor roles only.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from agentguard.compliance.reports import ComplianceReporter
from agentguard.compliance.retention import RetentionPolicy
from api.auth import TokenPayload, require_role

router = APIRouter(prefix="/compliance", tags=["Compliance"])


def _get_store():
    """Import store lazily to avoid circular imports."""
    from api.main import get_store

    return get_store()


@router.get("/soc2")
def soc2_report(
    _user: Annotated[TokenPayload, Depends(require_role("admin", "auditor"))] = None,
) -> dict[str, Any]:
    """Generate SOC2 CC6 compliance report with auto-populated data."""
    store = _get_store()
    reporter = ComplianceReporter(store)
    return reporter.generate_soc2_cc6()


@router.get("/hipaa")
def hipaa_report(
    _user: Annotated[TokenPayload, Depends(require_role("admin", "auditor"))] = None,
) -> dict[str, Any]:
    """Generate HIPAA §164.312 compliance report."""
    store = _get_store()
    reporter = ComplianceReporter(store)
    return reporter.generate_hipaa_164_312()


@router.get("/iso27001")
def iso27001_report(
    _user: Annotated[TokenPayload, Depends(require_role("admin", "auditor"))] = None,
) -> dict[str, Any]:
    """Generate ISO 27001 A.12.4 compliance report."""
    store = _get_store()
    reporter = ComplianceReporter(store)
    return reporter.generate_iso27001_a12_4()


@router.get("/retention/status")
def retention_status(
    regulation: str = Query(default="default", regex="^(default|soc2|hipaa|iso27001)$"),
    _user: Annotated[TokenPayload, Depends(require_role("admin", "auditor"))] = None,
) -> dict[str, Any]:
    """Check data retention policy status."""
    store = _get_store()
    policy = RetentionPolicy(regulation=regulation)
    return policy.status(store)


@router.post("/retention/enforce")
def enforce_retention(
    regulation: str = Query(default="default", regex="^(default|soc2|hipaa|iso27001)$"),
    dry_run: bool = Query(default=True),
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Enforce data retention — purge expired events. Admin only.

    Set dry_run=false to actually delete events.
    """
    store = _get_store()
    policy = RetentionPolicy(regulation=regulation)
    return policy.enforce(store, dry_run=dry_run)
