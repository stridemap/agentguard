"""Compliance report generators — SOC2 CC6, HIPAA §164.312, ISO 27001 A.12.4.

Auto-populates report templates with data from the EventStore and
audit chain. Generates JSON reports that can be exported to PDF
or submitted to auditors.

Usage:
    from agentguard.compliance.reports import ComplianceReporter

    reporter = ComplianceReporter(store)
    soc2 = reporter.generate_soc2_cc6()
    hipaa = reporter.generate_hipaa_164_312()
    iso = reporter.generate_iso27001_a12_4()
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from agentguard.event_store import EventStore


class ComplianceReporter:
    """Generates compliance reports from EventStore data.

    Attributes:
        store: The EventStore to pull data from.
    """

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def _get_summary(self) -> dict[str, Any]:
        """Compute common summary metrics from the store."""
        events = self.store.get_events(limit=10000)
        total = len(events)
        blocked = sum(1 for e in events if e.get("policy_result") == "BLOCK")
        alerted = sum(1 for e in events if e.get("policy_result") == "ALERT")
        allowed = sum(1 for e in events if e.get("policy_result") == "ALLOW")

        risk_events = 0
        for e in events:
            flags = e.get("risk_flags", "[]")
            try:
                parsed = json.loads(flags) if isinstance(flags, str) else flags
                if parsed:
                    risk_events += 1
            except (json.JSONDecodeError, TypeError):
                pass

        chain = self.store.verify_chain()
        agents = list({e.get("agent_id", "") for e in events})
        tools = list({e.get("tool_name", "") for e in events})

        return {
            "report_generated_at": datetime.now(UTC).isoformat(),
            "total_events": total,
            "policy_blocked": blocked,
            "policy_alerted": alerted,
            "policy_allowed": allowed,
            "risk_flagged_events": risk_events,
            "audit_chain_valid": chain["is_valid"],
            "audit_chain_events": chain["total_events"],
            "unique_agents": agents,
            "unique_tools": tools,
        }

    def generate_soc2_cc6(self) -> dict[str, Any]:
        """Generate SOC2 CC6 — Logical Access Controls report.

        Covers:
          CC6.1 — Logical access security software, infrastructure, and architectures
          CC6.6 — Restricting access to system boundaries
          CC6.8 — Preventing unauthorized access

        Returns:
            JSON-serializable compliance report dict.
        """
        summary = self._get_summary()

        return {
            "report_type": "SOC2 CC6 — Logical Access Controls",
            "framework": "AICPA SOC 2 Type II",
            "generated_at": summary["report_generated_at"],
            "organization": "Stridemap / AgentGuard",
            "controls": {
                "CC6.1": {
                    "title": "Logical Access Security",
                    "description": "AgentGuard implements role-based access control (RBAC) "
                    "with JWT authentication for all API endpoints. Three roles "
                    "(admin, analyst, auditor) restrict access to system functions.",
                    "evidence": {
                        "auth_mechanism": "JWT Bearer tokens (HS256, 30-min expiry)",
                        "roles_defined": ["admin", "analyst", "auditor"],
                        "rate_limiting": "100 requests/minute per role",
                        "sso_supported": "OIDC (Okta, Azure AD, Google)",
                    },
                    "status": "IMPLEMENTED",
                },
                "CC6.6": {
                    "title": "System Boundaries",
                    "description": "All AI agent tool calls are intercepted at the "
                    "LangGraph callback layer. Policy rules enforce ALLOW/BLOCK/ALERT "
                    "decisions at the system boundary before tool execution.",
                    "evidence": {
                        "total_events_monitored": summary["total_events"],
                        "events_blocked": summary["policy_blocked"],
                        "events_alerted": summary["policy_alerted"],
                        "unique_agents_governed": len(summary["unique_agents"]),
                        "unique_tools_monitored": len(summary["unique_tools"]),
                    },
                    "status": "IMPLEMENTED",
                },
                "CC6.8": {
                    "title": "Unauthorized Access Prevention",
                    "description": "DLP scanning detects PII in tool inputs/outputs. "
                    "Prompt injection detection (21 regex patterns + LLM classifier) "
                    "identifies and blocks injection attacks. Unknown tools are flagged.",
                    "evidence": {
                        "risk_flagged_events": summary["risk_flagged_events"],
                        "audit_chain_integrity": summary["audit_chain_valid"],
                        "audit_chain_events": summary["audit_chain_events"],
                        "dlp_scanning": "Microsoft Presidio (15+ PII entity types, 100% local)",
                        "injection_detection": "Two-stage (regex + LLM, precision >= 0.90)",
                    },
                    "status": "IMPLEMENTED",
                },
            },
            "summary": summary,
        }

    def generate_hipaa_164_312(self) -> dict[str, Any]:
        """Generate HIPAA §164.312 — Technical Safeguards report.

        Covers:
          §164.312(a) — Access control
          §164.312(b) — Audit controls
          §164.312(c) — Integrity controls
          §164.312(d) — Person or entity authentication
          §164.312(e) — Transmission security

        Returns:
            JSON-serializable compliance report dict.
        """
        summary = self._get_summary()

        return {
            "report_type": "HIPAA §164.312 — Technical Safeguards",
            "framework": "HIPAA Security Rule",
            "generated_at": summary["report_generated_at"],
            "organization": "Stridemap / AgentGuard",
            "safeguards": {
                "164.312(a)": {
                    "title": "Access Control",
                    "requirement": "Implement technical policies to allow access only to "
                    "authorized persons or software programs.",
                    "implementation": "RBAC with JWT tokens. Row-level tenant isolation "
                    "ensures users see only events for their assigned agent_ids.",
                    "evidence": {
                        "access_control_mechanism": "JWT RBAC (admin/analyst/auditor)",
                        "tenant_isolation": "Row-level filtering by agent_id",
                    },
                    "status": "IMPLEMENTED",
                },
                "164.312(b)": {
                    "title": "Audit Controls",
                    "requirement": "Implement mechanisms to record and examine activity.",
                    "implementation": "Every AI agent tool call is captured as a structured "
                    "event with SHA-256 cryptographic chaining. Tamper-evident audit "
                    "chain detects any modification to historical records.",
                    "evidence": {
                        "total_events_logged": summary["total_events"],
                        "audit_chain_algorithm": "SHA-256",
                        "audit_chain_valid": summary["audit_chain_valid"],
                        "tamper_detection": "verify_chain() detects any single-byte modification",
                    },
                    "status": "IMPLEMENTED",
                },
                "164.312(c)": {
                    "title": "Integrity Controls",
                    "requirement": "Protect ePHI from improper alteration or destruction.",
                    "implementation": "Append-only event store (no UPDATE/DELETE). DLP scanner "
                    "detects PHI in agent tool calls and blocks exfiltration via policy rules.",
                    "evidence": {
                        "store_design": "Append-only (INSERT OR IGNORE)",
                        "phi_detection": "Microsoft Presidio (SSN, medical license, DOB)",
                        "phi_events_blocked": summary["policy_blocked"],
                    },
                    "status": "IMPLEMENTED",
                },
                "164.312(d)": {
                    "title": "Person or Entity Authentication",
                    "requirement": "Verify the identity of persons seeking access to ePHI.",
                    "implementation": "API key + JWT token exchange. SSO via OIDC (Okta, Azure AD). "
                    "Refresh tokens with configurable TTL (default 7 days).",
                    "evidence": {
                        "auth_methods": ["API key → JWT", "OIDC SSO"],
                        "token_expiry": "30 minutes (JWT), 7 days (refresh)",
                    },
                    "status": "IMPLEMENTED",
                },
                "164.312(e)": {
                    "title": "Transmission Security",
                    "requirement": "Guard against unauthorized access to ePHI during transmission.",
                    "implementation": "All API endpoints served over HTTPS (TLS). DLP scanning "
                    "runs 100% locally — zero PHI transmitted to external services.",
                    "evidence": {
                        "encryption": "TLS 1.2+ (enforced at ingress/load balancer)",
                        "dlp_data_egress": "Zero — Presidio runs locally",
                    },
                    "status": "IMPLEMENTED",
                },
            },
            "summary": summary,
        }

    def generate_iso27001_a12_4(self) -> dict[str, Any]:
        """Generate ISO 27001 Annex A.12.4 — Logging and Monitoring report.

        Covers:
          A.12.4.1 — Event logging
          A.12.4.2 — Protection of log information
          A.12.4.3 — Administrator and operator logs
          A.12.4.4 — Clock synchronization

        Returns:
            JSON-serializable compliance report dict.
        """
        summary = self._get_summary()

        return {
            "report_type": "ISO 27001 Annex A.12.4 — Logging and Monitoring",
            "framework": "ISO/IEC 27001:2022",
            "generated_at": summary["report_generated_at"],
            "organization": "Stridemap / AgentGuard",
            "controls": {
                "A.12.4.1": {
                    "title": "Event Logging",
                    "requirement": "Event logs shall be produced, kept, and regularly reviewed.",
                    "implementation": "Every AI agent tool call produces a structured event "
                    "with Loguru JSON logging. Events stored in append-only SQLite/PostgreSQL.",
                    "evidence": {
                        "total_events_logged": summary["total_events"],
                        "log_format": "Structured JSON (Loguru)",
                        "event_fields": [
                            "event_id",
                            "timestamp",
                            "agent_id",
                            "tool_name",
                            "input_hash",
                            "output_hash",
                            "latency_ms",
                            "risk_flags",
                            "policy_result",
                        ],
                    },
                    "status": "IMPLEMENTED",
                },
                "A.12.4.2": {
                    "title": "Protection of Log Information",
                    "requirement": "Logging facilities and log information shall be protected.",
                    "implementation": "SHA-256 cryptographic audit chain. Each event hash "
                    "includes the previous event hash — any tampering is detectable.",
                    "evidence": {
                        "integrity_mechanism": "SHA-256 cryptographic chaining",
                        "chain_valid": summary["audit_chain_valid"],
                        "chain_events": summary["audit_chain_events"],
                        "store_design": "Append-only (no UPDATE/DELETE API)",
                    },
                    "status": "IMPLEMENTED",
                },
                "A.12.4.3": {
                    "title": "Administrator and Operator Logs",
                    "requirement": "Activities of system administrators and operators shall be logged.",
                    "implementation": "All API calls authenticated via JWT. Policy reload "
                    "operations restricted to admin role and logged.",
                    "evidence": {
                        "admin_actions_logged": "Policy reload, chain verification, export",
                        "rbac_roles": ["admin", "analyst", "auditor"],
                    },
                    "status": "IMPLEMENTED",
                },
                "A.12.4.4": {
                    "title": "Clock Synchronization",
                    "requirement": "Clocks of all relevant systems shall be synchronized.",
                    "implementation": "All event timestamps use UTC ISO 8601 format. "
                    "Server time synchronization via NTP (infrastructure level).",
                    "evidence": {
                        "timestamp_format": "ISO 8601 UTC",
                        "synchronization": "NTP (infrastructure responsibility)",
                    },
                    "status": "IMPLEMENTED",
                },
            },
            "summary": summary,
        }
