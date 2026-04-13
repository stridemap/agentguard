"""Finance scenario: 3-agent system with AgentGuard interceptor.

Demonstrates AgentGuard monitoring a realistic 3-agent financial workflow:

  EmailReaderAgent  →  reads incoming client emails
  CRMLookupAgent   →  queries CRM for customer records
  ResponseWriter   →  drafts and sends response emails

Key points:
  - AgentGuard injected via config={"callbacks": [...]} — ZERO agent code changes
  - Mock tool outputs contain real PII patterns (SSN, email, phone, credit card)
  - All tool calls captured, risk-flagged, and persisted to SQLite
  - Runnable standalone: python -m demo.finance_scenario

Sprint 2 deliverable — screen recording shows interceptor + dashboard in action.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

from langchain_core.callbacks import CallbackManager
from langchain_core.tools import tool

# ── Ensure project root is on sys.path for standalone execution ──────
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agentguard import AgentGuardInterceptor  # noqa: E402
from agentguard.models import InterceptorConfig  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════
# MOCK TOOLS — realistic financial operations with PII in responses
# ═══════════════════════════════════════════════════════════════════════


@tool
def read_email(email_id: str) -> str:
    """Read an incoming client email from the inbox."""
    emails = {
        "EM-1001": (
            "From: john.martinez@acmecorp.com\n"
            "Subject: Account Balance Inquiry\n\n"
            "Hi, I need to verify the balance on my account ending in 4829.\n"
            "My SSN for verification is 421-83-7219.\n"
            "Please respond ASAP.\n"
            "Thanks, John Martinez\n"
            "Phone: (415) 555-0142"
        ),
        "EM-1002": (
            "From: sarah.chen@globaltrade.io\n"
            "Subject: Wire Transfer Request\n\n"
            "Please initiate a wire transfer of $45,000 to:\n"
            "Account: 8827-3341-0092\n"
            "Routing: 021000021\n"
            "Recipient: Offshore Holdings LLC\n"
            "My authorization code: AUTH-X9912\n"
            "DOB for verification: 03/15/1988"
        ),
        "EM-1003": (
            "From: mike.johnson@internal.company.com\n"
            "Subject: Quarterly Report\n\n"
            "Attached is the Q1 revenue summary.\n"
            "Total revenue: $2.4M, up 18% YoY.\n"
            "No action needed."
        ),
    }
    return emails.get(email_id, f"Email {email_id} not found.")


@tool
def query_crm(customer_email: str) -> str:
    """Look up customer record in the CRM system."""
    records = {
        "john.martinez@acmecorp.com": (
            "Customer: John Martinez\n"
            "Email: john.martinez@acmecorp.com\n"
            "Phone: (415) 555-0142\n"
            "SSN: 421-83-7219\n"
            "Account: ****-****-****-4829\n"
            "Balance: $127,849.32\n"
            "Credit Card: 4532-8721-0093-4829\n"
            "Status: Active | Tier: Platinum\n"
            "Address: 742 Evergreen Terrace, San Francisco, CA 94110"
        ),
        "sarah.chen@globaltrade.io": (
            "Customer: Sarah Chen\n"
            "Email: sarah.chen@globaltrade.io\n"
            "Phone: (650) 555-0198\n"
            "SSN: 539-22-8814\n"
            "Account: ****-****-****-3341\n"
            "Balance: $89,221.07\n"
            "Credit Card: 5425-1100-8839-3341\n"
            "Status: Active | Tier: Gold\n"
            "Risk Flag: HIGH — recent large transfer requests"
        ),
    }
    return records.get(customer_email, f"No CRM record for {customer_email}")


@tool
def lookup_contact(name: str) -> str:
    """Look up internal contact information."""
    contacts = {
        "John Martinez": "john.martinez@acmecorp.com | (415) 555-0142",
        "Sarah Chen": "sarah.chen@globaltrade.io | (650) 555-0198",
        "Compliance Team": "compliance@internal.company.com | ext. 4401",
    }
    return contacts.get(name, f"Contact '{name}' not found in directory.")


@tool
def write_response(to: str, subject: str, body: str) -> str:
    """Draft a response email."""
    return (
        f"DRAFT CREATED\n"
        f"To: {to}\n"
        f"Subject: Re: {subject}\n"
        f"Body:\n{body}\n"
        f"---\nStatus: Awaiting review before send"
    )


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to an external recipient."""
    return f"EMAIL SENT to {to} | Subject: {subject} | {len(body)} chars"


# ═══════════════════════════════════════════════════════════════════════
# MOCK AGENTS — simulate tool calls as a real LangGraph agent would
# ═══════════════════════════════════════════════════════════════════════


def _header(text: str) -> None:
    """Print a section header."""
    width = 64
    sys.stdout.write(f"\n{'=' * width}\n")
    sys.stdout.write(f"  {text}\n")
    sys.stdout.write(f"{'=' * width}\n\n")


def _step(agent: str, action: str) -> None:
    """Print a step marker."""
    sys.stdout.write(f"  [{agent}] {action}\n")


def _result(text: str) -> None:
    """Print a truncated result."""
    preview = text[:120].replace("\n", " | ")
    if len(text) > 120:
        preview += "..."
    sys.stdout.write(f"    -> {preview}\n")


def run_email_reader_agent(callback_manager: CallbackManager) -> dict:
    """EmailReaderAgent: reads 3 emails and extracts key data.

    Uses read_email tool — the AgentGuard interceptor captures every call
    via the callback_manager without any changes to this function.
    """
    _header("Agent 1: EmailReaderAgent")

    results = {}
    for email_id in ["EM-1001", "EM-1002", "EM-1003"]:
        _step("EmailReader", f"Reading {email_id}")
        content = read_email.invoke(
            {"email_id": email_id},
            config={"callbacks": callback_manager},
        )
        results[email_id] = content
        _result(content)
        time.sleep(0.05)

    return results


def run_crm_lookup_agent(emails: dict, callback_manager: CallbackManager) -> dict:
    """CRMLookupAgent: looks up customer records for external senders.

    Uses query_crm and lookup_contact tools — interceptor captures all
    calls including the PII-laden CRM responses.
    """
    _header("Agent 2: CRMLookupAgent")

    records = {}
    external_senders = [
        "john.martinez@acmecorp.com",
        "sarah.chen@globaltrade.io",
    ]

    for sender in external_senders:
        _step("CRMLookup", f"Querying CRM for {sender}")
        record = query_crm.invoke(
            {"customer_email": sender},
            config={"callbacks": callback_manager},
        )
        records[sender] = record
        _result(record)
        time.sleep(0.05)

    # Also look up the compliance team contact
    _step("CRMLookup", "Looking up Compliance Team contact")
    contact = lookup_contact.invoke(
        {"name": "Compliance Team"},
        config={"callbacks": callback_manager},
    )
    records["compliance"] = contact
    _result(contact)

    return records


def run_response_writer_agent(records: dict, callback_manager: CallbackManager) -> None:
    """ResponseWriterAgent: drafts and sends response emails.

    Uses write_response and send_email tools. The send_email to an
    external domain will be flagged by AgentGuard's risk detection.
    """
    _header("Agent 3: ResponseWriterAgent")

    # Draft response to John (contains account balance — no PII leak)
    _step("ResponseWriter", "Drafting response to John Martinez")
    draft = write_response.invoke(
        {
            "to": "john.martinez@acmecorp.com",
            "subject": "Account Balance Inquiry",
            "body": (
                "Dear John,\n\n"
                "Your account ending in 4829 has a current balance of $127,849.32.\n"
                "For security, we cannot confirm SSN details via email.\n\n"
                "Best regards,\nFinance Team"
            ),
        },
        config={"callbacks": callback_manager},
    )
    _result(draft)
    time.sleep(0.05)

    # Send the response (external domain — will be risk-flagged)
    _step("ResponseWriter", "Sending response to john.martinez@acmecorp.com")
    result = send_email.invoke(
        {
            "to": "john.martinez@acmecorp.com",
            "subject": "Re: Account Balance Inquiry",
            "body": "Your account balance is $127,849.32. Thank you.",
        },
        config={"callbacks": callback_manager},
    )
    _result(result)
    time.sleep(0.05)

    # Flag Sarah's wire transfer for compliance review
    _step("ResponseWriter", "Escalating Sarah Chen's wire transfer to compliance")
    escalation = send_email.invoke(
        {
            "to": "compliance@internal.company.com",
            "subject": "REVIEW: Wire Transfer Request - Sarah Chen",
            "body": (
                "Sarah Chen (sarah.chen@globaltrade.io) requested a $45,000 wire "
                "transfer to Offshore Holdings LLC.\n"
                "Account: 8827-3341-0092 | Routing: 021000021\n"
                "Customer SSN: 539-22-8814\n"
                "Risk flag: HIGH — please review before processing."
            ),
        },
        config={"callbacks": callback_manager},
    )
    _result(escalation)


# ═══════════════════════════════════════════════════════════════════════
# SCENARIO RUNNER
# ═══════════════════════════════════════════════════════════════════════


def run_scenario(db_path: str | None = None) -> AgentGuardInterceptor:
    """Run the 3-agent finance scenario with AgentGuard monitoring.

    Args:
        db_path: Optional SQLite path for event persistence.
            If None, uses a temporary file.

    Returns:
        The interceptor instance (for inspection in tests or dashboard).
    """
    if db_path is None:
        db_path = str(Path(tempfile.mkdtemp()) / "finance_demo.db")

    # ── Create interceptor (the ONLY AgentGuard setup needed) ────
    interceptor = AgentGuardInterceptor(
        config=InterceptorConfig(
            agent_id="finance-system",
            session_id="demo-session-001",
            internal_domains=["internal.company.com"],
            known_tools=[
                "read_email",
                "query_crm",
                "lookup_contact",
                "write_response",
                "send_email",
            ],
            sensitive_keywords=[
                "ssn",
                "credit card",
                "password",
                "secret",
                "routing",
                "authorization code",
            ],
        ),
        db_path=db_path,
    )
    callback_manager = CallbackManager([interceptor])

    sys.stdout.write("\n")
    sys.stdout.write(
        "  AgentGuard Finance Demo\n"
        "  3-agent system: EmailReader -> CRMLookup -> ResponseWriter\n"
        f"  Events persisted to: {db_path}\n"
    )

    # ── Run the 3 agents in sequence ─────────────────────────────
    emails = run_email_reader_agent(callback_manager)
    records = run_crm_lookup_agent(emails, callback_manager)
    run_response_writer_agent(records, callback_manager)

    # ── Wait for queue to flush ──────────────────────────────────
    time.sleep(0.5)

    # ── Print summary ────────────────────────────────────────────
    _header("AgentGuard Event Summary")

    events = interceptor.get_events()
    sys.stdout.write(f"  Total events captured: {len(events)}\n\n")

    sys.stdout.write(f"  {'Tool':<20} {'Latency':>10} {'Flags':<30} {'Policy':<8}\n")
    sys.stdout.write(f"  {'-'*20} {'-'*10} {'-'*30} {'-'*8}\n")

    for event in events:
        flags_str = ", ".join(event.risk_flags) if event.risk_flags else "-"
        latency_str = f"{event.latency_ms:.1f}ms" if event.latency_ms else "-"
        sys.stdout.write(
            f"  {event.tool_name:<20} {latency_str:>10} {flags_str:<30} {event.policy_result:<8}\n"
        )

    # Risk summary
    flagged = [e for e in events if e.risk_flags]
    sys.stdout.write(f"\n  Events with risk flags: {len(flagged)}/{len(events)}\n")

    if interceptor.event_queue:
        sys.stdout.write(
            f"  Events written to DB:   {interceptor.event_queue.events_written}\n"
            f"  Events dropped:         {interceptor.event_queue.events_dropped}\n"
        )

    sys.stdout.write(f"\n  Demo complete. Inspect events in: {db_path}\n\n")

    return interceptor


# ═══════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_scenario()
