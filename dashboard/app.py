"""AgentGuard — Agent Trace Viewer

Real-time Streamlit dashboard for monitoring AI agent tool calls.
Auto-refreshes every 2 seconds. Colour-coded by risk level.

Run:
    streamlit run dashboard/app.py
    streamlit run dashboard/app.py -- --db path/to/agentguard.db
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# ── Page config (must be first Streamlit call) ───────────────────────

st.set_page_config(
    page_title="AgentGuard — Agent Trace Viewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Constants ────────────────────────────────────────────────────────

DEFAULT_DB_PATH = os.environ.get("DATABASE_URL", "agentguard.db")
REFRESH_INTERVAL = 2  # seconds
MAX_EVENTS = 100

RISK_COLORS = {
    "CLEAN": "#00D4AA",  # teal / green
    "LOW": "#00D4AA",
    "MEDIUM": "#F59E0B",  # amber
    "HIGH": "#EF4444",  # red
    "BLOCKED": "#EF4444",
}

CSS = """
<style>
    .risk-clean { color: #00D4AA; font-weight: 600; }
    .risk-low { color: #00D4AA; }
    .risk-medium { color: #F59E0B; font-weight: 600; }
    .risk-high { color: #EF4444; font-weight: 600; }
    .risk-blocked { color: #EF4444; font-weight: 700; }
    .metric-card { padding: 0.5rem; }
    div[data-testid="stMetric"] { background: #111827; border-radius: 8px; padding: 12px; }
</style>
"""


# ── Database helpers ─────────────────────────────────────────────────


def get_db_path() -> str:
    """Resolve the SQLite database path."""
    # Check CLI args (streamlit run dashboard/app.py -- --db path)
    if "--db" in sys.argv:
        idx = sys.argv.index("--db")
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return DEFAULT_DB_PATH


@st.cache_resource
def get_connection(db_path: str) -> sqlite3.Connection:
    """Get a cached SQLite connection."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection) -> bool:
    """Check if the events table exists."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    ).fetchone()
    return row is not None


def load_events(
    conn: sqlite3.Connection,
    limit: int = MAX_EVENTS,
    agent_id: str | None = None,
    tool_name: str | None = None,
    risk_flag: str | None = None,
    policy_result: str | None = None,
    time_start: str | None = None,
    time_end: str | None = None,
) -> pd.DataFrame:
    """Load events from SQLite with optional filters."""
    query = "SELECT * FROM events WHERE 1=1"
    params: list = []

    if agent_id and agent_id != "All":
        query += " AND agent_id = ?"
        params.append(agent_id)
    if tool_name and tool_name != "All":
        query += " AND tool_name = ?"
        params.append(tool_name)
    if risk_flag and risk_flag != "All":
        query += " AND risk_flags LIKE ?"
        params.append(f"%{risk_flag}%")
    if policy_result and policy_result != "All":
        query += " AND policy_result = ?"
        params.append(policy_result)
    if time_start:
        query += " AND timestamp >= ?"
        params.append(time_start)
    if time_end:
        query += " AND timestamp <= ?"
        params.append(time_end)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    df = pd.read_sql_query(query, conn, params=params)
    return df


def load_distinct_values(conn: sqlite3.Connection, column: str) -> list[str]:
    """Load distinct values for a column (for filter dropdowns)."""
    rows = conn.execute(
        f"SELECT DISTINCT {column} FROM events ORDER BY {column}"
    ).fetchall()  # noqa: S608
    return [row[0] for row in rows]


def load_event_count(conn: sqlite3.Connection) -> int:
    """Total event count."""
    row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    return row[0] if row else 0


def load_risk_flags_list(conn: sqlite3.Connection) -> list[str]:
    """Extract all unique risk flags across events."""
    rows = conn.execute("SELECT DISTINCT risk_flags FROM events").fetchall()
    flags = set()
    for row in rows:
        try:
            parsed = json.loads(row[0])
            if isinstance(parsed, list):
                flags.update(parsed)
        except (json.JSONDecodeError, TypeError):
            pass
    return sorted(flags)


# ── Risk level helpers ───────────────────────────────────────────────


def compute_risk_level(risk_flags_str: str, policy_result: str) -> str:
    """Determine risk level from flags and policy result."""
    if policy_result == "BLOCK":
        return "BLOCKED"
    try:
        flags = json.loads(risk_flags_str) if risk_flags_str else []
    except (json.JSONDecodeError, TypeError):
        flags = []
    if not flags:
        return "CLEAN"
    high_risk = {"pii_detected", "unknown_tool"}
    medium_risk = {"external_domain", "large_payload", "high_frequency"}
    if any(f in high_risk for f in flags):
        return "HIGH"
    if any(f in medium_risk for f in flags):
        return "MEDIUM"
    return "LOW"


def risk_badge(level: str) -> str:
    """Return an HTML badge for a risk level."""
    css_class = f"risk-{level.lower()}"
    return f'<span class="{css_class}">{level}</span>'


# ── Metrics helpers ──────────────────────────────────────────────────


def compute_metrics(df: pd.DataFrame, total_count: int) -> dict:
    """Compute summary metrics from the event dataframe."""
    metrics = {
        "total_events": total_count,
        "latency_p99": 0.0,
        "events_per_sec": 0.0,
        "high_risk_count": 0,
    }

    if df.empty:
        return metrics

    # p99 latency
    latencies = df["latency_ms"].dropna()
    if not latencies.empty:
        metrics["latency_p99"] = float(latencies.quantile(0.99))

    # Events per second (based on time range of visible events)
    if len(df) >= 2:
        try:
            timestamps = pd.to_datetime(df["timestamp"])
            time_range = (timestamps.max() - timestamps.min()).total_seconds()
            if time_range > 0:
                metrics["events_per_sec"] = len(df) / time_range
        except Exception:
            pass

    # High risk count
    for _, row in df.iterrows():
        level = compute_risk_level(
            row.get("risk_flags", "[]"), row.get("policy_result", "ALLOW")
        )
        if level in ("HIGH", "BLOCKED"):
            metrics["high_risk_count"] += 1

    return metrics


# ── Main app ─────────────────────────────────────────────────────────


def main() -> None:
    """Main Streamlit application."""
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("🛡️ AgentGuard — Agent Trace Viewer")

    db_path = get_db_path()

    # Check DB exists
    if not Path(db_path).exists() and db_path != ":memory:":
        st.warning(
            f"Database not found: `{db_path}`\n\n"
            "Run a demo first to generate events:\n"
            "```\npython -m demo.finance_scenario\n```\n"
            "Then point the dashboard to the DB:\n"
            "```\nstreamlit run dashboard/app.py -- --db /path/to/finance_demo.db\n```"
        )
        time.sleep(REFRESH_INTERVAL)
        st.rerun()
        return

    conn = get_connection(db_path)

    if not table_exists(conn):
        st.warning("Events table not found. Run a scenario to populate data.")
        time.sleep(REFRESH_INTERVAL)
        st.rerun()
        return

    # ── Sidebar filters ──────────────────────────────────────────

    with st.sidebar:
        st.header("Filters")

        agent_ids = ["All"] + load_distinct_values(conn, "agent_id")
        tool_names = ["All"] + load_distinct_values(conn, "tool_name")
        risk_flags_options = ["All"] + load_risk_flags_list(conn)
        policy_options = ["All", "ALLOW", "BLOCK", "ALERT", "BYPASS"]

        selected_agent = st.selectbox("Agent ID", agent_ids)
        selected_tool = st.selectbox("Tool Name", tool_names)
        selected_risk = st.selectbox("Risk Flag", risk_flags_options)
        selected_policy = st.selectbox("Policy Result", policy_options)

        st.divider()
        st.subheader("Time Range")
        col_start, col_end = st.columns(2)
        with col_start:
            date_start = st.date_input("From", value=None)
        with col_end:
            date_end = st.date_input("To", value=None)

        time_start = date_start.isoformat() if date_start else None
        time_end = (date_end.isoformat() + "T23:59:59") if date_end else None

        st.divider()
        auto_refresh = st.toggle("Auto-refresh (2s)", value=True)
        event_limit = st.slider("Max events", 10, 500, MAX_EVENTS, step=10)

        st.divider()
        st.caption(f"DB: `{db_path}`")

    # ── Load data ────────────────────────────────────────────────

    total_count = load_event_count(conn)
    df = load_events(
        conn,
        limit=event_limit,
        agent_id=selected_agent,
        tool_name=selected_tool,
        risk_flag=selected_risk,
        policy_result=selected_policy,
        time_start=time_start,
        time_end=time_end,
    )

    # ── Summary metrics ──────────────────────────────────────────

    metrics = compute_metrics(df, total_count)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", f"{metrics['total_events']:,}")
    col2.metric("Latency p99", f"{metrics['latency_p99']:.1f} ms")
    col3.metric("Events/sec", f"{metrics['events_per_sec']:.1f}")
    col4.metric(
        "High Risk",
        metrics["high_risk_count"],
        delta=(
            f"{metrics['high_risk_count']} flagged"
            if metrics["high_risk_count"] > 0
            else None
        ),
        delta_color="inverse",
    )

    # ── Tabs: Live Feed / Session Grouping ───────────────────────

    tab_feed, tab_sessions = st.tabs(["📋 Live Event Feed", "🔗 Session Grouping"])

    # ── Tab 1: Live event feed ───────────────────────────────────

    with tab_feed:
        if df.empty:
            st.info("No events found. Adjust filters or run a demo scenario.")
        else:
            # Add risk level column
            df["risk_level"] = df.apply(
                lambda row: compute_risk_level(row["risk_flags"], row["policy_result"]),
                axis=1,
            )

            # Display table
            display_df = df[
                [
                    "timestamp",
                    "agent_id",
                    "tool_name",
                    "latency_ms",
                    "risk_flags",
                    "policy_result",
                    "risk_level",
                    "event_id",
                    "session_id",
                ]
            ].copy()
            display_df["latency_ms"] = display_df["latency_ms"].apply(
                lambda x: f"{x:.1f}" if pd.notna(x) else "-"
            )
            display_df["risk_flags"] = display_df["risk_flags"].apply(
                lambda x: ", ".join(json.loads(x)) if x and x != "[]" else "-"
            )

            # Color-code risk level
            def color_risk(val: str) -> str:
                colors = {
                    "CLEAN": "color: #00D4AA",
                    "LOW": "color: #00D4AA",
                    "MEDIUM": "color: #F59E0B; font-weight: 600",
                    "HIGH": "color: #EF4444; font-weight: 600",
                    "BLOCKED": "color: #EF4444; font-weight: 700",
                }
                return colors.get(val, "")

            styled = display_df.style.applymap(color_risk, subset=["risk_level"])
            st.dataframe(
                styled,
                use_container_width=True,
                height=min(400, 40 + len(display_df) * 35),
                hide_index=True,
            )

            # ── Event detail panel ───────────────────────────────

            st.subheader("Event Details")
            event_ids = df["event_id"].tolist()
            selected_event_id = st.selectbox(
                "Select event to inspect",
                event_ids,
                format_func=lambda eid: f"{eid[:8]}... | {df[df['event_id'] == eid].iloc[0]['tool_name']}",
            )

            if selected_event_id:
                event_row = df[df["event_id"] == selected_event_id].iloc[0]
                with st.expander(f"Event {selected_event_id[:12]}...", expanded=True):
                    col_left, col_right = st.columns(2)
                    with col_left:
                        st.markdown("**Metadata**")
                        st.json(
                            {
                                "event_id": event_row["event_id"],
                                "timestamp": event_row["timestamp"],
                                "agent_id": event_row["agent_id"],
                                "session_id": event_row["session_id"],
                                "tool_name": event_row["tool_name"],
                                "run_id": event_row["run_id"],
                                "parent_run_id": event_row.get("parent_run_id", None),
                            }
                        )
                    with col_right:
                        st.markdown("**Security**")
                        st.json(
                            {
                                "policy_result": event_row["policy_result"],
                                "risk_flags": (
                                    json.loads(event_row["risk_flags"])
                                    if event_row["risk_flags"]
                                    else []
                                ),
                                "risk_level": event_row.get("risk_level", "CLEAN"),
                                "input_hash": event_row["input_hash"],
                                "output_hash": event_row["output_hash"],
                                "latency_ms": event_row["latency_ms"],
                            }
                        )

    # ── Tab 2: Session grouping ──────────────────────────────────

    with tab_sessions:
        if df.empty:
            st.info("No events to group.")
        else:
            sessions = (
                df.groupby("session_id")
                .agg(
                    event_count=("event_id", "count"),
                    tools_used=("tool_name", lambda x: ", ".join(sorted(set(x)))),
                    first_event=("timestamp", "min"),
                    last_event=("timestamp", "max"),
                    avg_latency=("latency_ms", "mean"),
                    risk_events=(
                        "risk_flags",
                        lambda x: sum(1 for f in x if f and f != "[]"),
                    ),
                )
                .reset_index()
            )

            sessions = sessions.sort_values("first_event", ascending=False)
            sessions["avg_latency"] = sessions["avg_latency"].apply(
                lambda x: f"{x:.1f} ms" if pd.notna(x) else "-"
            )

            st.dataframe(sessions, use_container_width=True, hide_index=True)

            # Session detail
            if not sessions.empty:
                selected_session = st.selectbox(
                    "Select session to inspect",
                    sessions["session_id"].tolist(),
                )

                if selected_session:
                    session_events = df[
                        df["session_id"] == selected_session
                    ].sort_values("timestamp")
                    st.subheader(f"Session: {selected_session}")
                    st.caption(f"{len(session_events)} events")

                    for _, event in session_events.iterrows():
                        flags = (
                            json.loads(event["risk_flags"])
                            if event["risk_flags"]
                            else []
                        )
                        level = compute_risk_level(
                            event["risk_flags"], event["policy_result"]
                        )
                        icon = {
                            "CLEAN": "✅",
                            "LOW": "✅",
                            "MEDIUM": "⚠️",
                            "HIGH": "🔴",
                            "BLOCKED": "🚫",
                        }.get(level, "⬜")
                        latency = (
                            f"{event['latency_ms']:.1f}ms"
                            if pd.notna(event["latency_ms"])
                            else "-"
                        )
                        st.markdown(
                            f"{icon} **{event['tool_name']}** — {latency} — "
                            f"`{event['policy_result']}` — "
                            f"{', '.join(flags) if flags else 'clean'}"
                        )

    # ── Auto-refresh ─────────────────────────────────────────────

    if auto_refresh:
        time.sleep(REFRESH_INTERVAL)
        st.rerun()


# ── Entry point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
