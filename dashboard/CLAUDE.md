# dashboard/ — Streamlit Trace Viewer

## Overview

Real-time agent trace visualization dashboard built with Streamlit. This is the MVP dashboard (Sprints 2-10). It will be replaced by a Next.js enterprise dashboard in Sprint 11.

## Running

```bash
streamlit run dashboard/app.py
```

## Features (Sprint 2)

- **Live event feed**: Auto-refresh every 2 seconds, shows last 100 events
- **Risk color coding**: Green=CLEAN, Yellow=SUSPICIOUS, Red=BLOCKED/HIGH_RISK
- **Filters sidebar**: agent_id, tool_name, risk_flag, time range
- **Event detail panel**: Click any event to see full JSON in expander
- **Summary metrics**: Total events today, avg latency p99, events/sec, high-risk count (st.metric cards)
- **Session grouping**: Group events by session_id, show session timeline

## Performance Target

Dashboard must load in **<3 seconds** with 10,000 events in the database.

## Data Source

Reads directly from the SQLite event store at `DATABASE_URL` (or default `agentguard.db`).

## UI Patterns

```python
# Auto-refresh pattern
import time
import streamlit as st

# Summary metrics at top
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", total_count)
col2.metric("Avg Latency (p99)", f"{latency_p99:.1f}ms")
col3.metric("Events/sec", f"{events_per_sec:.1f}")
col4.metric("High Risk", high_risk_count, delta_color="inverse")

# Sidebar filters
with st.sidebar:
    agent_filter = st.selectbox("Agent ID", options=agent_ids)
    tool_filter = st.selectbox("Tool Name", options=tool_names)

# Color-coded event table
# Use st.dataframe with column_config for risk level styling

# Auto-refresh
time.sleep(2)
st.rerun()
```

## Conventions

- Page title: "AgentGuard - Agent Trace Viewer"
- Use `st.set_page_config(layout="wide")` for full-width layout
- Paginate large datasets (max 100 rows per page)
- Show timestamps in local timezone
- JSON details in `st.expander` (not inline)
