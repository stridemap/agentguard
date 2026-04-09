# dashboard/ — Streamlit Trace Viewer

Real-time agent trace visualization dashboard (MVP phase, Sprints 2–10).

## Running

```bash
streamlit run dashboard/app.py
```

## Features (Planned)

- Live event feed with 2-second auto-refresh
- Risk color coding: green (CLEAN), yellow (SUSPICIOUS), red (BLOCKED)
- Sidebar filters: agent_id, tool_name, risk_flag, time range
- Summary metrics: total events, avg latency p99, events/sec, high-risk count
- Event detail panel with full JSON in expanders
- Session grouping by session_id with timeline view

## Performance Target

Dashboard must load in **<3 seconds** with 10,000 events.

## Data Source

Reads directly from the SQLite event store at `DATABASE_URL`.

## Replacement

This Streamlit dashboard will be replaced by a Next.js enterprise dashboard in Sprint 11 with WebSocket real-time feeds and RBAC-gated views.
