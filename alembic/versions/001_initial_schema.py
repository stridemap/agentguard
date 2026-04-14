"""Initial schema — events table with audit chain columns.

Revision ID: 001
Revises: None
Create Date: 2026-04-13
"""

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("event_id", sa.Text(), primary_key=True),
        sa.Column("timestamp", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("parent_run_id", sa.Text(), nullable=True),
        sa.Column("input_hash", sa.Text(), nullable=False),
        sa.Column("output_hash", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("risk_flags", sa.Text(), nullable=False),
        sa.Column("policy_result", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("event_hash", sa.Text(), nullable=False, server_default=""),
    )

    op.create_index("idx_events_agent_id", "events", ["agent_id"])
    op.create_index("idx_events_session_id", "events", ["session_id"])
    op.create_index("idx_events_timestamp", "events", ["timestamp"])
    op.create_index("idx_events_tool_name", "events", ["tool_name"])


def downgrade() -> None:
    op.drop_table("events")
