"""CLI entry point for AgentGuard.

Usage:
    python -m agentguard verify-chain [--db path/to/agentguard.db]
"""

from __future__ import annotations

import argparse
import sys

from agentguard.event_store import EventStore


def cmd_verify_chain(args: argparse.Namespace) -> None:
    """Verify the cryptographic audit chain integrity."""
    store = EventStore(db_path=args.db)
    result = store.verify_chain()

    if result["is_valid"]:
        sys.stdout.write(
            f"Chain valid — {result['total_events']} events verified "
            f"({result['verification_latency_ms']:.1f}ms)\n"
        )
        sys.exit(0)
    else:
        sys.stdout.write(
            f"Chain broken at event {result['first_tampered_event_id']} "
            f"— tampering detected "
            f"({result['total_events']} events, "
            f"{result['verification_latency_ms']:.1f}ms)\n"
        )
        sys.exit(1)


def main() -> None:
    """Parse CLI arguments and dispatch commands."""
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard CLI — governance tools for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # verify-chain
    verify_parser = subparsers.add_parser(
        "verify-chain",
        help="Verify the cryptographic audit chain integrity",
    )
    verify_parser.add_argument(
        "--db",
        default="agentguard.db",
        help="Path to SQLite database (default: agentguard.db)",
    )

    args = parser.parse_args()

    if args.command == "verify-chain":
        cmd_verify_chain(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
