#!/usr/bin/env python3
"""Retire everything seed_linear.py created, as far as Linear's MCP server allows.

There is no delete_issue, no delete_project and no delete_document in Linear's MCP
surface — only delete_comment, delete_attachment, delete_diff_comment and
delete_status_update. So a true wipe is not reachable from here and this script does not
pretend otherwise. What it does:

  * deletes every comment on the seeded issues        (really deleted)
  * cancels every seeded issue                        (state = Canceled)
  * renames each seeded document out of the namespace (RETIRED <stamp> — <title>)
  * renames each seeded project out of the namespace  (RETIRED <stamp> — <name>)
  * cancels each seeded project                       (state = canceled)

Only the comments are actually gone. Everything else survives under a RETIRED name.

The rename is the part that matters for re-seeding. seed_linear.py looks projects up by
name before creating, so a leftover project with the seeded name would be silently reused
instead of recreated. Moving the old ones out of the namespace lets a fresh run start
clean without a duplicate.

To actually remove the retired shells, delete them in Linear's UI, or delete the whole
Demo team — one action, removes everything.

Runs direct to the vendor by default. Reading the seeded issues back through MiniGate is
refused by design — the injection payloads are exactly what the gateway withholds — and a
cleanup tool that trips the control it is cleaning up after is no use to anyone.

    python3 demo/minigate/teardown_linear.py --team Demo --dry-run
    python3 demo/minigate/teardown_linear.py --team Demo
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
)

# Kept in step with seed_linear.PROJECTS. Imported rather than duplicated so the two
# cannot drift apart and leave a project silently un-retired.
sys.path.insert(0, str(Path(__file__).parent))
from seed_linear import PROJECTS  # noqa: E402

SEEDED_NAMES = {p["name"] for p in PROJECTS.values()}


class Client:
    """One MCP connection, one request at a time."""

    def __init__(self, argv: list[str]) -> None:
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, cwd=str(REPO),
        )
        self._next_id = 0

    def _request(self, method: str, params: dict | None = None) -> dict | None:
        self._next_id += 1
        rpc_id = self._next_id
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": method,
                        "params": params or {}}) + "\n")
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                return None
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == rpc_id:
                return message

    def handshake(self) -> list[str]:
        self._request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "minigate-teardown", "version": "1.0"}})
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.process.stdin.flush()
        listed = self._request("tools/list") or {}
        return [t["name"] for t in listed.get("result", {}).get("tools", [])]

    def call(self, tool: str, arguments: dict) -> tuple[bool, str]:
        answer = self._request("tools/call", {"name": tool, "arguments": arguments})
        result = (answer or {}).get("result", {})
        text = "".join(c.get("text", "") for c in result.get("content", []))
        return (not result.get("isError", False)), text

    def rows(self, tool: str, arguments: dict, *keys: str) -> list[dict]:
        """Call a list_* tool and unwrap whatever envelope Linear used."""
        ok, text = self.call(tool, arguments)
        if not ok:
            raise RuntimeError(f"{tool} refused: {text[:160]}")
        data = json.loads(text)
        if isinstance(data, list):
            return data
        for key in (*keys, "nodes"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.process.stdin.close()
            self.process.wait(timeout=15)
        if self.process.poll() is None:
            self.process.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="Retire the MiniGate demo fixtures")
    parser.add_argument("--team", required=True, help="team the fixtures live in")
    parser.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    parser.add_argument("--via-minigate", action="store_true",
                        help="route through MiniGate instead of direct. Expect refusals: "
                             "reading the injection fixtures is what the gateway blocks.")
    parser.add_argument("--config", default=str(REPO / "minigate.yaml"))
    parser.add_argument("--server-name", default="linear")
    parser.add_argument("--upstream", nargs="+",
                        default=["npx", "-y", "mcp-remote", "https://mcp.linear.app/mcp"])
    args = parser.parse_args()

    argv = ([str(REPO / ".venv" / "bin" / "minigate"), "stdio",
             "--server-name", args.server_name, "--config", args.config]
            if args.via_minigate else args.upstream)

    client = Client(argv)
    available = client.handshake()
    path = "through MiniGate" if args.via_minigate else "direct to the vendor"
    print(f"\n{BOLD}Teardown{RESET}  {path}  ({len(available)} tools)")

    try:
        projects = [p for p in client.rows("list_projects", {"limit": 50}, "projects")
                    if p.get("name") in SEEDED_NAMES]
    except RuntimeError as error:
        print(f"  {RED}{error}{RESET}\n")
        client.close()
        return 1

    if not projects:
        print(f"  {DIM}nothing to retire — no project carries a seeded name{RESET}\n")
        client.close()
        return 0

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    print(f"  {len(projects)} project(s) carrying seeded names\n")

    issues_seen = comments_deleted = issues_cancelled = 0
    documents_seen = documents_retired = 0
    for project in projects:
        print(f"{BOLD}{project['name']}{RESET}  {DIM}{project['id']}{RESET}")
        try:
            issues = client.rows("list_issues",
                                 {"project": project["id"], "limit": 250, "fields": ["title"]},
                                 "issues")
        except RuntimeError as error:
            print(f"  {RED}{error}{RESET}")
            continue

        for issue in issues:
            issues_seen += 1
            title = issue.get("title", "")[:52]
            if args.dry_run:
                print(f"  {DIM}would cancel{RESET}  {title}")
                continue

            # Comments are the only thing here that can genuinely be deleted. Do them
            # before cancelling, purely so a failure leaves the issue findable.
            with contextlib.suppress(RuntimeError, json.JSONDecodeError):
                for comment in client.rows("list_comments",
                                           {"issueId": issue["id"], "limit": 250}, "comments"):
                    ok, _ = client.call("delete_comment", {"id": comment["id"]})
                    comments_deleted += 1 if ok else 0

            ok, text = client.call("save_issue", {"id": issue["id"], "state": "Canceled"})
            issues_cancelled += 1 if ok else 0
            print(f"  {GREEN + 'cancelled' + RESET if ok else RED + 'failed   ' + RESET}  {title}")
            if not ok:
                print(f"     {DIM}{text[:96]}{RESET}")

        # Documents are project-scoped and, like issues, cannot be deleted. Left alone
        # they accumulate one copy per teardown/re-seed cycle, all sharing a title, which
        # makes "which Vendor integration notes is the live one" unanswerable at a glance.
        try:
            documents = client.rows("list_documents",
                                    {"projectId": project["id"], "limit": 100,
                                     "fields": ["title"]}, "documents")
        except (RuntimeError, json.JSONDecodeError) as error:
            documents = []
            print(f"  {DIM}could not list documents: {error}{RESET}")

        for document in documents:
            documents_seen += 1
            title = document.get("title", "")[:52]
            if args.dry_run:
                print(f"  {DIM}would retire document{RESET}  {title}")
                continue
            ok, text = client.call(
                "save_document",
                {"id": document["id"], "title": f"RETIRED {stamp} — {document.get('title', '')}"})
            documents_retired += 1 if ok else 0
            print(f"  {GREEN + 'retired  ' + RESET if ok else RED + 'failed   ' + RESET}  "
                  f"{DIM}doc{RESET} {title}")
            if not ok:
                print(f"     {DIM}{text[:96]}{RESET}")

        retired = f"RETIRED {stamp} — {project['name']}"
        if args.dry_run:
            print(f"  {DIM}would rename to{RESET} {retired}")
            print(f"  {DIM}would set project state = canceled{RESET}\n")
            continue

        ok, text = client.call("save_project",
                               {"id": project["id"], "name": retired, "state": "canceled"})
        print(f"  {GREEN + 'retired' + RESET if ok else RED + 'rename failed' + RESET}  {retired}")
        if not ok:
            print(f"     {DIM}{text[:96]}{RESET}")
        print()

    client.close()

    if args.dry_run:
        print(f"{BOLD}Dry run{RESET}  {issues_seen} issue(s) and {documents_seen} document(s) "
              f"across {len(projects)} project(s)")
        print(f"{DIM}  Re-run without --dry-run to apply.{RESET}\n")
        return 0

    print(f"{BOLD}Done{RESET}  {issues_cancelled}/{issues_seen} issues cancelled, "
          f"{documents_retired}/{documents_seen} documents retired, "
          f"{comments_deleted} comment(s) deleted, {len(projects)} project(s) retired")
    print(f"{DIM}  Only the comments were actually deleted. Everything else is cancelled{RESET}")
    print(f"{DIM}  and renamed: Linear's MCP server has no delete_issue, delete_project or{RESET}")
    print(f"{DIM}  delete_document. Remove the RETIRED shells in the UI, or delete the whole{RESET}")
    print(f"{DIM}  team. Either way the seeded names are free for the next run.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
