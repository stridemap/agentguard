#!/usr/bin/env python3
"""Run one MiniGate demo scenario against the live Linear workspace.

    python3 demo/minigate/run_scenario.py 4          # through the gateway
    python3 demo/minigate/run_scenario.py 4 --without # straight to Linear, for the contrast
    python3 demo/minigate/run_scenario.py all

One command per scenario, so a demo is not a sequence of hand-typed JSON-RPC. Scenarios 6,
8 and 9 cannot run against Linear at all — it advertises only `tools`, and never initiates
a request back to the client — so they explain themselves and name the server to use
instead rather than pretending.

`--without` re-runs the same steps with no gateway in the path. That is the half that
makes the point: the left-hand column of every comparison in the runbook came from it.

Scenarios 3, 5 and 10 need config variants. Generate them first, and after any change to
minigate.yaml:

    python3 demo/minigate/make_demo_configs.py
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
MINIGATE = REPO / ".venv" / "bin" / "minigate"
UPSTREAM = ["npx", "-y", "mcp-remote", "https://mcp.linear.app/mcp"]

# A non-existent id. Letters throughout on purpose: an all-digit id matches the policy
# engine's credit-card fallback, and the call is then refused by the wrong rule.
SAFE_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m"
)


def head(text: str) -> None:
    print(f"\n{BOLD}{text}{RESET}")


def step(text: str) -> None:
    print(f"\n{CYAN}▸{RESET} {text}")


def out(text: str, colour: str = "") -> None:
    print(f"    {colour}{text}{RESET}")


def wrapped(text: str, width: int = 96) -> None:
    for i in range(0, min(len(text), width * 3), width):
        out(text[i:i + width], DIM)


class Session:
    """One MCP connection, driven the way a real client drives it: one request at a time."""

    def __init__(self, argv: list[str]) -> None:
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=str(REPO),
        )
        self._id = 0

    def _request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        rpc_id = self._id
        self.process.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params or {}}) + "\n")
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise SystemExit(f"{RED}connection closed — is the config path right?{RESET}")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == rpc_id:
                return message

    def start(self) -> list[str]:
        self._request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "minigate-demo", "version": "1.0"}})
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.process.stdin.flush()
        listed = self._request("tools/list")
        return [t["name"] for t in listed.get("result", {}).get("tools", [])]

    def call(self, tool: str, args: dict) -> tuple[bool, str]:
        result = self._request("tools/call", {"name": tool, "arguments": args}).get("result", {})
        text = "".join(c.get("text", "") for c in result.get("content", []))
        return (not result.get("isError", False)), text

    def rows(self, tool: str, args: dict, *keys: str) -> list[dict]:
        ok, text = self.call(tool, args)
        if not ok:
            raise RuntimeError(text)
        data = json.loads(text)
        if isinstance(data, list):
            return data
        for key in (*keys, "nodes"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def project(self, name: str) -> str:
        for row in self.rows("list_projects", {"limit": 50}, "projects"):
            if row.get("name") == name:
                return row["id"]
        raise SystemExit(f"{RED}project {name!r} not found — run seed_linear.py --direct{RESET}")

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.process.stdin.close()
            self.process.wait(timeout=15)
        if self.process.poll() is None:
            self.process.kill()


class HttpSession:
    """The same conversation, driven against a deployed gateway over Streamable HTTP.

    Mirrors Session's interface so the scenarios do not care which transport they are on
    — which is the point being demonstrated: one decision layer, two front doors.

    Responses arrive as either JSON or SSE depending on what the upstream returns, so both
    shapes are unwrapped here rather than in every caller.
    """

    def __init__(self, url: str, token: str) -> None:
        self.url = url
        self.client = httpx.Client(timeout=90)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        }
        self._id = 0

    def _request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        reply = self.client.post(self.url, headers=self.headers, json={
            "jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        # The session id is issued on initialize and must be echoed on every later POST,
        # or the gateway cannot correlate a response to its request.
        if reply.headers.get("mcp-session-id"):
            self.headers["Mcp-Session-Id"] = reply.headers["mcp-session-id"]
        body = reply.text
        if "data: " in body:
            body = [ln[6:] for ln in body.splitlines() if ln.startswith("data: ")][-1]
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"result": {"isError": True, "content": [{"text": body[:200]}]}}

    def start(self) -> list[str]:
        self._request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "minigate-demo", "version": "1.0"}})
        listed = self._request("tools/list")
        return [t["name"] for t in listed.get("result", {}).get("tools", [])]

    call = Session.call
    rows = Session.rows
    project = Session.project

    def close(self) -> None:
        self.client.close()


def gateway(config: str = "minigate.yaml", upstream: list[str] | None = None) -> list[str]:
    argv = [str(MINIGATE), "stdio", "--server-name", "linear", "--config", str(REPO / config)]
    return argv + (["--", *upstream] if upstream else [])


REMOTE: dict[str, str] = {}


def open_session(without: bool, config: str = "minigate.yaml",
                 upstream: list[str] | None = None):
    if without:
        out("MiniGate is NOT in the path — straight to Linear", YELLOW)
        return Session(upstream or UPSTREAM)
    if REMOTE:
        out(f"through the DEPLOYED gateway: {REMOTE['url']}", CYAN)
        return HttpSession(REMOTE["url"], REMOTE["token"])
    return Session(gateway(config, upstream))


# ── scenarios ────────────────────────────────────────────────────────────────

def scenario_1(without: bool) -> None:
    head("Scenario 1 — Unsanctioned tool never reaches the model")
    if not without and not REMOTE:
        out("delegating to the narrated version, which also counts what was forwarded", DIM)
        subprocess.run([sys.executable, str(REPO / "demo/minigate/scenario1_linear.py")],
                       cwd=str(REPO), check=False)
        return
    s = open_session(without)
    names = s.start()
    step(f"tools/list → {len(names)} tools")
    deletes = sorted(n for n in names if n.startswith("delete"))
    out(f"delete verbs handed to the model: {deletes}", RED if deletes else GREEN)
    step(f"call delete_comment with a non-existent id ({SAFE_ID})")
    ok, text = s.call("delete_comment", {"id": SAFE_ID})
    if without:
        out("reached Linear — this is the vendor's own error, not a gateway refusal:", RED)
    else:
        out("REFUSED by the gateway; the call never reached Linear:", GREEN)
    wrapped(text)
    s.close()


def scenario_2(without: bool) -> None:
    head("Scenario 2 — Tool poisoning")
    out("one tool description is rewritten in flight by poison_shim", DIM)
    shim = [sys.executable, str(REPO / "demo/minigate/poison_shim.py"),
            "--tool", "get_issue", "--", *UPSTREAM]
    s = Session(shim if without else gateway("minigate.yaml", shim))
    names = s.start()
    step(f"tools delivered: {len(names)}")
    poisoned = "get_issue" in names
    out(f"get_issue   (poisoned)  {'OFFERED' if poisoned else 'WITHHELD'}",
        RED if poisoned else GREEN)
    out(f"get_project (control)   {'OFFERED' if 'get_project' in names else 'WITHHELD'}", GREEN)
    s.close()


def scenario_3(without: bool) -> None:
    head("Scenario 3 — The rug-pull")
    registry = REPO / "demo/minigate/evidence/minigate-registry.pre-sync.yaml"
    if without:
        s = open_session(True)
        names = s.start()
        step(f"tools/list → {len(names)} tools")
        for tool in ("list_issues", "save_issue"):
            out(f"{tool}: {'OFFERED' if tool in names else 'withheld'}", RED)
        out("the definitions changed; nothing here can tell", RED)
        s.close()
        return

    step("registry diff — live Linear against the registry as it stood before the drift")
    proc = subprocess.run(
        [str(MINIGATE), "registry", "diff", "--server-name", "linear",
         "--config", str(REPO / "minigate.yaml"), "--registry", str(registry)],
        cwd=str(REPO), capture_output=True, text=True, check=False)
    # The diff prints one pretty-printed JSON object on stdout. Summarise it: listing all
    # 55 unchanged tool names buries the two that matter.
    try:
        diff = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        diff = None
    if isinstance(diff, dict):
        out(f'new:       {diff.get("new") or "[]"}')
        out(f'changed:   {diff.get("changed") or "[]"}', YELLOW)
        out(f'missing:   {diff.get("missing") or "[]"}')
        out(f'unchanged: {len(diff.get("unchanged") or [])} tools', DIM)
    else:
        for line in proc.stdout.splitlines():
            out(line)
    out(f"exit code: {proc.returncode}  (non-zero on drift — this is what gates CI)",
        GREEN if proc.returncode else RED)

    step("live session pinned to that same stale registry")
    s = Session(gateway("minigate-s3.yaml"))
    names = s.start()
    out(f"tools offered: {len(names)}")
    for tool in ("list_issues", "save_issue", "get_issue"):
        held = tool not in names
        out(f"{tool}: {'WITHHELD' if held else 'OFFERED'}", GREEN if held else DIM)
    ok, text = s.call("save_issue", {"title": "x", "team": "Demo"})
    wrapped(text)
    s.close()


def scenario_4(without: bool) -> None:
    head("Scenario 4 — Indirect prompt injection in returned content")
    s = open_session(without)
    s.start()
    pid = s.project("MiniGate S4 — Prompt Injection")
    step("list_issues on the injection project")
    ok, text = s.call("list_issues", {"project": pid, "limit": 50,
                                      "fields": ["title", "description"]})
    if ok:
        phrases = [p for p in ("Ignore all previous instructions", "ignore previous instructions",
                               "Pretend you are an admin", "forget everything you were told")
                   if p in text]
        out(f"RETURNED {len(text)} chars", RED)
        out(f"injection phrases now in the model's context: {phrases}", RED)
    else:
        out("WITHHELD", GREEN)
        wrapped(text)
    step("the same call on the control project, for contrast")
    ok, _ = s.call("list_issues", {"project": s.project("MiniGate S5 — Data Lineage"),
                                   "limit": 50, "fields": ["title", "description"]})
    out(f"MiniGate S5 → {'returned normally' if ok else 'withheld'}", GREEN if ok else RED)
    s.close()


def scenario_5(without: bool) -> None:
    head("Scenario 5 — Trust-boundary crossing")
    taint = REPO / "minigate-taint.db"
    if taint.exists():
        taint.unlink()
        out("removed minigate-taint.db — stale taint fires for the wrong reason", DIM)
    s = open_session(without, "minigate-s5.yaml")
    s.start()
    pid = s.project("MiniGate S5 — Data Lineage")
    rows = s.rows("list_issues", {"project": pid, "limit": 50, "fields": ["title"]}, "issues")
    issue = next(r for r in rows if "KX-99182" in r["title"])

    step(f"read the confidential issue — get_issue {issue['id']}")
    ok, _ = s.call("get_issue", {"id": issue["id"]})
    out("returned" if ok else "refused", GREEN if ok else RED)

    step("now write what we just read into a public sink — save_comment")
    ok, text = s.call("save_comment", {
        "issueId": issue["id"],
        "body": "Summary: renewal for account KX-99182-ALPHA, owner Marcus Feldt, "
                "ref INV-2026-0817."})
    if ok:
        out("POSTED — no control fired. Two ordinary calls, one breach.", RED)
        # Leave nothing behind: delete_comment is one of the four verbs Linear does expose.
        with contextlib.suppress(Exception):
            cid = json.loads(text)
            cid = cid.get("id") or cid.get("comment", {}).get("id")
            if cid and s.call("delete_comment", {"id": cid})[0]:
                out("(demo comment deleted)", DIM)
    else:
        out("BLOCKED", GREEN)
        wrapped(text)
    s.close()


def scenario_7(without: bool) -> None:
    head("Scenario 7 — PII redaction in flight")
    s = open_session(without)
    s.start()
    pid = s.project("MiniGate S7 — PII Redaction")
    step("read each issue individually")
    for row in s.rows("list_issues", {"project": pid, "limit": 50, "fields": ["title"]}, "issues"):
        ok, text = s.call("get_issue", {"id": row["id"]})
        if not ok:
            out(f"{row['id']:8} {row['title'][:42]:44} REFUSED  {text[:52]}", GREEN)
            continue
        tags = [t for t in ("[PERSON]", "[EMAIL_ADDRESS]", "[PHONE_NUMBER]",
                            "[US_SSN]", "[CREDIT_CARD]", "[LOCATION]") if t in text]
        leaks = [v for v in ("123-45-6789", "4111-1111-1111-1111", "415-555-0142") if v in text]
        state = ", ".join(tags) if tags else ("NOT redacted" if leaks else "nothing to redact")
        out(f"{row['id']:8} {row['title'][:42]:44} returned  {state}"
            + (f"  {RED}in the clear: {leaks}" if leaks else ""),
            "" if tags or not leaks else RED)
    step("now the whole project in one call")
    ok, text = s.call("list_issues", {"project": pid, "limit": 50,
                                      "fields": ["title", "description"]})
    out("RETURNED — every value in the clear" if ok else "REFUSED", RED if ok else GREEN)
    if not ok:
        wrapped(text)
        out("the SSN issue is in the batch, and MG-001 blocks rather than redacts", DIM)
    s.close()


def scenario_10(without: bool) -> None:
    head("Scenario 10 — The same controls, deployed centrally")
    if without:
        step("a client dialling Linear's remote endpoint directly")
        reply = httpx.post("https://mcp.linear.app/mcp", timeout=30,
                           headers={"Content-Type": "application/json"},
                           content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
        out(f"HTTP {reply.status_code}", YELLOW)
        out(f"www-authenticate: {reply.headers.get('www-authenticate', '')[:120]}", DIM)
        out("Auth is correct. But: all 57 tools, no policy, no audit record,", RED)
        out("and every endpoint configured one by one.", RED)
        return

    port = 8848
    server = subprocess.Popen(
        [str(MINIGATE), "serve", "--config", str(REPO / "minigate-s10.yaml"),
         "--port", str(port)],
        cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(30):
            time.sleep(0.5)
            with contextlib.suppress(Exception):
                httpx.get(f"{base}/healthz", timeout=2)
                break

        step("POST tools/list with no token")
        reply = httpx.post(f"{base}/mcp/linear-remote", timeout=20,
                           headers={"Content-Type": "application/json"},
                           content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
        if reply.status_code == 401:
            out(f"HTTP {reply.status_code} {reply.reason_phrase}", GREEN)
            out(f"www-authenticate: {reply.headers.get('www-authenticate', '')}", DIM)
        else:
            out(f"HTTP {reply.status_code} — expected 401; check auth.require", RED)

        step("the protected-resource metadata it points at")
        doc = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp/linear-remote",
                        timeout=20).json()
        out(json.dumps(doc, indent=2))
        out(f"authorization_servers → {doc.get('authorization_servers')}", GREEN)
        out("Linear's own AS. MiniGate mints, stores and refreshes nothing.", DIM)
    finally:
        server.terminate()
        with contextlib.suppress(Exception):
            server.wait(timeout=10)


def not_on_linear(number: int, name: str, why: str, instead: str) -> None:
    head(f"Scenario {number} — {name}")
    out(why, YELLOW)
    out("")
    out("Run it against a server that has the primitive:", DIM)
    out(instead, CYAN)


SCENARIOS = {
    1: scenario_1, 2: scenario_2, 3: scenario_3, 4: scenario_4,
    5: scenario_5, 7: scenario_7, 10: scenario_10,
}

UNSUPPORTED = {
    6: (lambda: not_on_linear(
        6, "Credential and system files",
        "Linear exposes no resources — it advertises {\"tools\":{...}} and nothing else, "
        "and resources/list answers 'Method not found'.",
        ".venv/bin/minigate stdio --server-name filesystem --config minigate.yaml")),
    8: (lambda: not_on_linear(
        8, "A server asking to run your model",
        "Linear never initiates a request back to the client, so it never calls "
        "sampling/createMessage.",
        "use the synthetic server in demo/minigate/ — see DEMO.md scenario 8")),
    9: (lambda: not_on_linear(
        9, "Phishing the human",
        "Same reason as scenario 8 — Linear never initiates elicitation/create.",
        "use the synthetic server in demo/minigate/ — see DEMO.md scenario 9")),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a MiniGate demo scenario against Linear")
    parser.add_argument("scenario", help="1-10, or 'all'")
    parser.add_argument("--without", action="store_true",
                        help="no gateway in the path — the contrast half")
    parser.add_argument("--gateway-url",
                        help="drive a DEPLOYED gateway over HTTP instead of spawning the "
                             "local stdio shim, e.g. https://host/mcp/linear")
    parser.add_argument("--token",
                        help="bearer token for --gateway-url. Defaults to the one "
                             "mcp-remote already holds for Linear.")
    args = parser.parse_args()

    if not MINIGATE.exists():
        print(f"{RED}{MINIGATE} not found — pip install -e '.[dev]' in the venv first{RESET}")
        return 1

    if args.gateway_url:
        token = args.token
        if not token:
            import glob
            files = glob.glob(str(Path.home() / ".mcp-auth/mcp-remote-v1/*_tokens.json"))
            if not files:
                print(f"{RED}no token: pass --token{RESET}")
                return 1
            with open(files[0]) as handle:
                token = json.load(handle)["access_token"]
        REMOTE["url"], REMOTE["token"] = args.gateway_url, token

    wanted = (sorted(SCENARIOS | UNSUPPORTED) if args.scenario == "all"
              else [int(args.scenario)])
    for number in wanted:
        if number in UNSUPPORTED:
            if not args.without:
                UNSUPPORTED[number]()
            continue
        if number not in SCENARIOS:
            print(f"{RED}no scenario {number}{RESET}")
            return 1
        SCENARIOS[number](args.without)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
