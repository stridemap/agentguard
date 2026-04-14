"""Native agent SDK adapters for OpenAI and Anthropic.

Provides wrapper functions that integrate AgentGuard governance
into non-LangChain agent frameworks with minimal code changes.

Usage:
    from agentguard.sdk_adapters import govern_openai_tool, govern_anthropic_tool

    # OpenAI
    result = govern_openai_tool(interceptor, tool_call)

    # Anthropic
    result = govern_anthropic_tool(interceptor, tool_use_block)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from agentguard.interceptor import AgentGuardInterceptor


def govern_tool_call(
    interceptor: AgentGuardInterceptor,
    tool_name: str,
    tool_input: str,
    execute_fn: Callable[[], Any],
) -> Any:
    """Universal wrapper: govern any tool call with AgentGuard.

    Calls on_tool_start, executes the tool, calls on_tool_end or
    on_tool_error. Works with any agent framework.

    Args:
        interceptor: AgentGuard interceptor instance.
        tool_name: Name of the tool being called.
        tool_input: Input string/JSON for the tool.
        execute_fn: Callable that executes the actual tool.

    Returns:
        The tool execution result.
    """
    run_id = uuid4()

    interceptor.on_tool_start(
        serialized={"name": tool_name},
        input_str=tool_input,
        run_id=run_id,
    )

    try:
        result = execute_fn()
        interceptor.on_tool_end(output=str(result), run_id=run_id)
        return result
    except Exception as e:
        interceptor.on_tool_error(error=e, run_id=run_id)
        raise


def govern_openai_tool(
    interceptor: AgentGuardInterceptor,
    tool_call: Any,
    execute_fn: Callable[[str, str], Any],
) -> Any:
    """Govern an OpenAI Agents SDK tool call.

    Args:
        interceptor: AgentGuard interceptor.
        tool_call: OpenAI tool_call object with .function.name and .function.arguments.
        execute_fn: Function(name, arguments) -> result.

    Returns:
        Tool execution result.
    """
    name = getattr(getattr(tool_call, "function", tool_call), "name", "unknown_tool")
    args = getattr(getattr(tool_call, "function", tool_call), "arguments", "{}")
    if not isinstance(args, str):
        args = json.dumps(args)

    return govern_tool_call(
        interceptor=interceptor,
        tool_name=name,
        tool_input=args,
        execute_fn=lambda: execute_fn(name, args),
    )


def govern_anthropic_tool(
    interceptor: AgentGuardInterceptor,
    tool_use: Any,
    execute_fn: Callable[[str, dict], Any],
) -> Any:
    """Govern an Anthropic Claude SDK tool_use block.

    Args:
        interceptor: AgentGuard interceptor.
        tool_use: Anthropic tool_use content block with .name and .input.
        execute_fn: Function(name, input_dict) -> result.

    Returns:
        Tool execution result.
    """
    name = getattr(tool_use, "name", "unknown_tool")
    input_data = getattr(tool_use, "input", {})
    input_str = (
        json.dumps(input_data) if isinstance(input_data, dict) else str(input_data)
    )

    return govern_tool_call(
        interceptor=interceptor,
        tool_name=name,
        tool_input=input_str,
        execute_fn=lambda: execute_fn(name, input_data),
    )


class GovernedToolRunner:
    """Reusable governed tool runner for any framework.

    Wraps an interceptor and provides a simple run() method.

    Usage:
        runner = GovernedToolRunner(interceptor)
        result = runner.run("tool_name", "input_data", lambda: my_tool())
    """

    def __init__(self, interceptor: AgentGuardInterceptor) -> None:
        self.interceptor = interceptor
        self._call_count = 0

    def run(
        self,
        tool_name: str,
        tool_input: str,
        execute_fn: Callable[[], Any],
    ) -> Any:
        """Execute a governed tool call."""
        self._call_count += 1
        return govern_tool_call(
            interceptor=self.interceptor,
            tool_name=tool_name,
            tool_input=tool_input,
            execute_fn=execute_fn,
        )

    @property
    def call_count(self) -> int:
        return self._call_count
