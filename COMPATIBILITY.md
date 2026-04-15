# AgentGuard — Agent Framework Compatibility Guide

A product by [Stridemap Labs LLC](https://stridemap.ai) — AI Security for the Enterprise.

AgentGuard works with any LLM agent framework that supports callback handlers. Here's how to integrate with the most popular frameworks.

---

## LangGraph / LangChain (Native Support)

AgentGuard's interceptor subclasses `BaseCallbackHandler` — plug and play.

```python
from agentguard import AgentGuardInterceptor

interceptor = AgentGuardInterceptor(agent_id="my-agent", db_path="agentguard.db")
config = {"callbacks": [interceptor]}

# LangGraph
agent.invoke(input, config=config)

# LangChain
chain.invoke(input, config=config)
```

---

## OpenAI Agents SDK

Wrap tool calls with AgentGuard's interceptor callbacks:

```python
from agentguard import AgentGuardInterceptor
from uuid import uuid4

interceptor = AgentGuardInterceptor(agent_id="openai-agent", db_path="agentguard.db")

# Before each tool call
run_id = uuid4()
interceptor.on_tool_start(
    serialized={"name": tool_call.function.name},
    input_str=tool_call.function.arguments,
    run_id=run_id,
)

# Execute the tool
result = execute_tool(tool_call)

# After the tool call
interceptor.on_tool_end(output=str(result), run_id=run_id)
```

---

## Anthropic Claude Agent SDK

Same pattern — wrap tool use blocks:

```python
from agentguard import AgentGuardInterceptor
from uuid import uuid4

interceptor = AgentGuardInterceptor(agent_id="claude-agent", db_path="agentguard.db")

for tool_use in response.content:
    if tool_use.type == "tool_use":
        run_id = uuid4()
        interceptor.on_tool_start(
            serialized={"name": tool_use.name},
            input_str=json.dumps(tool_use.input),
            run_id=run_id,
        )

        result = execute_tool(tool_use.name, tool_use.input)

        interceptor.on_tool_end(output=str(result), run_id=run_id)
```

---

## CrewAI

Use the callback handler with CrewAI's task execution:

```python
from agentguard import AgentGuardInterceptor
from crewai import Agent, Task, Crew

interceptor = AgentGuardInterceptor(agent_id="crewai-agent", db_path="agentguard.db")

crew = Crew(
    agents=[agent],
    tasks=[task],
    callbacks=[interceptor],  # CrewAI supports LangChain callbacks
)
crew.kickoff()
```

---

## AutoGen

Wrap AutoGen tool execution:

```python
from agentguard import AgentGuardInterceptor
from uuid import uuid4

interceptor = AgentGuardInterceptor(agent_id="autogen-agent", db_path="agentguard.db")

# Register as a hook on tool execution
def agentguard_hook(tool_name, tool_input, tool_output):
    run_id = uuid4()
    interceptor.on_tool_start(serialized={"name": tool_name}, input_str=str(tool_input), run_id=run_id)
    interceptor.on_tool_end(output=str(tool_output), run_id=run_id)
```

---

## Generic Integration (Any Framework)

If your framework doesn't support callbacks, wrap tool calls manually:

```python
from agentguard import AgentGuardInterceptor
from uuid import uuid4

interceptor = AgentGuardInterceptor(
    agent_id="my-agent",
    db_path="agentguard.db",
    policy_path="policies/default.yaml",
    dlp_sensitivity="HIGH",
    injection_sensitivity="MEDIUM",
)

def governed_tool_call(tool_name: str, input_data: str) -> str:
    run_id = uuid4()
    interceptor.on_tool_start(
        serialized={"name": tool_name},
        input_str=input_data,
        run_id=run_id,
    )
    try:
        result = your_tool_function(tool_name, input_data)
        interceptor.on_tool_end(output=str(result), run_id=run_id)
        return result
    except Exception as e:
        interceptor.on_tool_error(error=e, run_id=run_id)
        raise
```

---

## Feature Support Matrix

| Feature | LangGraph | OpenAI | Anthropic | CrewAI | AutoGen | Generic |
|---------|:---------:|:------:|:---------:|:------:|:-------:|:-------:|
| Zero code changes | ✅ | — | — | ✅ | — | — |
| Callback handler | ✅ | Manual | Manual | ✅ | Manual | Manual |
| Policy enforcement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DLP scanning | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Injection detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Audit chain | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Federation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
