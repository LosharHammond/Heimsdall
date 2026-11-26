"""
LangChain: protect any tool (BaseTool, @tool, StructuredTool) with Heimdall.

    from heimdall.integrations.langchain import protect_tool
    safe_delete = protect_tool(delete_file, executor, operation="delete", resource="docs/{path}")
    agent = create_agent(model, tools=[safe_read, safe_delete])

The protected tool keeps the original name, description and argument schema, so the model sees no difference. When Heimdall
refuses (or the action waits for a person), the tool returns a short explanation the model can act on, instead of running.
Pass on_denied="raise" to raise HeimdallDenied instead.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from langchain_core.tools import BaseTool, StructuredTool

from ..executor import ProtectedExecutor, RunResult
from . import ActionPart, build_action


class HeimdallDenied(Exception):
    def __init__(self, result: RunResult):
        super().__init__(result.message())
        self.result = result


def protect_tool(
    tool: BaseTool,
    executor: ProtectedExecutor,
    *,
    operation: str,
    resource: ActionPart = None,
    destination: ActionPart = None,
    data_classification: Optional[str] = None,
    heimdall_tool: Optional[str] = None,
    on_denied: Literal["message", "raise"] = "message",
    wait_for_approval_s: float = 0,
) -> StructuredTool:
    """heimdall_tool: the tool name policies match (default: the LangChain tool name, lowercased)."""
    name = (heimdall_tool or tool.name).lower()

    def outcome(r: RunResult) -> Any:
        if r.status == "executed":
            return r.result
        if on_denied == "raise":
            raise HeimdallDenied(r)
        return r.message()

    def run(**kwargs: Any) -> Any:
        action = build_action(name, operation, kwargs, resource, destination, data_classification)
        return outcome(executor.run(action, handler=lambda _a: tool.invoke(kwargs), wait_for_approval_s=wait_for_approval_s))

    async def arun(**kwargs: Any) -> Any:
        action = build_action(name, operation, kwargs, resource, destination, data_classification)
        return outcome(await executor.arun(action, handler=lambda _a: tool.ainvoke(kwargs), wait_for_approval_s=wait_for_approval_s))

    return StructuredTool.from_function(
        func=run, coroutine=arun, name=tool.name, description=tool.description, args_schema=tool.args_schema,
        return_direct=tool.return_direct, infer_schema=False,
    )


def protect_tools(tools: list[BaseTool], executor: ProtectedExecutor, rules: dict[str, dict]) -> list[StructuredTool]:
    """Protect several tools at once: rules maps each tool name to protect_tool keyword arguments. A tool without a rule is refused."""
    missing = [t.name for t in tools if t.name not in rules]
    if missing:
        raise ValueError(f"No Heimdall rule for tool(s): {', '.join(missing)}. Every tool must say what it does (operation, resource).")
    return [protect_tool(t, executor, **rules[t.name]) for t in tools]
