"""
OpenAI Agents SDK: protect any FunctionTool with Heimdall.

    from agents import Agent, function_tool
    from heimdall.integrations.openai_agents import protect, protected_function_tool

    @function_tool
    def send_report(url: str, path: str) -> str: ...

    agent = Agent(name="ops", tools=[
        protect(send_report, executor, operation="external_transfer", resource="{path}", destination="{url}"),
    ])

    # or in one step
    @protected_function_tool(executor, operation="read", resource="docs/{path}")
    def read_doc(path: str) -> str: ...

The protected tool is a copy of the original (same name, description, JSON schema, guardrails and settings) whose
invocation goes through ProtectedExecutor.arun. A refusal is returned to the model as text by default; on_denied="raise"
raises HeimdallDenied, which the Agents SDK reports as a tool error.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable, Literal, Optional

from agents import FunctionTool, function_tool

from ..executor import ProtectedExecutor, RunResult
from . import ActionPart, build_action


class HeimdallDenied(Exception):
    def __init__(self, result: RunResult):
        super().__init__(result.message())
        self.result = result


def protect(
    tool: FunctionTool,
    executor: ProtectedExecutor,
    *,
    operation: str,
    resource: ActionPart = None,
    destination: ActionPart = None,
    data_classification: Optional[str] = None,
    heimdall_tool: Optional[str] = None,
    on_denied: Literal["message", "raise"] = "message",
    wait_for_approval_s: float = 0,
) -> FunctionTool:
    name = (heimdall_tool or tool.name).lower()
    original = tool.on_invoke_tool

    async def on_invoke(ctx: Any, input_json: str) -> Any:
        try:
            args = json.loads(input_json) if input_json else {}
        except ValueError:
            args = {}
        if not isinstance(args, dict):
            args = {"input": args}
        action = build_action(name, operation, args, resource, destination, data_classification)
        r = await executor.arun(action, handler=lambda _a: original(ctx, input_json), wait_for_approval_s=wait_for_approval_s)
        if r.status == "executed":
            return r.result
        if on_denied == "raise":
            raise HeimdallDenied(r)
        return r.message()

    return dataclasses.replace(tool, on_invoke_tool=on_invoke)


def protected_function_tool(executor: ProtectedExecutor, **heimdall: Any) -> Callable[[Callable[..., Any]], FunctionTool]:
    """Decorator: @protected_function_tool(executor, operation=..., resource=...) on a plain function."""

    def wrap(fn: Callable[..., Any]) -> FunctionTool:
        return protect(function_tool(fn), executor, **heimdall)

    return wrap
