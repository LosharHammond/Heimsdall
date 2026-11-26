"""LangChain and OpenAI Agents SDK tools protected by Heimdall, against a real server."""
import asyncio
import json

from agents import function_tool
from agents.tool_context import ToolContext
from langchain_core.tools import tool

from heimdall import FastPath, HeimdallClient, ProtectedExecutor
from heimdall.integrations.langchain import HeimdallDenied, protect_tool, protect_tools
from heimdall.integrations.openai_agents import protect, protected_function_tool


def executor(server, fast=False):
    client = HeimdallClient(server.url, server.api_key)
    fp = None
    if fast:
        fp = FastPath(client, public_key_pem=server.public_key_pem, refresh_s=3600, check_s=3600, flush_s=3600)
        fp.start()
    return ProtectedExecutor(client, fast_path=fp)


def test_langchain_tools(server):
    ran = []

    @tool
    def read_doc(path: str) -> str:
        """Read a document."""
        ran.append(path)
        return f"contents of {path}"

    @tool
    def delete_doc(path: str) -> str:
        """Delete a document."""
        ran.append(("deleted", path))
        return "deleted"

    ex = executor(server, fast=True)
    safe_read = protect_tool(read_doc, ex, operation="read", resource="docs/{path}")
    safe_delete = protect_tool(delete_doc, ex, operation="delete", resource="docs/{path}", heimdall_tool="documents")
    assert safe_read.name == "read_doc" and safe_read.description == read_doc.description
    assert safe_read.args == read_doc.args  # the model sees the same tool
    assert safe_read.invoke({"path": "handbook.txt"}) == "contents of handbook.txt"
    out = safe_read.invoke({"path": "secret/k.txt"})
    assert out.startswith("Blocked by Heimdall (EXPLICIT_DENY)")
    out = safe_delete.invoke({"path": "old.txt"})
    assert "needs a person's approval" in out
    assert ran == ["handbook.txt"]
    assert asyncio.run(safe_read.ainvoke({"path": "a.txt"})) == "contents of a.txt"
    strict = protect_tool(read_doc, ex, operation="read", resource="docs/{path}", on_denied="raise")
    try:
        strict.invoke({"path": "secret/k.txt"})
        raise AssertionError("should have raised")
    except HeimdallDenied as e:
        assert e.result.reason_code == "EXPLICIT_DENY"
    try:
        protect_tools([read_doc, delete_doc], ex, {"read_doc": {"operation": "read", "resource": "docs/{path}"}})
        raise AssertionError("should have refused an unprotected tool")
    except ValueError as e:
        assert "delete_doc" in str(e)


def test_openai_agents_tools(server):
    ran = []

    @function_tool
    def send_report(url: str, path: str) -> str:
        """Send a report to a partner."""
        ran.append(url)
        return f"sent {path}"

    ex = executor(server, fast=True)
    safe = protect(send_report, ex, operation="external_transfer", resource="{path}", destination="{url}")
    assert safe.name == send_report.name and safe.params_json_schema == send_report.params_json_schema

    async def call(t, args):
        ctx = ToolContext(context=None, tool_name=t.name, tool_call_id="call_1", tool_arguments=json.dumps(args))
        return await t.on_invoke_tool(ctx, json.dumps(args))

    assert asyncio.run(call(safe, {"url": "https://partner.example.com/in", "path": "q3.pdf"})) == "sent q3.pdf"
    out = asyncio.run(call(safe, {"url": "https://evil.example.org/x", "path": "q3.pdf"}))
    assert out.startswith("Blocked by Heimdall (DESTINATION_NOT_APPROVED)")
    assert ran == ["https://partner.example.com/in"]

    @protected_function_tool(ex, operation="read", resource="docs/{path}")
    def read_doc(path: str) -> str:
        """Read a document."""
        return f"contents of {path}"

    assert asyncio.run(call(read_doc, {"path": "a.txt"})) == "contents of a.txt"
    assert asyncio.run(call(read_doc, {"path": "secret/k.txt"})).startswith("Blocked by Heimdall")
