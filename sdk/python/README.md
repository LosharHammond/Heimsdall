# Kenuxa Heimdall — Python SDK

Decide what your AI agents may do, ask a person when it matters, and prove what really ran. Works with plain Python,
**LangChain** and the **OpenAI Agents SDK**.

```bash
pip install "kenuxa-heimdall[all]"            # or: [fast], [langchain], [openai-agents]
# from this repository:  pip install -e "sdk/python[all]"
```

## Protect a tool

```python
from heimdall import HeimdallClient, ProtectedExecutor, FastPath

client = HeimdallClient("https://heimdall.example.com", api_key="hdk_...")   # an agent key from the dashboard
fast = FastPath(client)            # optional: in-process decisions (needs the `fast` extra)
fast.start()                       # never raises; until a policy loads, calls use the service
executor = ProtectedExecutor(client, fast_path=fast)

r = executor.run({"tool": "documents", "operation": "delete", "resource": "docs/old.txt"}, handler=delete_file)
if r.executed:
    print(r.result)
else:
    print(r.status, r.reason_code, r.explanation)   # denied | pending_approval | not_authorized
```

`operation` is one of `read`, `create`, `update`, `delete`, `external_transfer`, `command_execution`. Add `destination`
(a URL) for transfers and, if you know it, `data_classification`. Use `await executor.arun(...)` in async code.

What happens on each call:

| Policy says | Fast path on | Fast path off |
| --- | --- | --- |
| allow | decided in-process (microseconds), handler runs, audit sent in the background | authorize, one-time claim, handler runs, outcome reported |
| deny | refused at once, nothing runs | refused, nothing runs |
| require approval | sent to the service: `pending_approval` until a person approves; then it runs once | same |

If the service cannot be reached, the online path **fails closed**: the handler does not run.

## LangChain

```python
from heimdall.integrations.langchain import protect_tool, protect_tools

safe_read = protect_tool(read_doc, executor, operation="read", resource="docs/{path}")
safe_send = protect_tool(send_email, executor, operation="external_transfer", resource="mail/{to}", destination="{to_domain}")
agent = create_agent(model, tools=[safe_read, safe_send])

# or all at once; a tool without a rule is refused, so nothing is left unprotected by accident
tools = protect_tools([read_doc, delete_doc], executor, {
    "read_doc":   {"operation": "read",   "resource": "docs/{path}"},
    "delete_doc": {"operation": "delete", "resource": "docs/{path}"},
})
```

## OpenAI Agents SDK

```python
from agents import Agent, function_tool
from heimdall.integrations.openai_agents import protect, protected_function_tool

@function_tool
def send_report(url: str, path: str) -> str: ...

@protected_function_tool(executor, operation="read", resource="docs/{path}")
def read_doc(path: str) -> str: ...

agent = Agent(name="ops", tools=[read_doc, protect(send_report, executor, operation="external_transfer", resource="{path}", destination="{url}")])
```

In both integrations the protected tool keeps its name, description and argument schema, so the model sees no change.
When Heimdall refuses, the model receives a one-line explanation (for example *"Blocked by Heimdall (EXPLICIT_DENY): ..."*
or *"needs a person's approval"*) instead of the tool's result. Pass `on_denied="raise"` to raise `HeimdallDenied`.

`resource` and `destination` can be a fixed string, a template filled from the tool's arguments (`"docs/{path}"`), or a
function `lambda args: ...`. `heimdall_tool=` sets the tool name policies match (default: the tool's own name, lowercased).

## Guarantees and limits

- Same policy engine as the server, ported and checked against it on thousands of generated cases
  (`tests/test_policy_parity.py`). Destinations whose host is not a plain DNS name (raw IPs, punycode, user:password@...) are
  never decided locally: they go to the service.
- Fast path: same trade-offs as the TypeScript SDK (docs/FAST-PATH.md): policy changes and revocation apply within the
  2-second check; budgets and one-time permits are per process; call `fast.stop()` on shutdown to send the last records.
- The handler receives a private copy of the action: changing it cannot change what was authorized or recorded.
- Only tools executed through the executor are protected (docs/EXECUTOR-BOUNDARY.md).

## Tests

```bash
cd sdk/python && pip install -e ".[test]" && pytest      # starts a real Heimdall server for each test (needs Node + npm install at the repo root)
```
