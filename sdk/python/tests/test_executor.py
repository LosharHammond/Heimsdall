"""ProtectedExecutor against a real Heimdall server: online path, approvals, fast path, revocation, integrity."""
import asyncio
import copy
import time

import pytest

from heimdall import ExecutorRefusal, FastPath, HeimdallClient, ProtectedExecutor


def ran():
    calls = []

    def handler(action):
        calls.append(action)
        return f"ran {action['operation']} {action['resource']}"

    return calls, handler


def test_online_allow_deny_and_unknown_tool(server):
    client = HeimdallClient(server.url, server.api_key)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h})
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/handbook.txt"})
    assert r.status == "executed" and r.result == "ran read docs/handbook.txt" and not r.local
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/secret/k.txt"})
    assert r.status == "denied" and r.reason_code == "EXPLICIT_DENY" and not r.executed
    r = ex.run({"tool": "documents", "operation": "command_execution", "resource": "docs/x"})
    assert r.reason_code == "EXPLICIT_DENY"
    r = ex.run({"tool": "nope", "operation": "read", "resource": "x"})
    assert r.reason_code == "NO_HANDLER"
    assert len(calls) == 1
    rows = server.control("actions")["items"]
    assert {(x["resource"], x["decision"]) for x in rows} >= {("docs/handbook.txt", "allow"), ("docs/secret/k.txt", "deny")}


def test_approval_waits_then_runs_once(server):
    client = HeimdallClient(server.url, server.api_key)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h})
    a = {"tool": "documents", "operation": "delete", "resource": "docs/old.txt"}
    r = ex.run(a, request_id="req_py_delete_0000001")
    assert r.status == "pending_approval" and r.approval_id and not calls
    server.control("approve", {"approval_id": r.approval_id})
    r = ex.run(a, request_id="req_py_delete_0000001")
    assert r.status == "executed" and len(calls) == 1
    r = ex.run(a, request_id="req_py_delete_0000001")
    assert r.status == "denied" and len(calls) == 1  # the approval is used up


def test_service_down_fails_closed():
    calls, h = ran()
    ex = ProtectedExecutor(HeimdallClient("http://127.0.0.1:9", "hdk_x", timeout=0.5, max_retries=0), {"documents": h})
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/a"})
    assert r.status == "not_authorized" and r.reason_code == "UNAVAILABLE" and not calls


def test_handler_cannot_change_what_was_authorized(server):
    client = HeimdallClient(server.url, server.api_key)
    seen = []

    def sneaky(action):
        action["resource"] = "docs/secret/k.txt"  # mutating its copy changes nothing recorded or decided
        seen.append(action)
        return "ok"

    ex = ProtectedExecutor(client, {"documents": sneaky})
    original = {"tool": "documents", "operation": "read", "resource": "docs/a.txt"}
    keep = copy.deepcopy(original)
    assert ex.run(original).status == "executed"
    assert original == keep


def test_verify_hook_refuses_before_the_permit(server):
    client = HeimdallClient(server.url, server.api_key)
    calls, h = ran()

    def verify(action):
        raise ExecutorRefusal("PATH_OUTSIDE_ROOT", "outside the protected folder")

    ex = ProtectedExecutor(client, {"documents": h}, verify=verify)
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/a.txt"})
    assert r.status == "denied" and r.reason_code == "EXECUTOR_PATH_OUTSIDE_ROOT" and not calls


def fast_setup(server, **kw):
    client = HeimdallClient(server.url, server.api_key)
    fp = FastPath(client, public_key_pem=server.public_key_pem, refresh_s=3600, check_s=3600, flush_s=3600, **kw)
    assert fp.start() == "ready"
    return client, fp


def test_fast_path_decides_locally_and_syncs_in_background(server, monkeypatch):
    client, fp = fast_setup(server)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h}, fast_path=fp)
    net = []
    orig = client._call
    monkeypatch.setattr(client, "_call", lambda *a, **k: (net.append(a[1]), orig(*a, **k))[1])
    t0 = time.perf_counter()
    r1 = ex.run({"tool": "documents", "operation": "read", "resource": "docs/handbook.txt"})
    r2 = ex.run({"tool": "documents", "operation": "read", "resource": "docs/secret/k.txt"})
    elapsed = time.perf_counter() - t0
    assert r1.status == "executed" and r1.local and r2.status == "denied" and r2.local
    assert net == []  # nothing on the agent's path touched the network
    assert elapsed < 0.05
    fp.flush()
    assert net == ["/v1/offline-sync"]
    assert fp.stats()["sent"] == 2 and fp.stats()["mismatches"] == 0
    rows = {x["resource"]: x for x in server.control("actions")["items"]}
    assert rows["docs/handbook.txt"]["source"] == "local_fast" and rows["docs/secret/k.txt"]["decision"] == "deny"


def test_fast_path_sends_approvals_and_unusual_destinations_online(server):
    client, fp = fast_setup(server)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h, "send_report": h}, fast_path=fp)
    r = ex.run({"tool": "documents", "operation": "delete", "resource": "docs/old.txt"})
    assert r.status == "pending_approval" and not r.local
    r = ex.run({"tool": "send_report", "operation": "external_transfer", "resource": "r.pdf", "destination": "https://partner.example.com/in"})
    assert r.status == "executed" and r.local
    r = ex.run({"tool": "send_report", "operation": "external_transfer", "resource": "r.pdf", "destination": "https://0x7f.1/in"})
    assert r.status == "denied" and not r.local  # decided by the server's URL parser


def test_fast_path_policy_change_and_revocation(server):
    client, fp = fast_setup(server)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h}, fast_path=fp)
    assert ex.run({"tool": "documents", "operation": "read", "resource": "docs/a"}).status == "executed"
    server.control("policy", {"document": {"schema_version": 1, "rules": []}})
    fp.check_state()
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/a"})
    assert r.status == "denied" and r.reason_code == "NO_MATCHING_RULE" and r.local
    server.control("revoke")
    assert fp.check_state() == "revoked"
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/a"})
    assert r.status == "not_authorized" and not r.executed


def test_fast_path_refuses_tampered_and_rolled_back_bundles(server):
    client, fp = fast_setup(server)
    signed = client.get_policy_bundle()
    evil = copy.deepcopy(signed)
    evil["bundle"]["document"]["rules"].insert(0, {"id": "evil", "effect": "allow", "match": {"tools": ["*"], "operations": ["command_execution"]}})
    assert fp.accept(evil) == (False, "BAD_SIGNATURE")
    server.control("policy", {})
    assert fp.refresh() == "ready"
    assert fp.accept(signed) == (False, "ROLLBACK")


def test_fast_path_queue_full_refuses_instead_of_running_unrecorded(server):
    client, fp = fast_setup(server, max_queue=1)
    calls, h = ran()
    ex = ProtectedExecutor(client, {"documents": h}, fast_path=fp)
    assert ex.run({"tool": "documents", "operation": "read", "resource": "docs/a"}).status == "executed"
    r = ex.run({"tool": "documents", "operation": "read", "resource": "docs/b"})
    assert r.reason_code == "AUDIT_QUEUE_FULL" and len(calls) == 1


def test_async_handlers(server):
    client, fp = fast_setup(server)

    async def h(action):
        await asyncio.sleep(0)
        return "async ok"

    ex = ProtectedExecutor(client, {"documents": h}, fast_path=fp)
    r = asyncio.run(ex.arun({"tool": "documents", "operation": "read", "resource": "docs/a"}))
    assert r.status == "executed" and r.result == "async ok"
    ex2 = ProtectedExecutor(client, {"documents": h})
    assert ex2.run({"tool": "documents", "operation": "read", "resource": "docs/a"}).result == "async ok"
