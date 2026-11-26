import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class Server:
    def __init__(self, info: dict, proc: subprocess.Popen):
        self.url, self.api_key, self.agent_id, self.public_key_pem = info["url"], info["api_key"], info["agent_id"], info["public_key_pem"]
        self.proc = proc

    def control(self, what: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(f"{self.url}/__test/{what}", data=json.dumps(body or {}).encode(), method="POST", headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())


@pytest.fixture()
def server():
    """A fresh Heimdall server (real app, embedded database) per test."""
    proc = subprocess.Popen(["npx", "tsx", "scripts/py-test-server.ts"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=os.name == "nt")
    line = proc.stdout.readline()
    if not line:
        proc.kill()
        raise RuntimeError("test server did not start: " + proc.stderr.read())
    s = Server(json.loads(line), proc)
    yield s
    proc.kill()
    proc.wait()
