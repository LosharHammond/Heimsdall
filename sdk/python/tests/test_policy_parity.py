"""The Python engine must make the same decision as the server's engine on every case the server's engine generated."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from heimdall._canon import action_digest
from heimdall.policy import NEEDS_SERVER, evaluate

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def corpus():
    path = os.environ.get("HEIMDALL_CORPUS")
    if path:
        return json.loads(Path(path).read_text())
    out = subprocess.run(["npx", "tsx", "scripts/policy-corpus.ts"], cwd=ROOT, capture_output=True, text=True, check=True, shell=os.name == "nt")
    return json.loads(out.stdout)


def test_decisions_match_the_server_engine(corpus):
    decided = deferred = 0
    mismatches = []
    for c in corpus["cases"]:
        got = evaluate(c["policy"], c["action"], c["ctx"]["allowedInWindow"], c["ctx"]["hasValidApproval"])
        if got is NEEDS_SERVER:
            deferred += 1  # the fast path sends these to the service: never a wrong local decision
            continue
        decided += 1
        exp = c["expected"]
        for k in ("decision", "reason_code", "matched_rule_id", "explanation", "classification", "approval"):
            if got.get(k) != exp.get(k):
                mismatches.append((k, c["action"], got.get(k), exp.get(k)))
                break
    assert not mismatches, mismatches[:5]
    assert decided > 0.7 * len(corpus["cases"]), (decided, deferred)


PLAIN = {None, "partner.example.com", "https://partner.example.com/in", "http://partner.example.com:8443/x?y=1#z", "https://evil.example.org",
         "https://a.files.example.com/up", "https://files.example.com", "ftp://partner.example.com", "https://PARTNER.EXAMPLE.COM.", "localhost",
         "not a url"}


def test_only_unusual_destinations_go_to_the_server(corpus):
    for c in corpus["cases"]:
        if c["action"].get("destination") in PLAIN:
            assert evaluate(c["policy"], c["action"], c["ctx"]["allowedInWindow"], c["ctx"]["hasValidApproval"]) is not NEEDS_SERVER, c["action"]


def test_action_digests_match(corpus):
    for d in corpus["digests"]:
        assert action_digest(d["action"]) == d["digest"], d["action"]
