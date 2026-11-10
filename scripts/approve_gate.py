#!/usr/bin/env python3
"""Approve or reject a workflow run waiting at an environment gate, acting as a GitHub App.

Interim operator tool until the engine's comment command (Phase 5) does this. The App's private
key never enters the repository: it is read from ~/.config/ai-governance-gitops/apps/<app>.pem.

  python scripts/approve_gate.py <run-id> <environment> approve|reject "<comment>" [--app <slug>]
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import time
import urllib.error
import urllib.request

import certifi
import jwt

REPO = os.environ.get("GOV_REPO", "substrai/ai-governance-gitops")
APPS = os.path.expanduser("~/.config/ai-governance-gitops/apps")
CTX = ssl.create_default_context(cafile=certifi.where())


def call(method: str, path: str, token: str, body: dict | None = None):
    req = urllib.request.Request("https://api.github.com" + path, method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "User-Agent": "ai-gov", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        r = urllib.request.urlopen(req, context=CTX)
        data = r.read()
        return r.status, (json.loads(data) if data else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("environment")
    ap.add_argument("decision", choices=["approve", "reject"])
    ap.add_argument("comment")
    ap.add_argument("--app", default="ai-gov-approval-spike")
    a = ap.parse_args()
    meta = json.load(open(f"{APPS}/{a.app}.json"))
    pem = open(f"{APPS}/{a.app}.pem").read()
    now = int(time.time())
    app_jwt = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(meta["id"])}, pem, algorithm="RS256")
    _, inst = call("GET", f"/repos/{REPO}/installation", app_jwt)
    _, tok = call("POST", f"/app/installations/{inst['id']}/access_tokens", app_jwt,
                  {"repositories": [REPO.split("/")[1]]})
    status, body = call("POST", f"/repos/{REPO}/actions/runs/{a.run_id}/deployment_protection_rule", tok["token"],
                        {"environment_name": a.environment, "state": "approved" if a.decision == "approve" else "rejected",
                         "comment": a.comment})
    print(f"{a.decision} as {meta['slug']}[bot] on {a.environment} (run {a.run_id}): HTTP {status}", body or "")


if __name__ == "__main__":
    main()
