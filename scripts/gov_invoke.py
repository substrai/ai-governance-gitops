#!/usr/bin/env python3
"""Call the gov-engine Lambda from a workflow step (credentials: gh-gov-engine via OIDC).

  python scripts/gov_invoke.py <action> [--agent NAME] [--manifest agents/NAME.yaml] [--pr N] [--run-id ID]
                               [--set key=value ...] [--outputs key1,key2]

Prints the engine's (already redacted) result, writes the requested keys to $GITHUB_OUTPUT and to the
job summary, and exits non-zero when the engine reports an error.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

import yaml


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action")
    ap.add_argument("--agent")
    ap.add_argument("--manifest")
    ap.add_argument("--pr", type=int)
    ap.add_argument("--run-id", type=int, default=int(os.environ.get("GITHUB_RUN_ID", "0")))
    ap.add_argument("--set", action="append", default=[], help="extra event fields, key=value")
    ap.add_argument("--outputs", default="")
    a = ap.parse_args()

    event = {"action": a.action, "run_id": a.run_id}
    if a.manifest:
        with open(a.manifest) as fh:
            event["manifest"] = yaml.safe_load(fh) or {}
        event["agent"] = event["manifest"].get("name")
    if a.agent:
        event["agent"] = a.agent
    if a.pr:
        event["pr"] = a.pr
    for kv in a.set:
        k, _, v = kv.partition("=")
        event[k] = v

    with tempfile.TemporaryDirectory() as d:
        payload, out = os.path.join(d, "in.json"), os.path.join(d, "out.json")
        with open(payload, "w") as fh:
            json.dump(event, fh)
        subprocess.run(["aws", "lambda", "invoke", "--function-name", "gov-engine", "--cli-binary-format", "raw-in-base64-out",
                        "--cli-read-timeout", "900", "--payload", f"fileb://{payload}", out], check=True, stdout=subprocess.DEVNULL)
        with open(out) as fh:
            result = json.load(fh)

    print(json.dumps(result, indent=2))
    text = result.get("error") or result.get("errorMessage") or result.get("summary") or result.get("message") or ""
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(f"### `{a.action}`\n\n{text}\n\n")
            if "allowed" in result:
                fh.write(f"**Allowed** ({result['allowed']['caller']} → {result['allowed']['target']}):\n\n"
                         f"> {result['allowed']['answer']}\n\n**Denied** ({result['denied']['caller']} → "
                         f"{result['denied']['target']}): HTTP {result['denied']['status']}\n\n`{result['denied']['body']}`\n\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            for k in filter(None, a.outputs.split(",")):
                fh.write(f"{k}={result.get(k, '')}\n")
    if "error" in result or "errorMessage" in result:
        print(f"::error::{text}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
