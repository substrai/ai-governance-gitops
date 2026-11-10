#!/usr/bin/env python3
"""Handle the private deployment config inside CI without ever exposing it.

  fetch   read /ai-gov/config from SSM (current AWS credentials), write config/local.json,
          and register every private value with GitHub's log masking (::add-mask::)
  redact  read text on stdin, replace every private value with ***, write to stdout
          (used before posting anything, such as a cdk diff, to this public repository)
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "config" / "local.json"
PARAMETER = "/ai-gov/config"


def private_values(cfg: dict) -> list[str]:
    """Every value that identifies the account or the organisation (longest first)."""
    vals: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and len(v) >= 4 and not re.fullmatch(r"[a-z]{2}-[a-z]+-\d|\d{1,3}", v):
            vals.add(v)

    walk({k: v for k, v in cfg.items() if k not in ("region", "githubRepo")})
    walk(list(cfg.get("guardrails", {})))  # guardrail profile names are keys, not values
    for term in cfg.get("blockedTerms", []):
        vals.update({term, term.capitalize(), term.upper()})
    return sorted(vals, key=len, reverse=True)


def fetch() -> None:
    raw = subprocess.run(["aws", "ssm", "get-parameter", "--name", PARAMETER, "--query", "Parameter.Value", "--output", "text"],
                         capture_output=True, text=True, check=True).stdout
    cfg = json.loads(raw)
    for v in private_values(cfg):
        print(f"::add-mask::{v}")
    LOCAL.write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"Wrote {LOCAL.relative_to(ROOT)} ({len(cfg)} keys); private values masked in logs.")


def redact() -> None:
    cfg = json.loads(LOCAL.read_text())
    text = sys.stdin.read()
    for v in private_values(cfg):
        text = re.sub(re.escape(v), "***", text, flags=re.IGNORECASE)
    sys.stdout.write(text)


if __name__ == "__main__":
    {"fetch": fetch, "redact": redact}[sys.argv[1]]()
