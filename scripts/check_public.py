#!/usr/bin/env python3
"""Fail if a file that would be committed contains something that must not be public.

Checks every file git would commit (tracked + untracked, not ignored):
  * any 12-digit AWS account ID, except documented placeholders
  * any value from config/local.json (registry, guardrail, gateway and policy-engine IDs)
  * access-key, private-key and API-key shaped strings
  * email addresses outside example domains
  * any term listed in config/local.json "blockedTerms" (e.g. the organisation name), case-insensitive
Run before every push; CI runs it on every pull request.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER_ACCOUNTS = {"111111111111", "123456789012", "000000000000"}
PATTERNS = {
    "aws-access-key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "elevenlabs-key": re.compile(r"\bsk_[a-f0-9]{40,}\b"),
}
ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "users.noreply.github.com", "anthropic.com"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip"}


def files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / f for f in out if (ROOT / f).is_file() and Path(f).suffix.lower() not in SKIP_SUFFIXES]


def secret_values() -> set[str]:
    local = ROOT / "config" / "local.json"
    if not local.exists():
        return set()
    vals: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, str) and len(v) >= 8 and not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", v) and "/" not in v:
            vals.add(v)

    walk(json.loads(local.read_text()))
    return vals


def blocked_terms() -> list[str]:
    """From config/local.json locally, or the GOV_BLOCKED_TERMS secret (comma-separated) in CI."""
    terms = [t.strip() for t in os.environ.get("GOV_BLOCKED_TERMS", "").split(",")]
    local = ROOT / "config" / "local.json"
    if local.exists():
        terms += json.loads(local.read_text()).get("blockedTerms", [])
    return sorted({t.lower() for t in terms if t})


def main() -> int:
    problems = []
    secrets = secret_values()
    terms = blocked_terms()
    for path in files():
        rel = path.relative_to(ROOT)
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for name, rx in PATTERNS.items():
                if rx.search(line):
                    problems.append(f"{rel}:{n}: {name}")
            for acct in ACCOUNT.findall(line):
                if acct not in PLACEHOLDER_ACCOUNTS:
                    problems.append(f"{rel}:{n}: 12-digit number (AWS account ID?)")
            for m in EMAIL.finditer(line):
                if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS and not m.group(0).lower().startswith("noreply@"):
                    problems.append(f"{rel}:{n}: email address outside example domains")
            for s in secrets:
                if s in line:
                    problems.append(f"{rel}:{n}: value from config/local.json")
            low = line.lower()
            for term in terms:
                if term in low:
                    problems.append(f"{rel}:{n}: blocked term (organisation name or similar)")
    if problems:
        print("Public-repo check FAILED:")
        print("\n".join(f"  {p}" for p in sorted(set(problems))))
        return 1
    print(f"Public-repo check passed ({len(files())} files, {len(terms)} blocked terms).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
