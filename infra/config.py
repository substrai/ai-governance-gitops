"""Deployment configuration for the governance stacks.

Nothing account-specific lives in this public repository. Values come from a JSON file:

* locally: ``config/local.json`` (git-ignored; copy ``config/example.json`` and fill it in)
* in CI/CD: written by the workflow from SSM Parameter Store before ``cdk synth``
* for credential-free checks (lint, unit tests, example synth): ``config/example.json``

Select a file with the ``GOV_CONFIG`` environment variable.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILE = ROOT / "config" / "local.json"
EXAMPLE_FILE = ROOT / "config" / "example.json"


@dataclass(frozen=True)
class Naming:
    """Organisation-specific names. Live resource names come from here, so renaming in code never replaces resources."""
    display_name: str          # shown in descriptions and the dashboard
    project_tag: str           # value of the "project" tag
    bucket_prefix: str         # <prefix>-evidence-<account>, -athena-, -config-
    trail_name: str
    glue_database: str
    metric_namespace: str
    dashboard_name: str
    intended_users_default: str
    agent_endpoint_base: str   # default agent URL is <base>/<agent-name>

    @classmethod
    def from_dict(cls, d: dict) -> "Naming":
        return cls(display_name=d["displayName"], project_tag=d["projectTag"], bucket_prefix=d["bucketPrefix"],
                   trail_name=d["trailName"], glue_database=d["glueDatabase"], metric_namespace=d["metricNamespace"],
                   dashboard_name=d["dashboardName"], intended_users_default=d["intendedUsersDefault"],
                   agent_endpoint_base=d["agentEndpointBase"].rstrip("/"))


@dataclass(frozen=True)
class GovConfig:
    account: str
    region: str
    registry_id: str
    guardrails: dict[str, dict[str, str]]
    policy_engine: str
    gateway: str
    github_repo: str
    naming: Naming
    guardrail_defaults: dict[str, str]  # {"customerFacing": <profile>, "internal": <profile>}
    engine_asset: str = field(default=str(ROOT / "engine" / "build"))
    source_file: str = ""

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "GovConfig":
        file = Path(path or os.environ.get("GOV_CONFIG") or DEFAULT_FILE)
        if not file.is_absolute() and not file.exists():
            file = ROOT / file  # relative paths are taken from the repo root
        if not file.exists():
            raise SystemExit(f"Config file {file} not found. Copy config/example.json to config/local.json, "
                             "or set GOV_CONFIG=config/example.json for a credential-free synth.")
        raw = json.loads(file.read_text())
        cfg = cls(account=str(raw["account"]), region=raw["region"], registry_id=raw["registryId"],
                  guardrails=raw["guardrails"], policy_engine=raw["policyEngine"], gateway=raw["gateway"],
                  github_repo=raw["githubRepo"], naming=Naming.from_dict(raw["naming"]),
                  guardrail_defaults=raw["guardrailDefaults"],
                  engine_asset=str(ROOT / raw.get("engineAsset", "engine/build")), source_file=str(file))
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not re.fullmatch(r"\d{12}", self.account):
            raise SystemExit("config: account must be a 12-digit AWS account ID")
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", self.region):
            raise SystemExit("config: region looks wrong")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", self.github_repo):
            raise SystemExit("config: githubRepo must be owner/name")
        for key in ("customerFacing", "internal"):
            if self.guardrail_defaults.get(key) not in self.guardrails:
                raise SystemExit(f"config: guardrailDefaults.{key} must name one of the guardrails")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", self.naming.bucket_prefix):
            raise SystemExit("config: naming.bucketPrefix must be lowercase letters, digits and hyphens")
        for name, g in self.guardrails.items():
            if not {"id", "version"} <= set(g):
                raise SystemExit(f"config: guardrail {name} needs id and version")
