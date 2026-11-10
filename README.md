# AI governance with no UI — through GitHub CI/CD

AI agents are requested, approved, built, released, changed, reviewed, suspended and retired
**only through this repository**. Nobody uses the AWS console: GitHub workflows reach AWS with
short-lived OIDC credentials, approvals are GitHub environment gates, and notifications are GitHub emails.

## Layout

| Path | What it is |
| --- | --- |
| `infra/` | AWS CDK app (Python): the governance stack — engine, state, evidence, events, controls |
| `engine/` | `gov-engine` Lambda source and unit tests |
| `agents/` | One YAML file per governed agent (requests and changes arrive as pull requests) |
| `config/` | `example.json` only. Real values are never committed (see below) |
| `scripts/` | Engine packaging and the public-repo check |
| `.github/workflows/` | CI now; infra and governance pipelines in later phases |

## Configuration — nothing account-specific in this repo

This repository is public. The AWS account ID and resource IDs (registry, guardrails, gateway,
policy engine) live outside it:

* **CI/CD:** the workflow loads them from AWS (SSM Parameter Store) after authenticating with OIDC.
* **Local:** copy `config/example.json` to `config/local.json` (git-ignored) and fill it in.

`scripts/check_public.py` fails the build if an account ID, a configured resource ID, a key or a
non-example email address appears in any committed file.

## Local checks

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/check_public.py
ruff check infra engine scripts
pytest -q
./scripts/build_engine.sh
cd infra && GOV_CONFIG=config/example.json cdk synth --quiet
```

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 0–1 | Code in the repo, parameterised config, credential-free CI | done |
| 2 | Spikes: GitHub App approvals, A2A through the gateway | done |
| 3 | One-time OIDC bootstrap (`GitHubBootstrap`) | done |
| 4 | Infra pipeline: `infra-plan` (redacted diff on PRs), `infra-deploy` (main, behind `infra-prod`) | this change |
| 5–7 | Role bots, engine changes, governance workflows | planned |
| 8–9 | Cutover, demo video | planned |
