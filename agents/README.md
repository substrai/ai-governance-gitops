# agents/

One YAML file per governed AI agent. **Pull requests that change a file here are how agents are
governed**: open a PR from a branch named `gov/<agent>/<step>` that changes exactly one file.
The `gov-agent` workflow asks the engine to plan the step, posts the result on the PR, and waits
at that step's gate until the owning role bot decides. Comment on the PR:

* `/approve <role> <note>` or `/reject <role> <reason>`

| Set `status:` to | Step | Gate (role) |
| --- | --- | --- |
| `requested` (new file) | Intake: risk is scored | `gov-intake` (security) |
| `build` | Identity, role, guardrail, policies, gateway, registry draft | `gov-build` (platform) |
| `release` | Release gates checked live, then registry approval | `gov-release` (security) |
| `active` + new `version` + `change:` | Change: PROMPT (and MODEL on LOW risk) is pre-approved; TOOL, PERMISSION, DATA_SOURCE need approval | `gov-change` (security) |
| `retired` + `retire:` | Retirement: owned resources removed in order | `gov-retire` (admin) |

Separation of duties: a role cannot approve a step for an agent where it is the requester, owner,
submitter, or change/retirement requester. Manual workflows cover periodic review (`gov-review`),
suspension (`gov-suspend`), the A2A demonstration (`a2a-demo`) and audit queries (`audit`).

This repository is public: never put account IDs, resource IDs or organisation names in these files.
Guardrails are referenced by neutral names: `guest-facing`, `employee-data`, `finance`.
See `_template.yaml.txt` for every field.
