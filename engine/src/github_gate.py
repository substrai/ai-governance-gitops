"""GitHub side of the governance engine: role bots (GitHub Apps) and gate decisions.

A person types `/approve <role> [note]` or `/reject <role> <reason>` on an issue or pull request.
The gov-command workflow passes only the comment ID here. The engine then:

1. re-reads the comment from GitHub as the engine bot (never trusts what the workflow passes),
2. checks that the author is an allowed operator,
3. finds the workflow runs waiting at an environment gate (`run=<id>` in the comment, or the
   pull request's head commit),
4. approves or rejects each gate that belongs to the named role, as that role's bot, and
5. replies on the thread with what happened.

Each bot's credentials live in Secrets Manager at <prefix><role> as {"appId": ..., "privateKey": ...}.
Tokens are always scoped to this one repository.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

import boto3
import jwt

REPO = os.environ.get("GITHUB_REPO", "")
SECRET_PREFIX = os.environ.get("GITHUB_APP_SECRET_PREFIX", "ai-gov/github-app/")
OPERATORS = {o.strip().lower() for o in os.environ.get("GOV_OPERATORS", "").split(",") if o.strip()}
API = "https://api.github.com"

# Which role bot guards which environment gate.
GATE_ROLE = {
    "gov-intake": "security", "gov-release": "security", "gov-change": "security", "gov-suspend": "security",
    "gov-build": "platform", "gov-review": "owner", "gov-retire": "admin", "infra-prod": "admin",
    "gov-audit": "auditor",
}
ROLES = {"security", "platform", "admin", "owner", "auditor"}
PAST = {"approve": "approved", "reject": "rejected"}
COMMAND = re.compile(r"^/(approve|reject)\s+([a-z]+)\b(.*)$", re.I | re.S)

_secrets = None
_tokens: dict[str, tuple[str, float]] = {}


class GateError(Exception):
    """A gate command could not be carried out; the message is shown to people."""


def parse_command(body: str) -> tuple[str, str, str, int | None]:
    """'/approve security looks good run=123' -> ('approve', 'security', 'looks good', 123)."""
    m = COMMAND.match((body or "").strip())
    if not m:
        raise GateError("Not a gate command. Use `/approve <role> [note]` or `/reject <role> <reason>`.")
    decision, role, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
    if role not in ROLES:
        raise GateError(f"Unknown role `{role}`. Roles: {', '.join(sorted(ROLES))}.")
    run = re.search(r"\brun=(\d+)\b", rest)
    note = re.sub(r"\brun=\d+\b", "", rest).strip()
    if decision == "reject" and not note:
        raise GateError("A rejection needs a reason: `/reject <role> <reason>`.")
    return decision, role, note, int(run.group(1)) if run else None


def _http(method: str, path: str, token: str, body: dict | None = None, auth: str = "Bearer"):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"{auth} {token}", "Accept": "application/vnd.github+json",
                                          "User-Agent": "ai-gov-engine", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = r.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        raise GateError(f"GitHub API {method} {path.split('?')[0]} failed: HTTP {e.code}") from e


def bot_token(role: str) -> tuple[str, str]:
    """Installation token for a role bot, scoped to this repository. Returns (token, bot login)."""
    global _secrets
    cached = _tokens.get(role)
    if cached and cached[1] > time.time() + 120:
        return cached[0], f"{_slug(role)}[bot]"
    _secrets = _secrets or boto3.client("secretsmanager")
    cred = json.loads(_secrets.get_secret_value(SecretId=SECRET_PREFIX + role)["SecretString"])
    now = int(time.time())
    app_jwt = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(cred["appId"])}, cred["privateKey"], algorithm="RS256")
    inst = _http("GET", f"/repos/{REPO}/installation", app_jwt)
    tok = _http("POST", f"/app/installations/{inst['id']}/access_tokens", app_jwt, {"repositories": [REPO.split("/")[1]]})
    _tokens[role] = (tok["token"], now + 3300)
    return tok["token"], f"{_slug(role)}[bot]"


def _slug(role: str) -> str:
    return f"{REPO.split('/')[0]}-gov-{role}"


def engine_token() -> str:
    return bot_token("engine")[0]


def role_of_bot(login: str) -> str | None:
    """'substrai-gov-security[bot]' -> 'security'."""
    m = re.fullmatch(r".+-gov-([a-z]+)\[bot\]", login or "")
    return m.group(1) if m and m.group(1) in ROLES else None


def agent_of_run(run: dict) -> str | None:
    """Governance workflows name their runs '<stage> · <agent>'."""
    m = re.search(r"·\s*([a-z0-9][a-z0-9-]{2,47})\s*$", run.get("display_title") or run.get("name") or "")
    return m.group(1) if m else None


def get_run(run_id: int) -> dict:
    return _http("GET", f"/repos/{REPO}/actions/runs/{int(run_id)}", engine_token())


def gate_approval(run_id: int, env: str) -> dict:
    """The decision recorded at an environment gate of a run: {state, bot, role, comment}."""
    for a in _http("GET", f"/repos/{REPO}/actions/runs/{int(run_id)}/approvals", engine_token()) or []:
        if env in [x["name"] for x in a.get("environments", [])]:
            bot = a["user"]["login"]
            return {"state": a["state"], "bot": bot, "role": role_of_bot(bot), "comment": a.get("comment") or ""}
    raise GateError(f"Run {run_id} has no decision recorded at `{env}`.")


def pr_author(pr_number: int) -> tuple[str, dict]:
    pr = _http("GET", f"/repos/{REPO}/pulls/{int(pr_number)}", engine_token())
    return pr["user"]["login"], pr


def require_operator(login: str) -> str:
    if login.lower() not in OPERATORS:
        raise GateError(f"@{login} is not an allowed governance operator.")
    return login


def open_issue(title: str, body: str, labels: list[str]) -> int:
    issue = _http("POST", f"/repos/{REPO}/issues", engine_token(),
                  {"title": title[:240], "body": body[:60000], "labels": labels, "assignees": sorted(OPERATORS)})
    return issue["number"]


def comment(issue_number: int, body: str) -> None:
    _http("POST", f"/repos/{REPO}/issues/{int(issue_number)}/comments", engine_token(), {"body": body[:60000]})


def dispatch_workflow(workflow_file: str, inputs: dict) -> None:
    _http("POST", f"/repos/{REPO}/actions/workflows/{workflow_file}/dispatches", engine_token(),
          {"ref": "main", "inputs": {k: str(v) for k, v in inputs.items()}})


# Roles that must not decide a gate for an agent, from the roles recorded on the agent.
def forbidden_roles(env: str, st: dict) -> dict[str, str]:
    """{role: why} for the gate `env` and agent state `st` (empty when nothing applies)."""
    roles = st.get("roles") or {}
    pending = st.get("pendingChange") or {}
    retirement = st.get("retirement") or {}
    rules = {
        "gov-intake": {"requestedBy": roles.get("requestedBy")},
        "gov-release": {"owner": roles.get("owner"), "submittedBy": st.get("submittedByRole")},
        "gov-change": {"change requester": pending.get("requestedByRole"), "owner": roles.get("owner")},
        "gov-review": {"owner": roles.get("owner")},
        "gov-retire": {"retirement requester": retirement.get("requestedByRole")},
        "gov-suspend": {"suspension requester": st.get("suspensionRequestedByRole")},
    }.get(env, {})
    return {role: why for why, role in rules.items() if role}


def waiting_runs(engine_token: str, issue_number: int, run_id: int | None) -> list[int]:
    if run_id:
        return [run_id]
    try:
        pr = _http("GET", f"/repos/{REPO}/pulls/{issue_number}", engine_token)
    except GateError as e:
        raise GateError("This is not a pull request, so name the run: `/approve <role> run=<id>`.") from e
    runs = _http("GET", f"/repos/{REPO}/actions/runs?head_sha={pr['head']['sha']}&status=waiting", engine_token)
    return [r["id"] for r in runs.get("workflow_runs", [])]


def gate_command(event: dict) -> dict:
    engine_token, _ = bot_token("engine")
    comment = _http("GET", f"/repos/{REPO}/issues/comments/{int(event['comment_id'])}", engine_token)
    issue_number = int(comment["issue_url"].rsplit("/", 1)[-1])
    author = comment["user"]["login"]

    def reply(text: str) -> None:
        _http("POST", f"/repos/{REPO}/issues/{issue_number}/comments", engine_token,
              {"body": f"> {comment['body'].splitlines()[0][:200]}\n\n{text}"})

    try:
        if author.lower() not in OPERATORS:
            raise GateError(f"@{author} is not allowed to issue gate commands.")
        decision, role, note, run_id = parse_command(comment["body"])
        runs = waiting_runs(engine_token, issue_number, run_id)
        if not runs:
            raise GateError("No workflow run is waiting at a gate for this pull request.")
        token, bot = bot_token(role)
        done, skipped = [], []
        for rid in runs:
            for pending in _http("GET", f"/repos/{REPO}/actions/runs/{rid}/pending_deployments", engine_token) or []:
                env = pending["environment"]["name"]
                owner_role = GATE_ROLE.get(env)
                if owner_role != role:
                    skipped.append(f"`{env}` (run {rid}) belongs to the **{owner_role or 'unknown'}** role, not {role}")
                    continue
                run = get_run(rid)
                agent = agent_of_run(run)
                if agent and decision == "approve":
                    import engine  # late import: engine imports this module
                    st = engine.get_state(agent) or {}
                    conflict = forbidden_roles(env, st).get(role)
                    if conflict:
                        engine.log_event(agent, "SOD_VIOLATION_BLOCKED", f"{bot} for @{author}", gate=env, conflict=conflict, run=rid)
                        engine.metric("SeparationOfDutiesViolations", 1)
                        raise GateError(f"Separation of duties: the **{role}** role is the {conflict} of `{agent}` and cannot "
                                        f"approve `{env}`. Ask a different role.")
                text = f"{PAST[decision].capitalize()} by the {role} role bot on behalf of @{author}" + (f": {note}" if note else ".")
                _http("POST", f"/repos/{REPO}/actions/runs/{rid}/deployment_protection_rule", token,
                      {"environment_name": env, "state": "approved" if decision == "approve" else "rejected", "comment": text[:1000]})
                done.append(f"`{env}` (run {rid})")
                if decision == "reject" and agent:
                    import gh_actions
                    gh_actions.on_gate_rejected(env, agent, bot, author, note)
        if not done:
            raise GateError("Nothing to decide for this role. " + "; ".join(skipped))
        msg = f"**{bot}** {PAST[decision]} {', '.join(done)}." + (f"\n\nNot touched: {'; '.join(skipped)}." if skipped else "")
        reply(msg)
        return {"ok": True, "decision": decision, "role": role, "gates": done, "skipped": skipped}
    except GateError as ex:
        reply(f"Not done: {ex}")
        return {"error": str(ex)}
