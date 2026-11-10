"""Governance actions driven from GitHub (pull requests, gated workflow runs, role bots).

Each action is called by a workflow with the agent's manifest (agents/<name>.yaml as JSON) and the
GitHub context (pull request number, run ID). Nothing in the event is trusted for identity:

* the requester is the pull request's author or the run's triggering actor, read from GitHub;
* an approval is the decision GitHub recorded at the run's environment gate, and it must come from
  the bot of the role that owns that gate, on a run named for the same agent.

The console runbooks (GOV-01..08) keep working alongside until the cutover; both paths share the
same state, evidence and core logic in engine.py.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
import uuid

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

import engine as E
import github_gate as G

HUMAN_ROLES = {"developer", "owner", "platform", "security", "admin"}
RISK_KEYS = ("personalData", "customerFacing", "takesActions", "financialImpact", "externalTools", "autonomous")


def _agent(e: dict) -> str:
    agent = str(e.get("agent") or (e.get("manifest") or {}).get("name") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,47}", agent):
        raise E.GovError("Agent name must be 3-48 characters: lowercase letters, digits and hyphens.")
    return agent


def _role(value: str | None, default: str) -> str:
    role = (value or default).strip().lower()
    if role not in HUMAN_ROLES:
        raise E.GovError(f"Unknown role '{role}'. Roles: {', '.join(sorted(HUMAN_ROLES))}.")
    return role


def _requester(e: dict) -> str:
    """The person behind the request: the PR author, or the actor who started the run."""
    if e.get("pr"):
        login, _ = G.pr_author(int(e["pr"]))
    else:
        login = (G.get_run(int(e["run_id"])).get("triggering_actor") or {}).get("login", "")
    return G.require_operator(login)


def _approved(e: dict, env: str, agent: str) -> dict:
    """The approval recorded at `env` on this run, from the bot that owns that gate, for this agent."""
    run = G.get_run(int(e["run_id"]))
    if G.agent_of_run(run) != agent:
        raise E.GovError(f"Run {e['run_id']} is not a run for '{agent}'.")
    d = G.gate_approval(int(e["run_id"]), env)
    if d["state"] != "approved" or d["role"] != G.GATE_ROLE[env]:
        raise E.GovError(f"`{env}` on run {e['run_id']} was not approved by the {G.GATE_ROLE[env]} role bot.")
    return d


# ----------------------------------------------------------------------------- GOV-01 / GOV-07 request

def gh_request(e: dict) -> dict:
    m = e.get("manifest") or {}
    agent = _agent(e)
    login = _requester(e)
    roles = m.get("roles") or {}
    requested_by_role, owner_role = _role(roles.get("requestedBy"), "developer"), _role(roles.get("owner"), "developer")
    for f in ("purpose", "department", "dataClassification"):
        if not m.get(f):
            raise E.GovError(f"agents/{agent}.yaml needs '{f}'.")
    if m["dataClassification"] not in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"):
        raise E.GovError("dataClassification must be PUBLIC, INTERNAL, CONFIDENTIAL or RESTRICTED.")
    if len(m["purpose"]) < 10:
        raise E.GovError("purpose must be at least 10 characters.")
    existing = E.get_state(agent)
    if existing and existing.get("stage") not in ("REJECTED", "RETIRED") and not (
            existing.get("stage") == "REQUESTED" and existing.get("pr") == int(e.get("pr") or 0)):
        raise E.GovError(f"'{agent}' already exists and is {existing['stage']}.")
    risk = m.get("risk") or {}
    answers = {k: E.truthy(risk.get(k, False)) for k in RISK_KEYS}
    platform = m.get("platform") or "AWS AgentCore"
    if platform != "AWS AgentCore":
        answers["externalTools"] = True  # GOV-07: external agents always count as third-party
    tier, reasons = E.compute_risk(answers, m["dataClassification"])
    who = f"@{login} ({requested_by_role})"
    state = {
        "agent": agent, "sk": "STATE", "stage": "REQUESTED", "riskTier": tier, "riskReasons": reasons,
        "purpose": m["purpose"], "department": m["department"], "intendedUsers": m.get("intendedUsers", ""),
        "dataClassification": m["dataClassification"], "platform": platform, "endpoint": m.get("endpoint") or "",
        "riskAnswers": answers, "owner": f"{owner_role} role", "requestedBy": who,
        "roles": {"requestedBy": requested_by_role, "owner": owner_role},
        "version": str(m.get("version") or "1.0.0"), "links": {}, "createdAt": E.iso(), "pr": int(e.get("pr") or 0),
        "via": "github",
    }
    E.put_state(state)
    key = E.put_evidence(f"evidence/agents/{agent}/intake-pr{state['pr']}.json", state)
    E.log_event(agent, "REQUESTED", who, riskTier=tier, riskReasons=reasons, evidence=key, pr=state["pr"])
    return {"agent": agent, "tier": tier, "reasons": reasons, "requester": who,
            "summary": f"`{agent}`: risk **{tier}** ({'; '.join(reasons)}). Requested by {who} for {m['department']}."}


def gh_decide_intake(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "REQUESTED")
    d = _approved(e, "gov-intake", agent)
    tier = st["riskTier"]
    m = re.search(r"tier\s*=\s*(LOW|MEDIUM|HIGH)", d["comment"], re.I)
    if m and m.group(1).upper() != tier:
        E.log_event(agent, "RISK_OVERRIDDEN", d["bot"], fromTier=tier, toTier=m.group(1).upper(), comment=d["comment"])
        tier = m.group(1).upper()
    E.update_state(agent, stage="BUILD_APPROVED", riskTier=tier, intakeApprovedBy=d["bot"])
    E.log_event(agent, "INTAKE_APPROVED", d["bot"], riskTier=tier, comment=d["comment"], run=e["run_id"])
    return {"message": f"Intake approved by {d['bot']}; risk tier {tier}."}


# ----------------------------------------------------------------------------- GOV-02 build

def gh_build(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "BUILD_APPROVED")
    d = _approved(e, "gov-build", agent)
    b = (e.get("manifest") or {}).get("build") or {}
    aliases = json.loads(os.environ.get("GUARDRAIL_ALIASES", "{}"))
    guardrail = aliases.get(b.get("guardrail", ""), "") if b.get("guardrail") else ""
    if b.get("guardrail") and not guardrail:
        raise E.GovError(f"Unknown guardrail '{b['guardrail']}'. Use one of: {', '.join(sorted(aliases))}.")
    return E.build_agent(agent, st, {"Guardrail": guardrail, "Endpoint": b.get("endpoint", ""),
                                     "RuntimeId": b.get("runtimeId", ""), "PolicyEngine": b.get("policyEngine", ""),
                                     "Gateway": b.get("gateway", "")}, d["bot"])


# ----------------------------------------------------------------------------- GOV-03 release

def gh_gates(e: dict) -> dict:
    agent = _agent(e)
    E.require_state(agent)
    return E.a_gates({"AgentName": agent})


def gh_submit(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "BUILD_APPROVED", "SUBMITTED")
    login = _requester(e)
    role = _role((e.get("manifest") or {}).get("actingRole"), "developer")
    if st["stage"] == "SUBMITTED":
        return {"message": f"'{agent}' is already submitted for release."}
    res = E.submit_release(agent, st, f"@{login} ({role})")
    E.update_state(agent, submittedByRole=role)
    return res


def gh_release(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "SUBMITTED")
    d = _approved(e, "gov-release", agent)
    registry = E.registry_set_status(st, "APPROVED", f"Release approved by {d['bot']} (GitHub run {e['run_id']})")
    due = E.now() + E.timedelta(days=E.REVIEW_DAYS.get(st["riskTier"], 180))
    E.update_state(agent, stage="ACTIVE", releaseApprovedBy=d["bot"], activatedAt=E.iso(), nextReviewDue=E.iso(due))
    E.log_event(agent, "RELEASE_APPROVED", d["bot"], registry=registry, nextReviewDue=E.iso(due), run=e["run_id"])
    return {"message": f"Released by {d['bot']}: registry record {registry}. Next review due {E.iso(due)[:10]}."}


# ----------------------------------------------------------------------------- GOV-04 change

def gh_change_classify(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "ACTIVE")
    m = e.get("manifest") or {}
    ch = m.get("change") or {}
    login = _requester(e)
    role = _role(m.get("actingRole"), "developer")
    tools = ch.get("tools", m.get("tools")) if ch.get("type") == "TOOL" else None
    extra = {"requestedByRole": role, "pr": int(e.get("pr") or 0)}
    if tools is not None:
        extra["tools"] = list(tools)
    return E.classify_change(agent, st, str(ch.get("type", "")).upper(), ch.get("summary", ""), str(m.get("version", "")),
                             f"@{login} ({role})", **extra)


def gh_change_apply(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "CHANGE_PENDING")
    decided_by = "policy (pre-approved)"
    if (st.get("pendingChange") or {}).get("needsApproval"):
        decided_by = _approved(e, "gov-change", agent)["bot"]
    return E.apply_change(agent, st, decided_by)


# ----------------------------------------------------------------------------- GOV-05 review

def gh_review_snapshot(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "ACTIVE", "SUSPENDED")
    pack = E.review_pack(agent, st)
    run_id = int(e.get("run_id") or 0)
    E.update_state(agent, reviewRun=run_id)
    issue = G.open_issue(f"Periodic review: {agent}",
                         f"{pack['summary']}\n\nEvidence pack stored in the evidence bucket.\n\n"
                         f"To sign off, the department-owner role comments here:\n"
                         f"`/approve owner run={run_id} outcome=PASS <notes>` (or `outcome=CHANGES_REQUIRED` / `outcome=RETIRE`),\n"
                         f"or `/reject owner run={run_id} <reason>`.", ["gov-review"])
    return {"summary": pack["summary"], "issue": issue}


def gh_review_decide(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    d = _approved(e, "gov-review", agent)
    return E.record_review(agent, st, d["bot"], d["comment"], True)


# ----------------------------------------------------------------------------- GOV-06 retire

def gh_retire_plan(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    E.require_stage(st, "ACTIVE", "SUSPENDED", "BUILD_APPROVED", "REJECTED", "RETIRING", "DETECTED")
    m = e.get("manifest") or {}
    retire = m.get("retire") or {}
    if str(retire.get("confirm", "")).strip().lower() != agent:
        raise E.GovError(f"Set retire.confirm to the agent's exact name ('{agent}') to retire it.")
    login = _requester(e)
    role = _role(m.get("actingRole"), "platform")
    if role not in ("platform", "admin"):
        raise E.GovError("Only the platform or admin role can request a retirement.")
    res = E.plan_retirement(agent, st, f"@{login} ({role})", str(retire.get("reason", "")))
    job = dict((E.get_state(agent) or {}).get("retirement") or {})
    E.update_state(agent, retirement={**job, "requestedByRole": role})
    return res


def gh_retire_execute(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    d = _approved(e, "gov-retire", agent)
    return E.execute_retirement(agent, st, d["bot"])


# ----------------------------------------------------------------------------- GOV-08 suspend / reinstate

def gh_suspend_request(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    action = str(e.get("suspendAction", "Suspend")).capitalize()
    E.require_stage(st, *(("SUSPENDED",) if action == "Reinstate" else ("ACTIVE", "CHANGE_PENDING")))
    login = _requester(e)
    role = _role(e.get("actingRole"), "security")
    E.update_state(agent, suspensionRequestedByRole=role, suspensionRequest={"action": action, "by": f"@{login} ({role})",
                                                                           "reason": str(e.get("reason", ""))})
    E.log_event(agent, f"{action.upper()}_REQUESTED", f"@{login} ({role})", reason=e.get("reason"), run=e.get("run_id"))
    issue = G.open_issue(f"{action} request: {agent}",
                         f"{action} of `{agent}` requested by @{login} ({role}). Reason: {e.get('reason', '')}\n\n"
                         f"The security role decides: `/approve security run={e.get('run_id')}` or "
                         f"`/reject security run={e.get('run_id')} <reason>`.", ["gov-suspend"])
    return {"message": f"{action} of '{agent}' requested by @{login} ({role}); waiting for the security role bot (issue #{issue}).",
            "issue": issue}


def gh_suspend_apply(e: dict) -> dict:
    agent = _agent(e)
    st = E.require_state(agent)
    d = _approved(e, "gov-suspend", agent)
    req = st.get("suspensionRequest") or {}
    if not req:
        raise E.GovError(f"No suspension request recorded for '{agent}'.")
    fn = E.reinstate_agent if req.get("action") == "Reinstate" else E.suspend_agent
    res = fn(agent, st, d["bot"], req.get("reason", ""))
    E.update_state(agent, suspensionRequest=None, suspensionRequestedByRole=None)
    return res


# ----------------------------------------------------------------------------- planner for pull requests

# status in agents/<name>.yaml -> (stage, plan action, gate, apply action)
NEXT_ROLE = {"gov-intake": "security", "gov-build": "platform", "gov-release": "security", "gov-change": "security",
             "gov-retire": "admin"}


def gh_plan(e: dict) -> dict:
    """Decide which lifecycle step a pull request asks for, run its plan, and say which gate comes next."""
    agent = _agent(e)
    m = e.get("manifest") or {}
    status = str(m.get("status", "")).lower()
    st = E.get_state(agent)
    stage_now = (st or {}).get("stage")
    if status == "requested" and stage_now in (None, "REQUESTED", "REJECTED", "RETIRED"):
        res, step, gate, apply = gh_request(e), "intake", "gov-intake", "gh_decide_intake"
    elif status == "build" and stage_now == "BUILD_APPROVED" and not ((st.get("links") or {}).get("registryRecord")):
        res, step, gate, apply = {"message": f"Build of `{agent}` is ready to run once the platform role approves."}, \
            "build", "gov-build", "gh_build"
    elif status == "release" and stage_now in ("BUILD_APPROVED", "SUBMITTED"):
        res, step, gate, apply = gh_submit(e), "release", "gov-release", "gh_release"
    elif status == "active" and stage_now in ("ACTIVE", "CHANGE_PENDING"):
        pending = st.get("pendingChange") or {}
        if stage_now == "CHANGE_PENDING" and pending.get("version") == str(m.get("version")):
            res = {"route": "Approval" if pending.get("needsApproval") else "PreApproved",
                   "message": f"{pending.get('type')} change to {pending.get('version')} is already planned."}
        elif str(m.get("version")) == str(st.get("version")):
            return _announce(e, "no change", {"message": "Version unchanged; bump `version` and describe `change` to request a change."})
        else:
            res = gh_change_classify(e)
        step, apply = "change", "gh_change_apply"
        gate = "gov-change" if res.get("route") == "Approval" else ""
    elif status == "retired" and stage_now not in (None, "RETIRED"):
        res, step, gate, apply = gh_retire_plan(e), "retire", "gov-retire", "gh_retire_execute"
    else:
        return _announce(e, "no step", {"message": f"Nothing to do: `{agent}` is {stage_now or 'not governed yet'} and the file asks for "
                                                   f"status `{status or '(missing)'}`."})
    res.update({"step": step, "gate": gate, "apply": apply})
    nxt = (f"Next: the **{NEXT_ROLE[gate]}** role decides. Comment `/approve {NEXT_ROLE[gate]} <note>` or "
           f"`/reject {NEXT_ROLE[gate]} <reason>` on this pull request.") if gate else "Pre-approved by policy: applying now."
    return _announce(e, step, res, nxt)


def _announce(e: dict, step: str, res: dict, nxt: str = "") -> dict:
    if e.get("pr"):
        body = res.get("summary") or res.get("message") or res.get("plan") or ""
        G.comment(int(e["pr"]), redact(f"**Governance plan: {step}**\n\n{body}\n\n{nxt}".strip(), e))
    return res


def redact(text: str, e: dict | None = None) -> str:
    """Remove account, resource and organisation identifiers before anything is posted to the public repository."""
    values = {os.environ.get(k, "") for k in ("ACCOUNT_ID", "REGISTRY_ID", "DEFAULT_POLICY_ENGINE", "DEFAULT_GATEWAY",
                                              "EVIDENCE_BUCKET", "METRIC_NAMESPACE", "AGENT_ENDPOINT_BASE")}
    for name, g in json.loads(os.environ.get("GUARDRAILS_JSON", "{}")).items():
        values.update({name, g.get("id", "")})
    try:
        agent = _agent(e or {})
        links = (E.get_state(agent) or {}).get("links") or {}
        for kind in ("registryRecord", "runtime", "guardrail", "policyEngine", "gateway"):  # opaque IDs, not names
            values.add(str((links.get(kind) or {}).get("id", "")))
    except Exception:  # redaction must never fail the action
        pass
    terms = [t for t in os.environ.get("REDACT_TERMS", "").split(",") if t]
    for v in sorted((v for v in values if v and len(v) >= 6), key=len, reverse=True):
        text = text.replace(v, "***")
    for t in terms:
        text = re.sub(re.escape(t), "***", text, flags=re.I)
    return re.sub(r"https://[a-z0-9-]+\.gateway\.bedrock-agentcore\.[a-z0-9-]+\.amazonaws\.com", "https://***", text)


# ----------------------------------------------------------------------------- A2A demonstration

def gh_a2a_demo(e: dict) -> dict:
    """Show agent-to-agent traffic through the agents gateway: one call the Cedar policies allow, one they deny.

    allowed: ask the caller agent (on its runtime); it calls the target agent through the gateway as its own role
    denied:  the engine calls the target directly through the gateway as itself; Cedar denies it by default
    """
    caller, target = _agent({"agent": e.get("caller")}), _agent({"agent": e.get("target")})
    cs, ts = E.require_state(caller), E.require_state(target)
    runtime = ((cs.get("links") or {}).get("runtime") or {}).get("id") or cs.get("runtimeId")
    if not runtime:
        raise E.GovError(f"'{caller}' has no AgentCore runtime linked.")
    if ts.get("stage") != "ACTIVE" or cs.get("stage") != "ACTIVE":
        raise E.GovError("Both agents must be ACTIVE.")
    prompt = str(e.get("prompt") or "Which promotions are running today? Please check with the promotions agent.")[:500]
    rt = boto3.client("bedrock-agentcore")
    out = rt.invoke_agent_runtime(agentRuntimeArn=f"arn:aws:bedrock-agentcore:{E.REGION}:{E.ACCOUNT}:runtime/{runtime}",
                                  qualifier="DEFAULT", runtimeSessionId=f"a2a-demo-{uuid.uuid4().hex}",
                                  contentType="application/json", accept="application/json",
                                  payload=json.dumps({"prompt": prompt}).encode())
    body = out["response"].read() if hasattr(out.get("response"), "read") else out.get("response", b"")
    try:
        answer = json.loads(body).get("answer", "")
    except (ValueError, AttributeError):
        answer = body.decode(errors="ignore") if isinstance(body, bytes) else str(body)
    url = ts.get("endpoint") or ""
    if ".gateway.bedrock-agentcore." not in url:
        raise E.GovError(f"'{target}' is not reachable through an AgentCore gateway.")
    msg = json.dumps({"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "message/send",
                      "params": {"message": {"role": "user", "messageId": uuid.uuid4().hex,
                                             "parts": [{"kind": "text", "text": prompt}]}}})
    req = AWSRequest(method="POST", url=url, data=msg, headers={"Content-Type": "application/json"})
    SigV4Auth(boto3.Session().get_credentials(), "bedrock-agentcore", E.REGION).add_auth(req)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=msg.encode(), headers=dict(req.headers), method="POST"),
                                    timeout=30) as r:
            denied = {"status": r.status, "body": r.read()[:300].decode(errors="ignore")}
    except urllib.error.HTTPError as ex:
        denied = {"status": ex.code, "body": ex.read()[:300].decode(errors="ignore")}
    E.log_event(caller, "A2A_DEMO", "gov-engine", target=target, allowedAnswerChars=len(answer), deniedStatus=denied["status"])
    return {"allowed": {"caller": caller, "target": target, "answer": redact(answer)},
            "denied": {"caller": "gov-engine (not permitted by any Cedar policy)", "target": target,
                       "status": denied["status"], "body": redact(denied["body"])}}


# ----------------------------------------------------------------------------- rejections at a gate

def on_gate_rejected(env: str, agent: str, bot: str, author: str, reason: str) -> None:
    """Record what a rejection at each gate means for the agent (the gated job never runs)."""
    st = E.get_state(agent)
    if not st:
        return
    who = f"{bot} for @{author}"
    if env == "gov-intake" and st.get("stage") == "REQUESTED":
        E.update_state(agent, stage="REJECTED", intakeDecidedBy=bot)
        E.log_event(agent, "INTAKE_REJECTED", who, comment=reason)
    elif env == "gov-release" and st.get("stage") == "SUBMITTED":
        registry = E.registry_set_status(st, "REJECTED", f"Release rejected by {bot}: {reason}")
        E.update_state(agent, stage="BUILD_APPROVED")
        E.log_event(agent, "RELEASE_REJECTED", who, reason=reason, registry=registry)
    elif env == "gov-change" and st.get("stage") == "CHANGE_PENDING":
        E.update_state(agent, stage="ACTIVE", pendingChange=None)
        E.log_event(agent, "CHANGE_REJECTED", who, comment=reason, keptVersion=st.get("version"))
    elif env == "gov-review":
        E.record_review(agent, st, bot, f"outcome=CHANGES_REQUIRED {reason}", False)
    elif env == "gov-retire":
        E.update_state(agent, retirement=None)
        E.log_event(agent, "RETIREMENT_REJECTED", who, comment=reason)
    elif env == "gov-suspend":
        E.update_state(agent, suspensionRequest=None, suspensionRequestedByRole=None)
        E.log_event(agent, "SUSPENSION_REJECTED", who, comment=reason)
    elif env == "gov-build":
        E.log_event(agent, "BUILD_REJECTED", who, comment=reason)


ACTIONS = {
    "gh_request": gh_request, "gh_decide_intake": gh_decide_intake, "gh_build": gh_build, "gh_gates": gh_gates,
    "gh_submit": gh_submit, "gh_release": gh_release, "gh_change_classify": gh_change_classify,
    "gh_change_apply": gh_change_apply, "gh_review_snapshot": gh_review_snapshot, "gh_review_decide": gh_review_decide,
    "gh_retire_plan": gh_retire_plan, "gh_retire_execute": gh_retire_execute, "gh_suspend_request": gh_suspend_request,
    "gh_suspend_apply": gh_suspend_apply, "gh_plan": gh_plan, "gh_a2a_demo": gh_a2a_demo,
}


def run(action: str, event: dict) -> dict:
    """Entry point from engine.handler: run the action, post errors on the pull request, redact the result."""
    try:
        res = ACTIONS[action](event)
    except (E.GovError, G.GateError) as ex:
        if event.get("pr"):
            G.comment(int(event["pr"]), redact(f"**Governance: not done**\n\n{ex}", event))
        return {"error": redact(str(ex), event)}
    except Exception as ex:  # unexpected (e.g. an AWS error): never let its raw text reach the public repository
        print(f"{action} failed: {type(ex).__name__}: {ex}")  # full detail stays in the engine's CloudWatch log
        msg = redact(f"{type(ex).__name__}: {ex}", event)
        if event.get("pr"):
            G.comment(int(event["pr"]), f"**Governance: failed unexpectedly**\n\n{msg}")
        return {"error": msg}
    return json.loads(redact(json.dumps(res, default=str), event))
