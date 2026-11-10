"""AI governance engine (no custom UI).

One Lambda that does the work behind the Systems Manager runbooks (GOV-01..08) and
reacts to AWS events. People never call it directly: runbook steps invoke it with an
``action``, and EventBridge invokes it with AWS events. State lives in DynamoDB
(``gov-lifecycle``); every decision is also written to the S3 evidence bucket
(Object Lock) so Athena can answer audit questions.

Errors meant for people are raised as ``GovError`` and returned as ``{"error": ...}``
so the runbook step fails with a readable message.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

import github_gate

REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT = os.environ["ACCOUNT_ID"]
TABLE = os.environ["TABLE_NAME"]
BUCKET = os.environ["EVIDENCE_BUCKET"]
REGISTRY_ID = os.environ["REGISTRY_ID"]
AUTOMATION_ROLE_ARN = os.environ["AUTOMATION_ROLE_ARN"]
ALERT_TOPIC = os.environ["ALERT_TOPIC_ARN"]
BOUNDARY_ARN = os.environ["BOUNDARY_ARN"]
METRIC_NS = os.environ.get("METRIC_NAMESPACE", "AIGovernance")
REVIEW_DAYS = {"HIGH": 90, "MEDIUM": 180, "LOW": 180}
BROAD_POLICIES = ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess")
GUARDRAILS = json.loads(os.environ.get("GUARDRAILS_JSON", "{}"))  # name -> {"id","version"}
DEFAULT_POLICY_ENGINE = os.environ.get("DEFAULT_POLICY_ENGINE", "")
DEFAULT_GATEWAY = os.environ.get("DEFAULT_GATEWAY", "")
GUARDRAIL_CUSTOMER_FACING = os.environ.get("GUARDRAIL_CUSTOMER_FACING", "guest-facing")
GUARDRAIL_INTERNAL = os.environ.get("GUARDRAIL_INTERNAL", "employee-data")
AGENT_ENDPOINT_BASE = os.environ.get("AGENT_ENDPOINT_BASE", "https://agents.example.com").rstrip("/")
GROUP_ROLE = {"Gov-Admin": "Admin", "Gov-Security": "Security", "Gov-Platform": "Platform",
              "Gov-Developer": "Developer", "Gov-DepartmentOwner": "DepartmentOwner", "Gov-Auditor": "Auditor"}

ddb = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
s3 = boto3.client("s3", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
iam = boto3.client("iam")
sns = boto3.client("sns", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)
bedrock = boto3.client("bedrock", region_name=REGION)
ac = boto3.client("bedrock-agentcore-control", region_name=REGION)
reg = boto3.client("agent-registry-control", region_name=REGION)
cfg = boto3.client("config", region_name=REGION)


class GovError(Exception):
    """A governance rule stopped the action; the message is shown to people."""


# --------------------------------------------------------------------------- helpers

def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).isoformat().replace("+00:00", "Z")


def truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1")


def username(arn: str | None) -> str:
    """'arn:aws:iam::1:user/gov-james' -> 'gov-james'; assumed roles -> role name."""
    if not arn:
        return "unknown"
    if ":user/" in arn:
        return arn.rsplit("/", 1)[-1]
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    if ":role/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn


def roles_of(user: str) -> set:
    try:
        groups = iam.list_groups_for_user(UserName=user)["Groups"]
    except ClientError:
        return set()
    return {GROUP_ROLE[g["GroupName"]] for g in groups if g["GroupName"] in GROUP_ROLE}


def get_state(agent: str) -> dict | None:
    return ddb.get_item(Key={"agent": agent, "sk": "STATE"}).get("Item")


def require_state(agent: str) -> dict:
    st = get_state(agent)
    if not st:
        raise GovError(f"No governed agent named '{agent}'. Request it first with GOV-01-RequestAgent.")
    return st


def put_state(state: dict) -> dict:
    state["updatedAt"] = iso()
    ddb.put_item(Item={k: v for k, v in state.items() if v is not None and v != ""})
    return state


def update_state(agent: str, **fields) -> dict:
    st = require_state(agent)
    st.update(fields)
    return put_state(st)


def require_stage(st: dict, *stages: str) -> None:
    if st.get("stage") not in stages:
        raise GovError(f"'{st['agent']}' is {st.get('stage')}; this step needs it to be {' or '.join(stages)}.")


def log_event(agent: str, action: str, actor: str, **detail) -> None:
    """Append-only audit: DynamoDB (per agent) and S3 Object Lock (Athena)."""
    t = iso()
    eid = uuid.uuid4().hex[:8]
    item = {"agent": agent, "sk": f"EVENT#{t}#{eid}", "action": action, "actor": actor, "at": t,
            "detail": json.dumps(detail, default=str)[:3500]}
    ddb.put_item(Item=item)
    line = {"time": t, "agent": agent, "action": action, "actor": actor, "detail": json.dumps(detail, default=str)}
    s3.put_object(Bucket=BUCKET, Key=f"evidence/events/dt={t[:10]}/{t}-{agent}-{action}-{eid}.json",
                  Body=json.dumps(line).encode(), ContentType="application/json")


def put_evidence(key: str, body: dict) -> str:
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(body, indent=2, default=str).encode(), ContentType="application/json")
    return key


def console_s3_url(key: str) -> str:
    return f"https://{REGION}.console.aws.amazon.com/s3/object/{BUCKET}?region={REGION}&prefix={key}"


def alert(subject: str, message: str) -> None:
    """SNS (legacy) plus a GitHub issue assigned to the operators, which GitHub emails."""
    sns.publish(TopicArn=ALERT_TOPIC, Subject=subject[:99], Message=message)
    try:
        github_gate.open_issue(subject, message, ["gov-alert"])
    except Exception as ex:  # an alert must never break the action that raised it
        print(f"alert issue not created: {ex}")


def metric(name: str, value: float, **dims) -> None:
    cw.put_metric_data(Namespace=METRIC_NS, MetricData=[{
        "MetricName": name, "Value": value, "Unit": "Count",
        "Dimensions": [{"Name": k, "Value": v} for k, v in dims.items()]}])


# --------------------------------------------------------------------------- runbook context

def execution(exec_id: str) -> dict:
    return ssm.get_automation_execution(AutomationExecutionId=exec_id)["AutomationExecution"]


def executor(exec_id: str) -> str:
    return username(execution(exec_id).get("ExecutedBy"))


def approval(exec_id: str, step: str) -> dict:
    """Who decided an aws:approve step, the decision and the comment."""
    ex = execution(exec_id)
    for s in ex.get("StepExecutions", []):
        if s.get("StepName") != step:
            continue
        outputs = s.get("Outputs") or {}
        status = (outputs.get("ApprovalStatus") or [s.get("StepStatus")])[0]
        approver, comment = None, ""
        for raw in outputs.get("ApproverDecisions") or []:
            try:
                d = json.loads(raw) if isinstance(raw, str) else raw
            except ValueError:
                d = {"raw": raw}
            if str(d.get("Decision", "")).lower() not in ("approve", "reject"):
                continue  # approvers who have not decided are listed as "Waiting"
            approver = d.get("Approver") or d.get("approver") or approver
            comment = d.get("Comment") or d.get("comment") or comment
            if isinstance(comment, list):
                comment = " ".join(comment)
        return {"status": status, "approver": username(approver), "comment": comment or "", "raw": outputs}
    raise GovError(f"Approval step '{step}' not found in execution {exec_id}.")


def separation_check(agent: str, decided_by: str, forbidden: dict, what: str) -> None:
    """forbidden: {"requester": "gov-james", ...}. Raise and record when someone approves their own work."""
    for role, user in forbidden.items():
        if user and decided_by == user:
            log_event(agent, "SOD_VIOLATION_BLOCKED", decided_by, what=what, conflict=role)
            metric("SeparationOfDutiesViolations", 1)
            alert(f"Separation of duties: {agent}",
                  f"{decided_by} tried to {what} for '{agent}' but is also its {role}. The step was stopped.")
            raise GovError(f"Separation of duties: {decided_by} is the {role} of '{agent}' and cannot {what}.")


# --------------------------------------------------------------------------- GOV-01 intake

def compute_risk(answers: dict, classification: str) -> tuple[str, list]:
    high, medium = [], []
    if answers["personalData"]:
        high.append("Handles personal or guest data")
    if answers["financialImpact"]:
        high.append("Can affect payments, refunds or pricing")
    if answers["customerFacing"] and answers["takesActions"]:
        high.append("Customer-facing and takes actions")
    if answers["autonomous"] and answers["takesActions"]:
        high.append("Takes actions without a human in the loop")
    if classification == "RESTRICTED":
        high.append("Uses RESTRICTED data")
    if answers["customerFacing"]:
        medium.append("Customer-facing")
    if answers["takesActions"]:
        medium.append("Takes actions in other systems")
    if answers["externalTools"]:
        medium.append("Uses third-party tools or agents")
    if answers["autonomous"]:
        medium.append("Runs without a human in the loop")
    if classification == "CONFIDENTIAL":
        medium.append("Uses CONFIDENTIAL data")
    if high:
        return "HIGH", high
    if medium:
        return "MEDIUM", medium
    return "LOW", ["No elevated-risk factors"]


def a_request(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,47}", agent):
        raise GovError("AgentName must be 3-48 characters: lowercase letters, digits and hyphens.")
    existing = get_state(agent)
    if existing and existing.get("stage") not in ("REJECTED", "RETIRED"):
        raise GovError(f"'{agent}' already exists and is {existing['stage']}.")
    requester = executor(e["exec"])
    answers = {k: truthy(e.get(k)) for k in ("personalData", "customerFacing", "takesActions",
                                              "financialImpact", "externalTools", "autonomous")}
    tier, reasons = compute_risk(answers, e["DataClassification"])
    state = {
        "agent": agent, "sk": "STATE", "stage": "REQUESTED", "riskTier": tier, "riskReasons": reasons,
        "purpose": e["Purpose"], "department": e["Department"], "intendedUsers": e.get("IntendedUsers", ""),
        "dataClassification": e["DataClassification"], "platform": e.get("Platform") or "AWS AgentCore",
        "endpoint": e.get("Endpoint") or "", "riskAnswers": answers, "owner": requester, "requestedBy": requester,
        "intakeExecution": e["exec"], "version": "1.0.0", "links": {}, "createdAt": iso(),
    }
    put_state(state)
    key = put_evidence(f"evidence/agents/{agent}/intake-{e['exec']}.json", state)
    log_event(agent, "REQUESTED", requester, riskTier=tier, riskReasons=reasons, evidence=key)
    summary = f"{agent}: risk {tier} ({'; '.join(reasons)}). Requested by {requester} for {e['Department']}."
    return {"agent": agent, "tier": tier, "requester": requester, "summary": summary}


def a_decide_intake(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    d = approval(e["exec"], e.get("step", "ApproveIntake"))
    if d["status"] != "Approved":
        update_state(agent, stage="REJECTED", intakeDecidedBy=d["approver"])
        log_event(agent, "INTAKE_REJECTED", d["approver"], comment=d["comment"])
        raise GovError(f"Intake rejected by {d['approver']}: {d['comment'] or 'no reason given'}")
    separation_check(agent, d["approver"], {"requester": st.get("requestedBy")}, "approve its intake")
    tier = st["riskTier"]
    m = re.search(r"tier\s*=\s*(LOW|MEDIUM|HIGH)", d["comment"], re.I)
    if m and m.group(1).upper() != tier:
        log_event(agent, "RISK_OVERRIDDEN", d["approver"], fromTier=tier, toTier=m.group(1).upper(), comment=d["comment"])
        tier = m.group(1).upper()
    update_state(agent, stage="BUILD_APPROVED", riskTier=tier, intakeApprovedBy=d["approver"])
    log_event(agent, "INTAKE_APPROVED", d["approver"], riskTier=tier, comment=d["comment"])
    return {"message": f"Approved by {d['approver']}; risk tier {tier}. Platform can now run GOV-02-BuildAgent."}


# --------------------------------------------------------------------------- GOV-02 build

def a_build(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    require_stage(st, "BUILD_APPROVED")
    builder = executor(e["exec"])
    roles = roles_of(builder)
    if "Developer" in roles and not roles & {"Platform", "Admin"} and builder != st["owner"]:
        raise GovError(f"{builder} is a developer and can only build agents they own (owner: {st['owner']}).")
    return build_agent(agent, st, e, builder)


def build_agent(agent: str, st: dict, e: dict, builder: str) -> dict:
    """Create or link everything the agent needs (shared by the console runbook and GitHub workflows)."""
    links = dict(st.get("links") or {})
    built = []

    # 1. Workload identity (owned)
    try:
        ac.get_workload_identity(name=agent)
    except ClientError:
        ac.create_workload_identity(name=agent)
    links["workloadIdentity"] = {"id": agent, "owned": True}
    built.append(f"workload identity {agent}")

    # 2. Guardrail (shared, chosen by profile)
    gname = e.get("Guardrail") or (GUARDRAIL_CUSTOMER_FACING if st["riskAnswers"].get("customerFacing") else GUARDRAIL_INTERNAL)
    g = GUARDRAILS.get(gname)
    if not g:
        raise GovError(f"Unknown guardrail profile '{gname}'. Choose one of: {', '.join(GUARDRAILS)}.")
    links["guardrail"] = {"id": g["id"], "version": str(g["version"]), "name": gname, "owned": False}
    built.append(f"guardrail {gname}")

    # 3. IAM role with permission boundary (owned)
    role = f"{agent}-agent-role"[:64]
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
             "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}}}]}
    try:
        iam.get_role(RoleName=role)
    except ClientError:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), PermissionsBoundary=BOUNDARY_ARN,
                        Description=f"Execution role for governed agent {agent}",
                        Tags=[{"Key": "gov:agent", "Value": agent}, {"Key": "gov:managed-by", "Value": "GOV-02-BuildAgent"}])
    gw = e.get("Gateway") or DEFAULT_GATEWAY
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "ModelsWithGuardrailOnly", "Effect": "Allow",
         "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": ["arn:aws:bedrock:*::foundation-model/amazon.nova-2-lite-v1:0",
                      f"arn:aws:bedrock:{REGION}:{ACCOUNT}:inference-profile/us.amazon.nova-2-lite-v1:0"]},
        {"Sid": "DenyModelCallsWithoutGuardrail", "Effect": "Deny",
         "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "Resource": "*",
         "Condition": {"Null": {"bedrock:GuardrailIdentifier": "true"}}},
        {"Sid": "UseAssignedGuardrail", "Effect": "Allow", "Action": "bedrock:ApplyGuardrail",
         "Resource": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/{g['id']}"},
        {"Sid": "ToolsThroughGateway", "Effect": "Allow", "Action": "bedrock-agentcore:InvokeGateway",
         "Resource": f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/{gw}"},
        {"Sid": "Observability", "Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "xray:PutTraceSegments",
                    "xray:PutTelemetryRecords", "cloudwatch:PutMetricData"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role, PolicyName="gov-agent-permissions", PolicyDocument=json.dumps(policy))
    links["iamRole"] = {"id": role, "owned": True}
    built.append(f"IAM role {role} (boundary GovAgentBoundary)")

    # 4. Cedar policy engine and gateway (shared)
    pe = e.get("PolicyEngine") or DEFAULT_POLICY_ENGINE
    links["policyEngine"] = {"id": pe, "owned": False}
    links["gateway"] = {"id": gw, "owned": False}
    built.append(f"Cedar policy engine {pe}, gateway {gw}")
    if e.get("RuntimeId"):
        links["runtime"] = {"id": e["RuntimeId"], "owned": False}

    # 5. Registry record (owned), static facts in custom metadata
    endpoint = e.get("Endpoint") or st.get("endpoint") or f"{AGENT_ENDPOINT_BASE}/{agent}"
    if not (links.get("registryRecord") or {}).get("id"):
        card = {"protocolVersion": "0.3.0", "name": agent, "description": st["purpose"][:900], "url": endpoint,
                "version": st["version"], "preferredTransport": "JSONRPC",
                "capabilities": {"streaming": False, "pushNotifications": False},
                "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
                "skills": [{"id": agent, "name": agent, "description": st["purpose"][:900], "tags": [st["department"]]}]}
        meta = {"riskTier": st["riskTier"], "dataClassification": st["dataClassification"], "owner": st["owner"],
                "department": st["department"][:128], "requestedBy": st["requestedBy"],
                "intakeApprovedBy": st.get("intakeApprovedBy", ""), "riskReasons": "; ".join(st["riskReasons"])[:128],
                "workloadIdentity": agent, "iamRole": role, "guardrailId": g["id"], "policyEngineId": pe[:128],
                "gatewayId": gw[:128], "governedByRunbooks": True}
        if st.get("platform") and st["platform"] != "AWS AgentCore":
            meta["externalPlatform"] = st["platform"][:128]
        if e.get("RuntimeId"):
            meta["runtimeId"] = e["RuntimeId"][:128]
        rec = reg.create_registry_record(registryId=REGISTRY_ID, name=agent, description=st["purpose"][:1000],
                                         recordType="AGENT", recordVersion=st["version"],
                                         descriptors={"a2aAgentCard": {"data": json.dumps(card), "dataSchemaVersion": "0.3"}},
                                         customMetadata={k: v for k, v in meta.items() if v != ""})
        links["registryRecord"] = {"id": rec["recordArn"].rsplit("/", 1)[-1], "owned": True}
    built.append(f"registry record {links['registryRecord']['id']} (DRAFT)")
    update_state(agent, links=links, endpoint=endpoint, builtBy=builder, builtAt=iso())
    log_event(agent, "BUILT", builder, links=links)
    return {"message": "Built: " + "; ".join(built) + ". Next: GOV-03-SubmitRelease."}


# --------------------------------------------------------------------------- GOV-03 release

def retry(fn, attempts: int = 8, delay: float = 4.0):
    """The registry briefly rejects calls right after an update ("Concurrent update detected")."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as ex:
            if ex.response["Error"]["Code"] not in ("ConflictException", "ValidationException") or i == attempts - 1:
                raise
            time.sleep(delay)


def registry_wait(record_id: str, timeout: int = 90) -> dict:
    end = time.time() + timeout
    while True:
        r = reg.get_registry_record(registryId=REGISTRY_ID, recordId=record_id)
        if r["status"] not in ("CREATING", "UPDATING") or time.time() > end:
            return r
        time.sleep(2)


def _check(key, label, required, ok, detail):
    return {"key": key, "label": label, "required": required, "ok": bool(ok), "detail": detail}


def release_checks(st: dict) -> list:
    links = st.get("links") or {}
    answers = st.get("riskAnswers") or {}
    tier = st["riskTier"]
    checks = []
    rid = (links.get("registryRecord") or {}).get("id")
    if not rid:
        checks.append(_check("registry", "Registered in the Agent Registry", True, False, "No registry record"))
    else:
        r = registry_wait(rid)
        checks.append(_check("registry", "Registered in the Agent Registry", True,
                             r["status"] not in ("CREATE_FAILED", "UPDATE_FAILED", "DEPRECATED"), f"{rid}: {r['status']}"))
    wid = (links.get("workloadIdentity") or {}).get("id")
    try:
        ok = bool(wid) and bool(ac.get_workload_identity(name=wid))
    except ClientError:
        ok = False
    checks.append(_check("identity", "Own workload identity", True, ok, wid or "No workload identity"))
    role = (links.get("iamRole") or {}).get("id")
    if role:
        try:
            attached = iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
            broad = [p["PolicyName"] for p in attached if p["PolicyName"] in BROAD_POLICIES]
            boundary = iam.get_role(RoleName=role)["Role"].get("PermissionsBoundary")
            checks.append(_check("iam", "Scoped IAM role with permission boundary", True, not broad and bool(boundary),
                                 f"{role}: " + (f"too broad: {', '.join(broad)}" if broad else "no admin policies")
                                 + ("; boundary set" if boundary else "; NO permission boundary")))
        except ClientError as ex:
            checks.append(_check("iam", "Scoped IAM role with permission boundary", True, False, str(ex)))
    else:
        checks.append(_check("iam", "Scoped IAM role with permission boundary", True, False, "No IAM role"))
    gl = links.get("guardrail") or {}
    if gl.get("id"):
        g = bedrock.get_guardrail(guardrailIdentifier=gl["id"])
        checks.append(_check("guardrail", "Guardrail READY", True, g["status"] == "READY", f"{g['name']}: {g['status']}"))
        if answers.get("personalData"):
            pii = (g.get("sensitiveInformationPolicy") or {}).get("piiEntities") or []
            checks.append(_check("guardrail_pii", "Guardrail masks personal data", True, bool(pii), f"{len(pii)} PII types"))
    else:
        checks.append(_check("guardrail", "Guardrail READY", True, False, "No guardrail"))
    needs_cedar = tier in ("MEDIUM", "HIGH")
    pe = (links.get("policyEngine") or {}).get("id")
    if pe:
        pols = ac.list_policies(policyEngineId=pe).get("policies", [])
        active = [p for p in pols if p.get("status") == "ACTIVE"]
        checks.append(_check("cedar", "Cedar policies control tool use", needs_cedar, bool(active), f"{len(active)} ACTIVE in {pe}"))
    else:
        checks.append(_check("cedar", "Cedar policies control tool use", needs_cedar, False, "No policy engine"))
    gw = (links.get("gateway") or {}).get("id")
    needs_gw = bool(answers.get("externalTools"))
    if gw:
        g = ac.get_gateway(gatewayIdentifier=gw)
        checks.append(_check("gateway", "Tools go through the Gateway", needs_gw, g["status"] == "READY", f"{g['name']}: {g['status']}"))
    else:
        checks.append(_check("gateway", "Tools go through the Gateway", needs_gw, False, "No gateway"))
    return checks


def a_gates(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    checks = release_checks(st)
    ready = all(c["ok"] for c in checks if c["required"])
    key = put_evidence(f"evidence/agents/{agent}/gates-{iso()}.json", {"agent": agent, "ready": ready, "checks": checks})
    report = " | ".join(f"{'PASS' if c['ok'] else ('FAIL' if c['required'] else 'n/a')}: {c['label']} ({c['detail']})" for c in checks)
    return {"ready": ready, "checks": checks, "evidence": key, "report": report,
            "message": ("READY for release. " if ready else "NOT READY. ") + report}


def a_submit(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    require_stage(st, "BUILD_APPROVED")
    return submit_release(agent, st, executor(e["exec"]))


def submit_release(agent: str, st: dict, who: str) -> dict:
    res = a_gates({"AgentName": agent})
    failed = [f"{c['label']} ({c['detail']})" for c in res["checks"] if c["required"] and not c["ok"]]
    if failed:
        log_event(agent, "RELEASE_BLOCKED", who, failed=failed, evidence=res["evidence"])
        raise GovError("Release blocked. Failed gates: " + " | ".join(failed))
    rid = st["links"]["registryRecord"]["id"]
    r = registry_wait(rid)
    if r["status"] == "REJECTED":  # re-open: a real content update returns it to DRAFT
        desc = r.get("description") or st["purpose"]
        reg.update_registry_record(registryId=REGISTRY_ID, recordId=rid,
                                   description={"optionalValue": desc[:-1] if desc.endswith(" ") else desc + " "})
        r = registry_wait(rid)
    if r["status"] != "PENDING_APPROVAL":
        reg.submit_registry_record_for_approval(registryId=REGISTRY_ID, recordId=rid)
        r = registry_wait(rid)
    update_state(agent, stage="SUBMITTED", submittedBy=who, submittedAt=iso())
    log_event(agent, "SUBMITTED_FOR_RELEASE", who, registryStatus=r["status"], evidence=res["evidence"])
    return {"message": f"All gates passed. Registry record {rid} is {r['status']}; Security or Admin approves it in the Agent Registry console."}


def find_by_record(record_id: str) -> dict | None:
    for item in scan_states():
        if ((item.get("links") or {}).get("registryRecord") or {}).get("id") == record_id:
            return item
    return None


def scan_states() -> list:
    items, kw = [], {}
    while True:
        r = ddb.scan(FilterExpression=Attr("sk").eq("STATE"), **kw)
        items += r["Items"]
        if "LastEvaluatedKey" not in r:
            return items
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def on_registry_status(detail: dict) -> dict:
    """Release approval happens in the Agent Registry console; this enforces separation of duties after the fact."""
    params = detail.get("requestParameters") or {}
    record_id, status = params.get("recordId"), params.get("status")
    principal = (detail.get("userIdentity") or {}).get("arn", "")
    who = username(principal)
    if not record_id or detail.get("errorCode"):
        return {"ignored": "no record or failed call"}
    if AUTOMATION_ROLE_ARN.rsplit("/", 1)[-1] in principal or "gov-engine" in principal:
        return {"ignored": "runbook-driven change"}
    st = find_by_record(record_id)
    if not st:
        return {"ignored": "record is not a governed agent"}
    agent = st["agent"]
    if status == "APPROVED":
        conflicts = {"owner": st.get("owner"), "release submitter": st.get("submittedBy")}
        for role, user in conflicts.items():
            if user and who == user:
                reg.update_registry_record_status(registryId=REGISTRY_ID, recordId=record_id, status="REJECTED",
                                                  statusReason=f"Separation of duties: {who} is the {role} and cannot approve the release."[:1000])
                update_state(agent, stage="BUILD_APPROVED")
                log_event(agent, "SOD_VIOLATION_REVERTED", who, conflict=role, registryRecord=record_id)
                metric("SeparationOfDutiesViolations", 1)
                alert(f"Self-approval reverted: {agent}", f"{who} approved '{agent}' in the Agent Registry but is its {role}. "
                      "The approval was reverted to REJECTED.")
                return {"reverted": True}
        due = now() + timedelta(days=REVIEW_DAYS.get(st["riskTier"], 180))
        update_state(agent, stage="ACTIVE", releaseApprovedBy=who, activatedAt=iso(), nextReviewDue=iso(due))
        log_event(agent, "RELEASE_APPROVED", who, registryRecord=record_id, nextReviewDue=iso(due))
        return {"activated": agent}
    if status == "REJECTED" and st.get("stage") == "SUBMITTED":
        update_state(agent, stage="BUILD_APPROVED")
        log_event(agent, "RELEASE_REJECTED", who, reason=params.get("statusReason"))
    return {"ok": True}


# --------------------------------------------------------------------------- GOV-04 change

REAPPROVAL = {"TOOL", "PERMISSION", "DATA_SOURCE"}


def a_classify_change(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    require_stage(st, "ACTIVE")
    return classify_change(agent, st, e["ChangeType"], e["Summary"], e["NewVersion"], executor(e["exec"]))


def classify_change(agent: str, st: dict, ct: str, summary: str, version: str, who: str, **extra) -> dict:
    if ct not in ("PROMPT", "MODEL", "TOOL", "PERMISSION", "DATA_SOURCE"):
        raise GovError("Change type must be PROMPT, MODEL, TOOL, PERMISSION or DATA_SOURCE.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise GovError("NewVersion must look like 1.2.0")
    needs = ct in REAPPROVAL or (ct == "MODEL" and st["riskTier"] != "LOW")
    update_state(agent, stage="CHANGE_PENDING", pendingChange={"type": ct, "summary": summary, "version": version,
                                                               "requestedBy": who, "needsApproval": needs, **extra})
    log_event(agent, "CHANGE_REQUESTED", who, changeType=ct, version=version, needsApproval=needs, summary=summary)
    return {"route": "Approval" if needs else "PreApproved",
            "message": f"{ct} change to {version} " + ("needs Security approval." if needs else "is pre-approved by policy.")}


def a_apply_change(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    ch = st.get("pendingChange") or {}
    decided_by = "policy (pre-approved)"
    if ch.get("needsApproval"):
        d = approval(e["exec"], "ApproveChange")
        if d["status"] != "Approved":
            update_state(agent, stage="ACTIVE", pendingChange=None)
            log_event(agent, "CHANGE_REJECTED", d["approver"], comment=d["comment"], keptVersion=st["version"])
            raise GovError(f"Change rejected by {d['approver']}; version {st['version']} stays live.")
        separation_check(agent, d["approver"], {"change requester": ch.get("requestedBy"), "owner": st.get("owner")}, "approve this change")
        decided_by = d["approver"]
    return apply_change(agent, st, decided_by)


def apply_change(agent: str, st: dict, decided_by: str) -> dict:
    ch = st.get("pendingChange") or {}
    applied = []
    if ch.get("type") == "TOOL" and ch.get("tools") is not None:
        applied.append(apply_tool_policy(agent, st, ch["tools"]))
    rid = st["links"]["registryRecord"]["id"]
    registry_wait(rid)
    if reg.get_registry_record(registryId=REGISTRY_ID, recordId=rid).get("recordVersion") != ch["version"]:
        retry(lambda: reg.update_registry_record(registryId=REGISTRY_ID, recordId=rid, recordVersion=ch["version"]))
    registry_wait(rid)
    time.sleep(3)
    if registry_wait(rid)["status"] == "DRAFT":
        retry(lambda: reg.submit_registry_record_for_approval(registryId=REGISTRY_ID, recordId=rid))
    registry_wait(rid)
    time.sleep(2)
    retry(lambda: reg.update_registry_record_status(registryId=REGISTRY_ID, recordId=rid, status="APPROVED",
                                                    statusReason=f"Change {ch['type']} {ch['version']} approved by {decided_by} via GOV-04"[:1000]))
    registry_wait(rid)
    update_state(agent, stage="ACTIVE", version=ch["version"], pendingChange=None,
                 lastChange=f"{ch['type']} {ch['version']} by {ch.get('requestedBy')}, approved by {decided_by}")
    log_event(agent, "CHANGE_APPLIED", decided_by, changeType=ch["type"], version=ch["version"], applied=applied)
    return {"message": f"Version {ch['version']} is live (approved by {decided_by})." + (f" Applied: {'; '.join(applied)}." if applied else "")}


def apply_tool_policy(agent: str, st: dict, tools: list) -> str:
    """TOOL change: the agent's Cedar policy on the tools gateway allows exactly the listed tools."""
    links = st.get("links") or {}
    role, pe = (links.get("iamRole") or {}).get("id"), (links.get("policyEngine") or {}).get("id")
    gw = (links.get("gateway") or {}).get("id") or DEFAULT_GATEWAY
    if not (role and pe):
        raise GovError(f"'{agent}' has no IAM role or policy engine linked; build it first.")
    if not tools or not all(re.fullmatch(r"[A-Za-z0-9_-]+___[A-Za-z0-9_:/.-]+", t) for t in tools):
        raise GovError("tools must be a non-empty list like Target___tool_name.")
    actions = ", ".join(f'AgentCore::Action::"{t}"' for t in tools)
    statement = (f'permit(\n  principal == AgentCore::IamEntity::"arn:aws:sts::{ACCOUNT}:assumed-role/{role}",\n'
                 f'  action in [{actions}],\n'
                 f'  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/{gw}"\n);')
    name = "gov_" + re.sub(r"[^a-z0-9_]", "_", agent) + "_tools"
    existing = next((p for p in ac.list_policies(policyEngineId=pe).get("policies", []) if p.get("name") == name), None)
    if existing:
        ac.update_policy(policyEngineId=pe, policyId=existing["policyId"], definition={"cedar": {"statement": statement}})
        return f"Cedar policy {name} updated ({len(tools)} tools)"
    ac.create_policy(policyEngineId=pe, name=name, definition={"cedar": {"statement": statement}},
                     description=f"Tools allowed for governed agent {agent} (managed by GOV-04)")
    return f"Cedar policy {name} created ({len(tools)} tools)"


# --------------------------------------------------------------------------- GOV-05 review

def metric_sum(ns: str, name: str, dims: dict, days: int = 90) -> float:
    r = cw.get_metric_statistics(Namespace=ns, MetricName=name, Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
                                 StartTime=now() - timedelta(days=days), EndTime=now(), Period=86400, Statistics=["Sum"])
    return sum(p["Sum"] for p in r["Datapoints"])


def a_review_snapshot(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    require_stage(st, "ACTIVE", "SUSPENDED")
    pack = review_pack(agent, st)
    update_state(agent, reviewExecution=e["exec"])
    return {"summary": pack["summary"], "packUrl": console_s3_url(pack["key"])}


def review_pack(agent: str, st: dict) -> dict:
    checks = release_checks(st)
    links = st.get("links") or {}
    g = links.get("guardrail") or {}
    usage = {}
    if g.get("id"):
        dims = {"GuardrailArn": f"arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/{g['id']}", "GuardrailVersion": g.get("version", "DRAFT")}
        usage["guardrailInvocations90d"] = metric_sum("AWS/Bedrock/Guardrails", "Invocations", dims)
        usage["guardrailInterventions90d"] = metric_sum("AWS/Bedrock/Guardrails", "InvocationsIntervened", dims)
    events = ddb.query(KeyConditionExpression=Key("agent").eq(agent) & Key("sk").begins_with("EVENT#"))["Items"]
    pack = {"agent": agent, "generatedAt": iso(), "riskTier": st["riskTier"], "owner": st["owner"], "version": st["version"],
            "lastReview": st.get("lastReviewDate"), "dueDate": st.get("nextReviewDue"), "gates": checks, "usage": usage,
            "recentEvents": [{"at": x["at"], "action": x["action"], "actor": x["actor"]} for x in events[-25:]],
            "checklist": ["Still needed by the business", "Access is minimal", "Safety results acceptable", "Registry entry accurate"]}
    key = put_evidence(f"evidence/agents/{agent}/review-{iso()}.json", pack)
    failing = [c["label"] for c in checks if c["required"] and not c["ok"]]
    summary = (f"Review pack for {agent} (risk {st['riskTier']}, owner {st['owner']}). Gates: "
               + ("all passing" if not failing else "FAILING " + ", ".join(failing))
               + f". Guardrail interventions in 90 days: {int(usage.get('guardrailInterventions90d', 0))}.")
    return {"summary": summary, "key": key, "pack": pack}


def a_review_decide(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    d = approval(e["exec"], "SignOff")
    separation_check(agent, d["approver"], {"owner": st.get("owner")}, "sign off its review")
    return record_review(agent, st, d["approver"], d["comment"], d["status"] == "Approved")


def record_review(agent: str, st: dict, approver: str, comment: str, approved: bool) -> dict:
    d = {"approver": approver, "comment": comment or "", "status": "Approved" if approved else "Rejected"}
    m = re.search(r"outcome\s*=\s*(PASS|CHANGES_REQUIRED|RETIRE)", d["comment"], re.I)
    outcome = m.group(1).upper() if m else ("PASS" if d["status"] == "Approved" else "CHANGES_REQUIRED")
    due = now() + timedelta(days=REVIEW_DAYS.get(st["riskTier"], 180))
    update_state(agent, lastReviewDate=iso(), nextReviewDue=iso(due), reviewOutcome=outcome, reviewExecution=None)
    log_event(agent, "REVIEW_COMPLETED", d["approver"], outcome=outcome, comment=d["comment"], nextReviewDue=iso(due))
    if outcome != "PASS":
        alert(f"Review outcome {outcome}: {agent}", f"{d['approver']} signed off the review of '{agent}' with {outcome}. {d['comment']}")
    return {"message": f"Review signed off by {d['approver']}: {outcome}. Next review due {iso(due)[:10]}."}


def reviews_due() -> dict:
    started = []
    horizon = now() + timedelta(days=14)
    for st in scan_states():
        if st.get("stage") != "ACTIVE" or not st.get("nextReviewDue"):
            continue
        if datetime.fromisoformat(st["nextReviewDue"].replace("Z", "+00:00")) > horizon:
            continue
        open_ex = st.get("reviewExecution")
        if open_ex:
            try:
                if execution(open_ex)["AutomationExecutionStatus"] in ("Pending", "InProgress", "Waiting"):
                    continue
            except ClientError:
                pass
        try:
            github_gate.dispatch_workflow("gov-review.yml", {"agent": st["agent"]})
            started.append(st["agent"])
            log_event(st["agent"], "REVIEW_STARTED", "scheduler", via="github:gov-review.yml", due=st["nextReviewDue"])
        except Exception as ex:  # until the GitHub workflow exists, fall back to the console runbook
            r = ssm.start_automation_execution(DocumentName="GOV-05-PeriodicReview", Parameters={"AgentName": [st["agent"]]})
            started.append(st["agent"])
            log_event(st["agent"], "REVIEW_STARTED", "scheduler", execution=r["AutomationExecutionId"], due=st["nextReviewDue"],
                      githubError=str(ex)[:200])
    return {"started": started}


# --------------------------------------------------------------------------- GOV-06 retire

RETIRE_ORDER = [("registryRecord", "Deprecate the registry record"), ("iamRole", "Delete the IAM role"),
                ("workloadIdentity", "Delete the workload identity"), ("guardrail", "Guardrail"),
                ("policyEngine", "Cedar policy engine"), ("gateway", "Gateway"), ("runtime", "Agent runtime")]


def _shared_with(agent: str, kind: str, rid: str) -> list:
    out = []
    for st in scan_states():
        if st["agent"] != agent and st.get("stage") not in ("RETIRED", "REJECTED"):
            if ((st.get("links") or {}).get(kind) or {}).get("id") == rid:
                out.append(st["agent"])
    return out


def retirement_plan(st: dict) -> list:
    steps = []
    for kind, label in RETIRE_ORDER:
        link = (st.get("links") or {}).get(kind)
        if not link:
            continue
        shared = _shared_with(st["agent"], kind, link["id"])
        if kind == "registryRecord":
            action, why = "DEPRECATE", "the agent's catalog entry is kept for audit"
        elif not link.get("owned"):
            action, why = "KEEP", "shared, not owned by this agent"
        elif shared:
            action, why = "KEEP", "also used by " + ", ".join(shared)
        else:
            action, why = "DELETE", "owned by this agent"
        steps.append({"kind": kind, "label": label, "id": link["id"], "action": action, "why": why, "status": "PENDING"})
    return steps


def a_retire_plan(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    require_stage(st, "ACTIVE", "SUSPENDED", "BUILD_APPROVED", "REJECTED", "RETIRING", "DETECTED")
    if e.get("ConfirmName", "").strip().lower() != agent:
        raise GovError("Type the agent's exact name in ConfirmName to retire it.")
    who = executor(e["exec"])
    if not roles_of(who) & {"Admin", "Platform"}:
        raise GovError(f"{who} is not Admin or Platform and cannot retire agents.")
    return plan_retirement(agent, st, who, e.get("Reason", ""))


def plan_retirement(agent: str, st: dict, who: str, reason: str) -> dict:
    job = st.get("retirement") if st.get("stage") == "RETIRING" else None
    steps = job["steps"] if job else retirement_plan(st)
    update_state(agent, retirement={"steps": steps, "requestedBy": who, "reason": reason}, stageBeforeRetire=st["stage"])
    lines = [f"{s['action']}: {s['label']} {s['id']} ({s['why']})" for s in steps]
    return {"plan": " | ".join(lines) or "Nothing linked", "requester": who}


def _teardown(kind: str, rid: str, reason: str) -> str:
    if kind == "registryRecord":
        registry_wait(rid)
        reg.update_registry_record_status(registryId=REGISTRY_ID, recordId=rid, status="DEPRECATED",
                                          statusReason=f"Retired: {reason}"[:1000])
        return "deprecated"
    if kind == "iamRole":
        for p in iam.list_role_policies(RoleName=rid)["PolicyNames"]:
            iam.delete_role_policy(RoleName=rid, PolicyName=p)
        for p in iam.list_attached_role_policies(RoleName=rid)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=rid, PolicyArn=p["PolicyArn"])
        try:
            iam.delete_role_permissions_boundary(RoleName=rid)
        except ClientError:
            pass
        iam.delete_role(RoleName=rid)
        return "deleted"
    if kind == "workloadIdentity":
        ac.delete_workload_identity(name=rid)
        return "deleted"
    if kind == "runtime":
        ac.delete_agent_runtime(agentRuntimeId=rid)
        return "deleted"
    return "kept"


def a_retire_execute(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    job = st.get("retirement") or {}
    d = approval(e["exec"], "ApproveRetirement")
    if d["status"] != "Approved":
        update_state(agent, retirement=None)
        log_event(agent, "RETIREMENT_REJECTED", d["approver"], comment=d["comment"])
        raise GovError(f"Retirement rejected by {d['approver']}.")
    separation_check(agent, d["approver"], {"retirement requester": job.get("requestedBy")}, "approve its retirement")
    return execute_retirement(agent, st, d["approver"])


def execute_retirement(agent: str, st: dict, approver: str) -> dict:
    job = st.get("retirement") or {}
    if not job.get("steps"):
        raise GovError(f"No retirement plan for '{agent}'.")
    d = {"approver": approver}
    update_state(agent, stage="RETIRING")
    log_event(agent, "RETIREMENT_STARTED", job.get("requestedBy", "?"), approvedBy=d["approver"],
              plan=[(s["action"], s["kind"], s["id"]) for s in job["steps"]])
    steps = job["steps"]
    for s in steps:
        if s["status"] in ("DONE", "SKIPPED"):
            continue
        if s["action"] == "KEEP":
            s["status"], s["result"] = "SKIPPED", s["why"]
            continue
        try:
            s["result"], s["status"] = _teardown(s["kind"], s["id"], job.get("reason", "")), "DONE"
        except ClientError as ex:
            if ex.response["Error"]["Code"] in ("ResourceNotFoundException", "NoSuchEntity"):
                s["result"], s["status"] = "already gone", "DONE"
            else:
                s["status"], s["result"] = "FAILED", ex.response["Error"]["Message"]
                update_state(agent, retirement={**job, "steps": steps})
                log_event(agent, "RETIREMENT_FAILED", "gov-engine", step=s)
                raise GovError(f"Retirement stopped at '{s['label']}': {s['result']}. Run GOV-06 again to resume.") from ex
    update_state(agent, stage="RETIRED", retiredAt=iso(), retirement={**job, "steps": steps}, nextReviewDue=None)
    log_event(agent, "RETIRED", d["approver"], steps=[(s["kind"], s["status"], s.get("result")) for s in steps])
    return {"message": "Retired: " + "; ".join(f"{s['label']} {s['status']}" for s in steps)}


# --------------------------------------------------------------------------- GOV-07 external, GOV-08 suspend

def a_register_external(e: dict) -> dict:
    e = {**e, "Platform": e.get("Platform") or "External", "externalTools": "true"}
    return a_request(e)


def suspend_role(agent: str, st: dict, reason: str) -> list:
    roles = []
    role = ((st.get("links") or {}).get("iamRole") or {}).get("id")
    if role:
        iam.put_role_policy(RoleName=role, PolicyName="gov-suspended", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Sid": "Suspended", "Effect": "Deny",
            "Action": ["bedrock:InvokeModel*", "bedrock-agentcore:InvokeGateway", "bedrock-agentcore:InvokeAgentRuntime"],
            "Resource": "*"}]}))
        roles.append(role)
    return roles


def a_check_trigger(e: dict) -> dict:
    """Automatic suspension skips human approval only when the engine itself started the runbook."""
    who = executor(e["exec"])
    automatic = e.get("Trigger") == "AutomaticCritical"
    if automatic and "gov-engine" not in who:
        raise GovError(f"Only the governance engine may start an automatic suspension; {who} must use Trigger=Manual.")
    return {"route": "Automatic" if automatic else "Manual", "requester": who}


def a_suspend(e: dict) -> dict:
    agent = e["AgentName"].strip().lower()
    st = require_state(agent)
    decided_by = "automatic (critical control failure)"
    if e.get("Trigger") != "AutomaticCritical":
        d = approval(e["exec"], "ApproveSuspension")
        if d["status"] != "Approved":
            raise GovError(f"{e.get('Action', 'Suspend')} rejected by {d['approver']}.")
        decided_by = d["approver"]
    if e.get("Action") == "Reinstate":
        return reinstate_agent(agent, st, decided_by, e.get("Reason", ""))
    return suspend_agent(agent, st, decided_by, e.get("Reason", ""))


def reinstate_agent(agent: str, st: dict, decided_by: str, reason: str) -> dict:
    require_stage(st, "SUSPENDED")
    if True:  # keeps the original block's indentation; removed when the console runbooks are retired
        role = ((st.get("links") or {}).get("iamRole") or {}).get("id")
        if role:
            try:
                iam.delete_role_policy(RoleName=role, PolicyName="gov-suspended")
            except ClientError:
                pass
        registry = registry_set_status(st, "APPROVED", f"Reinstated by {decided_by}: {reason}")
        update_state(agent, stage="ACTIVE", suspendedReason=None)
        log_event(agent, "REINSTATED", decided_by, reason=reason, registry=registry)
        return {"message": f"{agent} reinstated by {decided_by}." + (f" Registry record {registry}." if registry else "")}


def suspend_agent(agent: str, st: dict, decided_by: str, reason: str) -> dict:
    require_stage(st, "ACTIVE", "CHANGE_PENDING")
    roles = suspend_role(agent, st, reason)
    registry = registry_set_status(st, "REJECTED", f"Suspended by {decided_by}: {reason}")
    update_state(agent, stage="SUSPENDED", suspendedReason=reason, suspendedAt=iso())
    log_event(agent, "SUSPENDED", decided_by, reason=reason, deniedRoles=roles, registry=registry)
    alert(f"Agent suspended: {agent}", f"{agent} was suspended ({decided_by}). Reason: {reason}")
    return {"message": f"{agent} suspended: model, gateway and runtime calls denied on {', '.join(roles) or 'no role'}"
                       + (f"; registry record {registry}." if registry else ".")}


def registry_set_status(st: dict, status: str, reason: str) -> str | None:
    """Move an agent's registry record to APPROVED or REJECTED, re-opening a REJECTED record first when needed."""
    rid = ((st.get("links") or {}).get("registryRecord") or {}).get("id")
    if not rid:
        return None
    r = registry_wait(rid)
    if r["status"] == status:
        return f"{rid} already {status}"
    if status == "APPROVED" and r["status"] in ("REJECTED", "DRAFT"):
        if r["status"] == "REJECTED":  # a real content update returns it to DRAFT
            desc = r.get("description") or st.get("purpose", "")
            retry(lambda: reg.update_registry_record(registryId=REGISTRY_ID, recordId=rid,
                                                     description={"optionalValue": desc[:-1] if desc.endswith(" ") else desc + " "}))
            registry_wait(rid)
            time.sleep(3)
        retry(lambda: reg.submit_registry_record_for_approval(registryId=REGISTRY_ID, recordId=rid))
        registry_wait(rid)
        time.sleep(2)
    retry(lambda: reg.update_registry_record_status(registryId=REGISTRY_ID, recordId=rid, status=status, statusReason=reason[:1000]))
    return f"{rid} {registry_wait(rid)['status']}"


# --------------------------------------------------------------------------- scheduled: shadow agents, metrics

def detect_shadow() -> dict:
    states = scan_states()
    governed = {((s.get("links") or {}).get("runtime") or {}).get("id") for s in states}
    found = []
    for r in ac.list_agent_runtimes().get("agentRuntimes", []):
        rid = r["agentRuntimeId"]
        if rid in governed:
            continue
        name = re.sub(r"[^a-z0-9-]", "-", r["agentRuntimeName"].lower())[:40] + "-detected"
        if get_state(name):
            continue
        put_state({"agent": name, "sk": "STATE", "stage": "DETECTED", "riskTier": "HIGH", "owner": "unknown",
                   "requestedBy": "unknown", "purpose": r.get("description") or "Detected outside the governance process",
                   "department": "unknown", "dataClassification": "RESTRICTED", "riskReasons": ["Not governed"],
                   "links": {"runtime": {"id": rid, "owned": False}}, "version": "0.0.0", "createdAt": iso()})
        log_event(name, "SHADOW_AGENT_DETECTED", "gov-engine", runtimeId=rid, runtimeName=r["agentRuntimeName"])
        alert(f"Shadow agent detected: {r['agentRuntimeName']}",
              f"Runtime {rid} is not linked to any approved agent. Bring it through GOV-01 intake or retire it with GOV-06.")
        found.append(rid)
    return {"detected": found}


def publish_metrics() -> dict:
    states = scan_states()
    counts = {}
    overdue = 0
    for s in states:
        counts[s.get("stage", "UNKNOWN")] = counts.get(s.get("stage", "UNKNOWN"), 0) + 1
        due = s.get("nextReviewDue")
        if s.get("stage") == "ACTIVE" and due and datetime.fromisoformat(due.replace("Z", "+00:00")) < now():
            overdue += 1
    waiting = ssm.describe_automation_executions(Filters=[{"Key": "ExecutionStatus", "Values": ["Waiting"]}]).get(
        "AutomationExecutionMetadataList", [])
    waiting = [w for w in waiting if w.get("DocumentName", "").startswith("GOV-")]
    pending_registry = 0
    for st in states:
        if st.get("stage") == "SUBMITTED":
            pending_registry += 1
    data = [{"MetricName": "AgentsByStage", "Dimensions": [{"Name": "Stage", "Value": k}], "Value": v, "Unit": "Count"}
            for k, v in counts.items()]
    for stage in ("ACTIVE", "SUBMITTED", "SUSPENDED", "DETECTED", "REQUESTED", "BUILD_APPROVED", "RETIRED"):
        if stage not in counts:
            data.append({"MetricName": "AgentsByStage", "Dimensions": [{"Name": "Stage", "Value": stage}], "Value": 0, "Unit": "Count"})
    data += [{"MetricName": "OverdueReviews", "Value": overdue, "Unit": "Count"},
             {"MetricName": "PendingApprovals", "Value": len(waiting) + pending_registry, "Unit": "Count"},
             {"MetricName": "ShadowAgents", "Value": counts.get("DETECTED", 0), "Unit": "Count"}]
    for i in range(0, len(data), 20):
        cw.put_metric_data(Namespace=METRIC_NS, MetricData=data[i:i + 20])
    return {"stages": counts, "overdue": overdue, "pending": len(waiting) + pending_registry}


# --------------------------------------------------------------------------- evidence export

def export_execution(detail: dict) -> dict:
    exec_id = detail.get("ExecutionId")
    doc = detail.get("Definition", "")
    if not exec_id or not doc.startswith("GOV-"):
        return {"ignored": True}
    ex = execution(exec_id)
    approvals = []
    for s in ex.get("StepExecutions", []):
        if s.get("Action") == "aws:approve":
            try:
                a = approval(exec_id, s["StepName"])
                approvals.append({"step": s["StepName"], "status": a["status"], "approver": a["approver"], "comment": a["comment"]})
            except GovError:
                pass
    agent = ((ex.get("Parameters") or {}).get("AgentName") or ["-"])[0].strip().lower()
    record = {"executionId": exec_id, "document": doc, "status": ex.get("AutomationExecutionStatus"),
              "executedBy": username(ex.get("ExecutedBy")), "agent": agent, "start": ex.get("ExecutionStartTime"),
              "end": ex.get("ExecutionEndTime"), "failure": ex.get("FailureMessage"), "approvals": approvals,
              "steps": [{"name": s.get("StepName"), "status": s.get("StepStatus"), "failure": s.get("FailureMessage")}
                        for s in ex.get("StepExecutions", [])]}
    t = iso()
    put_evidence(f"evidence/executions/{doc}/{exec_id}.json", record)
    s3.put_object(Bucket=BUCKET, Key=f"evidence/runbooks/dt={t[:10]}/{exec_id}-{record['status']}.json",
                  Body=json.dumps({**record, "approvals": json.dumps(approvals), "steps": json.dumps(record["steps"]),
                                   "time": t}, default=str).encode())
    return {"exported": exec_id}


# --------------------------------------------------------------------------- AWS Config custom rules

def config_eval(event: dict) -> dict:
    params = json.loads(event.get("ruleParameters") or "{}")
    check = params.get("check")
    token = event["resultToken"]
    ordered = now()
    evals = []
    if check == "agent-role-no-admin":
        roles = []
        for page in iam.get_paginator("list_roles").paginate():
            roles += [r for r in page["Roles"] if "agent" in r["RoleName"].lower() and "AWSServiceRole" not in r["RoleName"]]
        for r in roles:
            attached = iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]
            broad = [p["PolicyName"] for p in attached if p["PolicyName"] in BROAD_POLICIES]
            evals.append({"ComplianceResourceType": "AWS::IAM::Role", "ComplianceResourceId": r["RoleId"],
                          "ComplianceType": "NON_COMPLIANT" if broad else "COMPLIANT",
                          "Annotation": (f"Agent role {r['RoleName']} has {', '.join(broad)}" if broad else f"{r['RoleName']}: scoped")[:255],
                          "OrderingTimestamp": ordered})
    elif check == "agent-runtimes-governed":
        states = scan_states()
        active = {((s.get("links") or {}).get("runtime") or {}).get("id") for s in states if s.get("stage") == "ACTIVE"}
        bad = [r["agentRuntimeName"] for r in ac.list_agent_runtimes().get("agentRuntimes", []) if r["agentRuntimeId"] not in active]
        evals.append({"ComplianceResourceType": "AWS::::Account", "ComplianceResourceId": ACCOUNT,
                      "ComplianceType": "NON_COMPLIANT" if bad else "COMPLIANT",
                      "Annotation": (f"Runtimes not linked to an ACTIVE governed agent: {', '.join(bad)}" if bad
                                     else "Every runtime belongs to an ACTIVE governed agent")[:255], "OrderingTimestamp": ordered})
    elif check == "agent-guardrail-ready":
        bad = []
        for r in ac.list_agent_runtimes().get("agentRuntimes", []):
            env = ac.get_agent_runtime(agentRuntimeId=r["agentRuntimeId"]).get("environmentVariables") or {}
            gid = env.get("GUARDRAIL_ID")
            try:
                ok = bool(gid) and bedrock.get_guardrail(guardrailIdentifier=gid)["status"] == "READY"
            except ClientError:
                ok = False
            if not ok:
                bad.append(r["agentRuntimeName"])
        evals.append({"ComplianceResourceType": "AWS::::Account", "ComplianceResourceId": ACCOUNT,
                      "ComplianceType": "NON_COMPLIANT" if bad else "COMPLIANT",
                      "Annotation": (f"Runtimes without a READY guardrail: {', '.join(bad)}" if bad
                                     else "Every runtime has a READY guardrail")[:255], "OrderingTimestamp": ordered})
    for i in range(0, len(evals), 100):
        cfg.put_evaluations(Evaluations=evals[i:i + 100], ResultToken=token)
    return {"evaluated": len(evals)}


def on_config_change(detail: dict) -> dict:
    rule = detail.get("configRuleName", "")
    new = (detail.get("newEvaluationResult") or {}).get("complianceType")
    if new != "NON_COMPLIANT":
        return {"ignored": True}
    alert(f"Control failed: {rule}", json.dumps((detail.get("newEvaluationResult") or {}).get("annotation") or detail, default=str)[:2000])
    if rule != "gov-agent-role-no-admin":
        return {"alerted": rule}
    role_id = detail.get("resourceId")
    for st in scan_states():
        role = ((st.get("links") or {}).get("iamRole") or {}).get("id")
        if not role or st.get("stage") != "ACTIVE":
            continue
        if iam.get_role(RoleName=role)["Role"]["RoleId"] == role_id:
            log_event(st["agent"], "AUTO_SUSPEND_STARTED", "aws-config", rule=rule)
            suspend_agent(st["agent"], st, "automatic (critical control failure)",
                          f"AWS Config: {rule} is NON_COMPLIANT (admin-level policy on {role})")
            return {"suspended": st["agent"]}
    return {"alerted": rule}


# --------------------------------------------------------------------------- entry point

ACTIONS = {
    "request": a_request, "decide_intake": a_decide_intake, "build": a_build, "gates": a_gates, "submit": a_submit,
    "classify_change": a_classify_change, "apply_change": a_apply_change, "review_snapshot": a_review_snapshot,
    "review_decide": a_review_decide, "retire_plan": a_retire_plan, "retire_execute": a_retire_execute,
    "register_external": a_register_external, "check_trigger": a_check_trigger, "suspend": a_suspend,
    "reviews_due": lambda e: reviews_due(), "detect_shadow": lambda e: detect_shadow(),
    "publish_metrics": lambda e: publish_metrics(),
    "tick": lambda e: {**detect_shadow(), **publish_metrics()},
    "gate_command": lambda e: github_gate.gate_command(e),
}


def handler(event, context):
    try:
        if "configRuleName" in event and "resultToken" in event:
            return config_eval(event)
        dt = event.get("detail-type")
        if dt == "EC2 Automation Execution Status-change Notification":
            return export_execution(event["detail"])
        if dt == "AWS API Call via CloudTrail" and event["detail"].get("eventName") == "UpdateRegistryRecordStatus":
            return on_registry_status(event["detail"])
        if dt == "Config Rules Compliance Change":
            return on_config_change(event["detail"])
        if dt and "Pending Approval" in dt:
            st = find_by_record(event["detail"].get("registryRecordId", ""))
            if st:
                log_event(st["agent"], "RELEASE_PENDING_APPROVAL", "agent-registry", record=event["detail"].get("registryRecordId"))
            return {"ok": True}
        action = event.get("action")
        if isinstance(action, str) and action.startswith("gh_"):
            import gh_actions
            if action not in gh_actions.ACTIONS:
                return {"error": f"Unknown action {action}"}
            return gh_actions.run(action, event)
        if action not in ACTIONS:
            return {"error": f"Unknown action {action}"}
        return ACTIONS[action](event)
    except (GovError, github_gate.GateError) as ex:
        return {"error": str(ex)}
