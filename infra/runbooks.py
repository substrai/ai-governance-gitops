"""Systems Manager Automation runbooks GOV-01..GOV-08.

Each runbook is the "form" people fill in from the Systems Manager console. Script steps
call the gov-engine Lambda; aws:approve steps are the human decisions.
"""
from __future__ import annotations

import yaml

ENGINE_SCRIPT = """import json, boto3
def handler(events, context):
    r = boto3.client('lambda').invoke(FunctionName='gov-engine', Payload=json.dumps(events).encode())
    body = json.loads(r['Payload'].read() or b'{}')
    if r.get('FunctionError'):
        raise Exception(body.get('errorMessage', 'Governance engine error'))
    if isinstance(body, dict) and body.get('error'):
        raise Exception(body['error'])
    return body
"""

WEEK = 604800


def call(name: str, action: str, payload: dict, outputs: list[str], **extra) -> dict:
    step = {
        "name": name, "action": "aws:executeScript", "timeoutSeconds": 900,
        "inputs": {"Runtime": "python3.11", "Handler": "handler", "Script": ENGINE_SCRIPT,
                   "InputPayload": {"action": action, "exec": "{{automation:EXECUTION_ID}}", **payload}},
        "outputs": [{"Name": o, "Selector": f"$.Payload.{o}", "Type": "String"} for o in outputs],
    }
    step.update(extra)
    return step


def approve(name: str, approvers: list[str], message: str, topic: str, **extra) -> dict:
    step = {"name": name, "action": "aws:approve", "timeoutSeconds": WEEK,
            "inputs": {"NotificationArn": topic, "Message": message, "MinRequiredApprovals": 1, "Approvers": approvers}}
    step.update(extra)
    return step


def p(desc: str, **kw) -> dict:
    return {"type": kw.pop("type", "String"), "description": desc, **kw}


RISK_PARAMS = {
    "PersonalData": p("Does it handle personal or guest data (names, emails, phone numbers)?", type="Boolean", default=False),
    "CustomerFacing": p("Will guests talk to it directly?", type="Boolean", default=False),
    "TakesActions": p("Can it take actions in other systems (orders, refunds, schedules)?", type="Boolean", default=False),
    "FinancialImpact": p("Can it affect payments, refunds or prices?", type="Boolean", default=False),
    "ExternalTools": p("Does it use third-party tools or other agents?", type="Boolean", default=False),
    "Autonomous": p("Does it act without a person checking each action?", type="Boolean", default=False),
}
RISK_PAYLOAD = {"personalData": "{{PersonalData}}", "customerFacing": "{{CustomerFacing}}", "takesActions": "{{TakesActions}}",
                "financialImpact": "{{FinancialImpact}}", "externalTools": "{{ExternalTools}}", "autonomous": "{{Autonomous}}"}


def documents(account: str, role_arn: str, topic: str, policy_engine: str, gateway: str, gov) -> dict[str, str]:
    """gov: GovConfig, for organisation-specific defaults and guardrail profile names."""
    def _arn(user: str) -> str:
        return f"arn:aws:iam::{account}:user/gov/{user}"

    SECURITY_APPROVERS = [_arn("gov-michael"), _arn("gov-sarah")]
    ADMIN_APPROVERS = [_arn("gov-sarah")]
    REVIEWERS = [_arn("gov-michael"), _arn("gov-lisa"), _arn("gov-sarah")]

    base_params = {"AutomationAssumeRole": p("Role the runbook runs as. Leave the default.", default=role_arn,
                                             allowedPattern=r"^arn:aws:iam::\d{12}:role/GovAutomationRole$")}
    agent = {"AgentName": p("The agent's name, for example catering-order-assistant.", allowedPattern=r"^[a-z0-9][a-z0-9-]{2,47}$")}

    docs = {}

    docs["GOV-01-RequestAgent"] = {
        "description": "# GOV-01 Request a new AI agent\n\nAnswer the questions below. The risk tier is calculated from your answers, "
                       "then Security approves or rejects the request. Nothing is built until it is approved.",
        "parameters": {**agent,
                       "Purpose": p("What the agent does and for whom (10+ characters).", allowedPattern=r"^.{10,1000}$"),
                       "Department": p("Owning department.", allowedValues=["Guest Experience", "Restaurant Operations", "Supply Chain",
                                                                             "Finance", "People", "Marketing", "Technology"]),
                       "IntendedUsers": p("Who will use it.", default=gov.naming.intended_users_default),
                       "DataClassification": p("Most sensitive data it touches.", allowedValues=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
                       **RISK_PARAMS, **base_params},
        "mainSteps": [
            call("ScoreRisk", "request", {"AgentName": "{{AgentName}}", "Purpose": "{{Purpose}}", "Department": "{{Department}}",
                                           "IntendedUsers": "{{IntendedUsers}}", "DataClassification": "{{DataClassification}}",
                                           **RISK_PAYLOAD}, ["summary", "tier", "requester"]),
            approve("ApproveIntake", SECURITY_APPROVERS,
                    "New AI agent request. {{ScoreRisk.summary}} Approve to allow the build, or reject with a reason. "
                    "To change the risk tier, approve with the comment tier=HIGH (or MEDIUM/LOW).", topic,
                    onFailure="step:RecordDecision"),
            call("RecordDecision", "decide_intake", {"AgentName": "{{AgentName}}", "step": "ApproveIntake"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-02-BuildAgent"] = {
        "description": "# GOV-02 Build an approved agent\n\nCreates the agent's workload identity, a least-privilege IAM role with a "
                       "permission boundary and a guardrail-only model policy, links its guardrail, Cedar policy engine and gateway, "
                       "and registers it in the Agent Registry as a DRAFT.",
        "parameters": {**agent,
                       "Guardrail": p("Guardrail profile.", allowedValues=list(gov.guardrails),
                                      default=gov.guardrail_defaults["customerFacing"]),
                       "Endpoint": p("Agent endpoint URL (optional).", default=""),
                       "RuntimeId": p("Existing AgentCore runtime ID to link (optional).", default=""),
                       "PolicyEngine": p("Cedar policy engine.", default=policy_engine),
                       "Gateway": p("AgentCore gateway for tools.", default=gateway), **base_params},
        "mainSteps": [call("Build", "build", {"AgentName": "{{AgentName}}", "Guardrail": "{{Guardrail}}", "Endpoint": "{{Endpoint}}",
                                              "RuntimeId": "{{RuntimeId}}", "PolicyEngine": "{{PolicyEngine}}", "Gateway": "{{Gateway}}"},
                           ["message"], isEnd=True)],
    }

    docs["GOV-03-SubmitRelease"] = {
        "description": "# GOV-03 Submit an agent for release\n\nChecks every release gate live against AWS. If all pass, the agent's "
                       "registry record moves to PENDING_APPROVAL, and Security or Admin approves it in the Agent Registry console.",
        "parameters": {**agent, **base_params},
        "mainSteps": [
            call("CheckReleaseGates", "gates", {"AgentName": "{{AgentName}}"}, ["message"]),
            call("SubmitToRegistry", "submit", {"AgentName": "{{AgentName}}"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-04-RequestChange"] = {
        "description": "# GOV-04 Change a live agent\n\nPrompt changes (and model changes on LOW-risk agents) are pre-approved by "
                       "policy. Tool, permission and data-source changes need Security approval. A rejected change leaves the "
                       "current version live.",
        "parameters": {**agent,
                       "ChangeType": p("What is changing.", allowedValues=["PROMPT", "MODEL", "TOOL", "PERMISSION", "DATA_SOURCE"]),
                       "Summary": p("What changes and why.", allowedPattern=r"^.{5,1000}$"),
                       "NewVersion": p("New version, for example 1.4.0.", allowedPattern=r"^\d+\.\d+\.\d+$"), **base_params},
        "mainSteps": [
            call("ClassifyChange", "classify_change", {"AgentName": "{{AgentName}}", "ChangeType": "{{ChangeType}}",
                                                       "Summary": "{{Summary}}", "NewVersion": "{{NewVersion}}"}, ["route", "message"]),
            {"name": "Route", "action": "aws:branch", "inputs": {"Choices": [
                {"NextStep": "ApproveChange", "Variable": "{{ClassifyChange.route}}", "StringEquals": "Approval"},
                {"NextStep": "ApplyChange", "Variable": "{{ClassifyChange.route}}", "StringEquals": "PreApproved"}]}},
            approve("ApproveChange", SECURITY_APPROVERS, "{{ClassifyChange.message}} Agent {{AgentName}}: {{Summary}}", topic,
                    onFailure="step:ApplyChange"),
            call("ApplyChange", "apply_change", {"AgentName": "{{AgentName}}"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-05-PeriodicReview"] = {
        "description": "# GOV-05 Periodic review\n\nStarted automatically when a review is due (every 90 days for HIGH risk, "
                       "180 for MEDIUM and LOW). Collects evidence, then a reviewer who does not own the agent signs off.",
        "parameters": {**agent, **base_params},
        "mainSteps": [
            call("CollectEvidence", "review_snapshot", {"AgentName": "{{AgentName}}"}, ["summary", "packUrl"]),
            approve("SignOff", REVIEWERS, "{{CollectEvidence.summary}} Review pack: {{CollectEvidence.packUrl}} . "
                    "Approve to sign off. Add a comment: outcome=PASS, outcome=CHANGES_REQUIRED or outcome=RETIRE, plus notes.",
                    topic, onFailure="step:RecordReview"),
            call("RecordReview", "review_decide", {"AgentName": "{{AgentName}}"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-06-RetireAgent"] = {
        "description": "# GOV-06 Retire an agent\n\nShows what will be removed, needs the agent's name typed to confirm and an "
                       "Admin's approval, then deletes owned resources in order. Shared resources are never deleted. "
                       "Run it again to resume a failed retirement.",
        "parameters": {**agent, "ConfirmName": p("Type the agent's name again to confirm."),
                       "Reason": p("Why it is being retired.", allowedPattern=r"^.{3,500}$"), **base_params},
        "mainSteps": [
            call("PlanRetirement", "retire_plan", {"AgentName": "{{AgentName}}", "ConfirmName": "{{ConfirmName}}",
                                                   "Reason": "{{Reason}}"}, ["plan", "requester"]),
            approve("ApproveRetirement", ADMIN_APPROVERS, "Retire {{AgentName}} (requested by {{PlanRetirement.requester}}). "
                    "Plan: {{PlanRetirement.plan}}. Reason: {{Reason}}", topic, onFailure="step:Retire"),
            call("Retire", "retire_execute", {"AgentName": "{{AgentName}}"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-07-RegisterExternalAgent"] = {
        "description": "# GOV-07 Register an agent that runs outside AWS\n\nSame intake and approval as GOV-01. After approval, "
                       "GOV-02 links it to the agent gateway so its credentials stay in the AgentCore Identity token vault.",
        "parameters": {**agent,
                       "Platform": p("Where it runs.", allowedValues=["Snowflake Cortex", "Google Vertex AI", "Salesforce Agentforce", "Other"]),
                       "Endpoint": p("Its endpoint URL (https).", allowedPattern=r"^https://\S+$"),
                       "Purpose": p("What it does (10+ characters).", allowedPattern=r"^.{10,1000}$"),
                       "Department": p("Owning department.", allowedValues=["Guest Experience", "Restaurant Operations", "Supply Chain",
                                                                             "Finance", "People", "Marketing", "Technology"]),
                       "DataClassification": p("Most sensitive data it touches.", allowedValues=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
                       **{k: v for k, v in RISK_PARAMS.items() if k != "ExternalTools"}, **base_params},
        "mainSteps": [
            call("ScoreRisk", "register_external", {"AgentName": "{{AgentName}}", "Purpose": "{{Purpose}}", "Department": "{{Department}}",
                                                    "Platform": "{{Platform}}", "Endpoint": "{{Endpoint}}",
                                                    "DataClassification": "{{DataClassification}}",
                                                    **{k: v for k, v in RISK_PAYLOAD.items() if k != "externalTools"}},
                 ["summary", "tier", "requester"]),
            approve("ApproveIntake", SECURITY_APPROVERS, "External agent on {{Platform}}. {{ScoreRisk.summary}}", topic,
                    onFailure="step:RecordDecision"),
            call("RecordDecision", "decide_intake", {"AgentName": "{{AgentName}}", "step": "ApproveIntake"}, ["message"], isEnd=True),
        ],
    }

    docs["GOV-08-SuspendAgent"] = {
        "description": "# GOV-08 Suspend or reinstate an agent\n\nSuspending adds a deny policy to the agent's role, so it can no "
                       "longer call models, tools or other agents. Security approves; critical control failures suspend automatically.",
        "parameters": {**agent, "Action": p("Suspend or reinstate.", allowedValues=["Suspend", "Reinstate"], default="Suspend"),
                       "Reason": p("Why.", allowedPattern=r"^.{3,500}$"),
                       "Trigger": p("Leave as Manual. AutomaticCritical is used only by the governance engine.",
                                    allowedValues=["Manual", "AutomaticCritical"], default="Manual"), **base_params},
        "mainSteps": [
            call("CheckTrigger", "check_trigger", {"AgentName": "{{AgentName}}", "Trigger": "{{Trigger}}"}, ["route", "requester"]),
            {"name": "Route", "action": "aws:branch", "inputs": {"Choices": [
                {"NextStep": "Apply", "Variable": "{{CheckTrigger.route}}", "StringEquals": "Automatic"},
                {"NextStep": "ApproveSuspension", "Variable": "{{CheckTrigger.route}}", "StringEquals": "Manual"}]}},
            approve("ApproveSuspension", SECURITY_APPROVERS, "{{Action}} agent {{AgentName}} (requested by {{CheckTrigger.requester}}). "
                    "Reason: {{Reason}}", topic, onFailure="step:Apply"),
            call("Apply", "suspend", {"AgentName": "{{AgentName}}", "Action": "{{Action}}", "Reason": "{{Reason}}",
                                       "Trigger": "{{Trigger}}"}, ["message"], isEnd=True),
        ],
    }

    out = {}
    for name, d in docs.items():
        out[name] = yaml.safe_dump({"schemaVersion": "0.3", "description": d["description"],
                                    "assumeRole": "{{AutomationAssumeRole}}", "parameters": d["parameters"],
                                    "mainSteps": d["mainSteps"]}, sort_keys=False, width=200)
    return out
