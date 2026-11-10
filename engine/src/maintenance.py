"""One-off maintenance for the cutover from the console runbooks to GitHub (gov-maintenance workflow).

Every task runs twice: first as a dry run that lists exactly what would change (posted in the job
summary), then, after the admin role bot approves the gov-maintenance gate, for real. Tasks are
idempotent: running one again changes only what is still left to change.

  map-legacy-roles       record roles on agents created by the console personas, so separation of
                         duties applies to them on GitHub
  registry-cleanup       bring registry records in line with the lifecycle: withdraw the console-era
                         pending release, deprecate the test record, reject the suspended agent's record
"""
from __future__ import annotations

import engine as E

PERSONA_ROLE = {"gov-james": "developer", "gov-lisa": "owner", "gov-emily": "platform", "gov-michael": "security",
                "gov-sarah": "admin", "gov-robert": "auditor"}
TEST_RECORDS = ("test-skill",)


def _registry_records() -> list:
    out, kw = [], {}
    while True:
        r = E.reg.list_registry_records(registryId=E.REGISTRY_ID, **kw)
        out += r.get("registryRecords", [])
        if not r.get("nextToken"):
            return out
        kw["nextToken"] = r["nextToken"]



def map_legacy_roles(apply: bool) -> list[str]:
    changes = []
    for st in E.scan_states():
        if st.get("roles") or st.get("stage") == "DETECTED":
            continue
        roles = {"requestedBy": PERSONA_ROLE.get(st.get("requestedBy", ""), "developer"),
                 "owner": PERSONA_ROLE.get(st.get("owner", ""), "developer")}
        changes.append(f"{st['agent']}: requestedBy {st.get('requestedBy')} -> {roles['requestedBy']}, "
                       f"owner {st.get('owner')} -> {roles['owner']}")
        if apply:
            E.update_state(st["agent"], roles=roles)
            E.log_event(st["agent"], "ROLES_MAPPED", "gov-maintenance", roles=roles)
    return changes


def registry_cleanup(apply: bool) -> list[str]:
    changes = []
    states = {s["agent"]: s for s in E.scan_states()}
    for rec in _registry_records():
        name, status, rid = rec.get("name"), rec.get("status"), rec.get("recordId") or rec["recordArn"].rsplit("/", 1)[-1]
        st = states.get(name)
        if st and st.get("stage") == "SUBMITTED" and status == "PENDING_APPROVAL" and st.get("via") != "github":
            changes.append(f"{name}: withdraw console-era release request (registry REJECTED, stage BUILD_APPROVED); "
                           "resubmit with a release pull request")
            if apply:
                E.registry_set_status(st, "REJECTED", "Cutover to GitHub: resubmit with a release pull request")
                E.update_state(name, stage="BUILD_APPROVED")
                E.log_event(name, "RELEASE_WITHDRAWN", "gov-maintenance", reason="cutover to GitHub")
        elif st and st.get("stage") == "SUSPENDED" and status == "APPROVED":
            changes.append(f"{name}: suspended agent's registry record APPROVED -> REJECTED")
            if apply:
                E.registry_set_status(st, "REJECTED", f"Suspended: {st.get('suspendedReason', '')}")
                E.log_event(name, "REGISTRY_ALIGNED", "gov-maintenance", status="REJECTED")
        elif name in TEST_RECORDS and status != "DEPRECATED":
            changes.append(f"{name}: test record {status} -> DEPRECATED")
            if apply:
                E.registry_wait(rid)
                E.reg.update_registry_record_status(registryId=E.REGISTRY_ID, recordId=rid, status="DEPRECATED",
                                                    statusReason="Test record removed at the cutover to GitHub")
    return changes


TASKS = {"map-legacy-roles": map_legacy_roles,
         "registry-cleanup": registry_cleanup}


def run(event: dict) -> dict:
    """Dry run: open an issue listing every change and naming the waiting run. Apply: report on that issue."""
    import github_gate as G
    from gh_actions import redact
    task = event.get("task")
    if task not in TASKS:
        raise E.GovError(f"Unknown task '{task}'. Tasks: {', '.join(TASKS)}.")
    apply = str(event.get("mode", "dry-run")) == "apply"
    changes = TASKS[task](apply)
    verb = "Changed" if apply else "Would change"
    body = "\n".join(f"- {c}" for c in changes) or "- nothing (already done)"
    message = redact(f"{task}: {verb} {len(changes)} item(s).\n\n{body}")
    run_id = event.get("run_id")
    if not apply:
        issue = G.open_issue(f"Maintenance: {task}",
                             f"**Dry run** (run {run_id})\n\n{message}\n\nTo apply exactly this, the admin role comments here: "
                             f"`/approve admin run={run_id} <note>`, or `/reject admin run={run_id} <reason>`.", ["gov-maintenance"])
    else:
        issue = int(event.get("issue") or 0)
        if issue:
            G.comment(issue, f"**Applied** (run {run_id})\n\n{message}")
    return {"message": message, "changes": changes, "applied": apply, "issue": issue}
