#!/usr/bin/env python3
"""Run a saved Athena query from the ai-governance workgroup and print a redacted Markdown table.

  python scripts/audit_query.py "<saved query name>"   (credentials: gh-audit-ro via OIDC)

Values listed one per line in $GOV_PRIVATE_VALUES are replaced with *** in the output.
"""
from __future__ import annotations

import os
import re
import sys
import time

import boto3

WORKGROUP = "ai-governance"


def main(name: str) -> int:
    athena = boto3.client("athena")
    ids = athena.list_named_queries(WorkGroup=WORKGROUP)["NamedQueryIds"]
    queries = athena.batch_get_named_query(NamedQueryIds=ids)["NamedQueries"] if ids else []
    q = next((x for x in queries if x["Name"] == name), None)
    if not q:
        print(f"::error::Saved query '{name}' not found")
        return 1
    qid = athena.start_query_execution(QueryString=q["QueryString"], WorkGroup=WORKGROUP,
                                       QueryExecutionContext={"Database": q["Database"]})["QueryExecutionId"]
    for _ in range(90):
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            print(f"::error::Query {state}")
            return 1
        time.sleep(2)
    rows = athena.get_query_results(QueryExecutionId=qid, MaxResults=51)["ResultSet"]["Rows"]
    secrets = sorted((v for v in os.environ.get("GOV_PRIVATE_VALUES", "").splitlines() if v), key=len, reverse=True)

    def clean(x: str | None) -> str:
        x = (x or "").replace("|", "\\|").replace("\n", " ")[:160]
        for v in secrets:
            x = re.sub(re.escape(v), "***", x, flags=re.I)
        return x

    cells = [[clean(c.get("VarCharValue")) for c in r["Data"]] for r in rows]
    print(f"### Audit: {name}\n")
    if cells:
        print("| " + " | ".join(cells[0]) + " |")
        print("|" + "---|" * len(cells[0]))
        for r in cells[1:]:
            print("| " + " | ".join(r) + " |")
    print(f"\n{max(len(cells) - 1, 0)} rows (first 50).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
