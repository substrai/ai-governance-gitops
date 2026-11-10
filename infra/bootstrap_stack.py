"""GitHubBootstrap: the one stack deployed outside GitHub (once, by an administrator).

It lets GitHub Actions in exactly one repository reach this account with short-lived OIDC
credentials, and stores the private deployment config where CI can read it. After this stack
exists, every other change goes through the repository's workflows.

Roles and who can assume them (OIDC "sub" claim). The repository uses GitHub's immutable
subject format, repo:<owner>@<owner-id>/<repo>@<repo-id>:<context>, so a deleted and
re-created repository with the same name cannot inherit this trust.
  gh-infra-plan    pull requests and main      read CloudFormation, run `cdk diff`, read config
  gh-infra-deploy  environment infra-prod      assume the CDK bootstrap roles to deploy
  gh-gov-engine    environments gov-*, main,   invoke the gov-engine Lambda only
                   pull requests
  gh-audit-ro      environment gov-audit       run Athena queries over the evidence bucket
"""
from __future__ import annotations

import json

from aws_cdk import CfnOutput, Duration, Stack, aws_iam as iam, aws_ssm as ssm
from constructs import Construct

from config import GovConfig

GITHUB_OIDC = "token.actions.githubusercontent.com"
CONFIG_PARAMETER = "/ai-gov/config"
CDK_QUALIFIER = "hnb659fds"


class GitHubBootstrapStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, gov: GovConfig, config_json: dict, **kw) -> None:
        super().__init__(scope, cid, **kw)
        acct, region, sub_prefix = self.account, self.region, gov.github_oidc_subject_prefix

        provider = iam.OidcProviderNative(self, "GitHubOidc", url=f"https://{GITHUB_OIDC}",
                                          client_ids=["sts.amazonaws.com"])

        def github_role(rid: str, name: str, subjects: list[str], description: str) -> iam.Role:
            principal = iam.WebIdentityPrincipal(provider.oidc_provider_arn, conditions={
                "StringEquals": {f"{GITHUB_OIDC}:aud": "sts.amazonaws.com"},
                "StringLike": {f"{GITHUB_OIDC}:sub": [f"{sub_prefix}:{s}" for s in subjects]},
            })
            return iam.Role(self, rid, role_name=name, assumed_by=principal, description=description,
                            max_session_duration=Duration.hours(1))

        config_param = ssm.StringParameter(self, "Config", parameter_name=CONFIG_PARAMETER,
                                           string_value=json.dumps(config_json, separators=(",", ":")),
                                           description="Private deployment config for the AI governance repo (IDs and names)",
                                           tier=ssm.ParameterTier.STANDARD)
        cdk_role = f"arn:aws:iam::{acct}:role/cdk-{CDK_QUALIFIER}-{{}}-{acct}-{region}"
        bootstrap_version = f"arn:aws:ssm:{region}:{acct}:parameter/cdk-bootstrap/{CDK_QUALIFIER}/version"

        plan = github_role("InfraPlanRole", "gh-infra-plan", ["pull_request", "ref:refs/heads/main"],
                           "GitHub Actions: read-only cdk diff for pull requests and main")
        plan.add_to_policy(iam.PolicyStatement(sid="ReadStacks", resources=["*"], actions=[
            "cloudformation:DescribeStacks", "cloudformation:GetTemplate", "cloudformation:ListStackResources",
            "cloudformation:DescribeStackResources", "cloudformation:GetTemplateSummary"]))
        plan.add_to_policy(iam.PolicyStatement(sid="CdkLookupRole", actions=["sts:AssumeRole"],
                                               resources=[cdk_role.format("lookup-role")]))
        plan.add_to_policy(iam.PolicyStatement(sid="ReadConfig", actions=["ssm:GetParameter"],
                                               resources=[config_param.parameter_arn, bootstrap_version]))

        deploy = github_role("InfraDeployRole", "gh-infra-deploy", ["environment:infra-prod"],
                             "GitHub Actions: cdk deploy from the infra-prod environment only")
        deploy.add_to_policy(iam.PolicyStatement(sid="CdkBootstrapRoles", actions=["sts:AssumeRole", "sts:TagSession"],
                                                 resources=[cdk_role.format(r) for r in
                                                            ("deploy-role", "file-publishing-role", "image-publishing-role",
                                                             "lookup-role")]))
        deploy.add_to_policy(iam.PolicyStatement(sid="ReadConfig", actions=["ssm:GetParameter"],
                                                 resources=[config_param.parameter_arn, bootstrap_version]))
        deploy.add_to_policy(iam.PolicyStatement(sid="ReadStacks", resources=["*"], actions=[
            "cloudformation:DescribeStacks", "cloudformation:GetTemplate"]))

        engine = github_role("GovEngineRole", "gh-gov-engine", ["environment:gov-*", "ref:refs/heads/main", "pull_request"],
                             "GitHub Actions: invoke the gov-engine Lambda (governance workflows)")
        engine.add_to_policy(iam.PolicyStatement(sid="InvokeEngine", actions=["lambda:InvokeFunction"],
                                                 resources=[f"arn:aws:lambda:{region}:{acct}:function:gov-engine"]))

        n = gov.naming
        evidence, results = f"{n.bucket_prefix}-evidence-{acct}", f"{n.bucket_prefix}-athena-{acct}"
        audit = github_role("AuditRole", "gh-audit-ro", ["environment:gov-audit"],
                            "GitHub Actions: read-only audit queries (Athena over the evidence bucket)")
        audit.add_to_policy(iam.PolicyStatement(sid="Athena", resources=[f"arn:aws:athena:{region}:{acct}:workgroup/ai-governance"],
                                                actions=["athena:StartQueryExecution", "athena:GetQueryExecution",
                                                         "athena:GetQueryResults", "athena:StopQueryExecution",
                                                         "athena:GetWorkGroup", "athena:ListNamedQueries",
                                                         "athena:GetNamedQuery", "athena:BatchGetNamedQuery"]))
        audit.add_to_policy(iam.PolicyStatement(sid="Catalog", actions=["glue:GetDatabase", "glue:GetTable", "glue:GetTables",
                                                                         "glue:GetPartitions"], resources=[
            f"arn:aws:glue:{region}:{acct}:catalog", f"arn:aws:glue:{region}:{acct}:database/{n.glue_database}",
            f"arn:aws:glue:{region}:{acct}:table/{n.glue_database}/*"]))
        audit.add_to_policy(iam.PolicyStatement(sid="ReadEvidence", actions=["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                                                resources=[f"arn:aws:s3:::{evidence}", f"arn:aws:s3:::{evidence}/*"]))
        audit.add_to_policy(iam.PolicyStatement(sid="QueryResults", actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket",
                                                                             "s3:GetBucketLocation", "s3:AbortMultipartUpload"],
                                                resources=[f"arn:aws:s3:::{results}", f"arn:aws:s3:::{results}/*"]))

        for rid, role in {"PlanRoleArn": plan, "DeployRoleArn": deploy, "EngineRoleArn": engine, "AuditRoleArn": audit}.items():
            CfnOutput(self, rid, value=role.role_arn)
        CfnOutput(self, "ConfigParameter", value=config_param.parameter_name)
