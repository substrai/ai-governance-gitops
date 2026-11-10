"""AIGovernance-NoUI: AI governance with AWS consoles only (single-account MVP)."""
from __future__ import annotations

import json

from aws_cdk import (CfnOutput, Duration, RemovalPolicy, Stack, aws_athena as athena, aws_cloudtrail as cloudtrail,
                     aws_cloudwatch as cwatch, aws_cloudwatch_actions as cw_actions, aws_config as config,
                     aws_dynamodb as dynamodb, aws_events as events, aws_events_targets as targets, aws_glue as glue,
                     aws_iam as iam, aws_lambda as _lambda, aws_s3 as s3, aws_secretsmanager as secretsmanager, aws_sns as sns,
                     aws_ssm as ssm)
from constructs import Construct

from config import GovConfig
from runbooks import documents

PERSONAS = {  # IAM user -> (display name, group)
    "gov-sarah": ("Sarah Chen", "Gov-Admin"), "gov-michael": ("Michael Torres", "Gov-Security"),
    "gov-emily": ("Emily Johnson", "Gov-Platform"), "gov-james": ("James Wilson", "Gov-Developer"),
    "gov-lisa": ("Lisa Martinez", "Gov-DepartmentOwner"), "gov-robert": ("Robert Kim", "Gov-Auditor"),
}
RUNBOOKS_BY_GROUP = {
    "Gov-Admin": ["01", "02", "03", "04", "05", "06", "07", "08"],
    "Gov-Security": ["05", "08"],
    "Gov-Platform": ["02", "03", "06", "07", "08"],
    "Gov-Developer": ["01", "02", "03", "04"],
    "Gov-DepartmentOwner": ["01", "07"],
    "Gov-Auditor": [],
}
APPROVER_GROUPS = {"Gov-Admin", "Gov-Security", "Gov-DepartmentOwner"}
REGISTRY_APPROVER_GROUPS = {"Gov-Admin", "Gov-Security"}


class NoUiGovernanceStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, gov: GovConfig, **kw) -> None:
        super().__init__(scope, cid, **kw)
        acct, region = self.account, self.region
        REGISTRY_ID, GUARDRAILS = gov.registry_id, gov.guardrails
        POLICY_ENGINE, GATEWAY = gov.policy_engine, gov.gateway
        n = gov.naming
        doc_names = list(documents(acct, "x", "x", "x", "x", gov).keys())

        # ---------------------------------------------------------------- evidence store
        evidence = s3.Bucket(self, "Evidence", bucket_name=f"{n.bucket_prefix}-evidence-{acct}",
                             object_lock_enabled=True,
                             object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(30)),
                             encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                             block_public_access=s3.BlockPublicAccess.BLOCK_ALL, removal_policy=RemovalPolicy.RETAIN)
        results = s3.Bucket(self, "AthenaResults", bucket_name=f"{n.bucket_prefix}-athena-{acct}", enforce_ssl=True,
                            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, removal_policy=RemovalPolicy.DESTROY,
                            auto_delete_objects=True,
                            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(30))])

        trail = cloudtrail.Trail(self, "Trail", trail_name=n.trail_name, bucket=evidence,
                                 s3_key_prefix="cloudtrail", is_multi_region_trail=False,
                                 include_global_service_events=True, management_events=cloudtrail.ReadWriteType.WRITE_ONLY,
                                 enable_file_validation=True)

        table = dynamodb.Table(self, "Lifecycle", table_name="gov-lifecycle",
                               partition_key=dynamodb.Attribute(name="agent", type=dynamodb.AttributeType.STRING),
                               sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
                               billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                               point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                                   point_in_time_recovery_enabled=True),
                               removal_policy=RemovalPolicy.DESTROY)

        approvals_topic = sns.Topic(self, "Approvals", topic_name="Automation-GovApprovals",
                                    display_name="AI governance approvals")
        alerts_topic = sns.Topic(self, "Alerts", topic_name="gov-alerts", display_name="AI governance alerts")

        # ---------------------------------------------------------------- agent permission boundary
        boundary = iam.ManagedPolicy(self, "AgentBoundary", managed_policy_name="GovAgentBoundary",
                                     description="Maximum permissions any AI agent role can ever have",
                                     statements=[
            iam.PolicyStatement(sid="AllowWorkloadActions", actions=["*"], resources=["*"]),
            iam.PolicyStatement(sid="NeverTouchIdentityOrGovernance", effect=iam.Effect.DENY, actions=[
                "iam:*", "organizations:*", "account:*", "sso:*", "identitystore:*", "ssm:StartAutomationExecution",
                "ssm:SendAutomationSignal", "agent-registry:Create*", "agent-registry:Update*", "agent-registry:Delete*",
                "agent-registry:Submit*", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                "config:Stop*", "config:Delete*", "config:Put*", "bedrock:CreateGuardrail*", "bedrock:UpdateGuardrail",
                "bedrock:DeleteGuardrail", "s3:PutObjectRetention", "s3:BypassGovernanceRetention",
                "s3:DeleteBucket*", "s3:PutBucketPolicy", "s3:PutBucketObjectLockConfiguration"], resources=["*"]),
            iam.PolicyStatement(sid="NeverChangeGovernanceRecords", effect=iam.Effect.DENY,
                                actions=["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"],
                                resources=[table.table_arn]),
        ])

        # ---------------------------------------------------------------- automation + engine roles
        automation_role = iam.Role(self, "AutomationRole", role_name="GovAutomationRole",
                                   assumed_by=iam.ServicePrincipal("ssm.amazonaws.com"),
                                   description="Systems Manager runbooks GOV-01..08 run as this role")
        automation_role.add_to_policy(iam.PolicyStatement(actions=["lambda:InvokeFunction"],
                                                          resources=[f"arn:aws:lambda:{region}:{acct}:function:gov-engine"]))
        approvals_topic.grant_publish(automation_role)
        automation_role.add_to_policy(iam.PolicyStatement(actions=["iam:GetUser", "iam:GetRole", "iam:ListGroupsForUser"],
                                                          resources=["*"]))

        engine_role = iam.Role(self, "EngineRole", role_name="gov-engine-role",
                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                               managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")])
        table.grant_read_write_data(engine_role)
        evidence.grant_read_write(engine_role)
        alerts_topic.grant_publish(engine_role)
        automation_role.grant_pass_role(engine_role)
        doc_arns = [f"arn:aws:ssm:{region}:{acct}:document/GOV-*", f"arn:aws:ssm:{region}:{acct}:automation-definition/GOV-*:*"]
        for stmt in [
            iam.PolicyStatement(actions=["ssm:GetAutomationExecution", "ssm:DescribeAutomationExecutions",
                                         "ssm:DescribeAutomationStepExecutions"], resources=["*"]),
            iam.PolicyStatement(actions=["ssm:StartAutomationExecution"],
                                resources=doc_arns + [f"arn:aws:ssm:{region}:{acct}:automation-execution/*"]),
            iam.PolicyStatement(actions=["iam:ListGroupsForUser", "iam:GetRole", "iam:ListRoles", "iam:ListRolePolicies",
                                         "iam:ListAttachedRolePolicies", "iam:GetRolePolicy"], resources=["*"]),
            iam.PolicyStatement(actions=["iam:CreateRole"], resources=[f"arn:aws:iam::{acct}:role/*-agent-role"],
                                conditions={"StringEquals": {"iam:PermissionsBoundary": f"arn:aws:iam::{acct}:policy/GovAgentBoundary"}}),
            iam.PolicyStatement(actions=["iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:DetachRolePolicy",
                                         "iam:DeleteRolePermissionsBoundary", "iam:TagRole"],
                                resources=[f"arn:aws:iam::{acct}:role/*-agent-role", f"arn:aws:iam::{acct}:role/*AgentRole"]),
            iam.PolicyStatement(actions=["cloudwatch:PutMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:GetMetricData"],
                                resources=["*"]),
            iam.PolicyStatement(actions=["bedrock:GetGuardrail", "bedrock:ListGuardrails"], resources=["*"]),
            iam.PolicyStatement(actions=["bedrock-agentcore:GetWorkloadIdentity", "bedrock-agentcore:CreateWorkloadIdentity",
                                         "bedrock-agentcore:DeleteWorkloadIdentity", "bedrock-agentcore:ListPolicies",
                                         "bedrock-agentcore:GetGateway", "bedrock-agentcore:ListAgentRuntimes",
                                         "bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:DeleteAgentRuntime",
                                         "bedrock-agentcore:GetPolicyEngine"], resources=["*"]),
            # Cutover (gov-maintenance disable-console-users): remove console passwords and MFA from the /gov/ users
            # so CloudFormation can delete them. Removed again together with the users.
            iam.PolicyStatement(sid="CutoverListUsers", actions=["iam:ListUsers"], resources=[f"arn:aws:iam::{acct}:user/*"]),
            iam.PolicyStatement(sid="CutoverConsoleUsers", actions=["iam:GetLoginProfile", "iam:DeleteLoginProfile",
                                                                    "iam:ListMFADevices", "iam:DeactivateMFADevice"],
                                resources=[f"arn:aws:iam::{acct}:user/gov/*"]),
            iam.PolicyStatement(sid="CutoverMfaDevices", actions=["iam:DeleteVirtualMFADevice"],
                                resources=[f"arn:aws:iam::{acct}:mfa/*"]),
            iam.PolicyStatement(sid="A2ADemonstration", actions=["bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeGateway"],
                                resources=[f"arn:aws:bedrock-agentcore:{region}:{acct}:runtime/*",
                                           f"arn:aws:bedrock-agentcore:{region}:{acct}:gateway/*"]),
            iam.PolicyStatement(sid="ToolPoliciesOnGateways", actions=["bedrock-agentcore:ManageResourceScopedPolicy",
                                                                       "bedrock-agentcore:ListGatewayTargets",
                                                                       "bedrock-agentcore:GetGatewayTarget"],
                                resources=[f"arn:aws:bedrock-agentcore:{region}:{acct}:gateway/*"]),
            iam.PolicyStatement(sid="ManageAgentToolPolicies", actions=["bedrock-agentcore:CreatePolicy", "bedrock-agentcore:UpdatePolicy",
                                                                        "bedrock-agentcore:GetPolicy", "bedrock-agentcore:DeletePolicy"],
                                resources=[f"arn:aws:bedrock-agentcore:{region}:{acct}:policy-engine/{POLICY_ENGINE}",
                                           f"arn:aws:bedrock-agentcore:{region}:{acct}:policy-engine/{POLICY_ENGINE}/*"]),
            iam.PolicyStatement(actions=["agent-registry:*"], resources=[f"arn:aws:agent-registry:{region}:{acct}:registry/{REGISTRY_ID}",
                                                                         f"arn:aws:agent-registry:{region}:{acct}:registry/{REGISTRY_ID}/*"]),
            iam.PolicyStatement(actions=["config:PutEvaluations"], resources=["*"]),
        ]:
            engine_role.add_to_policy(stmt)

        engine = _lambda.Function(self, "Engine", function_name="gov-engine", runtime=_lambda.Runtime.PYTHON_3_13,
                                  handler="engine.handler", code=_lambda.Code.from_asset(gov.engine_asset), role=engine_role,
                                  timeout=Duration.minutes(15), memory_size=512,
                                  description="AI governance engine behind the GOV runbooks (no custom UI)",
                                  environment={"ACCOUNT_ID": acct, "TABLE_NAME": table.table_name,
                                               "EVIDENCE_BUCKET": evidence.bucket_name, "REGISTRY_ID": REGISTRY_ID,
                                               "AUTOMATION_ROLE_ARN": automation_role.role_arn,
                                               "ALERT_TOPIC_ARN": alerts_topic.topic_arn, "BOUNDARY_ARN": boundary.managed_policy_arn,
                                               "GUARDRAILS_JSON": json.dumps(GUARDRAILS),
                                               "DEFAULT_POLICY_ENGINE": POLICY_ENGINE, "DEFAULT_GATEWAY": GATEWAY,
                                               "METRIC_NAMESPACE": n.metric_namespace,
                                               "GUARDRAIL_CUSTOMER_FACING": gov.guardrail_defaults["customerFacing"],
                                               "GUARDRAIL_INTERNAL": gov.guardrail_defaults["internal"],
                                               "AGENT_ENDPOINT_BASE": n.agent_endpoint_base,
                                               "GITHUB_REPO": gov.github_repo, "GITHUB_APP_SECRET_PREFIX": "ai-gov/github-app/",
                                               "GOV_OPERATORS": ",".join(gov.operators),
                                               "GUARDRAIL_ALIASES": json.dumps(gov.guardrail_aliases()),
                                               "REDACT_TERMS": ",".join(gov.blocked_terms)})

        # ---------------------------------------------------------------- GitHub role bots
        # One secret per role bot (GitHub App). Values {"appId", "privateKey"} are uploaded once by an
        # administrator; CloudFormation never sees the keys. Only the engine can read them.
        for role in ("security", "platform", "admin", "owner", "auditor", "engine"):
            secret = secretsmanager.Secret(self, f"GitHubApp{role.capitalize()}", secret_name=f"ai-gov/github-app/{role}",
                                           description=f"GitHub App credentials for the {role} role bot",
                                           removal_policy=RemovalPolicy.RETAIN)
            secret.grant_read(engine_role)

        # ---------------------------------------------------------------- runbooks
        for name, content in documents(acct, automation_role.role_arn, approvals_topic.topic_arn, POLICY_ENGINE, GATEWAY, gov).items():
            ssm.CfnDocument(self, name.replace("-", ""), name=name, document_type="Automation", document_format="YAML",
                            update_method="NewVersion", content=__import__("yaml").safe_load(content),
                            tags=[{"key": "gov:component", "value": "runbook"}])

        # ---------------------------------------------------------------- events
        events.Rule(self, "RunbookFinished", rule_name="gov-runbook-finished",
                    description="Export every GOV runbook execution and its approvals to the evidence bucket",
                    event_pattern=events.EventPattern(source=["aws.ssm"], detail_type=["EC2 Automation Execution Status-change Notification"],
                                                      detail={"Definition": [{"prefix": "GOV-"}],
                                                              "Status": ["Success", "Failed", "TimedOut", "Cancelled"]}),
                    targets=[targets.LambdaFunction(engine)])
        events.Rule(self, "RegistryStatusChanged", rule_name="gov-registry-status-changed",
                    description="Separation-of-duties check on every Agent Registry approval",
                    event_pattern=events.EventPattern(source=["aws.agent-registry"], detail_type=["AWS API Call via CloudTrail"],
                                                      detail={"eventName": ["UpdateRegistryRecordStatus"]}),
                    targets=[targets.LambdaFunction(engine)])
        events.Rule(self, "RegistryPendingApproval", rule_name="gov-registry-pending-approval",
                    event_pattern=events.EventPattern(source=["aws.agent-registry"],
                                                      detail_type=["Registry Record State changed to Pending Approval"]),
                    targets=[targets.LambdaFunction(engine), targets.SnsTopic(alerts_topic)])
        events.Rule(self, "ConfigCompliance", rule_name="gov-config-compliance",
                    event_pattern=events.EventPattern(source=["aws.config"], detail_type=["Config Rules Compliance Change"],
                                                      detail={"configRuleName": [{"prefix": "gov-"}]}),
                    targets=[targets.LambdaFunction(engine)])
        events.Rule(self, "Tick", rule_name="gov-tick-5min", description="Shadow-agent detection and governance metrics",
                    schedule=events.Schedule.rate(Duration.minutes(5)),
                    targets=[targets.LambdaFunction(engine, event=events.RuleTargetInput.from_object({"action": "tick"}))])
        events.Rule(self, "ReviewsDue", rule_name="gov-reviews-due-daily", description="Start GOV-05 for agents due a review",
                    schedule=events.Schedule.cron(minute="0", hour="13"),
                    targets=[targets.LambdaFunction(engine, event=events.RuleTargetInput.from_object({"action": "reviews_due"}))])

        # ---------------------------------------------------------------- AWS Config
        # The Config recorder and delivery channel are created through the API (see scripts/post_deploy.py):
        # CloudFormation's recorder handler waits for recording to start, which needs the channel first.
        # Config snapshots go to their own bucket: Object Lock buckets need a checksum on every write,
        # which Config's delivery check does not send.
        config_bucket = s3.Bucket(self, "ConfigSnapshots", bucket_name=f"{n.bucket_prefix}-config-{acct}", enforce_ssl=True,
                                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL, removal_policy=RemovalPolicy.DESTROY,
                                  auto_delete_objects=True, versioned=True)
        config_bucket.add_to_resource_policy(iam.PolicyStatement(
            principals=[iam.ServicePrincipal("config.amazonaws.com")], actions=["s3:GetBucketAcl", "s3:ListBucket"],
            resources=[config_bucket.bucket_arn], conditions={"StringEquals": {"AWS:SourceAccount": acct}}))
        config_bucket.add_to_resource_policy(iam.PolicyStatement(
            principals=[iam.ServicePrincipal("config.amazonaws.com")], actions=["s3:PutObject"],
            resources=[config_bucket.arn_for_objects(f"config/AWSLogs/{acct}/Config/*")],
            conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "AWS:SourceAccount": acct}}))
        engine.add_permission("ConfigInvoke", principal=iam.ServicePrincipal("config.amazonaws.com"), source_account=acct)
        rules = {"gov-agent-role-no-admin": ("agent-role-no-admin", "Agent IAM roles have no admin-level policies"),
                 "gov-agent-runtimes-governed": ("agent-runtimes-governed", "Every agent runtime belongs to an ACTIVE governed agent"),
                 "gov-agent-guardrail-ready": ("agent-guardrail-ready", "Every agent runtime has a READY guardrail")}
        for rname, (check, desc) in rules.items():
            config.CfnConfigRule(self, rname, config_rule_name=rname, description=desc,
                                        input_parameters={"check": check},
                                        source=config.CfnConfigRule.SourceProperty(
                                            owner="CUSTOM_LAMBDA", source_identifier=engine.function_arn,
                                            source_details=[config.CfnConfigRule.SourceDetailProperty(
                                                event_source="aws.config", message_type="ScheduledNotification",
                                                maximum_execution_frequency="One_Hour")]))

        # ---------------------------------------------------------------- Athena
        db = n.glue_database
        glue.CfnDatabase(self, "GlueDb", catalog_id=acct, database_input=glue.CfnDatabase.DatabaseInputProperty(
            name=db, description="AI governance evidence (Object Lock bucket)"))

        def json_table(tid: str, name: str, prefix: str, cols: list[tuple[str, str]], desc: str):
            t = glue.CfnTable(self, tid, catalog_id=acct, database_name=db, table_input=glue.CfnTable.TableInputProperty(
                name=name, description=desc, table_type="EXTERNAL_TABLE",
                partition_keys=[glue.CfnTable.ColumnProperty(name="dt", type="string")],
                parameters={"projection.enabled": "true", "projection.dt.type": "date", "projection.dt.format": "yyyy-MM-dd",
                            "projection.dt.range": "2026-11-01,NOW", "projection.dt.interval": "1",
                            "projection.dt.interval.unit": "DAYS",
                            "storage.location.template": f"s3://{evidence.bucket_name}/{prefix}/dt=${{dt}}/"},
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{evidence.bucket_name}/{prefix}/",
                    columns=[glue.CfnTable.ColumnProperty(name=c, type=ty) for c, ty in cols],
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(serialization_library="org.openx.data.jsonserde.JsonSerDe"))))
            t.add_dependency(self.node.find_child("GlueDb"))

        json_table("TblEvents", "lifecycle_events", "evidence/events",
                   [("time", "string"), ("agent", "string"), ("action", "string"), ("actor", "string"), ("detail", "string")],
                   "Every governance decision, one row per event")
        json_table("TblRunbooks", "runbook_executions", "evidence/runbooks",
                   [("time", "string"), ("executionid", "string"), ("document", "string"), ("status", "string"),
                    ("executedby", "string"), ("agent", "string"), ("failure", "string"), ("approvals", "string"),
                    ("steps", "string")], "Every GOV runbook run with who approved it")
        ct = glue.CfnTable(self, "TblCloudTrail", catalog_id=acct, database_name=db, table_input=glue.CfnTable.TableInputProperty(
            name="cloudtrail_logs", table_type="EXTERNAL_TABLE",
            partition_keys=[glue.CfnTable.ColumnProperty(name="day", type="string")],
            parameters={"projection.enabled": "true", "projection.day.type": "date", "projection.day.format": "yyyy/MM/dd",
                        "projection.day.range": "2026/11/01,NOW", "projection.day.interval": "1", "projection.day.interval.unit": "DAYS",
                        "storage.location.template": f"s3://{evidence.bucket_name}/cloudtrail/AWSLogs/{acct}/CloudTrail/{region}/${{day}}"},
            storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                location=f"s3://{evidence.bucket_name}/cloudtrail/AWSLogs/{acct}/CloudTrail/{region}/",
                columns=[glue.CfnTable.ColumnProperty(name=c, type=ty) for c, ty in [
                    ("eventversion", "string"),
                    ("useridentity", "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,"
                                     "accesskeyid:string,username:string>"),
                    ("eventtime", "string"), ("eventsource", "string"), ("eventname", "string"), ("awsregion", "string"),
                    ("sourceipaddress", "string"), ("useragent", "string"), ("errorcode", "string"), ("errormessage", "string"),
                    ("requestparameters", "string"), ("responseelements", "string"), ("additionaleventdata", "string"),
                    ("requestid", "string"), ("eventid", "string"), ("readonly", "string"), ("eventtype", "string"),
                    ("recipientaccountid", "string")]],
                input_format="com.amazon.emr.cloudtrail.CloudTrailInputFormat",
                output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                serde_info=glue.CfnTable.SerdeInfoProperty(serialization_library="org.apache.hive.hcatalog.data.JsonSerDe"))))
        ct.add_dependency(self.node.find_child("GlueDb"))

        wg = athena.CfnWorkGroup(self, "WorkGroup", name="ai-governance", state="ENABLED", recursive_delete_option=True,
                                 work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                                     enforce_work_group_configuration=True,
                                     result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                                         output_location=f"s3://{results.bucket_name}/results/")))
        queries = {
            "1 Who approved what": "SELECT time, agent, document, executedby AS started_by, status, approvals, failure\n"
                                   "FROM runbook_executions ORDER BY time DESC LIMIT 100",
            "2 Agent lifecycle history": "SELECT time, agent, action, actor, detail FROM lifecycle_events\n"
                                         "ORDER BY time DESC LIMIT 200",
            "3 Separation-of-duties violations": "SELECT time, agent, action, actor, detail FROM lifecycle_events\n"
                                                 "WHERE action LIKE 'SOD_%' ORDER BY time DESC",
            "4 Registry approvals in CloudTrail": "SELECT eventtime, useridentity.arn AS who,\n"
                                                  " json_extract_scalar(requestparameters, '$.recordId') AS record,\n"
                                                  " json_extract_scalar(requestparameters, '$.status') AS status\n"
                                                  "FROM cloudtrail_logs WHERE eventname = 'UpdateRegistryRecordStatus'\n"
                                                  "ORDER BY eventtime DESC",
            "5 Shadow agents and suspensions": "SELECT time, agent, action, actor, detail FROM lifecycle_events\n"
                                               "WHERE action IN ('SHADOW_AGENT_DETECTED','SUSPENDED','AUTO_SUSPEND_STARTED','REINSTATED')\n"
                                               "ORDER BY time DESC",
        }
        for i, (qname, sql) in enumerate(queries.items()):
            q = athena.CfnNamedQuery(self, f"Query{i}", name=qname, database=db, query_string=sql, work_group=wg.name)
            q.add_dependency(wg)

        # ---------------------------------------------------------------- people: IAM groups and demo users
        deny_direct = iam.ManagedPolicy(self, "DenyDirect", managed_policy_name="GovDenyDirectChanges",
                                        description="Agent resources change only through GOV runbooks", statements=[
            iam.PolicyStatement(sid="RunbooksOnly", effect=iam.Effect.DENY, resources=["*"], actions=[
                "agent-registry:CreateRegistry*", "agent-registry:UpdateRegistry", "agent-registry:DeleteRegistry*",
                "agent-registry:UpdateRegistryRecord", "agent-registry:SubmitRegistryRecordForApproval",
                "bedrock-agentcore:Create*", "bedrock-agentcore:Update*", "bedrock-agentcore:Delete*", "bedrock-agentcore:Put*",
                "bedrock:CreateGuardrail*", "bedrock:UpdateGuardrail", "bedrock:DeleteGuardrail",
                "iam:CreateRole", "iam:DeleteRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
                "iam:DeleteRolePolicy", "iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary",
                "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "config:StopConfigurationRecorder",
                "config:DeleteConfigRule", "s3:BypassGovernanceRetention"]),
            iam.PolicyStatement(sid="GovernanceRecordsReadOnly", effect=iam.Effect.DENY, resources=[table.table_arn],
                                actions=["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"]),
            iam.PolicyStatement(sid="OnlyGovRunbooks", effect=iam.Effect.DENY, actions=["ssm:StartAutomationExecution"],
                                not_resources=doc_arns + [f"arn:aws:ssm:{region}:{acct}:automation-execution/*"]),
        ])
        mfa = iam.ManagedPolicy(self, "RequireMfa", managed_policy_name="GovRequireMfa", statements=[
            iam.PolicyStatement(sid="ManageOwnMfaAndPassword", resources=[f"arn:aws:iam::{acct}:user/gov/${{aws:username}}",
                                                                          f"arn:aws:iam::{acct}:mfa/${{aws:username}}"],
                                actions=["iam:ChangePassword", "iam:GetUser", "iam:ListMFADevices", "iam:ResyncMFADevice",
                                         "iam:CreateVirtualMFADevice", "iam:EnableMFADevice"]),
            iam.PolicyStatement(sid="DenyWithoutMfa", effect=iam.Effect.DENY, resources=["*"],
                                not_actions=["iam:ChangePassword", "iam:GetUser", "iam:ListMFADevices", "iam:ListVirtualMFADevices",
                                             "iam:ResyncMFADevice", "iam:CreateVirtualMFADevice", "iam:EnableMFADevice",
                                             "sts:GetSessionToken", "iam:GetAccountPasswordPolicy"],
                                conditions={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}),
        ])
        console_read = iam.ManagedPolicy(self, "ConsoleRead", managed_policy_name="GovConsoleRead", statements=[
            iam.PolicyStatement(actions=["agent-registry:Get*", "agent-registry:List*", "agent-registry:Search*",
                                         "bedrock-agentcore:Get*", "bedrock-agentcore:List*", "bedrock:Get*", "bedrock:List*",
                                         "cloudwatchomni:Get*", "cloudwatchomni:List*"], resources=["*"])])
        groups = {}
        for gname, nums in RUNBOOKS_BY_GROUP.items():
            g = iam.Group(self, gname.replace("-", ""), group_name=gname, path="/gov/", managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"), deny_direct, mfa, console_read])
            names = [n for n in doc_names if n[4:6] in nums]
            if names:
                g.add_to_policy(iam.PolicyStatement(sid="RunMyRunbooks", actions=["ssm:StartAutomationExecution"], resources=
                    [f"arn:aws:ssm:{region}:{acct}:document/{n}" for n in names]
                    + [f"arn:aws:ssm:{region}:{acct}:automation-definition/{n}:*" for n in names]
                    + [f"arn:aws:ssm:{region}:{acct}:automation-execution/*"]))
                g.add_to_policy(iam.PolicyStatement(sid="PassRunbookRole", actions=["iam:PassRole"], resources=[automation_role.role_arn]))
                g.add_to_policy(iam.PolicyStatement(sid="StopOwnRuns", actions=["ssm:StopAutomationExecution"],
                                                    resources=[f"arn:aws:ssm:{region}:{acct}:automation-execution/*"]))
            if gname in APPROVER_GROUPS:
                g.add_to_policy(iam.PolicyStatement(sid="ApproveRunbookSteps", actions=["ssm:SendAutomationSignal"],
                                                    resources=[f"arn:aws:ssm:{region}:{acct}:automation-execution/*"]))
            if gname in REGISTRY_APPROVER_GROUPS:
                g.add_to_policy(iam.PolicyStatement(sid="ApproveReleasesInRegistry", actions=["agent-registry:UpdateRegistryRecordStatus"],
                                                    resources=[f"arn:aws:agent-registry:{region}:{acct}:registry/{REGISTRY_ID}/*"]))
            if gname in ("Gov-Auditor", "Gov-Admin", "Gov-Security"):
                g.add_to_policy(iam.PolicyStatement(sid="RunAuditQueries", actions=[
                    "athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution",
                    "athena:GetWorkGroup", "athena:ListNamedQueries", "athena:GetNamedQuery", "athena:BatchGetNamedQuery",
                    "athena:ListQueryExecutions", "athena:BatchGetQueryExecution"],
                    resources=[f"arn:aws:athena:{region}:{acct}:workgroup/ai-governance"]))
                g.add_to_policy(iam.PolicyStatement(sid="QueryResults", actions=["s3:PutObject", "s3:GetObject", "s3:ListBucket",
                                                                                 "s3:GetBucketLocation", "s3:AbortMultipartUpload"],
                                                    resources=[results.bucket_arn, results.arn_for_objects("*")]))
            groups[gname] = g
        for user, (_display, gname) in PERSONAS.items():
            iam.User(self, user.replace("-", ""), user_name=user, path="/gov/", groups=[groups[gname]])

        # ---------------------------------------------------------------- dashboard and alarms
        def gm(name: str, stat: str = "Maximum", **dims) -> cwatch.Metric:
            return cwatch.Metric(namespace=n.metric_namespace, metric_name=name, dimensions_map=dims or None,
                                 statistic=stat, period=Duration.minutes(5))

        dash = cwatch.Dashboard(self, "Dashboard", dashboard_name=n.dashboard_name,
                                default_interval=Duration.days(7))
        dash.add_widgets(cwatch.TextWidget(markdown=(
            f"# {n.display_name} AI governance\nEvery agent is **known** (Agent Registry), **approved** (GOV runbooks), "
            "**controlled** (Guardrails, Cedar, IAM) and **watched** (traces, evaluations, AWS Config). "
            "Start a request: Systems Manager > Automation > Execute automation > *Owned by me* > GOV-01-RequestAgent. "
            "Audit: Athena workgroup *ai-governance* > Saved queries."), width=24, height=3))
        dash.add_widgets(
            cwatch.SingleValueWidget(title="Agents by lifecycle stage", width=12, height=4, metrics=[
                gm("AgentsByStage", Stage=s).with_(label=s) for s in ("ACTIVE", "SUBMITTED", "BUILD_APPROVED", "REQUESTED", "SUSPENDED", "RETIRED")]),
            cwatch.SingleValueWidget(title="Needs attention", width=12, height=4, metrics=[
                gm("PendingApprovals").with_(label="Pending approvals"), gm("OverdueReviews").with_(label="Overdue reviews"),
                gm("ShadowAgents").with_(label="Shadow agents"),
                gm("SeparationOfDutiesViolations", "Sum").with_(label="Self-approvals blocked", period=Duration.days(7))]))
        dash.add_widgets(
            cwatch.GraphWidget(title="Guardrail interventions (blocked or masked)", width=12, height=6, left=[cwatch.MathExpression(
                expression="SEARCH('{AWS/Bedrock/Guardrails,GuardrailArn,GuardrailVersion} MetricName=\"InvocationsIntervened\"', 'Sum', 3600)",
                label="", period=Duration.hours(1))]),
            cwatch.GraphWidget(title="Agent runtime invocations and errors", width=12, height=6, left=[cwatch.MathExpression(
                expression="SEARCH('Bedrock-AgentCore (MetricName=\"Invocations\" OR MetricName=\"SystemErrors\" OR MetricName=\"UserErrors\")', 'Sum', 3600)",
                label="", period=Duration.hours(1))]))
        dash.add_widgets(
            cwatch.GraphWidget(title="Online evaluation scores (AgentCore Evaluations)", width=12, height=6, left=[cwatch.MathExpression(
                expression="SEARCH('Bedrock-AgentCore/Evaluations', 'Average', 3600)", label="", period=Duration.hours(1))]),
            cwatch.GraphWidget(title="Lifecycle trend", width=12, height=6, left=[
                gm("AgentsByStage", Stage="ACTIVE").with_(label="Active"), gm("PendingApprovals").with_(label="Pending approvals"),
                gm("ShadowAgents").with_(label="Shadow agents")]))
        alarm_action = cw_actions.SnsAction(alerts_topic)
        for aid, (m, thr, desc) in {
            "gov-overdue-reviews": (gm("OverdueReviews"), 1, "An ACTIVE agent is past its review date"),
            "gov-shadow-agents": (gm("ShadowAgents"), 1, "An agent runtime exists outside the governance process"),
            "gov-self-approval-attempt": (gm("SeparationOfDutiesViolations", "Sum"), 1, "Someone tried to approve their own work"),
        }.items():
            a = cwatch.Alarm(self, aid, alarm_name=aid, alarm_description=desc, metric=m, threshold=thr, evaluation_periods=1,
                             comparison_operator=cwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                             treat_missing_data=cwatch.TreatMissingData.NOT_BREACHING)
            a.add_alarm_action(alarm_action)

        # ---------------------------------------------------------------- online evaluations role
        eval_role = iam.Role(self, "EvaluationRole", role_name="GovEvaluationRole",
                             assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com",
                                                             conditions={"StringEquals": {"aws:SourceAccount": acct}}),
                             description="AgentCore online evaluations read agent traces and write scores")
        eval_role.add_to_policy(iam.PolicyStatement(actions=[
            "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery",
            "logs:GetQueryResults", "logs:StopQuery", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
            "logs:PutRetentionPolicy", "cloudwatch:PutMetricData", "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
            "xray:GetTraceSummaries", "xray:BatchGetTraces"], resources=["*"]))

        CfnOutput(self, "EvidenceBucket", value=evidence.bucket_name)
        CfnOutput(self, "EngineFunction", value=engine.function_name)
        CfnOutput(self, "TrailArn", value=trail.trail_arn)
