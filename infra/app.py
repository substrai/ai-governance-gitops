"""CDK app for AI governance with no custom UI, deployed only through GitHub CI/CD.

Stacks:
  AIGovernance-NoUI  the governance stack; deployed by the infra pipeline
  GitHubBootstrap    OIDC trust for this repository; deployed once by an administrator
"""
import json

import aws_cdk as cdk

from bootstrap_stack import GitHubBootstrapStack
from config import GovConfig
from governance_stack import NoUiGovernanceStack

gov = GovConfig.load()
env = cdk.Environment(account=gov.account, region=gov.region)
app = cdk.App()
NoUiGovernanceStack(app, "AIGovernance-NoUI", gov=gov, env=env,
                    description=f"{gov.naming.display_name} AI governance with AWS consoles only: runbooks, registry, evidence, controls")
GitHubBootstrapStack(app, "GitHubBootstrap", gov=gov, env=env,
                     config_json=json.loads(open(gov.source_file).read()),
                     description="GitHub OIDC trust for the AI governance repository (deployed once by an administrator)")
cdk.Tags.of(app).add("project", gov.naming.project_tag)
cdk.Tags.of(app).add("component", "noui-mvp")
app.synth()
