"""CDK app for AI governance with no custom UI, deployed only through GitHub CI/CD."""
import aws_cdk as cdk

from config import GovConfig
from governance_stack import NoUiGovernanceStack

gov = GovConfig.load()
app = cdk.App()
NoUiGovernanceStack(app, "AIGovernance-NoUI", gov=gov, env=cdk.Environment(account=gov.account, region=gov.region),
                    description=f"{gov.naming.display_name} AI governance with AWS consoles only: runbooks, registry, evidence, controls")
cdk.Tags.of(app).add("project", gov.naming.project_tag)
cdk.Tags.of(app).add("component", "noui-mvp")
app.synth()
