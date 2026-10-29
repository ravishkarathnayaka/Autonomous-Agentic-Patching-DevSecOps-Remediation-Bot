from agent_engine.agents.terraform_agent import TerraformRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_terraform_agent_s3_encryption():
    finding = Finding(
        id="checkov-ckv-aws-18",
        scanner="checkov",
        finding_type=FindingType.IAC,
        rule_id="CKV_AWS_18",
        title="Ensure S3 bucket has server-side encryption enabled",
        description="S3 bucket unencrypted at rest",
        severity=SeverityLevel.HIGH,
        file_path="infra/s3.tf"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = TerraformRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "server_side_encryption_configuration" in updated.patch_diff
    assert "aws:kms" in updated.patch_diff
    assert "PCI DSS" in updated.patch_explanation


def test_terraform_agent_security_group():
    finding = Finding(
        id="tfsec-aws-vpc-no-public-ingress-sgr",
        scanner="tfsec",
        finding_type=FindingType.IAC,
        rule_id="aws-vpc-no-public-ingress-sgr",
        title="An ingress security group rule allows unrestricted public SSH access",
        description="Unrestricted ingress on port 22",
        severity=SeverityLevel.CRITICAL,
        file_path="infra/sg.tf"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = TerraformRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "10.0.0.0/16" in updated.patch_diff
    assert "-    cidr_blocks = [\"0.0.0.0/0\"]" in updated.patch_diff
