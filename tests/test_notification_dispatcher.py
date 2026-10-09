"""Unit tests for NotificationDispatcher."""

from unittest.mock import MagicMock, patch
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel
from agent_engine.tools.notification_dispatcher import NotificationDispatcher


def create_sample_state(status=RemediationStatus.PR_READY):
    finding = Finding(
        id="f-notif-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.sqli",
        title="SQL Injection",
        description="SQL injection in /items",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        file_path="target_repo/app.py",
        start_line=28,
        end_line=29
    )
    state = RemediationState(finding=finding, target_repo_path=".")
    state.status = status
    state.pr_branch = "security/fix-cwe-89"
    return state


def test_dispatcher_no_url():
    dispatcher = NotificationDispatcher(webhook_url=None)
    state = create_sample_state()
    assert dispatcher.dispatch_pr_created(state) is False
    assert dispatcher.dispatch_remediation_failed(state) is False


@patch("urllib.request.urlopen")
def test_dispatch_pr_created_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    dispatcher = NotificationDispatcher(webhook_url="https://hooks.slack.com/services/dummy")
    state = create_sample_state(RemediationStatus.PR_READY)

    result = dispatcher.dispatch_pr_created(state)
    assert result is True
    assert mock_urlopen.called


@patch("urllib.request.urlopen")
def test_dispatch_failed_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 204
    mock_urlopen.return_value.__enter__.return_value = mock_response

    dispatcher = NotificationDispatcher(webhook_url="https://discord.com/api/webhooks/dummy")
    state = create_sample_state(RemediationStatus.FAILED)
    state.last_error_trace = "Test verification failed"

    result = dispatcher.dispatch_remediation_failed(state)
    assert result is True
