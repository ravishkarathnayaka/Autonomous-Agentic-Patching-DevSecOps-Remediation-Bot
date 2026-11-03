from pathlib import Path
import pytest
from agent_engine.tools.finding_aggregator import FindingAggregator


def test_finding_aggregator_dispatch_insightappsec():
    aggregator = FindingAggregator()
    findings = aggregator.parse_and_add("insightappsec", Path("tests/fixtures/insightappsec_findings.json"))
    assert len(findings) == 2
    assert findings[0].scanner == "insightappsec"
    assert len(aggregator.findings) == 2
