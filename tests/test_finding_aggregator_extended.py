from pathlib import Path
import pytest
from agent_engine.tools.finding_aggregator import FindingAggregator


def test_finding_aggregator_dispatch_aqua():
    aggregator = FindingAggregator()
    findings = aggregator.parse_and_add("aqua", Path("tests/fixtures/aqua_findings.json"))
    assert len(findings) == 2
    assert len(aggregator.findings) == 2


def test_finding_aggregator_dispatch_spectral():
    aggregator = FindingAggregator()
    findings = aggregator.parse_and_add("spectral", Path("tests/fixtures/spectral_findings.json"))
    assert len(findings) == 2
    assert findings[0].scanner == "spectral"


def test_finding_aggregator_dispatch_anchore():
    aggregator = FindingAggregator()
    findings = aggregator.parse_and_add("anchore", Path("tests/fixtures/anchore_enterprise_findings.json"))
    assert len(findings) == 2
    assert findings[0].scanner == "anchore"


def test_finding_aggregator_dispatch_and_deduplicate():
    aggregator = FindingAggregator()
    aggregator.parse_and_add("bearer", Path("tests/fixtures/bearer_findings.json"))
    aggregator.parse_and_add("appcheck", Path("tests/fixtures/appcheck_findings.json"))
    assert len(aggregator.findings) == 4
    deduped = aggregator.deduplicate()
    assert len(deduped) >= 3
