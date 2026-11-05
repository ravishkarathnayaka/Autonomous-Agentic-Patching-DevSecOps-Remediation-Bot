from pathlib import Path
from agent_engine.tools.finding_aggregator import FindingAggregator


def test_finding_aggregator_dispatch_new_scanners():
    aggregator = FindingAggregator()

    # Qualys WAS
    f_qualys = aggregator.parse_and_add("qualys-was", Path("tests/fixtures/qualys_was_findings.json"))
    assert len(f_qualys) == 2
    assert f_qualys[0].scanner == "qualys"

    # StackHawk
    f_hawk = aggregator.parse_and_add("stackhawk", Path("tests/fixtures/stackhawk_findings.json"))
    assert len(f_hawk) == 2
    assert f_hawk[0].scanner == "stackhawk"

    # JFrog Xray
    f_xray = aggregator.parse_and_add("jfrog-xray", Path("tests/fixtures/jfrog_xray_findings.json"))
    assert len(f_xray) == 2
    assert f_xray[0].scanner == "jfrog-xray"

    # Acunetix
    f_acunetix = aggregator.parse_and_add("acunetix", Path("tests/fixtures/acunetix_findings.json"))
    assert len(f_acunetix) == 2
    assert f_acunetix[0].scanner == "acunetix"

    # SonarCloud
    f_sonar = aggregator.parse_and_add("sonarcloud", Path("tests/fixtures/sonarcloud_findings.json"))
    assert len(f_sonar) == 2
    assert f_sonar[0].scanner == "sonarcloud"

    # Lacework
    f_lacework = aggregator.parse_and_add("lacework", Path("tests/fixtures/lacework_findings.json"))
    assert len(f_lacework) == 2
    assert f_lacework[0].scanner == "lacework"

    # Bridgecrew
    f_bc = aggregator.parse_and_add("bridgecrew", Path("tests/fixtures/bridgecrew_findings.json"))
    assert len(f_bc) == 2
    assert f_bc[0].scanner == "bridgecrew"

    # Overall deduplication and sorting
    total_deduped = aggregator.deduplicate()
    assert len(total_deduped) > 0
