from pathlib import Path
from agent_engine.tools.finding_aggregator import FindingAggregator


def test_finding_aggregator_dispatch_v4_scanners():
    aggregator = FindingAggregator()

    # Prisma Compute
    f_prisma = aggregator.parse_and_add("prisma-compute", Path("tests/fixtures/prisma_compute_findings.json"))
    assert len(f_prisma) == 2
    assert f_prisma[0].scanner == "prisma-compute"

    # DeepSource
    f_ds = aggregator.parse_and_add("deepsource", Path("tests/fixtures/deepsource_findings.json"))
    assert len(f_ds) == 2
    assert f_ds[0].scanner == "deepsource"

    # Wiz
    f_wiz = aggregator.parse_and_add("wiz", Path("tests/fixtures/wiz_findings.json"))
    assert len(f_wiz) == 2
    assert f_wiz[0].scanner == "wiz"

    # Mend Bolt
    f_mend = aggregator.parse_and_add("mend-bolt", Path("tests/fixtures/mend_bolt_findings.json"))
    assert len(f_mend) == 2
    assert f_mend[0].scanner == "mend-bolt"

    # Orca
    f_orca = aggregator.parse_and_add("orca", Path("tests/fixtures/orca_findings.json"))
    assert len(f_orca) == 2
    assert f_orca[0].scanner == "orca"

    # Prowler
    f_prowler = aggregator.parse_and_add("prowler", Path("tests/fixtures/prowler_findings.json"))
    assert len(f_prowler) == 2
    assert f_prowler[0].scanner == "prowler"

    # Deduplication and sorting
    total_deduped = aggregator.deduplicate()
    assert len(total_deduped) > 0
