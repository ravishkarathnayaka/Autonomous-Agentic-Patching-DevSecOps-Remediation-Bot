from agent_engine.tools.semver_bumper import SemVerBumper


def test_semver_parse():
    assert SemVerBumper.parse_version("1.2.3") == (1, 2, 3)
    assert SemVerBumper.parse_version("v2.10.0-rc1") == (2, 10, 0)
    assert SemVerBumper.parse_version("3.4") == (3, 4, 0)


def test_semver_compare():
    assert SemVerBumper.compare("1.0.0", "1.0.1") == -1
    assert SemVerBumper.compare("2.1.0", "2.1.0") == 0
    assert SemVerBumper.compare("3.0.0", "2.9.9") == 1


def test_semver_evaluate_upgrade_risk():
    patch_risk = SemVerBumper.evaluate_upgrade_risk("1.2.0", "1.2.1")
    assert patch_risk["is_breaking"] is False
    assert patch_risk["upgrade_tier"] == "PATCH"
    assert patch_risk["safe_to_autopatch"] is True

    major_risk = SemVerBumper.evaluate_upgrade_risk("1.2.0", "2.0.0")
    assert major_risk["is_breaking"] is True
    assert major_risk["upgrade_tier"] == "MAJOR"
    assert major_risk["safe_to_autopatch"] is False
