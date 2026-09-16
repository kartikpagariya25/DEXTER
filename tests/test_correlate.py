from dexter.loop import correlate
from dexter.models import Finding


def _finding(**overrides) -> Finding:
    defaults = dict(
        title="Finding",
        severity="high",
        category="X",
        description="d",
        evidence="e",
        remediation="r",
        file="/app.py",
        line=5,
        cwe=None,
        cvss=None,
        source="local-rule",
        confidence=0.5,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_merges_same_line_different_tools_related_topic():
    f1 = _finding(title="Hard-coded secret", description="A credential-like value is embedded.", source="local-rule", confidence=0.5)
    f2 = _finding(title="Hardcoded JWT secret", description="JWT signed with a literal string.", source="semgrep", confidence=0.7)

    result = correlate([f1, f2])

    assert len(result) == 1
    assert result[0].confidence > 0.7  # corroboration boosts confidence
    assert "local-rule" in result[0].description
    assert "semgrep" in result[0].description


def test_does_not_merge_same_tool_flagging_twice():
    f1 = _finding(title="Rule A", source="semgrep")
    f2 = _finding(title="Rule B", source="semgrep")

    result = correlate([f1, f2])

    assert len(result) == 2


def test_does_not_merge_unrelated_topics_on_same_line():
    f1 = _finding(title="Hard-coded secret", description="A credential value.", source="local-rule")
    f2 = _finding(title="Debug mode enabled", description="Debug config exposed.", source="bandit")

    result = correlate([f1, f2])

    assert len(result) == 2


def test_does_not_merge_findings_on_different_lines():
    f1 = _finding(line=5, source="local-rule")
    f2 = _finding(line=42, source="semgrep")

    result = correlate([f1, f2])

    assert len(result) == 2


def test_keeps_highest_severity_as_primary():
    f1 = _finding(title="Minor issue", severity="low", description="secret-ish", source="local-rule", confidence=0.4)
    f2 = _finding(title="Real problem", severity="critical", description="secret leak", source="gitleaks", confidence=0.9)

    result = correlate([f1, f2])

    assert len(result) == 1
    assert result[0].title == "Real problem"


def test_findings_without_location_pass_through_unmerged():
    f1 = _finding(file=None, line=None, source="local-rule")
    f2 = _finding(file=None, line=None, source="semgrep")

    result = correlate([f1, f2])

    assert len(result) == 2


def test_confidence_capped_below_one():
    findings = [_finding(title="Secret", description="secret", source=f"tool{i}", confidence=0.9) for i in range(5)]

    result = correlate(findings)

    assert len(result) == 1
    assert result[0].confidence <= 0.98
