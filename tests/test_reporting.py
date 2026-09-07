from websec_audit.findings import Finding
from websec_audit.reporting import summarize_findings


def make_finding(
    finding_id: str,
    severity: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Test finding",
        severity=severity,
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )


def test_summarize_findings():
    findings = [
        make_finding(
            "TEST-001",
            "Medium",
        ),
        make_finding(
            "TEST-002",
            "Low",
        ),
        make_finding(
            "TEST-003",
            "Low",
        ),
        make_finding(
            "TEST-004",
            "Informational",
        ),
    ]

    summary = summarize_findings(
        findings
    )

    assert summary["Critical"] == 0
    assert summary["High"] == 0
    assert summary["Medium"] == 1
    assert summary["Low"] == 2
    assert summary["Informational"] == 1


def test_empty_findings_summary():
    summary = summarize_findings([])

    assert summary["Critical"] == 0
    assert summary["High"] == 0
    assert summary["Medium"] == 0
    assert summary["Low"] == 0
    assert summary["Informational"] == 0