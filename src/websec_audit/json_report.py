import json
from pathlib import Path

import httpx

from websec_audit.findings import Finding


def build_json_report(
    target: str,
    response: httpx.Response,
    findings: list[Finding],
) -> dict:
    """
    Build a JSON-serializable scan report.
    """

    return {
        "target": target,
        "final_url": str(response.url),
        "http_status": response.status_code,
        "findings": [
            {
                "id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
    }


def write_json_report(
    path: Path,
    target: str,
    response: httpx.Response,
    findings: list[Finding],
) -> None:
    """
    Write scan results to a JSON file.
    """

    report = build_json_report(
        target=target,
        response=response,
        findings=findings,
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )