import json

from dataclasses import asdict
from pathlib import Path

import httpx

from websec_audit.findings import Finding
from websec_audit.tls import TLSInfo


def build_json_report(
    target: str,
    response: httpx.Response,
    findings: list[Finding],
    tls_info: TLSInfo | None = None,
    tls_error: str | None = None,
) -> dict:
    """
    Build a JSON-serializable scan report.
    """

    if tls_info is not None:
        tls_section = {
            "status": "inspected",
            **asdict(tls_info),
        }

    elif tls_error is not None:
        tls_section = {
            "status": "error",
            "error": tls_error,
        }

    else:
        tls_section = {
            "status": "not_applicable",
        }

    return {
        "target": target,
        "final_url": str(response.url),
        "http_status": response.status_code,
        "tls": tls_section,
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
    tls_info: TLSInfo | None = None,
    tls_error: str | None = None,
) -> None:
    """
    Write scan results to a JSON file.
    """

    report = build_json_report(
        target=target,
        response=response,
        findings=findings,
        tls_info=tls_info,
        tls_error=tls_error,
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