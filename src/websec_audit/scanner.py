from dataclasses import dataclass

import httpx

from websec_audit.checks.headers import check_security_headers
from websec_audit.findings import Finding
from websec_audit.http_client import fetch_target
from websec_audit.tls import (
    TLSInfo,
    TLSInspectionError,
    inspect_tls,
)


@dataclass
class ScanResult:
    """
    Results produced by a security assessment.
    """

    target: str
    response: httpx.Response
    findings: list[Finding]
    tls_info: TLSInfo | None
    tls_error: str | None


def run_scan(
    target: str,
) -> ScanResult:
    """
    Run the currently enabled security checks.
    """

    response = fetch_target(target)

    tls_info = None
    tls_error = None
    tls_findings = []

    try:
        tls_info, tls_findings = inspect_tls(
            str(response.url)
        )

    except TLSInspectionError as exc:
        tls_error = str(exc)

    findings = check_security_headers(
        response
    )

    findings.extend(
        tls_findings
    )

    return ScanResult(
        target=target,
        response=response,
        findings=findings,
        tls_info=tls_info,
        tls_error=tls_error,
    )