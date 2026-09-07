import httpx

from websec_audit.findings import Finding


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "id": "WEB-HEADER-001",
        "severity": "Medium",
        "description": (
            "Content-Security-Policy is not present. "
            "A CSP can help reduce the impact of certain "
            "client-side attacks such as cross-site scripting."
        ),
        "recommendation": (
            "Implement an appropriate Content-Security-Policy "
            "for the application."
        ),
    },
    "X-Content-Type-Options": {
        "id": "WEB-HEADER-002",
        "severity": "Low",
        "description": (
            "X-Content-Type-Options is not present. "
            "Browsers may attempt to MIME-sniff responses."
        ),
        "recommendation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },
    "Referrer-Policy": {
        "id": "WEB-HEADER-003",
        "severity": "Low",
        "description": (
            "Referrer-Policy is not present. "
            "Referrer information may be disclosed more broadly "
            "than intended."
        ),
        "recommendation": (
            "Configure an appropriate Referrer-Policy."
        ),
    },
    "Permissions-Policy": {
        "id": "WEB-HEADER-004",
        "severity": "Informational",
        "description": (
            "Permissions-Policy is not present. "
            "Browser features are not explicitly restricted "
            "through this header."
        ),
        "recommendation": (
            "Consider configuring Permissions-Policy "
            "according to application requirements."
        ),
    },
}


def check_security_headers(
    response: httpx.Response,
) -> list[Finding]:
    """
    Check an HTTP response for common security headers.
    """

    findings: list[Finding] = []

    for header_name, rule in SECURITY_HEADERS.items():
        if header_name not in response.headers:
            findings.append(
                Finding(
                    finding_id=rule["id"],
                    title=f"Missing {header_name}",
                    severity=rule["severity"],
                    description=rule["description"],
                    evidence=(
                        f"The HTTP response did not include the "
                        f"{header_name} header."
                    ),
                    recommendation=rule["recommendation"],
                )
            )

    if (
        response.url.scheme == "https"
        and "Strict-Transport-Security" not in response.headers
    ):
        findings.append(
            Finding(
                finding_id="WEB-HEADER-005",
                title="Missing Strict-Transport-Security",
                severity="Low",
                description=(
                    "The site is served over HTTPS but does not "
                    "send the Strict-Transport-Security header."
                ),
                evidence=(
                    "The final response was delivered over HTTPS "
                    "without a Strict-Transport-Security header."
                ),
                recommendation=(
                    "Consider enabling HSTS after confirming that "
                    "HTTPS is correctly configured across the site."
                ),
            )
        )

    return findings