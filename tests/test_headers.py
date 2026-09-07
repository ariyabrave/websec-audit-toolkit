import httpx

from websec_audit.checks.headers import check_security_headers


def test_detects_missing_security_headers():
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    response = httpx.Response(
        200,
        request=request,
        headers={},
    )

    findings = check_security_headers(response)

    titles = [
        finding.title
        for finding in findings
    ]

    assert "Missing Content-Security-Policy" in titles
    assert "Missing X-Content-Type-Options" in titles
    assert "Missing Referrer-Policy" in titles
    assert "Missing Permissions-Policy" in titles
    assert "Missing Strict-Transport-Security" in titles


def test_no_findings_when_headers_are_present():
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    response = httpx.Response(
        200,
        request=request,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Strict-Transport-Security": "max-age=31536000",
        },
    )

    findings = check_security_headers(response)

    assert findings == []


def test_hsts_is_not_required_for_plain_http():
    request = httpx.Request(
        "GET",
        "http://example.com",
    )

    response = httpx.Response(
        200,
        request=request,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        },
    )

    findings = check_security_headers(response)

    titles = [
        finding.title
        for finding in findings
    ]

    assert "Missing Strict-Transport-Security" not in titles
def test_findings_have_unique_ids_and_evidence():
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    response = httpx.Response(
        200,
        request=request,
        headers={},
    )

    findings = check_security_headers(
        response
    )

    finding_ids = [
        finding.finding_id
        for finding in findings
    ]

    assert len(finding_ids) == len(
        set(finding_ids)
    )

    for finding in findings:
        assert finding.finding_id
        assert finding.evidence









    