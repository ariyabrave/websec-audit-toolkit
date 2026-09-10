import httpx

from websec_audit.scanner import ScanResult


def test_scan_result_holds_scan_data():
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    response = httpx.Response(
        200,
        request=request,
    )

    result = ScanResult(
        target="https://example.com",
        response=response,
        findings=[],
        tls_info=None,
        tls_error=None,
    )

    assert result.target == "https://example.com"
    assert result.response.status_code == 200
    assert result.findings == []
    assert result.tls_info is None
    assert result.tls_error is None