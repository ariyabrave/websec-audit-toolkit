import httpx

from websec_audit.json_report import build_json_report
from websec_audit.tls import TLSInfo


def make_response() -> httpx.Response:
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    return httpx.Response(
        200,
        request=request,
    )


def test_json_report_includes_tls_info():
    response = make_response()

    tls_info = TLSInfo(
        hostname="example.com",
        port=443,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        issuer="Example CA",
        subject="example.com",
        expires_at="2027-01-01T00:00:00+00:00",
        days_until_expiry=100,
    )

    report = build_json_report(
        target="https://example.com",
        response=response,
        findings=[],
        tls_info=tls_info,
    )

    assert report["tls"]["status"] == "inspected"
    assert report["tls"]["hostname"] == "example.com"
    assert report["tls"]["port"] == 443
    assert report["tls"]["protocol"] == "TLSv1.3"
    assert report["tls"]["days_until_expiry"] == 100


def test_json_report_records_tls_error():
    response = make_response()

    report = build_json_report(
        target="https://example.com",
        response=response,
        findings=[],
        tls_error="TLS test error",
    )

    assert report["tls"]["status"] == "error"
    assert report["tls"]["error"] == "TLS test error"