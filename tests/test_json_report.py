import json

import httpx

from websec_audit.findings import Finding
from websec_audit.json_report import (
    build_json_report,
    write_json_report,
)


def make_response() -> httpx.Response:
    request = httpx.Request(
        "GET",
        "https://example.com",
    )

    return httpx.Response(
        200,
        request=request,
    )


def make_finding() -> Finding:
    return Finding(
        finding_id="TEST-001",
        title="Test Finding",
        severity="Low",
        description="Test description.",
        evidence="Test evidence.",
        recommendation="Test recommendation.",
    )


def test_build_json_report():
    response = make_response()
    finding = make_finding()

    report = build_json_report(
        target="https://example.com",
        response=response,
        findings=[finding],
    )

    assert report["target"] == "https://example.com"
    assert report["final_url"] == "https://example.com"
    assert report["http_status"] == 200
    assert len(report["findings"]) == 1
    assert report["findings"][0]["id"] == "TEST-001"


def test_write_json_report(tmp_path):
    response = make_response()
    finding = make_finding()

    output_file = tmp_path / "reports" / "scan.json"

    write_json_report(
        path=output_file,
        target="https://example.com",
        response=response,
        findings=[finding],
    )

    assert output_file.exists()

    data = json.loads(
        output_file.read_text(
            encoding="utf-8"
        )
    )

    assert data["http_status"] == 200
    assert data["findings"][0]["title"] == "Test Finding"