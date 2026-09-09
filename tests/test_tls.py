from websec_audit.tls import (
    inspect_tls,
)


def test_plain_http_skips_tls():
    info, findings = inspect_tls(
        "http://example.com"
    )

    assert info is None
    assert findings == []