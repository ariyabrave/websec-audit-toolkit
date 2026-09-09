import socket
import ssl

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from websec_audit.findings import Finding


@dataclass
class TLSInfo:
    hostname: str
    port: int
    protocol: str
    cipher: str
    issuer: str
    subject: str
    expires_at: str
    days_until_expiry: int


class TLSInspectionError(Exception):
    """
    Raised when TLS inspection cannot be completed.
    """


def _format_name(
    name_parts: tuple,
) -> str:
    """
    Convert certificate subject/issuer tuples
    into a readable string.
    """

    values = []

    for group in name_parts:
        for key, value in group:
            values.append(
                f"{key}={value}"
            )

    return ", ".join(values)


def inspect_tls(
    target: str,
    timeout: float = 5.0,
) -> tuple[TLSInfo | None, list[Finding]]:
    """
    Inspect the TLS connection and certificate
    for an HTTPS target.

    Plain HTTP targets are skipped.
    """

    parsed = urlparse(target)

    if parsed.scheme != "https":
        return None, []

    hostname = parsed.hostname

    if hostname is None:
        raise TLSInspectionError(
            "Could not determine target hostname."
        )

    port = parsed.port or 443

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as tcp_socket:

            with context.wrap_socket(
                tcp_socket,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                protocol = (
                    tls_socket.version()
                    or "Unknown"
                )

                cipher_info = (
                    tls_socket.cipher()
                )

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        OSError,
        ssl.SSLError,
    ) as exc:
        raise TLSInspectionError(
            f"TLS inspection failed for "
            f"{hostname}:{port}: {exc}"
        ) from exc

    if cipher_info is None:
        cipher = "Unknown"
    else:
        cipher = cipher_info[0]

    not_after = certificate.get(
        "notAfter"
    )

    if not not_after:
        raise TLSInspectionError(
            "Certificate expiration date "
            "was not available."
        )

    expires_at = datetime.strptime(
        not_after,
        "%b %d %H:%M:%S %Y %Z",
    ).replace(
        tzinfo=timezone.utc
    )

    now = datetime.now(
        timezone.utc
    )

    remaining = (
        expires_at - now
    ).days

    issuer = _format_name(
        certificate.get(
            "issuer",
            (),
        )
    )

    subject = _format_name(
        certificate.get(
            "subject",
            (),
        )
    )

    info = TLSInfo(
        hostname=hostname,
        port=port,
        protocol=protocol,
        cipher=cipher,
        issuer=issuer,
        subject=subject,
        expires_at=expires_at.isoformat(),
        days_until_expiry=remaining,
    )

    findings = []

    if remaining < 0:
        findings.append(
            Finding(
                finding_id="TLS-001",
                title="Expired TLS Certificate",
                severity="High",
                description=(
                    "The TLS certificate has expired."
                ),
                evidence=(
                    f"The certificate expired at "
                    f"{expires_at.isoformat()}."
                ),
                recommendation=(
                    "Replace the expired certificate "
                    "with a valid certificate."
                ),
            )
        )

    elif remaining <= 30:
        findings.append(
            Finding(
                finding_id="TLS-002",
                title="TLS Certificate Expiring Soon",
                severity="Medium",
                description=(
                    "The TLS certificate is approaching "
                    "its expiration date."
                ),
                evidence=(
                    f"The certificate expires in "
                    f"{remaining} days at "
                    f"{expires_at.isoformat()}."
                ),
                recommendation=(
                    "Renew the certificate before "
                    "it expires."
                ),
            )
        )

    return info, findings