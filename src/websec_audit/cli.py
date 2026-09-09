from pathlib import Path
from urllib.parse import urlparse

import typer

from websec_audit.checks.headers import check_security_headers
from websec_audit.http_client import FetchError, fetch_target
from websec_audit.json_report import write_json_report
from websec_audit.reporting import render_scan_result
from websec_audit.tls import (
    TLSInspectionError,
    inspect_tls,
)
from websec_audit.tls_reporting import render_tls_info


app = typer.Typer(
    name="websec",
    help="A modular Web and API security assessment toolkit.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """
    WebSec Audit Toolkit.

    Intended for authorized security testing and local lab environments.
    """
    pass


def normalize_target(target: str) -> str:
    """
    Normalize and validate a target URL.
    """

    target = target.strip()

    if not target:
        raise typer.BadParameter(
            "Target cannot be empty."
        )

    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise typer.BadParameter(
            "Target must use HTTP or HTTPS."
        )

    if not parsed.netloc:
        raise typer.BadParameter(
            "Invalid target URL."
        )

    return target.rstrip("/")


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Authorized HTTP or HTTPS target to assess.",
    ),
    json_output: Path | None = typer.Option(
        None,
        "--json",
        help="Write scan results to a JSON file.",
    ),
) -> None:
    """
    Run security checks against a target.
    """

    normalized_target = normalize_target(
        target
    )

    try:
        response = fetch_target(
            normalized_target
        )

    except FetchError as exc:
        typer.echo(
            f"[ERROR] {exc}"
        )
        raise typer.Exit(
            code=1
        )

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

    render_tls_info(
        info=tls_info,
        error=tls_error,
    )

    render_scan_result(
        target=normalized_target,
        response=response,
        findings=findings,
    )

    if json_output is not None:
        write_json_report(
            path=json_output,
            target=normalized_target,
            response=response,
            findings=findings,
            tls_info=tls_info,
            tls_error=tls_error,
        )

        typer.echo(
            f"JSON report written to: {json_output}"
        )


if __name__ == "__main__":
    app()