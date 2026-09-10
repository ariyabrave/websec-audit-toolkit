from pathlib import Path
from urllib.parse import urlparse

import typer

from websec_audit.http_client import FetchError
from websec_audit.json_report import write_json_report
from websec_audit.reporting import render_scan_result
from websec_audit.scanner import run_scan
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


def normalize_target(
    target: str,
) -> str:
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
        result = run_scan(
            normalized_target
        )

    except FetchError as exc:
        typer.echo(
            f"[ERROR] {exc}"
        )
        raise typer.Exit(
            code=1
        )

    render_tls_info(
        info=result.tls_info,
        error=result.tls_error,
    )

    render_scan_result(
        target=result.target,
        response=result.response,
        findings=result.findings,
    )

    if json_output is not None:
        write_json_report(
            path=json_output,
            target=result.target,
            response=result.response,
            findings=result.findings,
            tls_info=result.tls_info,
            tls_error=result.tls_error,
        )

        typer.echo(
            f"JSON report written to: {json_output}"
        )


if __name__ == "__main__":
    app()