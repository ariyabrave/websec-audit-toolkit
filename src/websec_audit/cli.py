from urllib.parse import urlparse

import typer

from websec_audit.checks.headers import check_security_headers
from websec_audit.http_client import FetchError, fetch_target


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
        raise typer.BadParameter("Target cannot be empty.")

    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
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
) -> None:
    """
    Run security checks against a target.
    """

    normalized_target = normalize_target(target)

    typer.echo()
    typer.echo("WebSec Audit Toolkit")
    typer.echo("--------------------")
    typer.echo(f"Target: {normalized_target}")
    typer.echo()

    try:
        response = fetch_target(normalized_target)

    except FetchError as exc:
        typer.echo(f"[ERROR] {exc}")
        raise typer.Exit(code=1)

    typer.echo(f"HTTP Status: {response.status_code}")
    typer.echo(f"Final URL: {response.url}")
    typer.echo()

    findings = check_security_headers(response)

    typer.echo("Security Header Analysis")
    typer.echo("------------------------")

    if not findings:
        typer.echo("No missing security headers detected.")
        return

    for finding in findings:
        typer.echo()
        typer.echo(
            f"[{finding.severity}] {finding.title}"
        )
        typer.echo(
            f"  Description: {finding.description}"
        )
        typer.echo(
            f"  Recommendation: {finding.recommendation}"
        )

    typer.echo()
    typer.echo(
        f"Total findings: {len(findings)}"
    )


if __name__ == "__main__":
    app()