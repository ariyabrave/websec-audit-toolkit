from rich.console import Console
from rich.table import Table

from websec_audit.tls import TLSInfo


console = Console()


def render_tls_info(
    info: TLSInfo | None,
    error: str | None = None,
) -> None:
    """
    Render TLS inspection information.
    """

    console.print()
    console.print("[bold]TLS Information[/bold]")

    if error is not None:
        console.print(
            f"[yellow]TLS inspection unavailable:[/yellow] {error}"
        )
        return

    if info is None:
        console.print(
            "Not applicable: the final response is not HTTPS."
        )
        return

    table = Table(
        show_header=False,
        box=None,
    )

    table.add_column("Field")
    table.add_column("Value")

    table.add_row(
        "Hostname",
        info.hostname,
    )
    table.add_row(
        "Port",
        str(info.port),
    )
    table.add_row(
        "Protocol",
        info.protocol,
    )
    table.add_row(
        "Cipher",
        info.cipher,
    )
    table.add_row(
        "Subject",
        info.subject,
    )
    table.add_row(
        "Issuer",
        info.issuer,
    )
    table.add_row(
        "Expires",
        info.expires_at,
    )
    table.add_row(
        "Days Until Expiry",
        str(info.days_until_expiry),
    )

    console.print(table)