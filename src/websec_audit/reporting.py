from collections import Counter

import httpx
from rich.console import Console
from rich.table import Table

from websec_audit.findings import Finding


console = Console()


SEVERITY_ORDER = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


def summarize_findings(
    findings: list[Finding],
) -> dict[str, int]:
    """
    Count findings by severity.
    """

    counts = Counter(
        finding.severity
        for finding in findings
    )

    return {
        severity: counts.get(severity, 0)
        for severity in SEVERITY_ORDER
    }


def render_scan_result(
    target: str,
    response: httpx.Response,
    findings: list[Finding],
) -> None:
    """
    Render scan results in a human-readable terminal format.
    """

    console.print()
    console.print(
        "[bold]WebSec Audit Toolkit[/bold]"
    )
    console.print()

    target_table = Table(
        show_header=False,
        box=None,
    )

    target_table.add_column(
        style="bold"
    )

    target_table.add_column()

    target_table.add_row(
        "Target",
        target,
    )

    target_table.add_row(
        "Final URL",
        str(response.url),
    )

    target_table.add_row(
        "HTTP Status",
        str(response.status_code),
    )

    console.print(target_table)
    console.print()

    console.print(
        "[bold]Security Findings[/bold]"
    )

    if not findings:
        console.print(
            "[green]No missing security headers detected.[/green]"
        )
        return

    findings_table = Table()

    findings_table.add_column(
        "ID",
        style="bold",
    )

    findings_table.add_column(
        "Severity"
    )

    findings_table.add_column(
        "Finding"
    )

    for finding in findings:
        findings_table.add_row(
            finding.finding_id,
            finding.severity,
            finding.title,
        )

    console.print(findings_table)

    console.print()
    console.print(
        "[bold]Finding Details[/bold]"
    )

    for finding in findings:
        console.print()
        console.print(
            f"[bold]{finding.finding_id} — "
            f"{finding.title}[/bold]"
        )

        console.print(
            f"Severity: {finding.severity}"
        )

        console.print(
            f"Evidence: {finding.evidence}"
        )

        console.print(
            f"Recommendation: "
            f"{finding.recommendation}"
        )

    summary = summarize_findings(findings)

    console.print()
    console.print(
        "[bold]Summary[/bold]"
    )

    summary_table = Table(
        show_header=False
    )

    summary_table.add_column(
        "Severity"
    )

    summary_table.add_column(
        "Count",
        justify="right",
    )

    for severity in SEVERITY_ORDER:
        count = summary[severity]

        if count > 0:
            summary_table.add_row(
                severity,
                str(count),
            )

    summary_table.add_row(
        "Total",
        str(len(findings)),
    )

    console.print(summary_table)