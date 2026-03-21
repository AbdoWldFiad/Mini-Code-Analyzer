from rich.console import Console
from rich.table import Table

console = Console()

SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
    "n/a": "white",
}


def print_report(filepath, issues):
    console.print(f"\n[bold underline cyan]Analysis Report for {filepath}[/bold underline cyan]\n")

    if not issues:
        console.print("[bold green]No security issues found.[/bold green]\n")
        return {}

    # -----------------------------
    # CLEAN GROUPING
    # -----------------------------
    grouped = {}
    severity_count = {}

    for issue in issues:
        issue_type = issue.get("type", "Unknown")
        sev = issue.get("severity", "n/a").lower()
        line = issue.get("line", None)

        severity_count[sev] = severity_count.get(sev, 0) + 1

        # KEY = only by TYPE (important fix)
        if issue_type not in grouped:
            grouped[issue_type] = {
                "type": issue_type,
                "severity": sev,
                "suggestion": issue.get("suggestion", "None"),
                "lines": set(),   # use set to remove duplicates
            }

        if line is not None:
            grouped[issue_type]["lines"].add(line)

    # -----------------------------
    # PRINT TABLE
    # -----------------------------
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type", style="bold red")
    table.add_column("Severity")
    table.add_column("Lines", style="cyan")
    table.add_column("Suggestion", style="green")

    for issue in grouped.values():
        color = SEVERITY_COLORS.get(issue["severity"], "white")

        lines_str = ", ".join(map(str, sorted(issue["lines"]))) if issue["lines"] else "-"

        table.add_row(
            issue["type"],
            f"[{color}]{issue['severity']}[/{color}]",
            lines_str,
            issue["suggestion"]
        )

    console.print(table)
    return severity_count