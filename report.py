from rich.console import Console
from rich.table import Table
from collections import defaultdict

console = Console()

SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
    "n/a": "white",
}

def print_report(filepath, issues, global_summary=None):
    try:
        console.print(
            f"\n[bold underline cyan]Analysis Report for {filepath}[/bold underline cyan]\n"
        )

        grouped = {}
        severity_count = {}

        # GLOBAL SUMMARY INIT
        if global_summary is None:
            global_summary = defaultdict(lambda: defaultdict(int))

        # GROUPING
        for issue in issues:
            issue_type = issue.get("type", "Unknown")
            severity = issue.get("severity", "n/a").lower()
            line = issue.get("line")

            severity_count[severity] = severity_count.get(severity, 0) + 1

            # file-level grouping
            if issue_type not in grouped:
                grouped[issue_type] = {
                    "type": issue_type,
                    "severity": severity,
                    "suggestion": issue.get("suggestion", "None"),
                    "lines": set(),
                }

            if line is not None:
                grouped[issue_type]["lines"].add(line)

            # GLOBAL SUMMARY UPDATE
            global_summary[filepath][issue_type] += 1

        # MAIN TABLE
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Type", style="bold red")
        table.add_column("Severity")
        table.add_column("Lines", style="cyan")
        table.add_column("Suggestion", style="green")

        if grouped:
            for issue in grouped.values():
                color = SEVERITY_COLORS.get(issue["severity"], "white")

                lines = ", ".join(map(str, sorted(issue["lines"]))) if issue["lines"] else "-"

                table.add_row(
                    issue["type"],
                    f"[{color}]{issue['severity']}[/{color}]",
                    lines,
                    issue["suggestion"],
                )
        else:
            table.add_row(
                "[green]No issues found[/green]",
                "-",
                "-",
                "[green]Your code looks safe[/green]",
            )

        console.print(table)

        console.print(
            f"\n[bold]Total vulnerabilities in file:[/bold] {len(issues)}\n"
        )

        return severity_count, global_summary

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Interrupted while generating report[/bold yellow]")
        raise  # re-raise to be handled by main()

def print_summary(severity_totals, total_issues):
    console.print("\n[bold underline green]Severity Breakdown:[/bold underline green]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")

    # Keep consistent order
    order = ["critical", "high", "medium", "low", "n/a"]

    has_data = False

    for sev in order:
        if sev in severity_totals:
            has_data = True
            color = SEVERITY_COLORS.get(sev, "white")
            count = severity_totals[sev]
            percent = (count / total_issues * 100) if total_issues else 0
            table.add_row(
                f"[{color}]{sev.capitalize()}[/{color}]",
                f"[{color}]{severity_totals[sev]}[/{color}]",
                f"[{color}]{percent:.1f}%[/{color}]",
            )

    if not has_data:
        table.add_row("[green]No issues[/green]", "[green]0[/green]")

    console.print(table)

    console.print(
        f"\n[bold red]Total Issues Found: {total_issues}[/bold red]\n"
    )