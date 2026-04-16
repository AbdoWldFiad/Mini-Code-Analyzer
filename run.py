#!/usr/bin/env python3
import os
import sys
import argparse
from pathlib import Path
from analyzer import SecureCodeAnalyzer
from report import SEVERITY_COLORS, print_report, print_summary
from autofix import apply_fixes
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from collections import defaultdict

console = Console()
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".html": "html",
    ".php": "php",
}

def detect_framework(root: Path):
    files = {f.lower() for f in os.listdir(root)}

    # Django (highest confidence)
    if "manage.py" in files:
        return "django"

    # Flask (check common structure signals)
    if (
        "app.py" in files or
        "wsgi.py" in files or
        "flask" in files
    ):
        return "flask"

    # React (needs package.json + JSX/TSX)
    if "package.json" in files:
        if any(f.endswith((".jsx", ".tsx")) for f in files):
            return "react"

    return None

def analyze_directory(directory: Path, autofix=False, dry_run=False, json_report=False, verbose=False,):
    # for summary
    severity_totals = defaultdict(int)
    total_issues = 0
    
    framework = detect_framework(directory)
    console.print(f"[bold cyan]Detected framework:[/bold cyan] {framework or 'None'}\n")

    # Gather all files first
    all_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            all_files.append(Path(root) / f)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:

        task = progress.add_task("Analyzing files...", total=len(all_files))

        for path in all_files:
            # Determine language
            suffix = path.suffix.lower()
            lang = EXTENSION_MAP.get(suffix)

            if not lang:
                progress.advance(task)
                continue

            analyzer = SecureCodeAnalyzer(language=lang, framework=framework)
            issues = analyzer.analyze_file(str(path))
            
            total_issues += len(issues)
            for issue in issues:
                sev = issue.get("severity", "n/a").lower()
                severity_totals[sev] += 1
            
            # Print report depending on mode
            if verbose:
                print_report(str(path), issues)
            

            # Apply fixes, dry-run, or generate centralized JSON report
            if autofix or dry_run or json_report:
                apply_fixes(
                    str(path),
                    issues,
                    dry_run=dry_run,
                    output_json=json_report,
                    report_dir=str(REPORTS_DIR)
                )

            progress.advance(task)
    print_summary(severity_totals, total_issues)
    
    console.print(Panel(Text("Analysis Complete!", style="bold green"), expand=False))

def parse_args():
    parser = argparse.ArgumentParser( prog="mini-analyzer", description="Mini Code Analyzer – Static Security Analysis Tool" )
                                    #TODO: change the default here
    parser.add_argument( "path", nargs="?", default=r"D:\shogle\progaming-lang\Projects\DVWA\testing_autofux\DVWA", help="Target file or directory to analyze (default: test_samples)" )

    parser.add_argument( "--fix", "-f", action="store_true", help="Automatically apply safe fixes" )

    parser.add_argument( "--dry-run", "-d", action="store_true", help="Show fixes without modifying files" )

    parser.add_argument( "--json", "-j", action="store_true", help="Generate centralized JSON reports" )

    parser.add_argument( "--aggressive", "-a", action="store_true", help="Apply unsafe/manual fixes (use with caution)" )

    parser.add_argument( "--verbose", "-v", action="store_true", help="Verbose mode (show detailed per-file reports)" )
    
    return parser.parse_args()

def main():
    args = parse_args()
    target = Path(args.path)

    if args.fix and not args.dry_run:
        user_input = input("Create backups for all modified files? (y/n): ").strip().lower()
        create_backup = (user_input == "y")
    
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Path '{target}' does not exist.")
        sys.exit(1)
    try:
        analyze_directory( target, autofix=args.fix, dry_run=args.dry_run,
         json_report=args.json, verbose=args.verbose,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user (Ctrl+C). Exiting gracefully...")
        return

if __name__ == "__main__":
    main()