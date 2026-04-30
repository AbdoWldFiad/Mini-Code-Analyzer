#!/usr/bin/env python3
import json
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
from rich.prompt import Prompt
from collections import defaultdict

console = Console()
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

EXTENSION_MAP = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".html": "html",
    ".htm": "html",
    ".php": "php",
    ".blade.php": "php",
}

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')

    print()

    print("                     \033[38;2;0;255;255m███╗   ███╗ ██████╗ █████╗ \033[0m")
    print("                     \033[38;2;0;204;255m████╗ ████║██╔════╝██╔══██╗\033[0m")
    print("                     \033[38;2;0;153;255m██╔████╔██║██║     ███████║\033[0m")
    print("                     \033[38;2;0;102;255m██║╚██╔╝██║██║     ██╔══██║\033[0m")
    print("                     \033[38;2;0;51;255m██║ ╚═╝ ██║╚██████ ██║  ██║\033[0m")
    print("                     \033[38;2;0;0;255m╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝\033[0m")

    print("\n                \033[1;36mMini Code Analyzer (MCA) v0.1\033[0m")
    print("         \033[38;2;0;0;255mStatic Security Analysis & Auto Fix Tool\033[0m\n")

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
        try:
            with open(root / "package.json") as f:
                pkg = json.load(f)

            deps = {
                **pkg.get("dependencies", {}),
                **pkg.get("devDependencies", {})
            }

            if "react" in deps:
                return "react"

        except Exception:
            pass

    return None

def analyze_directory(directory: Path, autofix=False, dry_run=False, json_report=False, verbose=False, aggressive=False,create_backup=False):
    stats = {
    "total_files": 0,
    "code_files": 0,
    "skipped_files": 0
}
    
    # for summary
    severity_totals = defaultdict(int)
    total_issues = 0
    
    framework = detect_framework(directory)
    console.print("[bold cyan]Detected framework:[/bold cyan] ", end="")
    console.print(framework or "None", style="bold white")

    # Gather all files first
    all_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            all_files.append(Path(root) / f)

    dots = ["", ".", "..", "..."]
    i = 0
    total = len(all_files)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:

        task = progress.add_task("[cyan]Analyzing files[/cyan]", total=len(all_files))

        for idx, path in enumerate(all_files, start=1):
            stats["total_files"] += 1
            progress.update(task, description=( f"[cyan]Analyzing files{dots[i % 4]:<3}[/cyan] " f"[green]{idx}/{total}[/green]" ) ) 
            i += 1
            # Determine language
            suffix = "".join(path.suffixes).lower()
            lang = EXTENSION_MAP.get(suffix)

            if not lang:
                stats["skipped_files"] += 1
                progress.advance(task)
                continue
            
            stats["code_files"] += 1
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
                    report_dir=str(REPORTS_DIR),
                    create_backup=create_backup,
                    aggressive=aggressive
                )

            progress.advance(task)
    print_summary(severity_totals, total_issues,stats)
    
    console.print(Panel(Text("Analysis Complete!", style="bold green"), expand=False))

def parse_args():
    parser = argparse.ArgumentParser( prog="mini-analyzer", description="Mini Code Analyzer – Static Security Analysis Tool for source code" )
                                    #TODO: delete later temp scan root for testing "D:\shogle\progaming-lang\Projects\DVWA\testing_autofux\DVWA"
    parser.add_argument( "path", nargs="?", help="Target file or directory to analyze" )

    parser.add_argument( "--fix", "-f", action="store_true", help="Automatically apply safe fixes" )

    parser.add_argument( "--dry-run", "-d", action="store_true", help="Show fixes without modifying files" )

    parser.add_argument( "--json", "-j", action="store_true", help="Generate centralized JSON reports" )

    parser.add_argument( "--aggressive", "-a", action="store_true", help="Apply unsafe/manual fixes (use with caution)" )

    parser.add_argument( "--verbose", "-v", action="store_true", help="Verbose mode (show detailed per-file reports)" )
    
    parser.add_argument( "--backup", action="store_true", help="Create backups before modifying files" )
    
    return parser.parse_args()

def main():
    banner()
    
    args = parse_args()
    try:
        if not args.path:
            console.print("[yellow]No directory provided.[/yellow]")
            args.path = Prompt.ask("Enter directory to analyze")
        
        target = Path(args.path)

        create_backup = False

        if args.fix and not args.dry_run:
            create_backup = args.backup
        
        if args.fix and args.dry_run:
            print("Error: Cannot use --fix with --dry-run")
            sys.exit(1)
        
        if not target.exists():
            console.print(f"[bold red]Error:[/bold red] Path '{target}' does not exist.")
            sys.exit(1)

        analyze_directory( target, autofix=args.fix, dry_run=args.dry_run,
        json_report=args.json, verbose=args.verbose,aggressive=args.aggressive,create_backup=create_backup
        )
    except KeyboardInterrupt:
        console.print("\n[yellow][INFO][/yellow] Scan interrupted by user. Exiting...")
        return

if __name__ == "__main__":
    main()