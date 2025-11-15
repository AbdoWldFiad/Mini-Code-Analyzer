import sys
import os
from analyzer import SecureCodeAnalyzer
from report import print_report
from autofix import apply_fixes

REPORTS_DIR = "reports"  # centralized folder for all JSON reports

def detect_framework(root):
    files = [f.lower() for f in os.listdir(root)]
    if "manage.py" in files:
        return "django"
    if "app.py" in files or "flask" in " ".join(files):
        return "flask"
    if any(f.endswith(".jsx") or f.endswith(".tsx") for f in files):
        return "react"
    return None

def analyze_directory(directory, autofix=False, dry_run=False, json_report=False):
    framework = detect_framework(directory)
    print(f" Detected framework: {framework or 'None'}")

    for root, _, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)

            # Determine language by extension
            if f.endswith(".py"):
                lang = "python"
            elif f.endswith(".js") or f.endswith(".jsx"):
                lang = "javascript"
            elif f.endswith(".html"):
                lang = "html"
            elif f.endswith(".php"):
                lang = "php"
            else:
                continue

            analyzer = SecureCodeAnalyzer(language=lang, framework=framework)
            issues = analyzer.analyze_file(path)
            print_report(path, issues)

            # Apply fixes, dry-run, or generate centralized JSON report
            if autofix or dry_run or json_report:
                apply_fixes(path, issues, dry_run=dry_run, output_json=json_report, report_dir=REPORTS_DIR)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "test_samples"
    autofix = "--fix" in sys.argv
    dry_run = "--dry-run" in sys.argv
    json_report = "--json" in sys.argv

    analyze_directory(target, autofix=autofix, dry_run=dry_run, json_report=json_report)
