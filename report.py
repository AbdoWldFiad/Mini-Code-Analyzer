def print_report(filepath, issues):
    print(f"\n Analysis Report for {filepath}:")

    if not issues:
        print(" No security issues found.")
        return

    for issue in issues:
        print(f"""
[!] Issue: {issue['type']}
    Line: {issue['line']}
    Severity: {issue['severity']}
    Suggestion: {issue['suggestion']}
        """)