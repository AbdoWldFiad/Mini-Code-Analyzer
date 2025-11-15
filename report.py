def print_report(filepath, issues):
    print(f"\nAnalysis Report for {filepath}:")

    if not issues:
        print("\033[92m No security issues found.\033[0m")
        return

    # --- Step 1: Group issues ---
    grouped = {}
    for issue in issues:
        key = (issue["type"], issue["severity"], issue["suggestion"])
        if key not in grouped:
            grouped[key] = {
                "type": issue["type"],
                "severity": issue["severity"],
                "suggestion": issue["suggestion"],
                "lines": []
            }
        grouped[key]["lines"].append(issue["line"])

    # --- Step 2: Print grouped issues ---
    for issue in grouped.values():
        lines_str = ", ".join(str(l) for l in sorted(issue["lines"]))

        print(f"\033[1;91m[!] Issue:\033[0m \033[91m{issue['type']}\033[0m")
        print(f"\033[2m    Lines:\033[0m \033[93m{lines_str}\033[0m")
        print(f"\033[2mSeverity:\033[0m \033[95m{issue['severity']}\033[0m")
        print(f"\033[2mSuggestion:\033[0m \033[96m{issue['suggestion']}\033[0m")
        print()  # blank line between issues
