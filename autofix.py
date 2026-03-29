import os
import json

def apply_fixes(filepath, issues, dry_run=False, output_json=False, report_dir="reports", aggressive=False):
    """
    Apply auto-fixable changes.

    Modes:
    - safe (default): apply only safe fixes
    - aggressive: apply manual fixes too
    - dry-run: preview all fixes (safe + TODO)
    """

    changes = []
    fixed_lines = None

    try:
        # Filter fixable issues with line and fix content
        fixable_issues = [i for i in issues if i.get("fixable") and i.get("line") and i.get("fix")]

        # Sort from bottom → top to keep line numbers stable when inserting
        fixable_issues.sort(key=lambda x: x["line"], reverse=True)

        for issue in fixable_issues:
            line_num = issue["line"]

            if fixed_lines is None:
                with open(filepath, "r", encoding="utf-8") as f:
                    fixed_lines = f.readlines()

            if line_num <= 0 or line_num > len(fixed_lines):
                continue

            original = fixed_lines[line_num - 1].rstrip("\n")
            fix_content = issue.get("fix")

            # Insert TODO comment above the line (with indentation matching original line)
            indentation = len(original) - len(original.lstrip())
            indent_str = " " * indentation
            todo_line = indent_str + fix_content.strip()  # strip to avoid trailing spaces

            if not dry_run:
                fixed_lines.insert(line_num - 1, todo_line + "\n")

            changes.append({
                "line": line_num,
                "original": original,
                "fixed": todo_line,
                "type": issue.get("type"),
                "confidence": issue.get("confidence", "High"),
                "mode": "safe"
            })

        # Save fixed file 
        if fixed_lines and not dry_run:
            fixed_path = filepath
            with open(fixed_path, "w", encoding="utf-8") as f:
                f.writelines(fixed_lines)
            print(f"[+] Fixed issues saved to: {fixed_path}")

        # JSON report 
        if output_json and issues:
            os.makedirs(report_dir, exist_ok=True)
            base_filename = os.path.basename(filepath)
            json_path = os.path.join(report_dir, base_filename + ".report.json")

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(issues, f, indent=4)

            print(f"[+] JSON report saved to: {json_path}")

    except Exception as e:
        print(f"[ERROR] Autofix failed for {filepath}: {e}")

    return changes