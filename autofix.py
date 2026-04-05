import os
import json
import shutil


def apply_fixes(
    filepath,
    issues,
    dry_run=False,
    output_json=False,
    report_dir="reports",
    aggressive=False,
    create_backup=False
):
    """
    Apply or annotate fixes to a file.

    Modes:
    - safe (default): apply only safe fixes
    - aggressive: apply all fixes including manual ones
    - dry-run: preview changes without modifying file

    Behavior:
    - Inserts fix comments OR replaces lines (if specified)
    """

    changes = []
    fixed_lines = None

    try:
        # Ask for backup (optional)
        if create_backup and not dry_run:
            backup_path = filepath + ".bak"
            shutil.copy(filepath, backup_path)

        # Validate and filter issues
        valid_issues = []
        for issue in issues:
            line = issue.get("line")
            fix = issue.get("fix")

            if not issue.get("fixable"):
                continue

            if not aggressive and issue.get("type") == "manual":
                continue

            if not isinstance(line, int) or line <= 0:
                print(f"[!] Skipping invalid issue (bad line): {issue}")
                continue

            if not fix or (isinstance(fix, dict) and not fix.get("content")):
                print(f"[!] Skipping invalid issue (no fix): {issue}")
                continue

            valid_issues.append(issue)

        # Sort bottom → top
        valid_issues.sort(key=lambda x: x["line"], reverse=True)

        # Load file once
        if valid_issues:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                fixed_lines = f.readlines()

        # Apply fixes
        for issue in valid_issues:
            line_num = issue["line"]

            if line_num > len(fixed_lines):
                print(f"[!] Skipping out-of-range line {line_num}")
                continue

            original = fixed_lines[line_num - 1].rstrip("\r\n")
            fix_data = issue.get("fix")

            if isinstance(fix_data, dict):
                fix_content = fix_data.get("content", "").rstrip()
                replace_mode = fix_data.get("type") == "replace"
            else:
                fix_content = str(fix_data).rstrip()
                replace_mode = issue.get("replace", False)

            if not fix_content:
                print(f"[!] Skipping issue with empty fix: {issue}")
                continue

            indentation = len(original) - len(original.lstrip())
            indent_str = " " * indentation

            

            if replace_mode:
                new_line = indent_str + fix_content + "\n"
                if not dry_run:
                    fixed_lines[line_num - 1] = new_line
            else:
                todo_line = indent_str + fix_content
                if not dry_run:
                    fixed_lines.insert(line_num - 1, todo_line + "\n")
                new_line = todo_line

            changes.append({
                "line": line_num,
                "original": original,
                "fixed": new_line.strip(),
                "type": issue.get("type"),
                "confidence": issue.get("confidence", "High"),
                "mode": "aggressive" if aggressive else "safe",
                "action": "replace" if replace_mode else "insert"
            })

        # Save file
        if fixed_lines is not None and not dry_run:
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.writelines(fixed_lines)
            print(f"[+] Changes saved to: {filepath}")

        # JSON report
        if output_json:
            os.makedirs(report_dir, exist_ok=True)
            base_filename = os.path.basename(filepath)
            json_path = os.path.join(report_dir, base_filename + ".report.json")

            report_data = {
                "file": filepath,
                "total_issues": len(issues),
                "applied_fixes": len(changes),
                "changes": changes
            }

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)

            print(f"[+] JSON report saved to: {json_path}")

    except Exception as e:
        raise RuntimeError(f"Autofix failed for {filepath}") from e

    return changes