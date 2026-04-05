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
    import os, json, shutil

    changes = []
    fixed_lines = None

    try:
        # Ask for backup (optional)
        if create_backup and not dry_run:
            shutil.copy(filepath, filepath + ".bak")

        # Validate and filter issues
        valid_issues = []
        for issue in issues:
            line = issue.get("line")
            fix = issue.get("fix")

            if not issue.get("fixable"):
                continue

            if not aggressive and issue.get("confidence") != "high":
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

        if not valid_issues:
            return []

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Apply fixes
        for issue in valid_issues:
            line_idx = issue["line"] - 1

            if line_idx >= len(lines):
                print(f"[!] Skipping out-of-range line {lines}")
                continue

            original = lines[line_idx].rstrip("\n")
            fix = issue["fix"]
            fix_type = fix.get("type")
            content = fix.get("content", "").rstrip()

            indent = len(original) - len(original.lstrip())
            indent_str = " " * indent

            new_line = None

            #  Handle fix types properly
            if fix_type == "replace":
                new_line = indent_str + content + "\n"
                if not dry_run:
                    lines[line_idx] = new_line

            elif fix_type == "insert":
                new_line = indent_str + content + "\n"
                if not dry_run:
                    lines.insert(line_idx, new_line)

            elif fix_type == "delete":
                new_line = ""
                if not dry_run:
                    lines.pop(line_idx)

            else:
                continue  # unknown fix type

            changes.append({
                "line": issue["line"],
                "original": original,
                "fixed": new_line.strip(),
                "type": issue.get("type"),
                "confidence": issue.get("confidence"),
                "action": fix_type
            })

        if not dry_run:
            with open(filepath, "w", encoding="utf-8") as f:
                f.writelines(lines)

        # JSON report
        if output_json:
            os.makedirs(report_dir, exist_ok=True)
            json_path = os.path.join(
                report_dir,
                os.path.basename(filepath) + ".report.json"
            )

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "file": filepath,
                    "applied_fixes": len(changes),
                    "changes": changes
                }, f, indent=4)

        return changes

    except Exception as e:
        raise RuntimeError(f"Autofix failed for {filepath}") from e