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
    Apply AST-based fixes using byte ranges (Tree-sitter).

    Supports:
    - replace / insert / delete
    - manual_hint (only applied in aggressive mode)
    - dry-run previews
    - overlap protection
    """

    def try_merge(a, b):
        # Same range → conflict
        if a["start"] == b["start"] and a["end"] == b["end"]:
            return None

        # One inside another
        if a["start"] <= b["start"] and a["end"] >= b["end"]:
            return a  # keep outer edit

        if b["start"] <= a["start"] and b["end"] >= a["end"]:
            return b  # keep outer edit

        # Touching but not overlapping → safe to keep both
        if a["end"] == b["start"] or b["end"] == a["start"]:
            return [a, b]

        # Partial overlap → unsafe
        return None

    def has_overlap(a, b):
        return not (a["end"] <= b["start"] or a["start"] >= b["end"])

    try:
        # Read full file as text
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        if create_backup and not dry_run:
            shutil.copy(filepath, filepath + ".bak")

        edits = []

 
        # Collect valid edits
        original_text = text
        original_length = len(original_text)
        
        for issue in issues:
            try:
                if not issue.get("fixable"):
                    continue

                if not aggressive and issue.get("confidence") != "high":
                    continue

                fix = issue.get("fix")
                if not fix:
                    continue
                
                if isinstance(fix, str):
                    fix = {
                        "type": "manual_hint",
                        "hint": fix
                    }

                if not isinstance(fix, dict):
                    print(f"[WARN] Invalid fix format: {issue}")
                    continue

                fix_type = fix.get("type")
                if not fix_type:
                    continue

                

                # --- REPLACE ---
                if fix_type == "replace":
                    start = fix.get("start", issue.get("start_byte"))
                    end = fix.get("end", issue.get("end_byte"))
                    content = fix.get("content")

                    if start is None or end is None or content is None:
                        continue

                    if not isinstance(start, int) or not isinstance(end, int):
                        continue

                    if start >= end:
                        continue

                    if not (0 <= start <= end <= original_length):
                        continue

                    original_slice = original_text[start:end]

                    if not original_slice.strip():
                        continue

                    edits.append({
                        "start": start,
                        "end": end,
                        "content": content,
                        "message": issue.get("message"),
                        "type": issue.get("type"),
                        "severity": issue.get("severity", "low").lower(),
                        "confidence": issue.get("confidence", "low")
                    })

                # --- INSERT ---
                elif fix_type == "insert":
                    start = fix.get("start", issue.get("start_byte"))
                    content = fix.get("content")

                    if start is None or content is None:
                        continue

                    if not isinstance(start, int):
                        continue

                    if not (0 <= start <= original_length):
                        continue

                    edits.append({
                        "start": start,
                        "end": start,
                        "content": content,
                        "message": issue.get("message"),
                        "type": issue.get("type"),
                        "severity": issue.get("severity", "low").lower(),
                        "confidence": issue.get("confidence", "low")
                    })

                # --- DELETE ---
                elif fix_type == "delete":
                    start = fix.get("start", issue.get("start_byte"))
                    end = fix.get("end", issue.get("end_byte"))

                    if start is None or end is None:
                        continue

                    if not (isinstance(start, int) and isinstance(end, int)):
                        continue

                    if not (0 <= start <= end <= original_length):
                        continue

                    if start == end:
                        continue

                    edits.append({
                        "start": start,
                        "end": end,
                        "content": "",
                        "message": issue.get("message"),
                        "type": issue.get("type"),
                        "severity": issue.get("severity", "low").lower(),
                        "confidence": issue.get("confidence", "low")
                    })

                # --- MANUAL (AGGRESSIVE MODE ONLY) ---
                elif fix_type == "manual_hint" and aggressive:
                    start = issue.get("start_byte")

                    if start is None or not isinstance(start, int):
                        continue

                    comment_prefix = "# " if filepath.endswith(".py") else "// "
                    comment = f"{comment_prefix}TODO: {fix.get('hint')}\n"

                    edits.append({
                        "start": start,
                        "end": start,
                        "content": comment,
                        "message": issue.get("message"),
                        "type": issue.get("type")
                    })
            except Exception as e:
                print(f"[WARN] Skipping invalid fix: {issue}")
                print(f"[ERROR] {type(e).__name__}: {e}")
        if not edits:
            return []

        # detect duplicates
        seen = set()
        unique_edits = []

        for e in edits:
            key = (e["start"], e["end"], e["content"])
            if key in seen:
                continue
            seen.add(key)
            unique_edits.append(e)

        edits = unique_edits
        # Remove overlapping edits
 
        edits.sort(key=lambda e: e["start"])

        filtered = []

        PRIORITY = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }

        def get_score(edit):
            severity_score = PRIORITY.get(edit.get("severity", "low"), 1)
            confidence_score = 1 if edit.get("confidence") == "high" else 0
            return (severity_score, confidence_score)

        for edit in edits:
            conflict = None

            for existing in filtered:
                if has_overlap(edit, existing):
                    conflict = existing
                    break

            if not conflict:
                filtered.append(edit)
                continue

            #  Resolve conflict instead of skipping blindly
            if get_score(edit) > get_score(conflict):
                print(f"[INFO] Replacing lower priority edit: {conflict}")
                filtered.remove(conflict)
                filtered.append(edit)
            else:
                print(f"[WARN] Skipping lower priority edit: {edit}")

        # Apply from bottom → top
        filtered.sort(key=lambda e: e["start"], reverse=True)

        changes = []

        # Apply edits
        for edit in filtered:
            start = edit["start"]
            end = edit["end"]
            content = edit["content"]

            original = text[start:end]

            if dry_run:
                preview = text[:start] + content + text[end:]

                snippet = preview[max(0, start - 40): start + 40]

                changes.append({
                    "type": edit["type"],
                    "message": edit["message"],
                    "preview": snippet
                })
            else:
                text = text[:start] + content + text[end:]

                changes.append({
                    "type": edit["type"],
                    "message": edit["message"],
                    "original": original,
                    "replacement": content
                })

        # Write file
        if not dry_run:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text)

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