import re

def detect_eval_usage(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if "eval(" in line:
            issues.append({
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval() — it can lead to code injection.",
                "line": i,
            })
    return issues


# the list of all defs
rules = [detect_eval_usage]
