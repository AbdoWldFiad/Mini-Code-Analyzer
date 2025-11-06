import re

def detect_dangerously_set_inner_html(source):
    pattern = re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE)
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            issues.append({
                "type": "Use of dangerouslySetInnerHTML",
                "severity": "High",
                "suggestion": "Avoid dangerouslySetInnerHTML or sanitize all content before using it.",
                "line": i,
            })
    return issues

rules = [
    detect_dangerously_set_inner_html,
]
