import re
from bs4 import BeautifulSoup

# 1. Detect inline JavaScript blocks that may lead to XSS
def detect_inline_js(source):
    soup = BeautifulSoup(source, "html.parser")
    issues = []
    for script in soup.find_all("script"):
        if not script.get("src") and script.string:
            issues.append({
                "type": "Inline JavaScript detected",
                "severity": "Medium",
                "suggestion": "Move inline scripts to external JS files to reduce XSS risks.",
                "line": get_line_number(source, script.string)
            })
    return issues

# 2. Detect attributes like onclick=, onmouseover= which may allow injection
def detect_inline_event_handlers(source):
    pattern = re.compile(r'on\w+="[^"]+"', re.IGNORECASE)
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            issues.append({
                "type": "Inline event handler detected",
                "severity": "Medium",
                "suggestion": "Avoid inline event handlers (e.g., onclick=). Use external JS event listeners.",
                "line": i,
            })
    return issues

#3. Detect forms without CSRF protection tokens
def detect_missing_csrf_token(source): 
    soup = BeautifulSoup(source, "html.parser")
    issues = []
    for form in soup.find_all("form"):
        if not form.find("input", {"name": re.compile("csrf", re.I)}):
            issues.append({
                "type": "Form missing CSRF token",
                "severity": "High",
                "suggestion": "Ensure every form includes a CSRF protection token.",
                "line": get_line_number(source, str(form))
            })
    return issues


def get_line_number(source, snippet):
    """Helper to find the approximate line number of a snippet."""
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        if snippet.strip() in line:
            return i
    return "Unknown"

# the list of all defs
rules = [
    detect_inline_js,
    detect_inline_event_handlers,
    detect_missing_csrf_token,
]
