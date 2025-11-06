import re

def detect_django_debug_on(source):
    if re.search(r"DEBUG\s*=\s*True", source):
        return [{
            "type": "Django DEBUG mode enabled",
            "severity": "High",
            "suggestion": "Set DEBUG = False in production settings.",
            "line": find_line(source, "DEBUG")
        }]
    return []

def detect_django_csrf_disabled(source):
    if "@csrf_exempt" in source:
        return [{
            "type": "CSRF protection disabled on a view",
            "severity": "High",
            "suggestion": "Avoid using @csrf_exempt unless absolutely necessary.",
            "line": find_line(source, "@csrf_exempt")
        }]
    return []

def detect_safe_filter(source):
    """Detect unsafe use of the `safe` template filter."""
    if "|safe" in source:
        return [{
            "type": "Unsafe use of 'safe' filter in template",
            "severity": "Medium",
            "suggestion": "Avoid using '|safe' unless the content is fully sanitized.",
            "line": find_line(source, "|safe")
        }]
    return []

def find_line(source, keyword):
    for i, line in enumerate(source.splitlines(), start=1):
        if keyword in line:
            return i
    return "Unknown"

rules = [
    detect_django_debug_on,
    detect_django_csrf_disabled,
    detect_safe_filter,
]
