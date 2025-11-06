import re

def detect_debug_mode(source):
    """Detect Flask debug mode enabled (security risk in production)."""
    if re.search(r"app\.run\(.*debug\s*=\s*True", source):
        return [{
            "type": "Flask debug mode enabled",
            "severity": "High",
            "suggestion": "Disable debug mode before deployment: app.run(debug=False).",
            "line": find_line(source, "debug=True"),
            "fixable": True,
            "fix": find_line(source, "debug=True").replace("debug=True", "debug=False"),
        }]
    return []

def detect_render_template_string(source):
    """Detect render_template_string, which may allow code injection."""
    if "render_template_string" in source:
        return [{
            "type": "Unsafe use of render_template_string()",
            "severity": "High",
            "suggestion": "Use render_template() with a safe template file instead.",
            "line": find_line(source, "render_template_string")
        }]
    return []

def detect_missing_csrf(source):
    """Detect Flask forms missing CSRF protection."""
    if "FlaskForm" in source and "csrf_token" not in source:
        return [{
            "type": "Possible missing CSRF protection in Flask form",
            "severity": "High",
            "suggestion": "Ensure FlaskForm includes a CSRF token (via Flask-WTF).",
            "line": "Unknown"
        }]
    return []

def find_line(source, keyword):
    for i, line in enumerate(source.splitlines(), start=1):
        if keyword in line:
            return i
    return "Unknown"

rules = [
    detect_debug_mode,
    detect_render_template_string,
    detect_missing_csrf,
]
