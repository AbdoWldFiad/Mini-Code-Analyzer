import re
from bs4 import BeautifulSoup

# 1. Detect inline JavaScript (onclick, onload, etc.)
def detect_inline_js(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'on\w+\s*=', line, re.IGNORECASE):
            issues.append({
                "type": "Inline JavaScript",
                "severity": "High",
                "suggestion": "Move JavaScript to external .js file.",
                "line": i,
            })
    return issues

# 2. Detect missing alt attribute on <img>
def detect_missing_alt(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        for match in re.finditer(r'<img\b[^>]*>', line, re.IGNORECASE):
            if not re.search(r'alt\s*=', match.group(0), re.IGNORECASE):
                issues.append({
                    "type": "Missing alt attribute",
                    "severity": "Medium",
                    "suggestion": "Add alt text to <img> for accessibility.",
                    "line": i,
                })
    return issues

# 3. Detect empty href attributes
def detect_empty_href(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<a\b[^>]*href\s*=\s*["\']\s*["\']', line, re.IGNORECASE):
            issues.append({
                "type": "Empty href",
                "severity": "Medium",
                "suggestion": "Provide a valid URL in href.",
                "line": i,
            })
    return issues

# 4. Detect <script> tags with inline code
def detect_inline_script(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if '<script' in line and not re.search(r'src\s*=', line, re.IGNORECASE):
            issues.append({
                "type": "Inline <script>",
                "severity": "High",
                "suggestion": "Move JavaScript to external file with src.",
                "line": i,
            })
    return issues

# 5. Detect <iframe> without sandbox attribute
def detect_iframe_no_sandbox(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if '<iframe' in line and 'sandbox' not in line.lower():
            issues.append({
                "type": "<iframe> without sandbox",
                "severity": "High",
                "suggestion": "Add sandbox attribute to <iframe> for security.",
                "line": i,
            })
    return issues

# 6. Detect deprecated tags like <center>, <font>
def detect_deprecated_tags(source):
    issues = []
    deprecated = ['<center', '<font', '<marquee', '<bgsound']
    for i, line in enumerate(source.splitlines(), start=1):
        if any(tag in line.lower() for tag in deprecated):
            issues.append({
                "type": "Deprecated HTML tag",
                "severity": "Medium",
                "suggestion": "Avoid using deprecated tags; use CSS instead.",
                "line": i,
            })
    return issues

# 7. Detect inline styles
def detect_inline_styles(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if 'style=' in line.lower():
            issues.append({
                "type": "Inline style",
                "severity": "Low",
                "suggestion": "Use external CSS instead of inline styles.",
                "line": i,
            })
    return issues

# 8. Detect <form> without action attribute
def detect_form_no_action(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if '<form' in line and 'action=' not in line.lower():
            issues.append({
                "type": "<form> missing action",
                "severity": "High",
                "suggestion": "Add action attribute to <form>.",
                "line": i,
            })
    return issues

# 9. Detect <a> with javascript: in href
def detect_js_href(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<a\b[^>]*href\s*=\s*["\']\s*javascript:', line, re.IGNORECASE):
            issues.append({
                "type": "<a> with javascript: href",
                "severity": "High",
                "suggestion": "Avoid using javascript: in href; use event listeners.",
                "line": i,
            })
    return issues

# 10. Detect <input type="password"> without autocomplete="off"
def detect_password_autocomplete(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<input\b[^>]*type\s*=\s*["\']password', line, re.IGNORECASE):
            if 'autocomplete=' not in line.lower():
                issues.append({
                    "type": "Password input without autocomplete",
                    "severity": "Medium",
                    "suggestion": "Add autocomplete='off' to password inputs for security.",
                    "line": i,
                })
    return issues

# 11. Detect missing lang attribute on <html>
def detect_html_no_lang(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if '<html' in line.lower() and 'lang=' not in line.lower():
            issues.append({
                "type": "<html> missing lang attribute",
                "severity": "Medium",
                "suggestion": "Add lang attribute for accessibility.",
                "line": i,
            })
    return issues

# 12. Detect <meta name="viewport"> missing
def detect_viewport_meta(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if '<head' in line.lower() and 'meta name="viewport"' not in source.lower():
            issues.append({
                "type": "Missing viewport meta",
                "severity": "Low",
                "suggestion": "Add <meta name='viewport'> for responsive design.",
                "line": i,
            })
            break
    return issues

# 13. Detect <img> with src pointing to http (non-https)
def detect_img_http(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<img\b[^>]*src\s*=\s*["\']http:', line, re.IGNORECASE):
            issues.append({
                "type": "Non-HTTPS image",
                "severity": "Medium",
                "suggestion": "Use HTTPS for image sources.",
                "line": i,
            })
    return issues

# 14. Detect <a> with target="_blank" missing rel="noopener"
def detect_blank_no_rel(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<a\b[^>]*target\s*=\s*"_blank"', line, re.IGNORECASE):
            if 'rel=' not in line.lower():
                issues.append({
                    "type": '<a target="_blank"> missing rel',
                    "severity": "Medium",
                    "suggestion": "Add rel='noopener' to links with target='_blank'.",
                    "line": i,
                })
    return issues

# 15. Detect multiple <title> tags
def detect_multiple_title(source):
    issues = []
    count = sum(1 for line in source.splitlines() if '<title>' in line.lower())
    if count > 1:
        issues.append({
            "type": "Multiple <title> tags",
            "severity": "Low",
            "suggestion": "Use only one <title> tag per document.",
            "line": 1,
        })
    return issues

# 16. Detect missing charset <meta charset="...">
def detect_missing_charset(source):
    issues = []
    if '<meta charset=' not in source.lower():
        issues.append({
            "type": "Missing charset meta",
            "severity": "Low",
            "suggestion": "Add <meta charset='UTF-8'> inside <head>.",
            "line": 1,
        })
    return issues

# 17. Detect <link rel="stylesheet"> using HTTP
def detect_css_http(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<link\b[^>]*rel\s*=\s*["\']stylesheet["\'][^>]*href\s*=\s*["\']http:', line, re.IGNORECASE):
            issues.append({
                "type": "Non-HTTPS CSS",
                "severity": "Medium",
                "suggestion": "Use HTTPS for CSS files.",
                "line": i,
            })
    return issues

# 18. Detect <script src="..."> using HTTP
def detect_script_http(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<script\b[^>]*src\s*=\s*["\']http:', line, re.IGNORECASE):
            issues.append({
                "type": "Non-HTTPS script",
                "severity": "Medium",
                "suggestion": "Use HTTPS for external scripts.",
                "line": i,
            })
    return issues

# 19. Detect <audio> or <video> missing controls
def detect_media_no_controls(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<(audio|video)\b', line, re.IGNORECASE) and 'controls' not in line.lower():
            issues.append({
                "type": "<audio> or <video> missing controls",
                "severity": "Low",
                "suggestion": "Add controls attribute to media elements.",
                "line": i,
            })
    return issues

# 20. Detect <input> missing type attribute
def detect_input_no_type(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<input\b', line, re.IGNORECASE) and 'type=' not in line.lower():
            issues.append({
                "type": "<input> missing type",
                "severity": "Low",
                "suggestion": "Specify input type for accessibility and security.",
                "line": i,
            })
    return issues

# 21. Detect attributes like onclick=, onmouseover= which may allow injection
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

# 22. Detect forms without CSRF protection tokens
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


# List of all rules
rules = [
    detect_inline_js,
    detect_missing_alt,
    detect_empty_href,
    detect_inline_script,
    detect_iframe_no_sandbox,
    detect_deprecated_tags,
    detect_inline_styles,
    detect_form_no_action,
    detect_js_href,
    detect_password_autocomplete,
    detect_html_no_lang,
    detect_viewport_meta,
    detect_img_http,
    detect_blank_no_rel,
    detect_multiple_title,
    detect_missing_charset,
    detect_css_http,
    detect_script_http,
    detect_media_no_controls,
    detect_input_no_type,
    detect_inline_event_handlers,
    detect_missing_csrf_token,
]
