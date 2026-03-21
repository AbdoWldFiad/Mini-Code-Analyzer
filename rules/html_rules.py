import re

# Helpers
def get_text(node, source):
    return source[node.start_byte:node.end_byte]

def get_line(node):
    return node.start_point[0] + 1


# 1. Inline JS (onclick, etc.)
def detect_inline_js(node, source):
    if node.type == "attribute":
        text = get_text(node, source)
        if re.search(r'on\w+\s*=', text):
            return [{
                "type": "Inline JavaScript",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 2. Missing alt in img
def detect_missing_alt(node, source):
    if node.type == "element":
        if get_text(node, source).startswith("<img"):
            if "alt=" not in get_text(node, source):
                return [{
                    "type": "Missing alt attribute",
                    "severity": "Low",
                    "line": get_line(node),
                }]
    return []


# 3. Empty href
def detect_empty_href(node, source):
    if node.type == "attribute":
        text = get_text(node, source)
        if re.search(r'href\s*=\s*["\']?\s*["\']', text):
            return [{
                "type": "Empty href",
                "severity": "Low",
                "line": get_line(node),
            }]
    return []


# 4. Inline <script>
def detect_inline_script(node, source):
    if node.type == "script_element":
        text = get_text(node, source)
        if "<script" in text and "src=" not in text:
            return [{
                "type": "Inline script",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 5. iframe without sandbox
def detect_iframe_no_sandbox(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<iframe") and "sandbox" not in text:
            return [{
                "type": "Iframe without sandbox",
                "severity": "High",
                "line": get_line(node),
            }]
    return []


# 6. Deprecated tags
def detect_deprecated_tags(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if re.search(r'<(font|center|marquee)\b', text):
            return [{
                "type": "Deprecated HTML tag",
                "severity": "Medium",
                "suggestion": "Avoid using deprecated tags; use CSS instead.",
                "line": get_line(node),
            }]
    return []


# 7. Inline styles
def detect_inline_styles(node, source):
    if node.type == "attribute":
        if "style=" in get_text(node, source):
            return [{
                "type": "Inline styles",
                "severity": "Low",
                "line": get_line(node),
            }]
    return []


# 8. Form without action
def detect_form_no_action(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<form") and "action=" not in text:
            return [{
                "type": "Form without action",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 9. javascript: href
def detect_js_href(node, source):
    if node.type == "attribute":
        text = get_text(node, source)
        if "javascript:" in text:
            return [{
                "type": "javascript: href",
                "severity": "High",
                "line": get_line(node),
            }]
    return []


# 10. Password autocomplete
def detect_password_autocomplete(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if "type=\"password\"" in text and "autocomplete" not in text:
            return [{
                "type": "Password without autocomplete control",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 11. Missing lang (run once)
def detect_html_no_lang(node, source):
    if node.type != "document":
        return []
    if "<html" in source and "lang=" not in source:
        return [{
            "type": "Missing lang attribute",
            "severity": "Low",
            "suggestion": "Use only one <title> tag per document.",
            "line": 1,
        }]
    return []


# 12. Missing viewport
def detect_viewport_meta(node, source):
    if node.type != "document":
        return []
    if "viewport" not in source:
        return [{
            "type": "Missing viewport meta",
            "severity": "Low",
            "suggestion": "Add <meta charset='UTF-8'> inside <head>.",
            "line": 1,
        }]
    return []


# 13. HTTP images
def detect_img_http(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if "<img" in text and "http://" in text:
            return [{
                "type": "Insecure image source",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 14. target=_blank without rel
def detect_blank_no_rel(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if 'target="_blank"' in text and "rel=" not in text:
            return [{
                "type": "target=_blank without rel",
                "severity": "High",
                "line": get_line(node),
            }]
    return []


# 15. Multiple title tags
def detect_multiple_title(node, source):
    if node.type != "document":
        return []
    if len(re.findall(r'<title>', source)) > 1:
        return [{
            "type": "Multiple title tags",
            "severity": "Low",
            "line": 1,
        }]
    return []


# 16. Missing charset
def detect_missing_charset(node, source):
    if node.type != "document":
        return []
    if "charset" not in source:
        return [{
            "type": "Missing charset",
            "severity": "Medium",
            "line": 1,
        }]
    return []


# 17. CSS over HTTP
def detect_css_http(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if "<link" in text and "http://" in text:
            return [{
                "type": "CSS over HTTP",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 18. Script over HTTP
def detect_script_http(node, source):
    if node.type == "script_element":
        text = get_text(node, source)
        if "http://" in text:
            return [{
                "type": "Script over HTTP",
                "severity": "High",
                "line": get_line(node),
            }]
    return []


# 19. Media without controls
def detect_media_no_controls(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if re.search(r'<(video|audio)\b', text) and "controls" not in text:
            return [{
                "type": "Media without controls",
                "severity": "Low",
                "line": get_line(node),
            }]
    return []


# 20. Input without type
def detect_input_no_type(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<input") and "type=" not in text:
            return [{
                "type": "Input without type",
                "severity": "Low",
                "line": get_line(node),
            }]
    return []


# 21. Inline event handlers
def detect_inline_event_handlers(node, source):
    if node.type == "attribute":
        if re.match(r'on\w+=', get_text(node, source)):
            return [{
                "type": "Inline event handler",
                "severity": "Medium",
                "line": get_line(node),
            }]
    return []


# 22. Missing CSRF token (heuristic)
def detect_missing_csrf_token(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<form"):
            if not re.search(r'csrf|token', text, re.IGNORECASE):
                return [{
                    "type": "Missing CSRF token",
                    "severity": "High",
                    "line": get_line(node),
                }]
    return []


# FINAL RULE LIST
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