import re

# Helpers
def get_text(node, source):
    return source[node.start_byte:node.end_byte]

def get_line(node):
    return node.start_point[0] + 1

def _meta(node, fixable=False, fix=None, confidence="high"):
    return {
        "fixable": fixable,
        "fix": fix,
        "confidence": confidence,
        "line": get_line(node)
    }

# 1. Inline JS (manual)
def detect_inline_js(node, source):
    if node.type == "attribute":
        if re.search(r'on\w+\s*=', get_text(node, source)):
            return [{
                "type": "Inline JavaScript",
                "message": "Move inline JS to external script.",
                "severity": "medium",
                **_meta(node)
            }]
    return []

# 2. Missing alt
def detect_missing_alt(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<img") and "alt=" not in text:
            fixed = text.replace("<img", '<img alt="description"', 1)
            return [{
                "type": "Missing alt attribute",
                "message": "Added alt attribute.",
                "severity": "low",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 3. Empty href
def detect_empty_href(node, source):
    if node.type == "attribute":
        text = get_text(node, source)
        if re.search(r'href\s*=\s*["\']?\s*["\']', text):
            return [{
                "type": "Empty href",
                "message": "Replaced empty href with '#'.",
                "severity": "low",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": 'href="#"'})
            }]
    return []

# 4. Inline script (manual)
def detect_inline_script(node, source):
    if node.type == "script_element":
        text = get_text(node, source)
        if "src=" not in text:
            return [{
                "type": "Inline script",
                "message": "Move script to external file.",
                "severity": "medium",
                **_meta(node)
            }]
    return []

# 5. iframe without sandbox
def detect_iframe_no_sandbox(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<iframe") and "sandbox" not in text:
            fixed = text.replace("<iframe", "<iframe sandbox", 1)
            return [{
                "type": "Iframe without sandbox",
                "message": "Added sandbox attribute.",
                "severity": "high",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 6. Deprecated tags (manual)
def detect_deprecated_tags(node, source):
    if node.type == "element":
        if re.search(r'<(font|center|marquee)\b', get_text(node, source)):
            return [{
                "type": "Deprecated HTML tag",
                "message": "Replace with CSS.",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []

# 7. Inline styles (manual)
def detect_inline_styles(node, source):
    if node.type == "attribute":
        if "style=" in get_text(node, source):
            return [{
                "type": "Inline styles",
                "message": "Move styles to CSS.",
                "severity": "low",
                **_meta(node, False, None, "low")
            }]
    return []

# 8. Form without action
def detect_form_no_action(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<form") and "action=" not in text:
            fixed = text.replace("<form", '<form action="/submit"', 1)
            return [{
                "type": "Form without action",
                "message": "Added form action.",
                "severity": "medium",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 9. javascript: href
def detect_js_href(node, source):
    if node.type == "attribute":
        text = get_text(node, source)
        if "javascript:" in text:
            return [{
                "type": "javascript: href",
                "message": "Replaced unsafe href.",
                "severity": "high",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": 'href="#"'})
            }]
    return []

# 10. Password autocomplete
def detect_password_autocomplete(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if 'type="password"' in text and "autocomplete" not in text:
            fixed = text.replace('type="password"', 'type="password" autocomplete="off"')
            return [{
                "type": "Password autocomplete",
                "message": "Added autocomplete control.",
                "severity": "medium",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 11. Missing lang
def detect_html_no_lang(node, source):
    if node.type == "document":
        if "<html" in source and "lang=" not in source:
            return [{
                "type": "Missing lang attribute",
                "message": "Added lang attribute.",
                "severity": "low",
                **_meta(node, True, {"type": "insert", "start": node.start_byte, "end": node.end_byte, "content": '<html lang="en">'})
            }]
    return []

# 12. Missing viewport
def detect_viewport_meta(node, source):
    if node.type == "document":
        if "viewport" not in source:
            return [{
                "type": "Missing viewport meta",
                "message": "Added viewport meta.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "insert",
                    "content": '<meta name="viewport" content="width=device-width, initial-scale=1">'
                })
            }]
    return []

# 13. HTTP images
def detect_img_http(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if "<img" in text and "http://" in text:
            fixed = text.replace("http://", "https://")
            return [{
                "type": "Insecure image source",
                "message": "Upgraded to HTTPS.",
                "severity": "medium",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 14. target=_blank without rel
def detect_blank_no_rel(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if 'target="_blank"' in text and "rel=" not in text:
            fixed = text.replace(
                'target="_blank"',
                'target="_blank" rel="noopener noreferrer"'
            )
            return [{
                "type": "target=_blank without rel",
                "message": "Added rel attribute.",
                "severity": "high",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 15. Multiple title (manual)
def detect_multiple_title(node, source):
    if node.type == "document":
        if len(re.findall(r'<title>', source)) > 1:
            return [{
                "type": "Multiple title tags",
                "message": "Keep only one title tag.",
                "severity": "low",
                **_meta(node, False, None, "medium")
            }]
    return []

# 16. Missing charset
def detect_missing_charset(node, source):
    if node.type == "document":
        if "charset" not in source:
            return [{
                "type": "Missing charset",
                "message": "Added charset meta.",
                "severity": "medium",
                **_meta(node, True, {
                    "type": "insert",
                    "content": '<meta charset="UTF-8">'
                })
            }]
    return []

# 17. CSS over HTTP
def detect_css_http(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if "<link" in text and "http://" in text:
            fixed = text.replace("http://", "https://")
            return [{
                "type": "CSS over HTTP",
                "message": "Upgraded to HTTPS.",
                "severity": "medium",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 18. Script over HTTP
def detect_script_http(node, source):
    if node.type == "script_element":
        text = get_text(node, source)
        if "http://" in text:
            fixed = text.replace("http://", "https://")
            return [{
                "type": "Script over HTTP",
                "message": "Upgraded to HTTPS.",
                "severity": "high",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 19. Media without controls
def detect_media_no_controls(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if re.search(r'<(video|audio)\b', text) and "controls" not in text:
            fixed = text.replace(">", " controls>", 1)
            return [{
                "type": "Media without controls",
                "message": "Added controls attribute.",
                "severity": "low",
                **_meta(node, True, {"type": "replace", "content": fixed}, "medium")
            }]
    return []

# 20. Input without type
def detect_input_no_type(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<input") and "type=" not in text:
            fixed = text.replace("<input", '<input type="text"', 1)
            return [{
                "type": "Input without type",
                "message": "Added default type.",
                "severity": "low",
                **_meta(node, True, {"type": "replace", "start": node.start_byte, "end": node.end_byte, "content": fixed})
            }]
    return []

# 21. Inline event handlers (manual)
def detect_inline_event_handlers(node, source):
    if node.type == "attribute":
        if re.match(r'on\w+=', get_text(node, source)):
            return [{
                "type": "Inline event handler",
                "message": "Use addEventListener instead.",
                "severity": "medium",
                **_meta(node)
            }]
    return []

# 22. Missing CSRF (manual)
def detect_missing_csrf_token(node, source):
    if node.type == "element":
        text = get_text(node, source)
        if text.startswith("<form") and not re.search(r'csrf|token', text, re.I):
            return [{
                "type": "Missing CSRF token",
                "message": "Add CSRF protection.",
                "severity": "high",
                **_meta(node)
            }]
    return []


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