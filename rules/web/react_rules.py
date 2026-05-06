import re

def get_text(node, source):
    return source[node.start_byte:node.end_byte]

def get_line(node):
    return node.start_point[0] + 1


def _meta(node, fixable=False, fix=None, confidence="high"):
    return {
        "fixable": fixable or False,
        "fix": fix,
        "confidence": confidence,
        "line": get_line(node),
        "start_byte": getattr(node, "start_byte", None),
        "end_byte": getattr(node, "end_byte", None),
    }


def detect_dangerous_html(node, source):
    if node.type == "jsx_attribute":
        name = node.child_by_field_name("name")
        if name and get_text(name, source) == "dangerouslySetInnerHTML":
            return [{
                "type": "dangerouslySetInnerHTML usage",
                "message": "Potential XSS vulnerability.",
                "severity": "high",
                **_meta(node, False, None, "high")
            }]
    return []

def detect_direct_dom(node, source):
    text = get_text(node, source)
    if "document.getElementById" in text or "document.querySelector" in text:
        return [{
            "type": "Direct DOM manipulation",
            "message": "Avoid direct DOM access in React.",
            "severity": "medium",
            **_meta(node)
        }]
    return []

def detect_missing_key(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source).endswith(".map"):
            text = get_text(node, source)
            if "key=" not in text:
                return [{
                    "type": "Missing key in list",
                    "message": "Each child in a list should have a unique key.",
                    "severity": "medium",
                    **_meta(node)
                }]
    return []

def detect_state_mutation(node, source):
    text = get_text(node, source)
    if "state." in text and "=" in text:
        return [{
            "type": "State mutation",
            "message": "Do not mutate state directly.",
            "severity": "high",
            **_meta(node)
        }]
    return []

def detect_unused_setter(node, source):
    text = get_text(node, source)
    if "useState(" in text and "set" not in text:
        return [{
            "type": "Unused state setter",
            "message": "State setter is never used.",
            "severity": "low",
            **_meta(node)
        }]
    return []

def detect_useeffect_no_deps(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "useEffect":
            args = node.child_by_field_name("arguments")
            if args and "[]" not in get_text(args, source):
                return [{
                    "type": "useEffect dependencies",
                    "message": "Missing dependency array in useEffect.",
                    "severity": "medium",
                    **_meta(node)
                }]
    return []

def detect_inline_function_jsx(node, source):
    if node.type == "jsx_attribute":
        value = node.child_by_field_name("value")
        if value and "=>" in get_text(value, source):
            return [{
                "type": "Inline function in JSX",
                "message": "Avoid inline functions in JSX (performance).",
                "severity": "low",
                **_meta(node)
            }]
    return []

def detect_console_log(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and "console.log" in get_text(func, source):
            return [{
                "type": "Console log",
                "message": "Remove console.log in production.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "delete",
                    "start": node.start_byte,
                    "end": node.end_byte
                })
            }]
    return []

def detect_useless_div(node, source):
    text = get_text(node, source)
    if "<div>" in text and "</div>" in text:
        return [{
            "type": "Unnecessary div",
            "message": "Use React.Fragment instead.",
            "severity": "low",
            **_meta(node)
        }]
    return []

def detect_boolean_props(node, source):
    text = get_text(node, source)
    if "= {true}" in text or "={true}" in text:
        return [{
            "type": "Boolean prop style",
            "message": "Use shorthand for boolean props.",
            "severity": "low",
            **_meta(node)
        }]
    return []

def detect_img_alt(node, source):
    if node.type == "jsx_opening_element":
        tag = node.child_by_field_name("name")
        if tag and get_text(tag, source) == "img":
            text = get_text(node, source)
            if "alt=" not in text:
                return [{
                    "type": "Missing alt attribute",
                    "message": "Image tag missing alt attribute.",
                    "severity": "medium",
                    **_meta(node)
                }]
    return []

def detect_anchor_rel(node, source):
    if node.type == "jsx_opening_element":
        tag = node.child_by_field_name("name")
        if tag and get_text(tag, source) == "a":
            text = get_text(node, source)
            if 'target="_blank"' in text and "rel=" not in text:
                return [{
                    "type": "Missing rel attribute",
                    "message": "Use rel='noopener noreferrer'.",
                    "severity": "medium",
                    **_meta(node)
                }]
    return []

def detect_inline_styles(node, source):
    text = get_text(node, source)
    if "style={{" in text:
        return [{
            "type": "Inline styles",
            "message": "Avoid large inline styles.",
            "severity": "low",
            **_meta(node)
        }]
    return []

def detect_large_jsx(node, source):
    if node.type == "jsx_element":
        text = get_text(node, source)
        if len(text) > 500:
            return [{
                "type": "Large JSX component",
                "message": "Component too large, consider splitting.",
                "severity": "low",
                **_meta(node)
            }]
    return []

def detect_no_memo(node, source):
    text = get_text(node, source)
    if "function " in text and "React.memo" not in text:
        return [{
            "type": "Unmemoized component",
            "message": "Consider React.memo.",
            "severity": "low",
            **_meta(node)
        }]
    return []

def detect_heavy_useeffect(node, source):
    text = get_text(node, source)
    if "useEffect" in text and len(text) > 300:
        return [{
            "type": "Heavy useEffect",
            "message": "Split large effects.",
            "severity": "low",
            **_meta(node)
        }]
    return []

rules = [
    detect_dangerous_html,
    detect_direct_dom,
    detect_missing_key,
    detect_state_mutation,
    detect_unused_setter,
    detect_useeffect_no_deps,
    detect_inline_function_jsx,
    detect_console_log,
    detect_useless_div,
    detect_boolean_props,
    detect_img_alt,
    detect_anchor_rel,
    detect_inline_styles,
    detect_no_memo,
    detect_heavy_useeffect,
    detect_large_jsx,
]