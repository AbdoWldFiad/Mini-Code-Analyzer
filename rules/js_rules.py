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
        "line": get_line(node),
        "start_byte": node.start_byte,
        "end_byte": node.end_byte
    }

# 1. eval usage (manual → aggressive adds comment)
def detect_eval_usage(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "message": "eval() is unsafe.",
                "severity": "high",
                **_meta(node, True, {
                    "type": "manual_hint",
                    "hint": "Replace eval() with JSON.parse() or safer alternative."
                }, "medium")
            }]
    return []

# 2. var → let (precise replace)
def detect_var_usage(node, source):
    if node.type == "variable_declaration":
        text = get_text(node, source)

        if text.startswith("var"):
            return [{
                "type": "Use of var",
                "message": "Replace 'var' with 'let'.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "start": node.start_byte,
                    "end": node.start_byte + 3,
                    "content": "let"
                })
            }]
    return []

# 3. console.log → delete whole call
def detect_console_log(node, source):
    if node.type == "call_expression":
        text = get_text(node, source)

        if text.startswith("console.log"):
            return [{
                "type": "console.log usage",
                "message": "Remove console.log.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "delete",
                    "start": node.start_byte,
                    "end": node.end_byte
                })
            }]
    return []

# 4. loose equality → replace operator only
def detect_loose_equality(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)

        match = re.search(r'(?<![=!])==(?!=)', text)
        if match:
            start = node.start_byte + match.start()
            end = node.start_byte + match.end()

            return [{
                "type": "Loose equality (==)",
                "message": "Use '===' instead.",
                "severity": "medium",
                **_meta(node, True, {
                    "type": "replace",
                    "start": start,
                    "end": end,
                    "content": "==="
                }, "medium")
            }]
    return []

# 5. assignment in condition (manual)
def detect_assignment_in_condition(node, source):
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition:
            text = get_text(condition, source)
            if re.search(r'(?<![=!])=(?!=)', text):
                return [{
                    "type": "Assignment in condition",
                    "message": "Avoid assignment in conditions.",
                    "severity": "high",
                    **_meta(condition, True, {
                        "type": "manual_hint",
                        "hint": "Use '===' instead of '=' in conditions."
                    }, "medium")
                }]
    return []

# 6. empty block → delete
def detect_empty_block(node, source):
    if node.type == "statement_block":
        if len(node.children) <= 2:
            return [{
                "type": "Empty block",
                "message": "Remove empty block.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "delete",
                    "start": node.start_byte,
                    "end": node.end_byte
                }, "medium")
            }]
    return []

# 7. unused imports (manual)
def detect_unused_imports(node, source):
    if node.type == "import_statement":
        return [{
            "type": "Import detected",
            "message": "Check for unused import.",
            "severity": "low",
            **_meta(node, False, None, "medium")
        }]
    return []

# 8. long functions (manual)
def detect_long_functions(node, source):
    if node.type == "function_declaration":
        body = node.child_by_field_name("body")
        if body:
            lines = body.end_point[0] - body.start_point[0]
            if lines > 50:
                return [{
                    "type": "Long function",
                    "message": "Function exceeds 50 lines.",
                    "severity": "medium",
                    **_meta(node, False, None, "medium")
                }]
    return []

# 9. deeply nested ifs (manual)
def detect_deeply_nested_ifs(node, source, if_depth=0):
    if node.type == "if_statement" and if_depth > 3:
        return [{
            "type": "Deeply nested if",
            "message": f"Nesting depth is {if_depth}, consider refactoring.",
            "severity": "medium",
            **_meta(node, False, None, "medium")
        }]
    return []

# 10. string concatenation → template literal
def detect_string_plus(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)

        match = re.match(r'"([^"]*)"\s*\+\s*(\w+)', text)
        if match:
            fixed = f"`{match.group(1)} ${{{match.group(2)}}}`"

            return [{
                "type": "String concatenation",
                "message": "Use template literals.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "start": node.start_byte,
                    "end": node.end_byte,
                    "content": fixed
                }, "medium")
            }]
    return []

# 11. global vars (manual)
def detect_global_vars(node, source, scope=None, parent=None):
    # Only trigger at root level
    if node.type == "program" and scope:
        globals_found = scope["declared"]

        if globals_found:
            return [{
                "type": "Global variables",
                "message": f"Global variables detected: {', '.join(globals_found)}",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []

# 12. missing use strict → insert at top
def detect_missing_use_strict(node, source):
    if node.type == "program":
        if '"use strict"' not in source and "'use strict'" not in source:
            return [{
                "type": "Missing 'use strict'",
                "message": "Add 'use strict'.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "insert",
                    "start": 0,
                    "content": "'use strict';\n"
                })
            }]
    return []

# 13. duplicate case (manual)
def detect_duplicate_cases(node, source):
    if node.type == "switch_statement":
        text = get_text(node, source)
        cases = re.findall(r'case\s+(.+?):', text)
        if len(cases) != len(set(cases)):
            return [{
                "type": "Duplicate case",
                "message": "Duplicate case found.",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []

# 14. param reassignment (manual)
def detect_param_reassignment(node, source, params=None):
    if node.type == "assignment_expression" and params:
        text = source[node.start_byte:node.end_byte]
        # Extract left side of assignment
        left = text.split("=")[0].strip()
        if left in params:
            return [{
                "type": "Parameter reassignment",
                "message": f"Parameter '{left}' is reassigned.",
                "severity": "medium",
                **_meta(node, True, {
                    "type": "manual_hint",
                    "hint": f"Avoid mutating parameter '{left}'. Use a new variable instead."
                }, "medium")
            }]
    return []

# 15. unreachable code (manual)
def detect_unreachable_code(node, source):
    if node.type == "return_statement":
        return [{
            "type": "Return statement",
            "message": "Check for unreachable code after return.",
            "severity": "low",
            **_meta(node, False, None, "medium")
        }]
    return []

# 16. nested functions (manual)
def detect_nested_functions(node, source):
    if node.type == "function_declaration":
        for child in node.children:
            if child.type == "function_declaration":
                return [{
                    "type": "Nested function",
                    "message": "Avoid nested functions.",
                    "severity": "low",
                    **_meta(child, False, None, "medium")
                }]
    return []

# 17. too many params (manual)
def detect_too_many_params(node, source):
    if node.type == "function_declaration":
        params = node.child_by_field_name("parameters")
        if params and len(params.children) > 5:
            return [{
                "type": "Too many parameters",
                "message": "Reduce parameter count.",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []
# 18. detect unused variables
def detect_unused_variables(node, source, scope=None):
    if node.type in ["program", "function_declaration"] and scope:
        unused = scope["declared"] - scope["used"]

        if unused:
            return [{
                "type": "Unused variables",
                "message": f"Unused variables: {', '.join(unused)}",
                "severity": "low",
                **_meta(node, False, None, "medium")
            }]
    return []
rules = [
    detect_eval_usage,
    detect_var_usage,
    detect_console_log,
    detect_loose_equality,
    detect_assignment_in_condition,
    detect_empty_block,
    detect_unused_imports,
    detect_long_functions,
    detect_deeply_nested_ifs,
    detect_string_plus,
    detect_global_vars,
    detect_missing_use_strict,
    detect_duplicate_cases,
    detect_param_reassignment,
    detect_unreachable_code,
    detect_nested_functions,
    detect_too_many_params,
    detect_unused_variables,
]