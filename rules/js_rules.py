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

# 1. eval usage (manual)
def detect_eval_usage(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "message": "eval() is unsafe. Replace with safer alternative.",
                "severity": "high",
                **_meta(node)
            }]
    return []

# 2. var usage → auto replace
def detect_var_usage(node, source):
    if node.type == "variable_declaration":
        text = get_text(node, source)
        if re.search(r'\bvar\b', text):
            fixed_text = re.sub(r'\bvar\b', 'let', text, count=1)
            return [{
                "type": "Use of var",
                "message": "Replaced 'var' with 'let'.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "content": fixed_text
                })
            }]
    return []

# 3. console.log → safer replace
def detect_console_log(node, source):
    if node.type == "call_expression":
        text = get_text(node, source)
        if "console.log" in text:
            return [{
                "type": "console.log usage",
                "message": "Removed console.log statement.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "content": ""
                })
            }]
    return []

# 4. loose equality → safer regex
def detect_loose_equality(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)
        if re.search(r'(?<![=!])==(?!=)', text):
            fixed_text = re.sub(r'(?<![=!])==(?!=)', '===', text)
            return [{
                "type": "Loose equality (==)",
                "message": "Replaced '==' with '==='.",
                "severity": "medium",
                **_meta(node, True, {
                    "type": "replace",
                    "content": fixed_text
                })
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
                    **_meta(condition)
                }]
    return []

# 6. empty block (optional fix)
def detect_empty_block(node, source):
    if node.type == "statement_block":
        if len(node.children) <= 2:
            return [{
                "type": "Empty block",
                "message": "Empty block detected.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "content": ""
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
def detect_deeply_nested_ifs(node, source, depth=0):
    if node.type == "if_statement":
        depth += 1
        if depth > 3:
            return [{
                "type": "Deeply nested if",
                "message": "Too much nesting.",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []

# 10. string concatenation (limited auto-fix)
def detect_string_plus(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)
        match = re.match(r'"([^"]*)"\s*\+\s*(\w+)', text)
        if match:
            fixed_text = f"`{match.group(1)} ${{{match.group(2)}}}`"
            return [{
                "type": "String concatenation",
                "message": "Use template literals.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "replace",
                    "content": fixed_text
                }, "medium")
            }]
    return []

# 11. global vars (manual)
def detect_global_vars(node, source):
    if node.type == "program":
        if re.search(r'^\s*(var|let|const)\s+', source, re.MULTILINE):
            return [{
                "type": "Global variable",
                "message": "Encapsulate globals.",
                "severity": "medium",
                **_meta(node, False, None, "medium")
            }]
    return []

# 12. missing use strict (auto insert)
def detect_missing_use_strict(node, source):
    if node.type == "program":
        if '"use strict"' not in source and "'use strict'" not in source:
            return [{
                "type": "Missing 'use strict'",
                "message": "Added 'use strict'.",
                "severity": "low",
                **_meta(node, True, {
                    "type": "insert",
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
def detect_param_reassignment(node, source):
    if node.type == "assignment_expression":
        text = get_text(node, source)
        if re.match(r'\w+\s*=', text):
            return [{
                "type": "Parameter reassignment",
                "message": "Avoid mutating parameters.",
                "severity": "low",
                **_meta(node, False, None, "medium")
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
]