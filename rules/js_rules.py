import re

# Helpers
def get_text(node, source):
    return source[node.start_byte:node.end_byte]

def get_line(node):
    return node.start_point[0] + 1

def _meta(node, fixable, fix, confidence="High"):
    return {
        "fixable": fixable,
        "fix": fix,
        "confidence": confidence,
        "line": get_line(node)
    }


# 1. eval usage
def detect_eval_usage(node, source):
    if node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "severity": "High",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "// TODO: Replace eval() with safer alternative"
                })
            }]
    return []


# 2. var usage
def detect_var_usage(node, source):
    if node.type == "variable_declaration":
        if "var " in get_text(node, source):
            return [{
                "type": "Use of var",
                "severity": "Low",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "// Replace var with let or const"
                }, "Low")
            }]
    return []


# 3. console.log
def detect_console_log(node, source):
    if node.type == "call_expression":
        text = get_text(node, source)
        if "console.log" in text:
            return [{
                "type": "console.log usage",
                "severity": "Low",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "delete_line",
                    "value": ""
                }, "Low")
            }]
    return []


# 4. loose equality
def detect_loose_equality(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)
        if "==" in text and "===" not in text:
            return [{
                "type": "Loose equality (==)",
                "severity": "Medium",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "// Replace == with ==="
                }, "Medium")
            }]
    return []


# 5. assignment in condition
def detect_assignment_in_condition(node, source):
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition:
            text = get_text(condition, source)
            if "=" in text and "==" not in text:
                return [{
                    "type": "Assignment in condition",
                    "severity": "High",
                    **_meta(node, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "// TODO: Replace assignment with comparison"
                    })
                }]
    return []


# 6. empty block
def detect_empty_block(node, source):
    if node.type == "statement_block":
        if len(node.children) <= 2:
            return [{
                "type": "Empty block",
                "severity": "Low",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "insert_line",
                    "value": "// TODO: Implement or remove empty block"
                }, "Low")
            }]
    return []


# 7. missing semicolon (fallback)
def detect_missing_semicolon(node, source):
    if node.type != "program":
        return []

    issues = []
    for i, line in enumerate(source.splitlines(), 1):
        if line.strip() and not line.strip().endswith((";", "{", "}", ",")):
            if not line.strip().startswith(("if", "for", "while", "function")):
                issues.append({
                    "type": "Missing semicolon",
                    "severity": "Low",
                    "line": i,
                    "fixable": True,
                    "fix": {
                        "mode": "safe",
                        "type": "replace_line",
                        "value": line + ";"
                    },
                    "confidence": "High"
                })
    return issues


# 8. unused imports (basic)
def detect_unused_imports(node, source):
    if node.type == "import_statement":
        return [{
            "type": "Import detected (check usage)",
            "severity": "Low",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "// TODO: Remove if unused"
            }, "Low")
        }]
    return []


# 9. long functions
def detect_long_functions(node, source):
    if node.type == "function_declaration":
        body = node.child_by_field_name("body")
        if body:
            lines = body.end_point[0] - body.start_point[0]
            if lines > 50:
                return [{
                    "type": "Long function",
                    "severity": "Medium",
                    **_meta(node, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "// TODO: Split into smaller functions"
                    }, "Medium")
                }]
    return []


# 10. deeply nested ifs
def detect_deeply_nested_ifs(node, source, depth=0):
    if node.type == "if_statement":
        depth += 1
        if depth > 3:
            return [{
                "type": "Deeply nested if",
                "severity": "Medium",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "// TODO: Refactor nested conditions"
                }, "Medium")
            }]
    return []


# 11. shadowed variables (basic)
def detect_shadowed_variables(node, source):
    if node.type == "variable_declarator":
        return [{
            "type": "Variable declaration (check shadowing)",
            "severity": "Low",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "// TODO: Check for shadowed variables"
            }, "Low")
        }]
    return []


# 12. unused variables (basic)
def detect_unused_variables(node, source):
    if node.type == "variable_declarator":
        return [{
            "type": "Variable declared (check usage)",
            "severity": "Low",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "// TODO: Remove if unused"
            }, "Low")
        }]
    return []


# 13. string concatenation with +
def detect_string_plus(node, source):
    if node.type == "binary_expression":
        text = get_text(node, source)
        if "+" in text and '"' in text:
            return [{
                "type": "String concatenation with +",
                "severity": "Low",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "// Replace with template literals"
                }, "Low")
            }]
    return []


# 14. global vars
def detect_global_vars(node, source):
    if node.type == "program":
        if re.search(r'^\s*(var|let|const)\s+', source, re.MULTILINE):
            return [{
                "type": "Global variable",
                "severity": "Medium",
                "line": 1,
                "fixable": False,
                "fix": {
                    "mode": "manual",
                    "type": "todo",
                    "value": "// TODO: Encapsulate globals"
                },
                "confidence": "Medium"
            }]
    return []


# 15. missing 'use strict'
def detect_missing_use_strict(node, source):
    if node.type != "program":
        return []

    if '"use strict"' not in source and "'use strict'" not in source:
        return [{
            "type": "Missing 'use strict'",
            "severity": "Low",
            "suggestion": "Add 'use strict' at the top of the file.",
            "line": 1,
            "fixable": True,
            "fix": {
                "mode": "safe",
                "type": "insert_line",
                "value": "'use strict';"
            },
            "confidence": "High"
        }]
    return []


# 16. duplicate case (basic)
def detect_duplicate_cases(node, source):
    if node.type == "switch_statement":
        text = get_text(node, source)
        cases = re.findall(r'case\s+(.+?):', text)
        if len(cases) != len(set(cases)):
            return [{
                "type": "Duplicate case in switch",
                "severity": "Medium",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "// TODO: Remove duplicate case"
                }, "Medium")
            }]
    return []


# 17. param reassignment
def detect_param_reassignment(node, source):
    if node.type == "assignment_expression":
        text = get_text(node, source)
        if re.match(r'\w+\s*=', text):
            return [{
                "type": "Parameter reassignment (possible)",
                "severity": "Low",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "// TODO: Avoid mutating parameters"
                }, "Low")
            }]
    return []


# 18. unreachable code
def detect_unreachable_code(node, source):
    if node.type == "return_statement":
        return [{
            "type": "Return statement (check unreachable code after)",
            "severity": "Low",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "// TODO: Remove unreachable code after return"
            }, "Low")
        }]
    return []


# 19. nested functions
def detect_nested_functions(node, source):
    if node.type == "function_declaration":
        for child in node.children:
            if child.type == "function_declaration":
                return [{
                    "type": "Nested function",
                    "severity": "Low",
                    **_meta(child, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "// TODO: Flatten nested functions"
                    }, "Low")
                }]
    return []


# 20. too many params
def detect_too_many_params(node, source):
    if node.type == "function_declaration":
        params = node.child_by_field_name("parameters")
        if params:
            count = len(params.children)
            if count > 5:
                return [{
                    "type": "Too many parameters",
                    "severity": "Medium",
                    **_meta(node, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "// TODO: Refactor function to reduce parameters"
                    }, "Medium")
                }]
    return []


rules = [
    detect_eval_usage,
    detect_var_usage,
    detect_console_log,
    detect_loose_equality,
    detect_assignment_in_condition,
    detect_empty_block,
    detect_missing_semicolon,
    detect_unused_imports,
    detect_long_functions,
    detect_deeply_nested_ifs,
    detect_shadowed_variables,
    detect_unused_variables,
    detect_string_plus,
    detect_global_vars,
    detect_missing_use_strict,
    detect_duplicate_cases,
    detect_param_reassignment,
    detect_unreachable_code,
    detect_nested_functions,
    detect_too_many_params,
]