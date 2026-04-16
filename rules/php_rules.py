import re

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

def hint(msg):
    return {"type": "manual_hint", "hint": msg}

# 1. eval()
def detect_eval_usage_php(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval().",
                **_meta(node, True, hint("Replace eval() with a safer alternative."), "medium")
            }]
    return []

# 2. shell execution
def detect_shell_exec(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func:
            name = get_text(func, source)
            if name in ["exec", "shell_exec", "system", "passthru"]:
                return [{
                    "type": "Shell execution",
                    "severity": "High",
                    "suggestion": "Avoid executing shell commands.",
                    **_meta(node, True, hint("Review this shell execution for security risks."), "medium")
                }]
    return []

# 3. dynamic include
def detect_dynamic_include(node, source):
    if node.type in ["include_expression", "require_expression"]:
        arg = node.child_by_field_name("argument")
        if arg and arg.type in ["variable_name", "subscript_expression"]:
            return [{
                "type": "Dynamic include/require",
                "severity": "High",
                **_meta(node, True, hint("Avoid dynamic file inclusion; use static paths."), "medium")
            }]
    return []

# 4. mysql deprecated
def detect_mysql_deprecated(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source).startswith("mysql_"):
            return [{
                "type": "Deprecated mysql_*",
                "severity": "High",
                **_meta(node, True, hint("Replace mysql_* with mysqli or PDO."), "medium")
            }]
    return []

# 5. unescaped output
def detect_unescaped_output(node, source):
    if node.type == "echo_statement":
        text = get_text(node, source)

        if not re.search(r'htmlspecialchars|htmlentities', text):
            expr = text.replace("echo", "", 1).strip().rstrip(";")

            return [{
                "type": "Unescaped output",
                "severity": "High",
                **_meta(node, True, {
                    "type": "replace",
                    "start": node.start_byte,
                    "end": node.end_byte,
                    "content": f"echo htmlspecialchars({expr}, ENT_QUOTES, 'UTF-8');"
                })
            }]
    return []

# 6. unsanitized input
def detect_unsanitized_input(node, source):
    if node.type == "subscript_expression":
        text = get_text(node, source)
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', text):
            return [{
                "type": "Unsanitized input",
                "severity": "High",
                **_meta(node, True, hint("Sanitize this user input before usage."), "medium")
            }]
    return []

# 7. base64_decode (not auto-fixable)
def detect_base64_decode(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "base64_decode":
            return [{
                "type": "base64_decode usage",
                "severity": "Medium",
                **_meta(node, False)
            }]
    return []

# 8. assignment in condition
def detect_assignment_in_if(node, source):
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition:
            text = get_text(condition, source)
            if "=" in text and "==" not in text and "===" not in text:
                fixed = text.replace("=", "==", 1)
                return [{
                    "type": "Assignment in condition",
                    "severity": "High",
                    **_meta(condition, True, {
                        "type": "replace",
                        "start": condition.start_byte,
                        "end": condition.end_byte,
                        "content": fixed
                    })
                }]
    return []

# 9. eval + user input
def detect_eval_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "eval":
            if re.search(r'\$_', get_text(args, source)):
                return [{
                    "type": "eval() with user input",
                    "severity": "Critical",
                    **_meta(node, True, {
                        "type": "manual_hint",
                        "hint": "CRITICAL: Remove eval() on user input. This is a remote code execution risk."
                    }, "high")
                }]
    return []

# 10. md5
def detect_md5_password(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args and get_text(func, source) == "md5":
            arg_text = get_text(args, source)[1:-1]  # remove ()

            return [{
                "type": "Weak hashing (md5)",
                "severity": "High",
                **_meta(node, True, {
                    "type": "replace",
                    "start": node.start_byte,
                    "end": node.end_byte,
                    "content": f"password_hash({arg_text}, PASSWORD_DEFAULT)"
                })
            }]
    return []

# 11. unserialize user input
def detect_unserialize_user(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "unserialize":
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                return [{
                    "type": "Unserialize user input",
                    "severity": "Critical",
                    **_meta(node, True, hint("Avoid unserialize() on user input."), "high")
                }]
    return []

# 12. short tags (FIXED PROPERLY)
def detect_short_tags(node, source):
    if node.type != "program":
        return []

    issues = []
    for match in re.finditer(r'<\?(?!php)', source):
        issues.append({
            "type": "Short PHP tag",
            "severity": "Low",
            "fixable": True,
            "confidence": "high",
            "start_byte": match.start(),
            "end_byte": match.start() + 2,
            "fix": {
                "type": "replace",
                "start": match.start(),
                "end": match.start() + 2,
                "content": "<?php"
            }
        })
    return issues

# 13. file input
def detect_file_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) in ["fopen","fread","fwrite","file_put_contents"]:
            if re.search(r'\$_', get_text(args, source)):
                return [{
                    "type": "File operation with user input",
                    "severity": "High",
                    **_meta(node, True, hint("Validate file paths from user input."), "medium")
                }]
    return []

# 14. error_reporting(0)
def detect_error_reporting_off(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")

        if func and get_text(func, source) == "error_reporting":
            return [{
                "type": "Error reporting disabled",
                "severity": "Medium",
                **_meta(node, True, {
                    "type": "replace",
                    "start": node.start_byte,
                    "end": node.end_byte,
                    "content": "error_reporting(E_ALL)"
                })
            }]
    return []

# 15. globals
def detect_global_variables(node, source):
    if node.type == "global_declaration":
        original = get_text(node, source)
        return [{
            "type": "Global variable usage",
            "severity": "Medium",
            **_meta(node, True, {
                "type": "replace",
                "start": node.start_byte,
                "end": node.end_byte,
                "content": f"// TODO: Refactor globals\n// {original}"
            })
        }]
    return []

# 16. empty catch
def detect_empty_catch(node, source):
    if node.type == "catch_clause":
        body = node.child_by_field_name("body")
        if body and len(body.children) <= 2:
            return [{
                "type": "Empty catch block",
                "severity": "Low",
                **_meta(node, True, hint("Add proper error handling."), "medium")
            }]
    return []

# 17. isset validation
def detect_isset_without_validation(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "isset":
            text = get_text(args, source)
            if re.search(r'\$_', text):
                return [{
                    "type": "isset() without validation",
                    "severity": "Medium",
                    **_meta(node, True, hint("Validate input after isset()."), "medium")
                }]
    return []

# 18. eval in include
def detect_eval_in_include(node, source):
    if node.type in ["include_expression", "require_expression"]:
        if "eval(" in get_text(node, source):
            return [{
                "type": "eval in include",
                "severity": "Critical",
                **_meta(node, True, hint("Remove eval from included files."), "high")
            }]
    return []

# 19. double assignment
def detect_double_assignment(node, source):
    if node.type == "assignment_expression":
        if re.search(r'\$\w+\s*=\s*\$\w+\s*=', get_text(node, source)):
            return [{
                "type": "Double assignment",
                "severity": "Low",
                **_meta(node, True, hint("Check if double assignment is intentional."), "low")
            }]
    return []

# 20. HTML issues (manual only)
def detect_unclosed_html_tags(node, source):
    if node.type != "program":
        return []

    issues = []
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(r'\b(echo|print)\b.*<[^>]+[^/]>[^<]*$', line):
            issues.append({
                "type": "Potential unclosed HTML tag",
                "severity": "Low",
                "line": i,
                "confidence": "low",
                "fixable": True,
                "fix": hint("Check HTML output for unclosed tags.")
            })
    return issues

# RULE LIST
rules = [
    detect_eval_usage_php,
    detect_shell_exec,
    detect_dynamic_include,
    detect_mysql_deprecated,
    detect_unescaped_output,
    detect_unsanitized_input,
    detect_base64_decode,
    detect_assignment_in_if,
    detect_eval_user_input,
    detect_md5_password,
    detect_unserialize_user,
    detect_short_tags,
    detect_file_user_input,
    detect_error_reporting_off,
    detect_global_variables,
    detect_empty_catch,
    detect_isset_without_validation,
    detect_eval_in_include,
    detect_double_assignment,
    detect_unclosed_html_tags,
]