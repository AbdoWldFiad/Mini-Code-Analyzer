import re

def get_text(node, source):
    return source[node.start_byte:node.end_byte]

def get_line(node):
    return node.start_point[0] + 1

def _meta(node, fixable, fix_content, confidence="High"):
    fix_type = fix_content.get("type", "replace") if isinstance(fix_content, dict) else "replace"
    mode = fix_content.get("mode", "safe") if isinstance(fix_content, dict) else "manual"
    content = fix_content.get("content", fix_content) if isinstance(fix_content, dict) else fix_content
    return {
        "fixable": fixable,
        "fix": {
            "type": fix_type,
            "mode": mode,
            "start": getattr(node, "start_byte", None),
            "end": getattr(node, "end_byte", None),
            "content": content
        },
        "confidence": confidence,
        "line": get_line(node)
    }

# 1. Detect eval()
def detect_eval_usage_php(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval().",
                **_meta(node, True, "# TODO: Replace eval safely\n# Use ast.literal_eval() or other safe alternatives.")
            }]
    return []

# 2. Detect shell execution
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
                    **_meta(node, True, "# TODO: Review shell execution for security.")
                }]
    return []

# 3. Dynamic include/require
def detect_dynamic_include(node, source):
    if node.type in ["include_expression", "require_expression"]:
        arg = node.child_by_field_name("argument")
        if arg and arg.type in ["variable_name", "subscript_expression"]:
            return [{
                "type": "Dynamic include/require",
                "severity": "High",
                "suggestion": "Avoid dynamic file inclusion.",
                **_meta(node, True, "# TODO: Replace dynamic include with static paths.")
            }]
    return []

# 4. Deprecated mysql_* functions
def detect_mysql_deprecated(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func:
            name = get_text(func, source)
            if name.startswith("mysql_"):
                return [{
                    "type": "Deprecated mysql_*",
                    "severity": "High",
                    "suggestion": "Use mysqli or PDO instead.",
                    **_meta(node, True, "# TODO: Replace mysql_* functions with mysqli or PDO.")
                }]
    return []

# 5. Unescaped echo/print
def detect_unescaped_output(node, source):
    if node.type == "echo_statement":
        text = get_text(node, source)
        if not re.search(r'htmlspecialchars|htmlentities', text):
            return [{
                "type": "Unescaped output",
                "severity": "High",
                "suggestion": "Escape output to prevent XSS.",
                **_meta(node, True, "# TODO: Add escaping function like htmlspecialchars() to output.")
            }]
    return []

# 6. Unsanitized input ($_GET, $_POST)
def detect_unsanitized_input(node, source):
    if node.type == "subscript_expression":
        text = get_text(node, source)
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', text):
            return [{
                "type": "Unsanitized input",
                "severity": "High",
                "suggestion": "Sanitize user input.",
                **_meta(node, True, "# TODO: Sanitize this user input before usage.")
            }]
    return []

# 7. base64_decode usage
def detect_base64_decode(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "base64_decode":
            return [{
                "type": "base64_decode usage",
                "severity": "Medium",
                **_meta(node, False, "# TODO: Ensure it's not hiding malicious code.")
            }]
    return []

# 8. Assignment inside condition
def detect_assignment_in_if(node, source):
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition:
            text = get_text(condition, source)
            if "=" in text and "==" not in text and "===" not in text:
                return [{
                    "type": "Assignment in condition",
                    "severity": "High",
                    "suggestion": "Use comparison operators instead of assignment in conditions.",
                    **_meta(node, True, "# TODO: Replace assignment with comparison operator.")
                }]
    return []

# 9. eval with user input
def detect_eval_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "eval":
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                return [{
                    "type": "eval() with user input",
                    "severity": "Critical",
                    "suggestion": "Never pass user input to eval().",
                    **_meta(node, True, "# TODO: Remove eval on user input immediately; very dangerous.")
                }]
    return []

# 10. md5 password hashing
def detect_md5_password(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "md5":
            return [{
                "type": "Weak hashing (md5)",
                "severity": "High",
                "suggestion": "Use password_hash() instead.",
                **_meta(node, True, "# TODO: Replace md5 with password_hash().")
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
                    "suggestion": "Avoid unserializing user input.",
                    **_meta(node, True, "# TODO: Validate or avoid unserialize on user input.")
                }]
    return []

# 12. Short PHP tags (run once)
def detect_short_tags(node, source):
    if node.type != "program":
        return []
    issues = []
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(r'<\?(?!php)', line):
            issues.append({
                "type": "Short PHP tag",
                "severity": "Low",
                "line": i,
                "confidence": "Medium",
                "fixable": True,
                "fix": {
                    "type": "replace",
                    "mode": "safe",
                    "start": None,
                    "end": None,
                    "content": "# TODO: Replace short PHP tag with <?php."
                }
            })
    return issues

# 13. File operations with user input
def detect_file_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) in ["fopen","fread","fwrite","file_put_contents"]:
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                return [{
                    "type": "File operation with user input",
                    "severity": "High",
                    "suggestion": "Validate file paths before use.",
                    **_meta(node, True, "# TODO: Validate file paths from user input.")
                }]
    return []

# 14. Error reporting off
def detect_error_reporting_off(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "error_reporting":
            if "0" in get_text(args, source):
                return [{
                    "type": "Error reporting disabled",
                    "severity": "Medium",
                    "suggestion": "Avoid disabling error reporting.",
                    **_meta(node, True, "# TODO: Avoid disabling error reporting.")
                }]
    return []

# 15. Global variables
def detect_global_variables(node, source):
    if node.type == "global_declaration":
        return [{
            "type": "Global variable usage",
            "severity": "Medium",
            "suggestion": "Avoid global variables.",
            **_meta(node, True, "# TODO: Refactor global variables.")
        }]
    return []

# 16. Empty catch blocks
def detect_empty_catch(node, source):
    if node.type == "catch_clause":
        body = node.child_by_field_name("body")
        if body and len(body.children) <= 2:  # empty catch block {}
            return [{
                "type": "Empty catch block",
                "severity": "Low",
                "suggestion": "Handle exceptions properly.",
                **_meta(node, True, "# TODO: Add error handling inside catch block.")
            }]
    return []

# 17. isset without validation
def detect_isset_without_validation(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func and args and get_text(func, source) == "isset":
            text = get_text(args, source)
            if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', text) and not re.search(r'filter_var|intval|htmlspecialchars', text):
                return [{
                    "type": "isset() without validation",
                    "severity": "Medium",
                    "suggestion": "Validate input after isset().",
                    **_meta(node, True, "# TODO: Validate input after isset() call.")
                }]
    return []

# 18. eval in include
def detect_eval_in_include(node, source):
    if node.type in ["include_expression", "require_expression"]:
        text = get_text(node, source)
        if "eval(" in text:
            return [{
                "type": "eval in include",
                "severity": "Critical",
                "suggestion": "Avoid eval in included files.",
                **_meta(node, True, "# TODO: Remove eval from included files.")
            }]
    return []

# 19. Double assignment
def detect_double_assignment(node, source):
    if node.type == "assignment_expression":
        text = get_text(node, source)
        if re.search(r'\$[a-zA-Z_]\w*\s*=\s*\$[a-zA-Z_]\w*\s*=', text):
            return [{
                "type": "Double assignment",
                "severity": "Low",
                "suggestion": "Check for accidental double assignment.",
                **_meta(node, True, "# TODO: Verify if double assignment is intentional.")
            }]
    return []

# 20. Unclosed HTML tags (program-level regex)
def detect_unclosed_html_tags(node, source):
    if node.type != "program":
        return []

    issues = []
    for i, line in enumerate(source.splitlines(), 1):
        if re.search(r'\b(echo|print)\b.*<[^>]+[^/]>[^<]*$', line):
            issues.append({
                "type": "Potential unclosed HTML tag",
                "severity": "Low",
                "suggestion": "Check HTML output.",
                "line": i,
                "confidence": "Low",
                "fixable": True,
                "fix": {
                    "type": "replace",
                    "mode": "safe",
                    "start": None,
                    "end": None,
                    "content": "# TODO: Verify HTML output for unclosed tags."
                }
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