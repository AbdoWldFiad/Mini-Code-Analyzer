import re

# Helper: extract node text
def get_text(node, source):
    return source[node.start_byte:node.end_byte]

# Helper: line number
def get_line(node):
    return node.start_point[0] + 1


# 1. Detect eval()
def detect_eval_usage_php(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        if func and get_text(func, source) == "eval":
            return [{
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval().",
                "line": get_line(node),
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
                    "line": get_line(node),
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
                "line": get_line(node),
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
                    "suggestion": "Use mysqli or PDO.",
                    "line": get_line(node),
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
                "line": get_line(node),
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
                "line": get_line(node),
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
                "suggestion": "Ensure it's not hiding malicious code.",
                "line": get_line(node),
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
                    "suggestion": "Use comparison operators.",
                    "line": get_line(node),
                }]
    return []


# 9. eval with user input
def detect_eval_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args:
            if get_text(func, source) == "eval":
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                    return [{
                        "type": "eval() with user input",
                        "severity": "Critical",
                        "suggestion": "Never pass user input to eval().",
                        "line": get_line(node),
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
                "suggestion": "Use password_hash().",
                "line": get_line(node),
            }]
    return []


# 11. unserialize user input
def detect_unserialize_user(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args:
            if get_text(func, source) == "unserialize":
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                    return [{
                        "type": "Unserialize user input",
                        "severity": "Critical",
                        "line": get_line(node),
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
            })
    return issues

def detect_file_user_input(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args:
            name = get_text(func, source)
            if name in ["fopen", "fread", "fwrite", "file_put_contents"]:
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', get_text(args, source)):
                    return [{
                        "type": "File operation with user input",
                        "severity": "High",
                        "suggestion": "Validate file paths before use.",
                        "line": get_line(node),
                    }]
    return []

def detect_error_reporting_off(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args:
            if get_text(func, source) == "error_reporting":
                if "0" in get_text(args, source):
                    return [{
                        "type": "Error reporting disabled",
                        "severity": "Medium",
                        "suggestion": "Avoid disabling error reporting.",
                        "line": get_line(node),
                    }]
    return []

def detect_global_variables(node, source):
    if node.type == "global_declaration":
        return [{
            "type": "Global variable usage",
            "severity": "Medium",
            "suggestion": "Avoid global variables.",
            "line": get_line(node),
        }]
    return []

def detect_empty_catch(node, source):
    if node.type == "catch_clause":
        body = node.child_by_field_name("body")

        if body and len(body.children) <= 2:  # { }
            return [{
                "type": "Empty catch block",
                "severity": "Low",
                "suggestion": "Handle exceptions properly.",
                "line": get_line(node),
            }]
    return []

def detect_isset_without_validation(node, source):
    if node.type == "function_call_expression":
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")

        if func and args:
            if get_text(func, source) == "isset":
                text = get_text(args, source)
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', text):
                    if not re.search(r'filter_var|intval|htmlspecialchars', text):
                        return [{
                            "type": "isset() without validation",
                            "severity": "Medium",
                            "suggestion": "Validate input after isset().",
                            "line": get_line(node),
                        }]
    return []

def detect_eval_in_include(node, source):
    if node.type in ["include_expression", "require_expression"]:
        text = get_text(node, source)

        if "eval(" in text:
            return [{
                "type": "eval in include",
                "severity": "Critical",
                "suggestion": "Avoid eval in included files.",
                "line": get_line(node),
            }]
    return []

def detect_double_assignment(node, source):
    if node.type == "assignment_expression":
        text = get_text(node, source)

        if re.search(r'\$[a-zA-Z_]\w*\s*=\s*\$[a-zA-Z_]\w*\s*=', text):
            return [{
                "type": "Double assignment",
                "severity": "Low",
                "suggestion": "Check for accidental double assignment.",
                "line": get_line(node),
            }]
    return []
#This one cannot be reliably done via AST, so we keep it as program-level regex
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