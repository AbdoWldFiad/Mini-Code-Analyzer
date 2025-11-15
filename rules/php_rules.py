import re

# 1. Detect use of eval()
def detect_eval_usage_php(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\beval\s*\(', line):
            issues.append({
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval() — it can execute arbitrary code.",
                "line": i,
            })
    return issues

# 2. Detect use of exec(), shell_exec(), system()
def detect_shell_exec(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\b(exec|shell_exec|system|passthru)\s*\(', line):
            issues.append({
                "type": "Use of shell execution",
                "severity": "High",
                "suggestion": "Avoid executing shell commands; validate inputs or use safer alternatives.",
                "line": i,
            })
    return issues

# 3. Detect use of include() / require() with variable paths
def detect_dynamic_include(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\b(include|require|include_once|require_once)\s*\(\s*\$', line):
            issues.append({
                "type": "Dynamic include/require",
                "severity": "High",
                "suggestion": "Avoid including files using variable paths — risk of file injection.",
                "line": i,
            })
    return issues

# 4. Detect short open tags "<?"
def detect_short_tags(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'<\?(?!php)', line):
            issues.append({
                "type": "Short PHP tag",
                "severity": "Low",
                "suggestion": "Use full '<?php' tags for compatibility.",
                "line": i,
            })
    return issues

# 5. Detect deprecated mysql_* functions
def detect_mysql_deprecated(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\bmysql_(query|connect|fetch)\b', line):
            issues.append({
                "type": "Deprecated mysql_* function",
                "severity": "High",
                "suggestion": "Use mysqli or PDO instead of mysql_* functions.",
                "line": i,
            })
    return issues

# 6. Detect unescaped output in echo/print
def detect_unescaped_output(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\b(echo|print)\s*\$[a-zA-Z_]\w*', line) and not re.search(r'htmlspecialchars|htmlentities', line):
            issues.append({
                "type": "Unescaped output",
                "severity": "High",
                "suggestion": "Escape output using htmlspecialchars() or htmlentities() to prevent XSS.",
                "line": i,
            })
    return issues

# 7. Detect usage of $_GET / $_POST without sanitization
def detect_unsanitized_input(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\$_(GET|POST|REQUEST)\s*\[', line) and not re.search(r'htmlspecialchars|filter_var|intval|mysqli_real_escape_string', line):
            issues.append({
                "type": "Unsanitized input",
                "severity": "High",
                "suggestion": "Sanitize user input before using it.",
                "line": i,
            })
    return issues

# 8. Detect use of base64_decode()
def detect_base64_decode(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\bbase64_decode\s*\(', line):
            issues.append({
                "type": "Use of base64_decode()",
                "severity": "Medium",
                "suggestion": "Check why base64 decoding is used; could hide malicious code.",
                "line": i,
            })
    return issues

# 9. Detect assignment inside if conditions
def detect_assignment_in_if(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'if\s*\(.*=.+\)', line) and not re.search(r'==|===', line):
            issues.append({
                "type": "Assignment inside conditional",
                "severity": "High",
                "suggestion": "Use '==' or '===' for comparison instead of '='.",
                "line": i,
            })
    return issues

# 10. Detect use of eval-like functions with user input
def detect_eval_user_input(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', line):
            issues.append({
                "type": "eval() with user input",
                "severity": "Critical",
                "suggestion": "Never pass user input directly to eval().",
                "line": i,
            })
    return issues

# 11. Detect fopen/fread/fwrite with user input
def detect_file_user_input(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\b(fopen|fread|fwrite|file_put_contents)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', line):
            issues.append({
                "type": "File operation with user input",
                "severity": "High",
                "suggestion": "Validate file paths before using them.",
                "line": i,
            })
    return issues

# 12. Detect use of md5() for passwords
def detect_md5_password(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\bmd5\s*\(', line) and re.search(r'password', line, re.IGNORECASE):
            issues.append({
                "type": "Weak password hashing",
                "severity": "High",
                "suggestion": "Use password_hash() instead of md5() for passwords.",
                "line": i,
            })
    return issues

# 13. Detect use of unserialize() on user input
def detect_unserialize_user(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', line):
            issues.append({
                "type": "Unserialize user input",
                "severity": "Critical",
                "suggestion": "Never unserialize untrusted user input — use json_decode() instead.",
                "line": i,
            })
    return issues

# 14. Detect error_reporting(0)
def detect_error_reporting_off(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'error_reporting\s*\(\s*0\s*\)', line):
            issues.append({
                "type": "Suppressing errors",
                "severity": "Medium",
                "suggestion": "Avoid disabling error reporting in production.",
                "line": i,
            })
    return issues

# 15. Detect use of global variables
def detect_global_variables(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\bglobal\b', line):
            issues.append({
                "type": "Use of global variable",
                "severity": "Medium",
                "suggestion": "Avoid using global variables; prefer dependency injection.",
                "line": i,
            })
    return issues

# 16. Detect empty catch blocks
def detect_empty_catch(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'catch\s*\([^\)]*\)\s*\{\s*\}', line):
            issues.append({
                "type": "Empty catch block",
                "severity": "Low",
                "suggestion": "Handle exceptions properly; avoid empty catch.",
                "line": i,
            })
    return issues

# 17. Detect isset() without validation
def detect_isset_without_validation(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'isset\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', line) and not re.search(r'filter_var|intval|htmlspecialchars', line):
            issues.append({
                "type": "isset() without validation",
                "severity": "Medium",
                "suggestion": "Validate inputs after isset() check.",
                "line": i,
            })
    return issues

# 18. Detect eval() in included files
def detect_eval_in_include(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'(include|require|include_once|require_once).*eval\s*\(', line):
            issues.append({
                "type": "eval() in included file",
                "severity": "Critical",
                "suggestion": "Avoid eval() in included/required files.",
                "line": i,
            })
    return issues

# 19. Detect double assignment
def detect_double_assignment(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\$[a-zA-Z_]\w*\s*=\s*\$[a-zA-Z_]\w*\s*=', line):
            issues.append({
                "type": "Double assignment",
                "severity": "Low",
                "suggestion": "Check for accidental double assignment.",
                "line": i,
            })
    return issues

# 20. Detect unclosed HTML tags in PHP output
def detect_unclosed_html_tags(source):
    issues = []
    # simple detection for echo/print statements
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r'\b(echo|print)\b.*<[^>]+[^/]>[^<]*$', line):
            issues.append({
                "type": "Potential unclosed HTML tag",
                "severity": "Low",
                "suggestion": "Check outputted HTML for unclosed tags.",
                "line": i,
            })
    return issues

# List of all PHP rules
rules = [
    detect_eval_usage_php,
    detect_shell_exec,
    detect_dynamic_include,
    detect_short_tags,
    detect_mysql_deprecated,
    detect_unescaped_output,
    detect_unsanitized_input,
    detect_base64_decode,
    detect_assignment_in_if,
    detect_eval_user_input,
    detect_file_user_input,
    detect_md5_password,
    detect_unserialize_user,
    detect_error_reporting_off,
    detect_global_variables,
    detect_empty_catch,
    detect_isset_without_validation,
    detect_eval_in_include,
    detect_double_assignment,
    detect_unclosed_html_tags,
]
