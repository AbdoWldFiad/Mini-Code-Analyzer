import ast

# 1. Use of eval()
def detect_eval_usage(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
        return {
            "type": "Use of eval()",
            "severity": "High",
            "suggestion": "Avoid eval(); use ast.literal_eval() or safer alternatives."
        }
    return None

# 2. Use of exec()
def detect_exec_usage(node, context):
    # Safely check for old Python 2 'ast.Exec' node (if defined)
    if hasattr(ast, "Exec") and isinstance(node, ast.Exec):
        return {
            "type": "Use of exec()",
            "severity": "High",
            "suggestion": "Avoid exec(); it's dangerous and hard to secure."
        }

    # Check for Python 3 style exec() calls
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec":
        return {
            "type": "Use of exec()",
            "severity": "High",
            "suggestion": "Avoid exec(); it's dangerous and hard to secure."
        }

    return None

# 3. Hardcoded password in variables
def detect_hardcoded_password(node, context):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and "pass" in target.id.lower():
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return {
                        "type": "Hardcoded password",
                        "severity": "High",
                        "suggestion": "Store secrets in environment variables or vaults."
                    }
    return None

# 4. Use of pickle.loads() AKA: insecure deserialization
def detect_pickle_loads(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                return {
                    "type": "Insecure deserialization (pickle.loads)",
                    "severity": "High",
                    "suggestion": "Use safer alternatives like json or restrict input source."
                }
    return None

# 5. Use of subprocess.Popen with shell=True
def detect_shell_true(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "Popen":
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return {
                        "type": "Command injection risk (shell=True)",
                        "severity": "High",
                        "suggestion": "Avoid shell=True; use list args instead."
                    }
    return None

# 6. SQL queries using string concatenation
def detect_sql_string_concat(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr):
                    return {
                        "type": "Possible SQL injection",
                        "severity": "High",
                        "suggestion": "Use parameterized queries instead of string formatting."
                    }
    return None

# 7. Use of yaml.load() without Loader=safe
def detect_yaml_unsafe_load(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                if not any(kw.arg == "Loader" for kw in node.keywords):
                    return {
                        "type": "Unsafe YAML loading",
                        "severity": "High",
                        "suggestion": "Use yaml.safe_load() or specify safe Loader."
                    }
    return None

# 8. Use of weak hash algorithms (e.g., MD5)
def detect_weak_hash_usage(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["md5", "sha1"]:
                return {
                    "type": f"Weak hash algorithm: {node.func.attr}",
                    "severity": "Medium",
                    "suggestion": "Use SHA-256 or SHA-3 instead of MD5/SHA-1."
                }
    return None

# 9. Insecure random (not using secrets)
def detect_insecure_random(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
                return {
                    "type": "Insecure random generator used",
                    "severity": "Medium",
                    "suggestion": "Use secrets module for secure tokens/passwords."
                }
    return None

#10. Use of input() in Python 2/3
def detect_raw_input_or_input(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ["input", "raw_input"]:
            return {
                "type": f"Use of {node.func.id}()",
                "severity": "Low",
                "suggestion": "Sanitize and validate input before use."
            }
    return None

# 11. Insecure use of os.system() | Like what i did in run.py lol
def detect_os_system_usage(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) or isinstance(node.func, ast.Name):
            if getattr(node.func, 'attr', '') == 'system' or getattr(node.func, 'id', '') == 'system':
                if getattr(node.func, 'value', None) and getattr(node.func.value, 'id', '') == 'os':
                    return {
                        "type": "Use of os.system()",
                        "severity": "High",
                        "suggestion": "Use subprocess with proper escaping instead of os.system()."
                    }
    return None

# 12. Use of getattr() with dynamic input
def detect_dynamic_getattr(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
        if len(node.args) >= 2:
            second_arg = node.args[1]
            if isinstance(second_arg, ast.Name):
                return {
                    "type": "Dynamic attribute access using getattr()",
                    "severity": "Medium",
                    "suggestion": "Avoid using untrusted input with getattr(); can lead to arbitrary code execution."
                }
    return None

# 13. Use of __import__() AKA: dynamic imports
def detect_dynamic_import(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return {
            "type": "Dynamic import using __import__()",
            "severity": "Medium",
            "suggestion": "Avoid dynamic imports unless absolutely necessary; restrict input and validate."
        }
    return None

# 14. Use of marshal module
def detect_marshal_import(node, context):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == "marshal":
                return {
                    "type": "Insecure module import: marshal",
                    "severity": "High",
                    "suggestion": "Avoid marshal for serialization of untrusted data; it is unsafe."
                }
    return None

# 15. Use of tempfile.mktemp() (unsafe temp file)
def detect_unsafe_tempfile(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "mktemp":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile":
                return {
                    "type": "Use of tempfile.mktemp()",
                    "severity": "High",
                    "suggestion": "Use tempfile.NamedTemporaryFile() instead; mktemp is vulnerable to race conditions."
                }
    return None

# 16. Use of open() without mode (defaulting to read/write)
def detect_open_without_mode(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
        if len(node.args) < 2:
            return {
                "type": "open() used without specifying mode",
                "severity": "Low",
                "suggestion": "Always specify file mode explicitly (e.g., 'r', 'w', 'rb')."
            }
    return None

# 17. Using assert in production code
def detect_assert_statements(node, context):
    if isinstance(node, ast.Assert):
        return {
            "type": "Use of assert statement",
            "severity": "Low",
            "suggestion": "Do not rely on assert for runtime checks; use proper validation and raise exceptions."
        }
    return None

# 18. Use of Flask with debug=True
def detect_flask_debug(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return {
                        "type": "Flask app running in debug mode",
                        "severity": "High",
                        "suggestion": "Disable debug mode in production to avoid remote code execution."
                    }
    return None

# 19. Use of requests without HTTPS
def detect_http_requests(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["get", "post", "put", "delete"]:
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                if node.args:
                    url_node = node.args[0]
                    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
                        if url_node.value.startswith("http://"):
                            return {
                                "type": "Unencrypted HTTP request",
                                "severity": "High",
                                "suggestion": "Use HTTPS instead of HTTP for sensitive data transmission."
                            }
    return None

# 20. Use of JWT decoding without signature verification
def detect_jwt_decode_no_verify(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "jwt":
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        return {
                            "type": "JWT decoded without verification",
                            "severity": "High",
                            "suggestion": "Always verify JWT signatures to avoid token forgery."
                        }
    return None

# the list of all defs
rules = [
    detect_eval_usage,
    detect_exec_usage,
    detect_hardcoded_password,
    detect_pickle_loads,
    detect_shell_true,
    detect_sql_string_concat,
    detect_yaml_unsafe_load,
    detect_weak_hash_usage,
    detect_insecure_random,
    detect_raw_input_or_input,
    detect_os_system_usage,
    detect_dynamic_getattr,
    detect_dynamic_import,
    detect_marshal_import,
    detect_unsafe_tempfile,
    detect_open_without_mode,
    detect_assert_statements,
    detect_flask_debug,
    detect_http_requests,
    detect_jwt_decode_no_verify
]