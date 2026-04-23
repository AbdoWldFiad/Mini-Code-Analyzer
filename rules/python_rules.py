import ast

def _meta(node, fixable, fix, confidence="High"):
    return {
        "fixable": fixable,
        "fix": fix,
        "confidence": confidence,
        "start": getattr(node, "lineno", None),
        "end": getattr(node, "end_lineno", getattr(node, "lineno", None))
    }

# 1. Use of eval()
def detect_eval_usage(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
        return {
            "type": "Use of eval()",
            "severity": "High",
            "suggestion": "Avoid eval(); use ast.literal_eval() or safer alternatives.",
            **_meta(node, True, {
                "mode": "safe",
                "type": "replace_line",
                "value": "# Replace eval() with ast.literal_eval() if safe"
            })
        }
    return None

# 2. Use of exec()
def detect_exec_usage(node, context):
    if hasattr(ast, "Exec") and isinstance(node, ast.Exec):
        return {
            "type": "Use of exec()",
            "severity": "High",
            "suggestion": "Avoid exec(); it's dangerous.",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "# TODO: Refactor to avoid exec()"
            })
        }
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec":
        return {
            "type": "Use of exec()",
            "severity": "High",
            "suggestion": "Avoid exec(); it's dangerous.",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "# TODO: Refactor to avoid exec()"
            })
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
                        "suggestion": "Store secrets in environment variables.",
                        **_meta(node, False, {
                            "mode": "manual",
                            "type": "todo",
                            "value": "# TODO: Move secret to environment variable"
                        })
                    }
    return None

# 4. Use of pickle.loads()
def detect_pickle_loads(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                return {
                    "type": "Insecure deserialization (pickle.loads)",
                    "severity": "High",
                    "suggestion": "Use safer alternatives like json.",
                    **_meta(node, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "# TODO: Replace pickle.loads with json.loads if possible"
                    })
                }
    return None

# 5. subprocess.Popen with shell=True
def detect_shell_true(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "Popen":
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return {
                        "type": "Command injection risk (shell=True)",
                        "severity": "High",
                        "suggestion": "Avoid shell=True; use list args instead.",
                        **_meta(node, True, {
                            "mode": "safe",
                            "type": "replace_line",
                            "value": "# Remove shell=True and pass args as list"
                        })
                    }
    return None

# 6. SQL string concatenation
def detect_sql_string_concat(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                    return {
                        "type": "Possible SQL injection",
                        "severity": "High",
                        "suggestion": "Use parameterized queries.",
                        **_meta(node, False, {
                            "mode": "manual",
                            "type": "todo",
                            "value": "# TODO: Convert to parameterized query"
                        })
                    }
    return None

# 7. yaml.load without safe loader
def detect_yaml_unsafe_load(node, context):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                if not any(kw.arg == "Loader" for kw in node.keywords):
                    return {
                        "type": "Unsafe YAML loading",
                        "severity": "High",
                        "suggestion": "Use yaml.safe_load() or specify Loader.",
                        **_meta(node, True, {
                            "mode": "safe",
                            "type": "replace_line",
                            "value": "# Replace yaml.load(...) with yaml.safe_load(...)"
                        })
                    }
    return None

# 8. Weak hash (MD5/SHA1)
def detect_weak_hash_usage(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ["md5", "sha1"]:
            return {
                "type": f"Weak hash algorithm: {node.func.attr}",
                "severity": "Medium",
                "suggestion": "Use SHA-256 or SHA-3 instead.",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "# Replace with hashlib.sha256()"
                }, "Medium")
            }
    return None

# 9. Insecure random
def detect_insecure_random(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
            return {
                "type": "Insecure random generator",
                "severity": "Medium",
                "suggestion": "Use secrets module for secure tokens.",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "# Replace random.* with secrets.*"
                }, "Medium")
            }
    return None

# 10. input()/raw_input()
def detect_raw_input_or_input(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ["input", "raw_input"]:
            return {
                "type": f"Use of {node.func.id}()",
                "severity": "Low",
                "suggestion": "Sanitize and validate input.",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "# TODO: Add input validation"
                }, "Low")
            }
    return None

# 11. os.system()
def detect_os_system_usage(node, context):
    if isinstance(node, ast.Call):
        func_name = getattr(node.func, 'id', getattr(node.func, 'attr', None))
        if func_name == "system":
            if getattr(node.func, 'value', None) and getattr(node.func.value, 'id', '') == 'os':
                return {
                    "type": "Use of os.system()",
                    "severity": "Low",
                    "suggestion": "Use subprocess.run with proper escaping.",
                    **_meta(node, False, {
                        "mode": "manual",
                        "type": "todo",
                        "value": "# TODO: Replace os.system with subprocess.run"
                    })
                }
    return None

# 12. Dynamic getattr()
def detect_dynamic_getattr(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Name):
            return {
                "type": "Dynamic attribute access using getattr()",
                "severity": "Medium",
                "suggestion": "Avoid using untrusted input with getattr().",
                **_meta(node, False, {
                    "mode": "manual",
                    "type": "todo",
                    "value": "# TODO: Validate attribute name"
                }, "Medium")
            }
    return None

# 13. Dynamic import (__import__())
def detect_dynamic_import(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return {
            "type": "Dynamic import using __import__()",
            "severity": "Medium",
            "suggestion": "Restrict and validate imports.",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "# TODO: Replace with static import"
            }, "Medium")
        }
    return None

# 14. marshal module import
def detect_marshal_import(node, context):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == "marshal":
                return {
                    "type": "Insecure module import: marshal",
                    "severity": "High",
                    "suggestion": "Avoid marshal for untrusted data.",
                    **_meta(node, True, {
                        "mode": "safe",
                        "type": "delete_line",
                        "value": ""
                    })
                }
    return None

# 15. tempfile.mktemp()
def detect_unsafe_tempfile(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "mktemp" and getattr(node.func.value, "id", "") == "tempfile":
            return {
                "type": "Use of tempfile.mktemp()",
                "severity": "High",
                "suggestion": "Use NamedTemporaryFile instead.",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "# Replace with tempfile.NamedTemporaryFile()"
                })
            }
    return None

# 16. open() without mode
def detect_open_without_mode(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
        if len(node.args) < 2:
            return {
                "type": "open() used without specifying mode",
                "severity": "Low",
                "suggestion": "Always specify file mode.",
                **_meta(node, True, {
                    "mode": "safe",
                    "type": "replace_line",
                    "value": "# Add explicit mode like 'r'"
                }, "Low")
            }
    return None

# 17. assert statement
def detect_assert_statements(node, context):
    if isinstance(node, ast.Assert):
        return {
            "type": "Use of assert statement",
            "severity": "Low",
            "suggestion": "Use proper validation.",
            **_meta(node, False, {
                "mode": "manual",
                "type": "todo",
                "value": "# TODO: Replace assert with explicit check"
            }, "Low")
        }
    return None

# 18. Flask debug=True
def detect_flask_debug(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return {
                    "type": "Flask app running in debug mode",
                    "severity": "High",
                    "suggestion": "Disable debug in production.",
                    **_meta(node, True, {
                        "mode": "safe",
                        "type": "replace_line",
                        "value": "# Set debug=False"
                    })
                }
    return None

# 19. requests without HTTPS
def detect_http_requests(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ["get", "post", "put", "delete"]:
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                if node.args:
                    url_node = node.args[0]
                    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
                        if url_node.value.startswith("http://"):
                            return {
                                "type": "Unencrypted HTTP request",
                                "severity": "High",
                                "suggestion": "Use HTTPS instead.",
                                **_meta(node, True, {
                                    "mode": "safe",
                                    "type": "replace_line",
                                    "value": "# Replace http:// with https://"
                                })
                            }
    return None

# 20. JWT decode without verify
def detect_jwt_decode_no_verify(node, context):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "decode" and isinstance(node.func.value, ast.Name) and node.func.value.id == "jwt":
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return {
                        "type": "JWT decoded without verification",
                        "severity": "High",
                        "suggestion": "Always verify JWT signatures.",
                        **_meta(node, True, {
                            "mode": "safe",
                            "type": "replace_line",
                            "value": "# Set verify=True"
                        })
                    }
    return None

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