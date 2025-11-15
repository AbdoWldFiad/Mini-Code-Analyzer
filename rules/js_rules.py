import re

def detect_eval_usage(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if "eval(" in line:
            issues.append({
                "type": "Use of eval()",
                "severity": "High",
                "suggestion": "Avoid using eval() — it can lead to code injection.",
                "line": i,
            })
    return issues

def detect_var_usage(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r"\bvar\b", line):
            issues.append({
                "type": "Use of var",
                "severity": "Medium",
                "suggestion": "Use let or const instead of var.",
                "line": i,
            })
    return issues

def detect_console_log(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if "console.log" in line:
            issues.append({
                "type": "console.log usage",
                "severity": "Low",
                "suggestion": "Remove console.log in production code.",
                "line": i,
            })
    return issues

def detect_loose_equality(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if "==" in line and "===" not in line:
            issues.append({
                "type": "Loose equality (==)",
                "severity": "Medium",
                "suggestion": "Use strict equality (===).",
                "line": i,
            })
    return issues

def detect_assignment_in_condition(source):
    issues = []
    pattern = re.compile(r"if\s*\([^=]*=[^=].*\)")
    for i, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            issues.append({
                "type": "Assignment inside conditional",
                "severity": "High",
                "suggestion": "Use == or === instead of = inside conditions.",
                "line": i,
            })
    return issues

def detect_empty_block(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r"\{\s*\}", line):
            issues.append({
                "type": "Empty code block",
                "severity": "Low",
                "suggestion": "Remove or fill the empty block.",
                "line": i,
            })
    return issues

def detect_missing_semicolon(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.endswith((";", "{", "}", ",")) and "(" not in stripped:
            issues.append({
                "type": "Missing semicolon",
                "severity": "Low",
                "suggestion": "Add semicolon at end of statement.",
                "line": i,
            })
    return issues

def detect_unused_imports(source):
    issues = []
    imports = {}
    lines = source.splitlines()

    for i, line in enumerate(lines, start=1):
        m = re.match(r"import\s+(\w+)", line)
        if m:
            imports[m.group(1)] = i

    for name, line_number in imports.items():
        if not re.search(rf"\b{name}\b", source.splitlines()[line_number:]):
            issues.append({
                "type": "Unused import",
                "severity": "Low",
                "suggestion": f"Remove unused import '{name}'.",
                "line": line_number,
            })
    return issues

def detect_long_functions(source):
    issues = []
    lines = source.splitlines()

    function_start = None
    for i, line in enumerate(lines, start=1):
        if re.match(r"function\s+\w+", line):
            function_start = i
        if function_start and "}" in line:
            length = i - function_start
            if length > 50:
                issues.append({
                    "type": "Function too long",
                    "severity": "Medium",
                    "suggestion": "Refactor function into smaller units.",
                    "line": function_start,
                })
            function_start = None
    return issues

def detect_deeply_nested_ifs(source):
    issues = []
    depth = 0

    for i, line in enumerate(source.splitlines(), start=1):
        opens = line.count("if")
        closes = line.count("}")
        depth += opens
        if depth > 3:
            issues.append({
                "type": "Deep nesting",
                "severity": "Medium",
                "suggestion": "Reduce nesting levels for readability.",
                "line": i,
            })
        depth -= closes
    return issues

def detect_shadowed_variables(source):
    issues = []
    declared = set()

    for i, line in enumerate(source.splitlines(), start=1):
        m = re.search(r"\b(let|const)\s+(\w+)", line)
        if m:
            name = m.group(2)
            if name in declared:
                issues.append({
                    "type": "Variable shadowing",
                    "severity": "Medium",
                    "suggestion": f"Rename variable '{name}'.",
                    "line": i,
                })
            declared.add(name)
    return issues

def detect_unused_variables(source):
    issues = []
    declared = {}
    used = set()

    for i, line in enumerate(source.splitlines(), start=1):
        decl = re.search(r"\b(let|const)\s+(\w+)", line)
        if decl:
            declared[decl.group(2)] = i

        for name in re.findall(r"\b\w+\b", line):
            used.add(name)

    for name, line_number in declared.items():
        if name not in used - {name}:
            issues.append({
                "type": "Unused variable",
                "severity": "Low",
                "suggestion": f"Remove unused variable '{name}'.",
                "line": line_number,
            })
    return issues

def detect_string_plus(source):
    issues = []
    pattern = re.compile(r'".*"\s*\+|\'[^\']*\'\s*\+')
    for i, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            issues.append({
                "type": "String concatenation with +",
                "severity": "Low",
                "suggestion": "Use template literals instead.",
                "line": i,
            })
    return issues

def detect_global_vars(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        if re.match(r"\w+\s*=", line) and "let " not in line and "const " not in line:
            issues.append({
                "type": "Global variable",
                "severity": "Medium",
                "suggestion": "Declare with let or const.",
                "line": i,
            })
    return issues

def detect_missing_use_strict(source):
    issues = []
    first_line = source.splitlines()[0].strip() if source.splitlines() else ""
    if '"use strict"' not in first_line and "'use strict'" not in first_line:
        issues.append({
            "type": "Missing 'use strict'",
            "severity": "Low",
            "suggestion": "Add 'use strict' at the top of the file.",
            "line": 1,
        })
    return issues

def detect_duplicate_cases(source):
    issues = []
    seen = set()

    for i, line in enumerate(source.splitlines(), start=1):
        m = re.search(r"case\s+(['\"]?\w+['\"]?)", line)
        if m:
            label = m.group(1)
            if label in seen:
                issues.append({
                    "type": "Duplicate case label",
                    "severity": "Medium",
                    "suggestion": f"Remove duplicate case '{label}'.",
                    "line": i,
                })
            seen.add(label)
    return issues

def detect_param_reassignment(source):
    issues = []
    params = set()

    # get function parameters
    m = re.search(r"function\s+\w*\s*\((.*?)\)", source)
    if m:
        params = {p.strip() for p in m.group(1).split(",") if p.strip()}

    for i, line in enumerate(source.splitlines(), start=1):
        for p in params:
            if re.search(rf"{p}\s*=", line):
                issues.append({
                    "type": "Parameter reassignment",
                    "severity": "Medium",
                    "suggestion": f"Do not reassign parameter '{p}'.",
                    "line": i,
                })
    return issues

def detect_unreachable_code(source):
    issues = []
    lines = source.splitlines()

    block_stack = []     # track where returns happen per block
    unreachable = False  # whether current block is dead

    # regexes
    re_return = re.compile(r"\breturn\b")
    re_throw = re.compile(r"\bthrow\b")
    re_break = re.compile(r"\bbreak\b")
    re_continue = re.compile(r"\bcontinue\b")
    re_infinite_loop = re.compile(r"\bwhile\s*\(true\)|for\s*\(\s*;;\s*\)")

    def strip_strings_and_comments(line):
        # remove strings
        line = re.sub(r'"[^"]*"', "", line)
        line = re.sub(r"'[^']*'", "", line)
        line = re.sub(r"`[^`]*`", "", line)
        # remove inline comments
        line = re.sub(r"//.*", "", line)
        return line

    for i, raw_line in enumerate(lines, start=1):
        line = strip_strings_and_comments(raw_line).strip()

        # Track opening or closing braces to manage block state
        if "{" in line:
            block_stack.append(unreachable)
        if "}" in line:
            if block_stack:
                unreachable = block_stack.pop()

        # If we are currently in an unreachable state
        if unreachable and line:
            issues.append({
                "type": "Unreachable code",
                "severity": "High",
                "suggestion": "This code can never run. Remove or restructure it.",
                "line": i,
            })

        # Detect statements that end the current block's reachability
        if re_return.search(line) or re_throw.search(line):
            unreachable = True

        # break/continue unreachable only inside loops
        if re_break.search(line) or re_continue.search(line):
            unreachable = True

        # Start unreachable region after infinite loop
        if re_infinite_loop.search(line):
            unreachable = True

    return issues

def detect_nested_functions(source):
    issues = []
    fn_depth = 0

    for i, line in enumerate(source.splitlines(), start=1):
        if re.search(r"\bfunction\b", line):
            fn_depth += 1
            if fn_depth > 2:
                issues.append({
                    "type": "Excessive nested functions",
                    "severity": "Low",
                    "suggestion": "Flatten nested functions.",
                    "line": i,
                })
        if "}" in line:
            fn_depth = max(0, fn_depth - 1)
    return issues

def detect_too_many_params(source):
    issues = []
    for i, line in enumerate(source.splitlines(), start=1):
        m = re.search(r"function\s+\w*\s*\((.*?)\)", line)
        if m:
            params = [p.strip() for p in m.group(1).split(",") if p.strip()]
            if len(params) > 4:
                issues.append({
                    "type": "Too many parameters",
                    "severity": "Medium",
                    "suggestion": "Use fewer than 5 parameters.",
                    "line": i,
                })
    return issues



# the list of all defs
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

