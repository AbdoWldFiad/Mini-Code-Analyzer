import ast
from parsers.tree_sitter_loader import get_parser
from rules import python_rules, js_rules, html_rules, php_rules
from rules.web import flask_rules, django_rules, react_rules


LANG_RULES = {
    "python": python_rules.rules,
    "javascript": js_rules.rules,
    "html": html_rules.rules,
    "php": php_rules.rules,
}

FRAMEWORK_RULES = {
    "flask": flask_rules.rules,
    "django": django_rules.rules,
    "react": react_rules.rules,
}

class AnalysisContext:
    def __init__(self):
        self.assignments = {}
        self.imports = set()

class SecureCodeAnalyzer:
    def __init__(self, language="python", framework=None):
        self.language = language.lower()
        self.framework = framework
        self.rules = LANG_RULES.get(self.language, []).copy()

        if not self.rules:
            raise ValueError(f"No rules found for language: {self.language}")

        if framework:
            self.rules += FRAMEWORK_RULES.get(framework, [])

        self.issues = []
        self.rule_errors = []

    def analyze_file(self, filepath):
        self.issues = []
        self.rule_errors = []

        # File reading
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception as e:
            return [{
                "type": "FileError",
                "message": str(e),
                "file": filepath
            }]

        #  Parsing & Analysis Safety 
        try:
            if self.language == "python":
                tree = ast.parse(source, filename=filepath)
                self._analyze_ast(tree, filepath)
            else:
                self._analyze_tree_sitter(source, filepath)

        except SyntaxError as e:
            self.issues.append(self._normalize_issue({
                "type": "SyntaxError",
                "message": str(e),
                "line": getattr(e, "lineno", None),
                "file": filepath
            }))
        except Exception as e:
            self.issues.append(self._normalize_issue({
                "type": "AnalyzerError",
                "message": str(e),
                "file": filepath
            }))

        self._deduplicate_issues()
        return self.issues

    # Python AST Analysis

    def _analyze_ast(self, tree, filepath):
        context = AnalysisContext()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    context.imports.add(name.name)

            for rule in self.rules:
                try:
                    result = rule(node, context)
                    if result:
                        self._handle_result(result, filepath)

                except Exception as e:
                    self.rule_errors.append({
                        "rule": rule.__name__,
                        "error": str(e),
                        "node": type(node).__name__
                    })


    # Tree-sitter Analysis

    def _analyze_tree_sitter(self, source, filepath):
        parser = get_parser(self.language)
        tree = parser.parse(source.encode("utf-8"))
        root = tree.root_node

        context = {"source": source}

        self._walk_tree_sitter(root, context, filepath)

    def _walk_tree_sitter(self, node, context, filepath):
        for rule in self.rules:
            try:
                result = rule(node, context)

                if result:
                    self._handle_result(result, filepath, node)

            except Exception as e:
                self.rule_errors.append({
                    "rule": rule.__name__,
                    "error": str(e),
                    "node": node.type
                })

        for child in node.children:
            self._walk_tree_sitter(child, context, filepath)

    # Helpers

    def _handle_result(self, result, filepath, node=None):
        if isinstance(result, list):
            for r in result:
                self.issues.append(self._normalize_issue(r, filepath, node))
        else:
            self.issues.append(self._normalize_issue(result, filepath, node))

    def _normalize_issue(self, issue, filepath=None, node=None):
        # Extract line (AST or Tree-sitter)
        line = issue.get("line")

        if line is None and node is not None:
            if hasattr(node, "lineno"):  # AST
                line = node.lineno
            elif hasattr(node, "start_point"):  # Tree-sitter
                line = node.start_point[0] + 1

        # Normalize severity
        severity = issue.get("severity", "low")
        severity = str(severity).lower()
        if severity not in {"low", "medium", "high"}:
            severity = "low"

        # Normalize fix
        fix = issue.get("fix")
        if isinstance(fix, str):
            fix = {
                "type": "insert",
                "content": fix.strip()
            }

        return {
            "type": issue.get("type", "Unknown"),
            "message": issue.get("message", ""),
            "line": line,
            "severity": severity,
            "fix": fix,
            "fixable": bool(fix and fix.get("content")),
            "confidence": issue.get("confidence", "medium"),
            "file": issue.get("file", filepath)
        }

    def _deduplicate_issues(self):
        seen = set()
        unique = []

        for issue in self.issues:
            key = (
                issue.get("type"),
                issue.get("line"),
                issue.get("message")
            )

            if key not in seen:
                seen.add(key)
                unique.append(issue)

        self.issues = unique


# CLI Runner
def run_analysis(files, language="python", framework=None):
    analyzer = SecureCodeAnalyzer(language=language, framework=framework)

    try:
        for file in files:
            print(f"Analyzing {file}...")
            issues = analyzer.analyze_file(file)

            if issues:
                print(f"[!] Issues found in {file}:")
                for issue in issues:
                    print(issue)
            else:
                print(f"[OK] No issues found in {file}")

    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")