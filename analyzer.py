import ast
import os
from rules import python_rules, js_rules, html_rules
from rules.web import flask_rules, django_rules, react_rules


LANG_RULES = {
    "python": python_rules.rules,
    "javascript": js_rules.rules,
    "html": html_rules.rules,
}

FRAMEWORK_RULES = {
    "flask": flask_rules.rules,
    "django": django_rules.rules,
    "react": react_rules.rules,
}


class SecureCodeAnalyzer:
    def __init__(self, language="python", framework=None):
        self.language = language
        self.framework = framework
        self.rules = LANG_RULES.get(language, [])
        if framework:
            self.rules += FRAMEWORK_RULES.get(framework, [])
        self.issues = []

    def analyze_file(self, filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            source = file.read()

        if self.language == "python":
            tree = ast.parse(source, filename=filepath)
            self._analyze_ast(tree)
        else:
            self._analyze_text(source)

        return self.issues

    def _analyze_ast(self, tree):
        for node in ast.walk(tree):
            for rule in self.rules:
                issue = rule(node) if callable(rule) else None
                if issue:
                    issue["line"] = getattr(node, "lineno", "Unknown")
                    self.issues.append(issue)

    def _analyze_text(self, source):
        for rule in self.rules:
            results = rule(source)
            if results:
                self.issues.extend(results)
