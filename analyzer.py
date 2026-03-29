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
        if framework:
            self.rules += FRAMEWORK_RULES.get(framework, [])
        self.issues = []

    def analyze_file(self, filepath):
        """Analyze a file and return a list of issues."""
        self.issues = []

        # File Reading Safety 
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
        except FileNotFoundError:
            return [{"error": f"File not found: {filepath}"}]
        except UnicodeDecodeError:
            return [{"error": f"Encoding error in file: {filepath}"}]
        except Exception as e:
            return [{"error": f"Unexpected error reading file {filepath}: {str(e)}"}]

        #  Parsing & Analysis Safety 
        try:
            if self.language == "python":
                tree = ast.parse(source, filename=filepath)
                self._analyze_ast(tree)
            else:
                self._analyze_tree_sitter(source)

        except SyntaxError as e:
            self.issues.append({
                "type": "SyntaxError",
                "message": str(e),
                "line": getattr(e, "lineno", None)
            })
        except Exception as e:
            self.issues.append({
                "type": "AnalyzerError",
                "message": str(e)
            })

        return self.issues

    # Python AST Analysis 
    def _analyze_ast(self, tree):
        context = AnalysisContext()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    context.imports.add(name.name)

            for rule in self.rules:
                try:
                    result = rule(node, context)
                    if result:
                        if isinstance(result, list):
                            self.issues.extend(result)
                        else:
                            self.issues.append(result)
                except Exception as e:
                    print(f"[WARN] Rule {rule.__name__} failed on node {type(node).__name__}: {e}")

    #  Tree-sitter Analysis 
    def _analyze_tree_sitter(self, source):
        """Analyze non-Python source with Tree-sitter."""
        parser = get_parser(self.language)
        tree = parser.parse(source.encode("utf-8"))
        root_node = tree.root_node
        self._walk_tree_sitter(root_node, source)

    def _walk_tree_sitter(self, node, source):
        """Recursively walk Tree-sitter nodes and apply rules."""
        for rule in self.rules:
            try:
                result = rule(node, source)
                if result:
                    if isinstance(result, list):
                        self.issues.extend(result)
                    else:
                        self.issues.append(result)
            except Exception as e:
                print( f"[WARN] Rule {rule.__name__} failed " f"on {type(node).__name__} " f"(line {getattr(node, 'lineno', 'N/A')}): {e}" )

        for child in node.children:
            self._walk_tree_sitter(child, source)

# Ctrl+C Handling
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
        print("\n[INFO] Scan interrupted by user (Ctrl+C). Exiting gracefully...")
