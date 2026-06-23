import pathlib
import ast
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parent


class _MainAttributeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.names = set()

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "main":
            if isinstance(node.ctx, (ast.Load, ast.Del, ast.Store)) and isinstance(node.attr, str):
                self.names.add(node.attr)
        self.generic_visit(node)


def _referenced_main_symbols():
    names = set()
    for py in REPO_ROOT.rglob("*.py"):
        if py.name in {"main.py", "test_main_surface_contract.py"}:
            continue
        text = py.read_text(encoding="utf-8")
        if re.search(r"^\s*import\s+main\b", text, re.M):
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            visitor = _MainAttributeVisitor()
            visitor.visit(tree)
            names |= visitor.names
    return names


def test_main_exposes_all_referenced_symbols():
    import main

    missing = sorted(name for name in _referenced_main_symbols() if not hasattr(main, name))
    assert not missing, f"main.X rupt: {missing}"
