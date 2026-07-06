#!/usr/bin/env python3
"""P-DUP: colapsează helperii duplicați din scan_analysis.py în re-export din provider_gate
(sursă unică de adevăr). Idempotent-ish, cu asserturi de siguranță. Rulează din rădăcina repo."""
import ast, sys

SA = "backend/services/scan_analysis.py"
PG = "backend/services/provider_gate.py"

sa_src = open(SA, encoding="utf-8").read()
pg_src = open(PG, encoding="utf-8").read()
sa_tree, pg_tree = ast.parse(sa_src), ast.parse(pg_src)

def top_funcs(tree):
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

sa_funcs, pg_funcs = top_funcs(sa_tree), top_funcs(pg_tree)
common = sorted(set(sa_funcs) & set(pg_funcs))
assert common, "ABORT: nicio funcție comună găsită."

# 1) Gardă anti-circular: provider_gate NU trebuie să importe din scan_analysis.
for node in ast.walk(pg_tree):
    if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("scan_analysis"):
        sys.exit("ABORT circular: provider_gate importă din scan_analysis: %r" % [a.name for a in node.names])

# 2) Nume deja importate din provider_gate (evită dubluri).
already = set()
for node in sa_tree.body:
    if isinstance(node, ast.ImportFrom) and node.module == "services.provider_gate":
        already |= {a.name for a in node.names}
to_import = [n for n in common if n not in already]

# 3) Șterge definițiile comune (cu decoratori), de jos în sus.
lines = sa_src.split("\n")
spans = []
for name in common:
    node = sa_funcs[name]
    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
    spans.append((start, node.end_lineno))
for start, end in sorted(spans, reverse=True):
    del lines[start - 1:end]

# 4) Inserează blocul de re-export după ultimul import de la nivel de modul.
last_import_end = 0
for node in sa_tree.body:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        last_import_end = max(last_import_end, node.end_lineno)
block = ["", "# P-DUP: sursă unică de adevăr în services.provider_gate (vezi audit).",
         "from services.provider_gate import ("] + [f"    {n}," for n in to_import] + [")"]
lines[last_import_end:last_import_end] = block
new_src = "\n".join(lines)

# 5) Verificări finale ÎNAINTE de scriere.
t2 = ast.parse(new_src)  # aruncă SyntaxError dacă e stricat
still = [n.name for n in t2.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in set(common)]
assert not still, f"ABORT: încă definite după codemod: {still}"
imported = set()
for node in ast.walk(t2):
    if isinstance(node, ast.ImportFrom) and node.module == "services.provider_gate":
        imported |= {a.name for a in node.names}
assert set(common) <= imported, f"ABORT: ne-reimportate: {sorted(set(common) - imported)}"

open(SA + ".bak", "w", encoding="utf-8").write(sa_src)
open(SA, "w", encoding="utf-8").write(new_src)
print(f"[ok] colapsate {len(common)} funcții; {len(sa_src.splitlines())} -> {len(new_src.splitlines())} linii; backup: {SA}.bak")
print("     (diff-uite vs main:", len([n for n in common]), "funcții; verifică cu git diff)")
