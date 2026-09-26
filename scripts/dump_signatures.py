"""Dump top-level signatures from Python sources (development helper).

Usage: python scripts/dump_signatures.py path [path ...]

Prints every module-level function/class plus nested methods with their full
parameter lists so the API layer can be written against exact interfaces.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def signature(source: str, node: ast.AST) -> str:
    if isinstance(node, ast.ClassDef):
        return f"class {node.name}"
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    parts: list[str] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    for index, arg in enumerate(positional):
        parts.append(arg.arg)
        if node.args.defaults and index >= len(positional) - len(node.args.defaults):
            parts[-1] += "=..."
    if node.args.vararg:
        parts.append(f"*{node.args.vararg.arg}")
    elif node.args.kwonlyargs:
        parts.append("*")
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        parts.append(arg.arg + ("=..." if default is not None else ""))
    if node.args.kwarg:
        parts.append(f"**{node.args.kwarg.arg}")
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    text = f"{prefix} {node.name}({', '.join(parts)})"
    if node.returns is not None:
        text += f" -> {ast.unparse(node.returns)}"
    return text


def dump(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    print(f"=== {path} ===")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            print(f"{node.lineno}: {signature(source, node)}")
            if isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        print(f"    {sub.lineno}: {signature(source, sub)}")
                    elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                        annotation = ast.unparse(sub.annotation) if sub.annotation else "?"
                        print(f"    {sub.lineno}:   {sub.target.id}: {annotation}")
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if names and len(names) <= 3:
                print(f"{node.lineno}: {' = '.join(names)} = ...")
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            annotation = ast.unparse(node.annotation) if node.annotation else "?"
            print(f"{node.lineno}: {node.target.id}: {annotation}")


def main() -> int:
    for arg in sys.argv[1:]:
        dump(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
