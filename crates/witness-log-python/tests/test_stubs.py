"""The .pyi stub must name exactly the public surface the Rust core exports:
a method added to lib.rs without a stub, or a stub for a method that does
not exist, fails here."""

from __future__ import annotations

import ast
import pathlib

import witness_log._core as core

STUB = pathlib.Path(__file__).resolve().parents[1] / "python" / "witness_log" / "_core.pyi"


def _stub_surface() -> dict[str, set[str]]:
    tree = ast.parse(STUB.read_text())
    out: dict[str, set[str]] = {"": set()}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            out[node.name] = {
                n.name for n in node.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("__")
            }
        elif isinstance(node, ast.FunctionDef):
            out[""].add(node.name)
    return out


def _runtime_surface() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"": set()}
    for name in dir(core):
        if name.startswith("_"):
            continue
        obj = getattr(core, name)
        if isinstance(obj, type):
            if issubclass(obj, BaseException):
                out[name] = set()
            else:
                out[name] = {
                    m for m in dir(obj) if not m.startswith("_") and callable(getattr(obj, m, None))
                }
        elif callable(obj):
            out[""].add(name)
    return out


def test_stub_matches_runtime_surface():
    stub, rt = _stub_surface(), _runtime_surface()
    assert set(stub) == set(rt), f"classes/functions differ: stub-only={set(stub)-set(rt)} runtime-only={set(rt)-set(stub)}"
    for cls in rt:
        assert stub[cls] == rt[cls], f"{cls or 'module'}: stub-only={stub[cls]-rt[cls]} runtime-only={rt[cls]-stub[cls]}"
