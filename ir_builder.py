import ast

from config import Config
from ir import SymbolicStore


def build_store(tree: ast.Module, config: Config) -> SymbolicStore:
    store = SymbolicStore()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            pass  # TODO: populate store

    return store
