import ast
from ir import SymbolicStore
from config import Config
import ast


def build_store(tree: ast.Module, config: Config) -> SymbolicStore:
    store = SymbolicStore()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            
