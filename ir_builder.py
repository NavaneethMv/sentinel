import ast

from config import Config
from ir import Constant, Derived, EnvValue, SymbolicStore, Tainted, Unknown


def build_store(tree: ast.Module, config: Config) -> SymbolicStore:
    store = SymbolicStore()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for targets in node.targets:
                if isinstance(targets, ast.Name):
                    value = infer_value(node.value, store, config)
                    store.set(targets.id, value, node.lineno)

    return store


def infer_value(node: ast.expr, store: SymbolicStore, config: Config):
    # if "abc" is a constant
    if isinstance(node, ast.Constant):
        return Constant(value=str(node.value))

    # api_key → look it up in the store
    if isinstance(node, ast.Name):
        existing = store.get(node.id)
        if isinstance(existing, Unknown):
            # not in store, check if it's a known secret
            if node.id in config.secrets:
                return Tainted(reason="name is a secret")
            return Derived(source=node.id)
        return Derived(source=node.id)

    # os.environ.get("API_KEY") → EnvValue
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("get", "getenv"):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return EnvValue(key=node.args[0].value)
    return Unknown()


if __name__ == "__main__":
    source = "f = open('x').read()\nkey = input()"
    tree = ast.parse(source)
    store = build_store(tree, Config(secrets=set(), sinks=set()))
    store.dump()
