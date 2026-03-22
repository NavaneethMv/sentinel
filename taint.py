# taint.py
import ast

from config import Config
from dsl import SourceRule, VarRule
from ir import EnvValue, Tainted
from ir_builder import build_store
from report import Violation

# map source names to IR types
SOURCE_MAP = {
    "env": EnvValue,
    "file": Tainted,
    "input": Tainted,
}


def is_tainted_arg(
    arg: ast.expr, tainted: set[str], config: Config, tainted_funcs: set[str]
) -> bool:
    if isinstance(arg, ast.Name):
        if arg.id in tainted:
            return True

    if isinstance(arg, ast.Subscript):
        # check if the object is tainted: data['key'] where data is tainted
        if isinstance(arg.value, ast.Name):
            if arg.value.id in tainted:
                return True

        # check if the key is a secret name: data['api_key']
        if isinstance(arg.slice, ast.Constant):
            if arg.slice.value in tainted or arg.slice.value in config.secrets:
                return True

    if isinstance(arg, ast.Call):
        if isinstance(arg.func, ast.Name):
            if arg.func.id in tainted_funcs:
                return True

    if isinstance(arg, ast.JoinedStr):
        for value in arg.values:
            if isinstance(value, ast.FormattedValue):
                if is_tainted_arg(value.value, tainted, config, tainted_funcs):
                    return True

    if isinstance(arg, ast.BinOp):
        if is_tainted_arg(arg.left, tainted, config, tainted_funcs) or is_tainted_arg(
            arg.right, tainted, config, tainted_funcs
        ):
            return True

    if isinstance(arg, ast.Dict):
        for value in arg.values:
            if is_tainted_arg(value, tainted, config, tainted_funcs):
                return True

    return False


def analyze(
    tree: ast.Module, config: Config, rules: list | None = None
) -> list[Violation]:
    if rules is None:
        rules = []
    # names that suggest a variable holds a secret
    tainted = set()

    # functions that return secrets
    tainted_func = set()

    # violations
    violations = []

    return_to_func: dict[int, str] = {}

    store = build_store(tree, config)

    # print(ast.dump(tree, indent=4))

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    return_to_func[id(child)] = node.name
                elif isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            if target.id in config.secrets:
                                tainted.add(target.id)

        # as function arguments
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if arg.arg in config.secrets:
                    tainted.add(arg.arg)

            for child in node.body:
                if isinstance(child, ast.Return):
                    if child.value and is_tainted_arg(
                        child.value, tainted, config, tainted_func
                    ):
                        func_name = return_to_func.get(id(child))
                        if func_name:
                            tainted_func.add(func_name)

        # when we see x = something
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # catches secrets
                    if target.id in config.secrets:
                        tainted.add(target.id)

                    elif any(target.id == rule.source for rule in rules):
                        tainted.add(target.id)

                    # catches assignments to tainted variables
                    elif is_tainted_arg(node.value, tainted, config, tainted_func):
                        tainted.add(target.id)

        # when we see print(x) or send(x)
        if isinstance(node, ast.Call):
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr

            config_fired = False
            if name and name in config.sinks:
                for arg in node.args:
                    # check IR store for taint: print(api_key) where api_key is tainted
                    if isinstance(arg, ast.Name) and store.is_tainted(arg.id):
                        violations.append(
                            Violation(var=arg.id, sink=name, line=node.lineno)
                        )
                        config_fired = True
                    # check if the argument is tainted by name or DSL rules / old method
                    elif is_tainted_arg(arg, tainted, config, tainted_func):
                        violations.append(
                            Violation(var="secret", sink=name, line=node.lineno)
                        )
                        config_fired = True

            if not config_fired:
                for rule in rules:
                    if name == rule.sink:
                        for arg in node.args:
                            if isinstance(rule, SourceRule):
                                # check origin in the IR store
                                value = store.get(arg.id)
                                ir_type = SOURCE_MAP.get(rule.source)
                                if ir_type and isinstance(value, ir_type):
                                    violations.append(
                                        Violation(
                                            var=arg.id, sink=name, line=node.lineno
                                        )
                                    )
                            elif isinstance(rule, VarRule):
                                # check variable name
                                if isinstance(arg, ast.Name) and arg.id == rule.source:
                                    violations.append(
                                        Violation(
                                            var=arg.id, sink=name, line=node.lineno
                                        )
                                    )
                                elif is_tainted_arg(arg, tainted, config, tainted_func):
                                    violations.append(
                                        Violation(
                                            var=rule.source, sink=name, line=node.lineno
                                        )
                                    )

    return violations
