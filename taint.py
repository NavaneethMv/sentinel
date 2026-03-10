# taint.py
import ast
import ast
from report import Violation
from config import Config
import dsl

def is_tainted_arg(arg: ast.expr, tainted: set[str], config: Config, tainted_funcs: set[str]) -> bool:
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
        if is_tainted_arg(arg.left, tainted, config, tainted_funcs) or \
           is_tainted_arg(arg.right, tainted, config, tainted_funcs):
            return True

    if isinstance(arg, ast.Dict):
        for value in arg.values:
            if is_tainted_arg(value, tainted, config, tainted_funcs):
                return True

    return False


def analyze(tree: ast.Module, config: Config, rules: list[Rule] = []) -> list[Violation]:
    # names that suggest a variable holds a secret
    tainted = set()

    # functions that return secrets
    tainted_func = set()

    # violations
    violations = []

    return_to_func: dict[int, str] = {}

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
                    if child.value and is_tainted_arg(child.value, tainted, config, tainted_func):
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

            if name and name in config.sinks:
                for arg in node.args:
                    if is_tainted_arg(arg, tainted, config, tainted_func):
                        violations.append(Violation(
                            var="secret",
                            sink=name,
                            line=node.lineno
                        ))
            
            for rule in rules:
                if name == rule.sink:
                    for arg in node.args:
                        if is_tainted_arg(arg, tainted, config, tainted_func):
                            violations.append(Violation(
                                var="secret",
                                sink=name,
                                line=node.lineno,
                            ))




    return violations