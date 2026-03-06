import ast
import ast
from report import Violation
from config import Config


def is_tainted_arg(arg: ast.expr, tainted: set[str]) -> bool:
    if isinstance(arg, ast.Name):
        if arg.id in tainted:
            return True
    
    if isinstance(arg, ast.JoinedStr):
        for value in arg.values:
            if isinstance(value, ast.FormattedValue):
                if is_tainted_arg(value.value, tainted):
                    return True
    if isinstance(arg, ast.BinOp):
        if is_tainted_arg(arg.left, tainted) or is_tainted_arg(arg.right, tainted):
            return True
    return False
    

def analyze(tree: ast.Module, config: Config) -> list[Violation]:
    # names that suggest a variable holds a secret
    tainted = set()

    # violations
    violations = []

    # print(ast.dump(tree, indent=4))
    
    for node in ast.walk(tree):

        # as function arguments
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if arg.arg in config.secrets:
                    tainted.add(arg.arg)

        # when we see x = something
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):

                    # catches secrets
                    if target.id in config.secrets:
                        tainted.add(target.id)

                    # catches assignments to tainted variables
                    elif is_tainted_arg(node.value, tainted):
                        tainted.add(target.id)
        
        # when we see print(x) or send(x)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in config.sinks:
                    for arg in node.args:
                        if is_tainted_arg(arg, tainted):
                            violations.append(Violation(
                                var="secret",
                                sink=node.func.id,
                                line=node.lineno
                            ))

    return violations