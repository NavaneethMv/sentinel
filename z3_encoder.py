import ast

import z3

# Python comparator AST → z3 op
_CMP_OPS = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
}

# arithmetic BinOps we encode
_BIN_OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
}


def to_bool(expr) -> z3.BoolRef | None:
    # coerce int expr to bool via C-style `!= 0`. Pass through Bool.
    if z3.is_bool(expr):
        return expr
    if z3.is_int(expr) or z3.is_int_value(expr):
        return expr != 0
    return None


class Encoder:
    """SSA-lite encoder: each Python name maps to its latest Z3 var.

    `fresh(name)` creates a new Z3 var (called on Assign). `get(name)` returns
    the current binding (lazy-creates as Int if unseen).
    """

    def __init__(self):
        self.env: dict[str, z3.ExprRef] = {}
        self._counter = 0

    def _new(self, name: str, kind: str) -> z3.ExprRef:
        self._counter += 1
        ident = f"{name}_{self._counter}"
        if kind == "bool":
            return z3.Bool(ident)
        return z3.Int(ident)

    def fresh(self, name: str, kind: str = "int") -> z3.ExprRef:
        v = self._new(name, kind)
        self.env[name] = v
        return v

    def get(self, name: str) -> z3.ExprRef:
        if name not in self.env:
            self.env[name] = self._new(name, "int")
        return self.env[name]

    def encode(self, expr: ast.expr):
        if isinstance(expr, ast.Constant):
            v = expr.value
            if isinstance(v, bool):
                return z3.BoolVal(v)
            if isinstance(v, int):
                return z3.IntVal(v)
            return None

        if isinstance(expr, ast.Name):
            return self.get(expr.id)

        if isinstance(expr, ast.UnaryOp):
            inner = self.encode(expr.operand)
            if inner is None:
                return None
            if isinstance(expr.op, ast.Not):
                b = to_bool(inner)
                return z3.Not(b) if b is not None else None
            if isinstance(expr.op, ast.USub):
                return -inner if z3.is_int(inner) else None
            return None

        if isinstance(expr, ast.BinOp):
            left = self.encode(expr.left)
            right = self.encode(expr.right)
            if left is None or right is None:
                return None
            op = _BIN_OPS.get(type(expr.op))
            return op(left, right) if op else None

        if isinstance(expr, ast.Compare):
            # single-op compare only — chained `a < b < c` skipped for Phase 11a
            if len(expr.ops) != 1 or len(expr.comparators) != 1:
                return None
            left = self.encode(expr.left)
            right = self.encode(expr.comparators[0])
            if left is None or right is None:
                return None
            op = _CMP_OPS.get(type(expr.ops[0]))
            return op(left, right) if op else None

        if isinstance(expr, ast.BoolOp):
            parts = [to_bool(self.encode(v)) for v in expr.values]
            if any(p is None for p in parts):
                return None
            if isinstance(expr.op, ast.And):
                return z3.And(*parts)
            if isinstance(expr.op, ast.Or):
                return z3.Or(*parts)
            return None

        return None


def is_path_satisfiable(path: list[z3.BoolRef]) -> bool:
    # empty path = trivially reachable
    if not path:
        return True
    solver = z3.Solver()
    solver.add(*path)
    return solver.check() == z3.sat
