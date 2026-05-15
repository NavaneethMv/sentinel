# taint.py
import ast
from dataclasses import dataclass, field

import z3

from config import Config
from dsl import SourceRule, VarRule
from ir import EnvValue, SymbolicStore, Tainted, Unknown
from ir_builder import infer_value
from report import Violation
from z3_encoder import Encoder, is_path_satisfiable, to_bool

# map source names to IR types
SOURCE_MAP = {
    "env": EnvValue,
    "file": Tainted,
    "input": Tainted,
}


@dataclass
class Ctx:
    config: Config
    rules: list
    var_rule_sources: set[str] = field(default_factory=set)
    tainted_funcs: set[str] = field(default_factory=set)
    violations: list[Violation] = field(default_factory=list)
    encoder: Encoder = field(default_factory=Encoder)


def _name_tainted(var: str, store: SymbolicStore, tainted: set[str]) -> bool:
    if store.is_tainted(var):
        return True
    if isinstance(store.get(var), Unknown) and var in tainted:
        return True
    return False


def is_tainted_arg(
    arg: ast.expr,
    tainted: set[str],
    config: Config,
    tainted_funcs: set[str],
    store: SymbolicStore,
) -> bool:
    if isinstance(arg, ast.Name):
        return _name_tainted(arg.id, store, tainted)

    if isinstance(arg, ast.Subscript):
        if isinstance(arg.value, ast.Name):
            if _name_tainted(arg.value.id, store, tainted):
                return True
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
                if is_tainted_arg(value.value, tainted, config, tainted_funcs, store):
                    return True

    if isinstance(arg, ast.BinOp):
        if is_tainted_arg(
            arg.left, tainted, config, tainted_funcs, store
        ) or is_tainted_arg(arg.right, tainted, config, tainted_funcs, store):
            return True

    if isinstance(arg, ast.Dict):
        for value in arg.values:
            if is_tainted_arg(value, tainted, config, tainted_funcs, store):
                return True

    return False


def _bind_assign(
    node: ast.Assign, ctx: Ctx, path: list[z3.BoolRef]
) -> list[z3.BoolRef]:
    """Update Z3 env for Assign; return new path (extended if RHS encodable)."""
    new_path = path
    for target in node.targets:
        if isinstance(target, ast.Name):
            rhs = ctx.encoder.encode(node.value)
            if rhs is None:
                # un-encodable RHS — still create fresh var so future refs are unconstrained
                ctx.encoder.fresh(target.id)
            else:
                kind = "bool" if z3.is_bool(rhs) else "int"
                fresh = ctx.encoder.fresh(target.id, kind)
                new_path = new_path + [fresh == rhs]
    return new_path


def _update_store_from_assign(
    node: ast.Assign, store: SymbolicStore, ctx: Ctx
) -> None:
    for target in node.targets:
        if isinstance(target, ast.Name):
            if target.id in ctx.var_rule_sources:
                store.set(target.id, Tainted(reason="declared by VarRule"), node.lineno)
            else:
                value = infer_value(node.value, store, ctx.config)
                store.set(target.id, value, node.lineno)


def _update_tainted_from_assign(
    node: ast.Assign, store: SymbolicStore, tainted: set[str], ctx: Ctx
) -> None:
    for target in node.targets:
        if isinstance(target, ast.Name):
            if target.id in ctx.config.secrets:
                tainted.add(target.id)
            elif any(target.id == rule.source for rule in ctx.rules):
                tainted.add(target.id)
            elif is_tainted_arg(
                node.value, tainted, ctx.config, ctx.tainted_funcs, store
            ):
                tainted.add(target.id)


def _check_sink_call(
    node: ast.Call,
    store: SymbolicStore,
    tainted: set[str],
    ctx: Ctx,
    path: list[z3.BoolRef],
) -> None:
    name = None
    if isinstance(node.func, ast.Name):
        name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        name = node.func.attr
    if not name:
        return

    # Z3 reachability: if path is unsat, this sink can't fire — skip
    if not is_path_satisfiable(path):
        return

    config_fired = False
    if name in ctx.config.sinks:
        for arg in node.args:
            if is_tainted_arg(arg, tainted, ctx.config, ctx.tainted_funcs, store):
                var = arg.id if isinstance(arg, ast.Name) else "secret"
                ctx.violations.append(
                    Violation(var=var, sink=name, line=node.lineno)
                )
                config_fired = True

    if config_fired:
        return

    for rule in ctx.rules:
        if name != rule.sink:
            continue
        for arg in node.args:
            if isinstance(rule, SourceRule):
                if isinstance(arg, ast.Name):
                    value = store.get(arg.id)
                    ir_type = SOURCE_MAP.get(rule.source)
                    if ir_type and isinstance(value, ir_type):
                        ctx.violations.append(
                            Violation(var=arg.id, sink=name, line=node.lineno)
                        )
            elif isinstance(rule, VarRule):
                if isinstance(arg, ast.Name) and arg.id == rule.source:
                    ctx.violations.append(
                        Violation(var=arg.id, sink=name, line=node.lineno)
                    )
                elif is_tainted_arg(
                    arg, tainted, ctx.config, ctx.tainted_funcs, store
                ):
                    ctx.violations.append(
                        Violation(var=rule.source, sink=name, line=node.lineno)
                    )


def _scan_expr_for_sinks(
    expr: ast.expr,
    store: SymbolicStore,
    tainted: set[str],
    ctx: Ctx,
    path: list[z3.BoolRef],
) -> None:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            _check_sink_call(sub, store, tainted, ctx, path)


def _names_assigned(stmts: list[ast.stmt]) -> set[str]:
    # collect names appearing as Assign targets anywhere in the statement list
    names: set[str] = set()
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(sub, ast.AugAssign):
                if isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
    return names


def _reset_redefined(ctx: Ctx, names: set[str]) -> None:
    # drop env bindings for `names` so future references see fresh, unconstrained Z3 vars
    for name in names:
        ctx.encoder.fresh(name)


def _visit_block(
    stmts: list[ast.stmt],
    store: SymbolicStore,
    tainted: set[str],
    ctx: Ctx,
    path: list[z3.BoolRef],
) -> list[z3.BoolRef]:
    for stmt in stmts:
        path = _visit_stmt(stmt, store, tainted, ctx, path)
    return path


def _visit_stmt(
    stmt: ast.stmt,
    store: SymbolicStore,
    tainted: set[str],
    ctx: Ctx,
    path: list[z3.BoolRef],
) -> list[z3.BoolRef]:
    if isinstance(stmt, ast.Assign):
        _scan_expr_for_sinks(stmt.value, store, tainted, ctx, path)
        _update_store_from_assign(stmt, store, ctx)
        _update_tainted_from_assign(stmt, store, tainted, ctx)
        path = _bind_assign(stmt, ctx, path)
        return path

    if isinstance(stmt, ast.AugAssign):
        _scan_expr_for_sinks(stmt.value, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.Expr):
        _scan_expr_for_sinks(stmt.value, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.Return):
        if stmt.value is not None:
            _scan_expr_for_sinks(stmt.value, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.If):
        _scan_expr_for_sinks(stmt.test, store, tainted, ctx, path)
        test_enc = ctx.encoder.encode(stmt.test)
        body_path = path
        else_path = path
        if test_enc is not None:
            test_bool = to_bool(test_enc)
            if test_bool is not None:
                body_path = path + [test_bool]
                else_path = path + [z3.Not(test_bool)]

        env_before = ctx.encoder.env.copy()
        _visit_block(stmt.body, store, tainted, ctx, body_path)
        # orelse sees the same starting env as body, not body's mutations
        ctx.encoder.env = env_before.copy()
        _visit_block(stmt.orelse, store, tainted, ctx, else_path)
        # post-If: any name assigned in either branch becomes unconstrained
        ctx.encoder.env = env_before
        _reset_redefined(
            ctx, _names_assigned(stmt.body) | _names_assigned(stmt.orelse)
        )
        return path

    if isinstance(stmt, (ast.While, ast.For)):
        if isinstance(stmt, ast.While):
            _scan_expr_for_sinks(stmt.test, store, tainted, ctx, path)
        else:
            _scan_expr_for_sinks(stmt.iter, store, tainted, ctx, path)
        env_before = ctx.encoder.env.copy()
        # vars assigned inside the loop become unconstrained before body runs
        # (loop may execute 0+ times; subsequent iterations see possibly-mutated state)
        _reset_redefined(
            ctx, _names_assigned(stmt.body) | _names_assigned(stmt.orelse)
        )
        _visit_block(stmt.body, store, tainted, ctx, path)
        ctx.encoder.env = env_before
        _reset_redefined(
            ctx, _names_assigned(stmt.body) | _names_assigned(stmt.orelse)
        )
        _visit_block(stmt.orelse, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.Try):
        env_before = ctx.encoder.env.copy()
        _visit_block(stmt.body, store, tainted, ctx, path)
        body_assigned = _names_assigned(stmt.body)
        for handler in stmt.handlers:
            ctx.encoder.env = env_before.copy()
            _reset_redefined(ctx, body_assigned)
            _visit_block(handler.body, store, tainted, ctx, path)
        ctx.encoder.env = env_before
        all_assigned = (
            body_assigned
            | _names_assigned(stmt.orelse)
            | _names_assigned(stmt.finalbody)
        )
        for handler in stmt.handlers:
            all_assigned |= _names_assigned(handler.body)
        _reset_redefined(ctx, all_assigned)
        _visit_block(stmt.orelse, store, tainted, ctx, path)
        _visit_block(stmt.finalbody, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.With):
        _visit_block(stmt.body, store, tainted, ctx, path)
        return path

    if isinstance(stmt, ast.FunctionDef):
        fn_store = store.copy()
        fn_tainted = set(tainted)
        for arg in stmt.args.args:
            if arg.arg in ctx.config.secrets:
                fn_store.set(
                    arg.arg, Tainted(reason="param matches config.secrets"), stmt.lineno
                )
        # fresh Z3 scope per function (vars don't bleed across scopes)
        saved_encoder = ctx.encoder
        ctx.encoder = Encoder()
        _visit_block(stmt.body, fn_store, fn_tainted, ctx, [])
        ctx.encoder = saved_encoder
        return path

    return path


def _collect_function_summaries(tree: ast.Module, ctx: Ctx) -> None:
    for _ in range(len(list(ast.walk(tree))) + 1):
        before = len(ctx.tainted_funcs)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name in ctx.tainted_funcs:
                continue

            fn_store = SymbolicStore()
            fn_tainted: set[str] = set()
            for arg in node.args.args:
                if arg.arg in ctx.config.secrets:
                    fn_store.set(
                        arg.arg,
                        Tainted(reason="param matches config.secrets"),
                        node.lineno,
                    )

            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    _update_store_from_assign(stmt, fn_store, ctx)
                    _update_tainted_from_assign(stmt, fn_store, fn_tainted, ctx)

            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value is not None:
                    if is_tainted_arg(
                        child.value,
                        fn_tainted,
                        ctx.config,
                        ctx.tainted_funcs,
                        fn_store,
                    ):
                        ctx.tainted_funcs.add(node.name)
                        break

        if len(ctx.tainted_funcs) == before:
            break


def analyze(
    tree: ast.Module, config: Config, rules: list | None = None
) -> list[Violation]:
    rules = rules or []
    ctx = Ctx(
        config=config,
        rules=rules,
        var_rule_sources={r.source for r in rules if isinstance(r, VarRule)},
    )

    _collect_function_summaries(tree, ctx)

    store = SymbolicStore()
    tainted: set[str] = set()
    _visit_block(tree.body, store, tainted, ctx, [])

    return ctx.violations
