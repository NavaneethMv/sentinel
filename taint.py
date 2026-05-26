"""The analyzer — sequential, flow-sensitive, IR-aware, Z3-aware.

Entry point: `analyze(tree, config, rules) -> list[Violation]`.

Pipeline:

1. `_collect_function_summaries` runs a fixed-point pass to find which
   functions return tainted values (handles forward references).
2. `_visit_block(tree.body, ...)` walks top-level statements in source
   order. Nested blocks (If, While, For, Try, With, FunctionDef) recurse.

Per statement, `_visit_stmt` does (in this order):

  a. Scan sub-expressions for sink calls (`_scan_expr_for_sinks`).
  b. Update IR store (`_update_store_from_assign`).
  c. Update name-set fallback (`_update_tainted_from_assign`).
  d. Update Z3 encoder env + path (`_bind_assign`).

Order matters: sinks scanned BEFORE assigns, so `print(x); x = secret`
does not retroactively flag the print.

Key data carried through the walk:

  store          — SymbolicStore, IR state at this point
  tainted        — set[str], heuristic-name fallback
  ctx.encoder    — Z3 encoder (per-scope: fresh on FunctionDef entry)
  ctx.tainted_funcs — functions known to return tainted values
  path           — list[z3.BoolRef], constraints to reach this point

Function scoping: each FunctionDef copies the store + tainted set, seeds
function params matching `config.secrets` as IR `Tainted`, and creates a
fresh Z3 Encoder so vars don't bleed across scopes.

Branch handling:
  - If (Phase 11c): full φ-merge via `_visit_if`. Each branch's path delta
    is captured; redefined names get a φ-var bound by
    `Implies(test, phi == body_val) AND Implies(Not(test), phi == else_val)`.
    Falls back to fresh-on-redefine if test isn't encodable.
  - While/For/Try (Phase 11b minimal): names assigned inside get fresh
    unconstrained Z3 vars. Sound but imprecise — loop widening is a future
    sub-phase.

See ARCHITECTURE.md §5 (analyzer) and §6 (Z3 layer).
"""

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
    # Phase 11d-i: per-function Z3 return summaries.
    # Maps func_name → list of possible Z3 return values (literal constants for now).
    # When `x = func()` is assigned, the analyzer constrains x to one of these.
    function_summaries: dict = field(default_factory=dict)


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
            # Phase 11d-i: if RHS is a call to a function with a known summary,
            # bind the target to one of the possible return values.
            summary = _summary_for_call(node.value, ctx)
            if summary is not None:
                first = summary[0]
                kind = "bool" if z3.is_bool(first) else "int"
                fresh = ctx.encoder.fresh(target.id, kind)
                options = [fresh == ret for ret in summary]
                clause = options[0] if len(options) == 1 else z3.Or(*options)
                new_path = new_path + [clause]
                continue

            rhs = ctx.encoder.encode(node.value)
            if rhs is None:
                # un-encodable RHS — still create fresh var so future refs are unconstrained
                ctx.encoder.fresh(target.id)
            else:
                kind = "bool" if z3.is_bool(rhs) else "int"
                fresh = ctx.encoder.fresh(target.id, kind)
                new_path = new_path + [fresh == rhs]
    return new_path


def _summary_for_call(expr: ast.expr, ctx: Ctx):
    """Return the Z3 summary list for `expr` if it's a Call to a summarized func."""
    if not isinstance(expr, ast.Call):
        return None
    if not isinstance(expr.func, ast.Name):
        return None
    return ctx.function_summaries.get(expr.func.id)


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


def _visit_if(
    stmt: ast.If,
    store: SymbolicStore,
    tainted: set[str],
    ctx: Ctx,
    path: list[z3.BoolRef],
) -> list[z3.BoolRef]:
    """Phase 11c φ-merge.

    After visiting body and orelse:
      1. Compute each branch's path delta (constraints added during the branch).
      2. Insert `Or(body_delta, else_delta)` into the post-If path so the solver
         knows one branch's facts hold.
      3. For each name assigned in either branch, create a fresh φ-var and bind:
            And(Implies(test, phi == body_val), Implies(Not(test), phi == else_val))
         Future references to the name resolve to the φ-var.

    If the test isn't encodable, fall back to Phase 11b (drop redefined to fresh).
    """
    _scan_expr_for_sinks(stmt.test, store, tainted, ctx, path)
    test_enc = ctx.encoder.encode(stmt.test)
    test_bool = to_bool(test_enc) if test_enc is not None else None

    body_path_in = path + [test_bool] if test_bool is not None else path
    else_path_in = path + [z3.Not(test_bool)] if test_bool is not None else path

    env_before = ctx.encoder.env.copy()
    body_path_out = _visit_block(stmt.body, store, tainted, ctx, body_path_in)
    env_after_body = ctx.encoder.env

    ctx.encoder.env = env_before.copy()
    else_path_out = _visit_block(stmt.orelse, store, tainted, ctx, else_path_in)
    env_after_else = ctx.encoder.env

    redefined = _names_assigned(stmt.body) | _names_assigned(stmt.orelse)

    # Un-encodable test → fall back to Phase 11b behavior.
    if test_bool is None:
        ctx.encoder.env = env_before
        _reset_redefined(ctx, redefined)
        return path

    # Constraints added inside each branch (everything beyond `path`).
    body_delta = body_path_out[len(path):]
    else_delta = else_path_out[len(path):]

    body_clause = z3.And(*body_delta) if body_delta else z3.BoolVal(True)
    else_clause = z3.And(*else_delta) if else_delta else z3.BoolVal(True)
    merged_clause = z3.Or(body_clause, else_clause)

    # Rebuild env at the merge point: keep pre-If bindings for untouched names,
    # bind φ-vars for redefined names.
    ctx.encoder.env = env_before.copy()
    new_path = path + [merged_clause]

    for name in redefined:
        body_val = env_after_body.get(name, env_before.get(name))
        else_val = env_after_else.get(name, env_before.get(name))

        # Name never seen in either branch's env → unreachable case; skip.
        if body_val is None and else_val is None:
            continue

        # Name assigned in only one branch: the other side keeps its pre-If
        # value if one existed, otherwise uses a placeholder unconstrained var.
        if body_val is None:
            body_val = ctx.encoder.make_var(name, "int")
        if else_val is None:
            else_val = ctx.encoder.make_var(name, "int")

        # Sort mismatch (e.g. one branch sets an int, the other a bool) — drop
        # precision by leaving the name unconstrained.
        body_is_bool = z3.is_bool(body_val)
        else_is_bool = z3.is_bool(else_val)
        if body_is_bool != else_is_bool:
            ctx.encoder.fresh(name)
            continue

        kind = "bool" if body_is_bool else "int"
        phi = ctx.encoder.make_var(name, kind)
        ctx.encoder.env[name] = phi
        new_path = new_path + [
            z3.And(
                z3.Implies(test_bool, phi == body_val),
                z3.Implies(z3.Not(test_bool), phi == else_val),
            )
        ]

    return new_path


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
        return _visit_if(stmt, store, tainted, ctx, path)

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


def _collect_z3_summaries(tree: ast.Module, ctx: Ctx) -> None:
    """Phase 11d-i: build a Z3 return-value summary per function.

    Only summarizes functions whose every Return statement returns a literal
    bool/int constant. Mixed or complex returns are left un-summarized — the
    analyzer falls back to existing behavior (the result is treated as Unknown
    in Z3, which keeps any sink reachable).
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        returns: list = []
        summarizable = True
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                if not isinstance(child.value, ast.Constant):
                    summarizable = False
                    break
                v = child.value.value
                # bool must be checked before int — `bool` is a subclass of `int` in Python
                if isinstance(v, bool):
                    returns.append(z3.BoolVal(v))
                elif isinstance(v, int):
                    returns.append(z3.IntVal(v))
                else:
                    summarizable = False
                    break
        if summarizable and returns:
            ctx.function_summaries[node.name] = returns


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
    _collect_z3_summaries(tree, ctx)

    store = SymbolicStore()
    tainted: set[str] = set()
    _visit_block(tree.body, store, tainted, ctx, [])

    return ctx.violations
