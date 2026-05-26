# Sentinel — Architecture

A pickup-anytime guide. Read top-to-bottom on first read; later, jump to the section that matches what you're touching.

---

## 1. Philosophy

> Write what should never happen. Let the tool prove whether it can.

Sentinel is a static analyzer for Python. You declare security properties (e.g. "an environment variable must never reach `print`"). Sentinel scans the code and either confirms the property holds, or reports a path that violates it.

The design splits into three layers:

1. **Intent** — what should never happen (`config.yaml`, `sentinel.rules`)
2. **Facts** — what the code actually does (IR, symbolic store)
3. **Proof** — does the code allow a violation? (Z3 solver on path conditions)

---

## 2. Phase timeline

Sentinel is built phase-by-phase. Each phase is a complete, runnable step. Don't skip ahead.

| Phase | Status | What landed |
|-------|--------|-------------|
| 1 | ✓ | Project scaffold, AST parsing |
| 2 | ✓ | Name-based taint tracking (`api_key`, `password`, etc.) |
| 3 | ✓ | Module split: `taint.py`, `report.py`, `config.py`, `parser.py` |
| 4 | ✓ | `tests.py` with named cases |
| 5 | ✓ | More patterns: method sinks, dict access, function returns |
| 6 | ✓ | `config.yaml` for user-defined secrets/sinks |
| 7 | ✓ | CLI: folder scanning, exit codes |
| 8 | ✓ | DSL grammar (Lark): `NEVER SOURCE: ...` / `NEVER VAR: ...` |
| 9 | ✓ | Symbolic IR — value types, store, origin tracking |
| 10 | ✓ | Cleanup: typo fix, double-assign fix, IR-authoritative sink check |
| 10.5 | ✓ | Sequential (flow-sensitive) analysis; function-param IR promotion |
| 11a | ✓ | Z3 path feasibility — bool/int, var bindings, dead-code detection |
| 11b | ✓ | Env merge after branches (minimal: drop redefined vars) |
| 11c | ✓ | Full φ-merge with `Implies` — precision on `if/else` joins |
| 11d-i | ✓ | Function return summaries in Z3 (literal-constant returns) |
| 11d-ii | future | Loop widening / fixed-point reasoning |
| 12 | future | CLI polish (`sentinel scan`), README, GitHub Action |

---

## 3. Two-tier rule model

Sentinel separates rules into two layers with different signal strength.

### 3.1 `config.yaml` — baseline heuristics (soft)

```yaml
secrets:
  - api_key
  - password
  - token
sinks:
  - print
  - log
  - send
```

- `secrets:` = names that *look like* secrets. Heuristic. Used to seed the name-set fallback inside `is_tainted_arg` for cases the IR doesn't know about (e.g. function parameters not yet analyzed).
- `sinks:` = output functions to watch.
- **IR treatment**: heuristic names do *not* override the IR. `api_key = "abc"` keeps IR `Constant`; it doesn't flip to `Tainted`. That keeps false positives low — a hardcoded literal isn't a real secret.

### 3.2 `sentinel.rules` — project-declared policy (hard)

```
NEVER SOURCE: env -> print
NEVER VAR: db_password -> write
```

Two rule kinds:

- `NEVER SOURCE: <origin> -> <sink>` — origin is one of `env` / `file` / `input`. Matched against IR value types via `SOURCE_MAP` in `taint.py`.
- `NEVER VAR: <varname> -> <sink>` — explicit user declaration. **Overrides** the IR: any assignment to `<varname>` is forced to `Tainted` in `build_store` (`ir_builder.py`).

The split exists because heuristic name matches and explicit user declarations should not have the same semantic weight. Don't conflate them by renaming `secrets:` to `sources:` in the yaml — they refer to different concepts.

---

## 4. The IR (symbolic store)

Each variable's value is one of these types (`ir.py`):

```
Constant(value)    # literal: "abc", 42
EnvValue(key)      # came from os.environ.get(key)
Tainted(reason)    # known dangerous origin (file read, input, VarRule)
Derived(source)    # copied from another variable — follow the chain
Unknown            # we don't know
```

The `SymbolicStore` maps variable names to their current `IRVar` (name + value + line). `store.is_tainted(name)` walks the `Derived` chain to find the root: if any link is `Tainted` or `EnvValue`, the chain is tainted.

### Origin recognizers (in `infer_value`, `ir_builder.py`)

| Python expression | IR value |
|---|---|
| `"abc"`, `42` | `Constant` |
| `os.environ.get("K")` / `os.getenv("K")` | `EnvValue` |
| `input()` | `Tainted("user input")` |
| `open(...).read()` | `Tainted("file read")` |
| `another_var` | `Derived("another_var")` |
| anything else | `Unknown` |

Extend `infer_value` to teach Sentinel new origins.

---

## 5. The analyzer (`taint.py`)

### 5.1 Sequential / flow-sensitive

`analyze(tree, config, rules)` does a single sequential pass over `tree.body`, recursing into nested blocks (`If`, `While`, `For`, `Try`, `With`, `FunctionDef`). Each statement, in source order:

1. **Scans sub-expressions for sink calls** (`_scan_expr_for_sinks`).
2. **Updates the IR store** (`_update_store_from_assign`).
3. **Updates the name-set fallback** (`_update_tainted_from_assign`).
4. **Updates the Z3 encoder env** (`_bind_assign`).

The order matters: sinks are scanned *before* the assignment, so `print(x); x = secret` does not retroactively flag the print.

This replaces the older `ast.walk` approach, which visited nodes in BFS order and pre-built the store. The BFS approach silently mishandled reassignments like:

```python
x = "abc"
print(x)        # safe
x = os.environ.get("K")
print(x)        # leak
```

(Old code flagged both prints; sequential flags only the second.)

### 5.2 Function scoping

When visiting a `FunctionDef`:
- The store and tainted-name set are copied (`store.copy()`, `set(tainted)`) so mutations stay scoped.
- Function parameters whose names match `config.secrets` are registered as `Tainted` in the function's store — function-param taint is now IR-driven, not name-set driven.
- A fresh Z3 `Encoder` is created so Z3 variables don't leak across function scopes.

### 5.3 Forward references

`_collect_function_summaries` runs a fixed-point pass before the main analysis to figure out which functions return tainted values. This handles:

```python
def caller(): return helper()  # uses helper before definition
def helper(): return os.environ.get("K")
```

The set `ctx.tainted_funcs` is queried by `is_tainted_arg` when an argument is a function call.

### 5.4 `is_tainted_arg` and `_name_tainted`

`is_tainted_arg(arg, ...)` is the unified taint check. For an `ast.Name`, it delegates to `_name_tainted`, which is IR-authoritative:

```
1. If IR says tainted (Tainted/EnvValue, or Derived chain ends in one) → True.
2. Else if IR has no info (Unknown) AND name is in the heuristic `tainted` set → True.
3. Else False.
```

This is *why* `api_key = "abc"` doesn't flag: IR sees `Constant`, not `Unknown`, so rule (1) misses and rule (2) is skipped.

For `ast.Subscript`, `ast.JoinedStr` (f-string), `ast.BinOp`, `ast.Dict`, `ast.Call` — the function recursively checks the inner pieces.

---

## 6. Z3 layer (`z3_encoder.py`)

The Z3 layer answers: *can the current path actually reach this sink?*

### 6.1 Encoder

`Encoder` translates Python AST expressions to Z3 expressions:

| Python | Z3 |
|---|---|
| `True` / `False` | `BoolVal(True/False)` |
| `42` | `IntVal(42)` |
| `name` | `Int("name_N")` (lazy-created) |
| `not x` | `Not(x)` |
| `a + b`, `a - b`, `a * b` | `a + b`, etc. |
| `a < b`, `a == b`, ... | same in Z3 |
| `a and b`, `a or b` | `And(a, b)`, `Or(a, b)` |

Returns `None` for anything it can't encode (strings, chained compares like `a < b < c`, function calls, attribute access). Unencodable expressions produce no constraint — the path stays satisfiable, conservative.

### 6.2 SSA-lite

Each Python variable maps to its *current* Z3 variable. On every Assign, `encoder.fresh(name)` creates a fresh `name_N` and updates the env. This avoids stale-constraint conflicts when a variable is reassigned:

```python
x = 5     # Int("x_1"), path adds x_1 == 5
x = 10    # Int("x_2"), path adds x_2 == 10
if x > 7: # encodes as x_2 > 7
```

### 6.3 Path conditions

`path: list[BoolRef]` is the list of constraints that must hold to reach the current program point. It's threaded as an immutable list through visit functions (passed in, returned).

- On `Assign`: push `new_var == encoded_rhs` (if RHS is encodable).
- On `If`: visit body with `path + [test]`, orelse with `path + [Not(test)]`.
- On sink call: before reporting a violation, run `is_path_satisfiable(path)`. If unsat, the sink is unreachable — skip silently.

### 6.4 Branch merge (Phase 11b minimal)

After an `If` body and orelse return, the Encoder env may have stale bindings from the branch that ran last. The minimal merge is:

1. Snapshot env before branches.
2. Visit body, then restore the snapshot and visit orelse.
3. For each name assigned in either branch, call `encoder.fresh(name)` — this creates a new unconstrained Z3 var. Future references see "unknown int."

This is sound but imprecise. `if c: x = 5 else: x = 5` loses the fact that x is 5 either way. Phase 11c fixes this.

### 6.5 Branch merge (Phase 11c — full φ-merge)

Implemented in `_visit_if` (`taint.py`). For each name assigned in either branch, a fresh φ-variable is created and bound via `Implies`:

```
And(
  Implies(test,        phi == body_value),
  Implies(Not(test),   phi == else_value),
)
```

Reads as English: "if test was true, phi equals body's value; if test was false, phi equals else's value." The solver then knows both possibilities and reasons about post-If usage precisely.

`Implies(A, B)` in Z3 is the logical "A implies B." `φ` is just SSA jargon for the merged variable.

Also: the merge inserts `Or(body_delta, else_delta)` into the post-If path so the solver knows one branch's facts hold (body's bind constraints survive the join, guarded by the disjunction).

**Precision wins.** `if c: x = 5 else: x = 5` followed by `if x > 10: print(secret)` correctly skips the violation (x is always 5). `if c: x = 100 else: x = 200; if x < 50:` also skips (both branches keep x ≥ 100).

**Fallbacks.**
- Un-encodable test (e.g. `if some_function():`) → drop to Phase 11b: redefined names become fresh, unconstrained.
- Sort mismatch (one branch sets bool, the other int) → drop redefined name to fresh.
- Name assigned in only one branch → other side uses pre-If binding (or a placeholder var if name never seen).

### 6.6 Function return summaries (Phase 11d-i)

Before the main analysis, `_collect_z3_summaries` (`taint.py`) computes a Z3 summary per function. For now, a function is summarizable only when every `Return` statement returns a literal bool/int constant.

```python
def pick():
    if c:
        return 5
    return 10
```

Summary: `[IntVal(5), IntVal(10)]`.

At a call site like `x = pick()`, `_bind_assign` creates a fresh `x_N` and adds `Or(x_N == 5, x_N == 10)` to the path. Subsequent reasoning (`if x > 20:`) becomes precise.

Functions with mixed returns, returns of complex expressions, or no `Return` at all are simply not summarized — the analyzer falls back to current behavior (returns Unknown, sinks reachable).

Phase 11d-ii (future) will extend this with loop widening and richer return-value reasoning (e.g. propagating from local vars inside the function).

---

## 7. File map

| File | Role |
|---|---|
| `main.py` | CLI entry: collect files, dispatch to `parse_file`, exit code. |
| `parser.py` | Per-file orchestrator: read source, parse AST, load config + rules, call `analyze`, print report. |
| `config.py` | YAML loader → `Config(secrets, sinks)`. |
| `dsl.py` | Lark-based DSL parser for `sentinel.rules`. Defines `SourceRule`, `VarRule`. |
| `grammar.lark` | Lark grammar for the DSL. |
| `ir.py` | IR value types (`Constant`, `EnvValue`, `Tainted`, `Derived`, `Unknown`) and `SymbolicStore`. |
| `ir_builder.py` | `infer_value(expr, ...)` translates AST expressions to IR values. `build_store` is a demo helper (not used by main analyzer). |
| `z3_encoder.py` | `Encoder` (SSA-lite AST → Z3), `is_path_satisfiable(path)`, `to_bool` coercion. |
| `taint.py` | The analyzer. `analyze(tree, config, rules)` is the entry point. Contains the sequential visitor and all sink-check logic. |
| `report.py` | `Violation` dataclass + `Report` printer. |
| `tests.py` | Hand-rolled test runner. `test(name, source, should_flag)` / `test_count(name, source, expected_count)`. |
| `sentinel.rules` | Example DSL rule file. |
| `config.yaml` | Default config. |
| `bug.py` | End-to-end demo file (exercises all phases). |

---

## 8. How to extend

### Add a new source origin (e.g. `requests.get(...).text`)

1. Add a recognizer in `infer_value` (`ir_builder.py`) that returns `Tainted(reason="http response")`.
2. Add a new entry to `SOURCE_MAP` in `taint.py` if you want a DSL alias (e.g. `http`).
3. Add a test in `tests.py` and a DSL rule in `sentinel.rules` if applicable.

### Add a new sink

For built-in heuristic: append the name to `config.yaml`'s `sinks:` list.
For project-specific: add a `NEVER SOURCE: ... -> sinkname` rule to `sentinel.rules`.

### Add a new property class (e.g. SQL injection)

Out of scope for current phases. Would need a new rule kind in the DSL (e.g. `NEVER TAINT: input -> sql_query_func`) and a new IR origin type.

---

## 9. Glossary

- **AST** — Abstract Syntax Tree. Python's `ast` module parses source code into a tree of nodes.
- **CFG** — Control Flow Graph. Sentinel does not build an explicit CFG; the sequential visitor approximates it.
- **IR** — Intermediate Representation. Here, the symbolic store mapping names to value types.
- **SSA** — Static Single Assignment. Each variable is assigned exactly once; reassignments create new variables (`x_1`, `x_2`).
- **φ (phi)** — In SSA, the fresh variable used to merge two branch outcomes.
- **Path condition** — The list of boolean constraints that must hold for execution to reach a given program point.
- **Source** — A program location that produces a tainted value (env, file, input).
- **Sink** — A program location that consumes a value dangerously (print, log, send).
- **Taint** — The property "this value originated from a source." Propagates through assignments.
- **Z3** — Microsoft's SMT (satisfiability modulo theories) solver. Decides whether a set of constraints is satisfiable.
- **`Implies(A, B)`** — Z3's logical implication. True unless A is true and B is false.
- **`is_path_satisfiable(path)`** — Asks Z3 whether the current path constraints are mutually consistent. If not, the path is dead code.

---

## 10. Running

```
uv sync
uv run python tests.py          # run test suite
uv run python main.py bug.py    # scan a file
uv run python main.py src/      # scan a folder
```

Exit codes: `0` = clean, `1` = violations or no files matched.
