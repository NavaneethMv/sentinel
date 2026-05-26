# Sentinel

A security property checker for Python.

> Write what should never happen. Let the tool prove whether it can.

Sentinel reads your Python source, builds a symbolic intermediate representation, encodes branch conditions as Z3 constraints, and reports the program points where a forbidden value can flow into a forbidden sink.

It is designed to hide solver complexity behind a small declarative rule language and stay readable to humans.

---

## Status

Early prototype (v0.1). Expect breaking changes and limited language support. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the design and current phase coverage.

---

## Install

Sentinel uses `uv` for environment management.

```sh
git clone <repo>
cd sentinel
uv sync
```

This creates a `.venv`, installs `lark`, `pyyaml`, and `z3-solver`, and registers the `sentinel` CLI.

Requires Python ≥ 3.14.

---

## Quick start

Scan a file:

```sh
uv run sentinel scan path/to/file.py
```

Scan a directory (recursive):

```sh
uv run sentinel scan src/
```

Mix files and directories:

```sh
uv run sentinel scan src/ tests/main.py
```

Exit code is `0` if clean, `1` if any violation was reported.

---

## Example

Given `app.py`:

```python
import os

api_key = os.environ.get("API_KEY")
print(api_key)              # leak — env value reaches print

password = "hardcoded"
print(password)             # safe — literal constant, not a real secret

def get_secret():
    return os.environ.get("SECRET")

leaked = get_secret()
log(leaked)                 # leak — value propagated from env

x = 5
if x > 10:
    print(api_key)          # safe — Sentinel proves this branch is unreachable
```

Run:

```sh
uv run sentinel scan app.py
```

Output:

```
========================================
  Sentinel — app.py
========================================
  ✗ 2 violation(s):

  [SECRET_LEAK] line 4
    tainted value flows into 'print'

  [SECRET_LEAK] line 13
    tainted value flows into 'log'
```

The hardcoded `password` is not flagged because Sentinel tracks values, not just names. The third print is silenced because Z3 proves `x > 10` is unsatisfiable given `x = 5`.

---

## Configuration

### `config.yaml` — baseline heuristics

Common secret-looking variable names and common output sinks. Treated as soft signals.

```yaml
secrets:
  - api_key
  - password
  - token

sinks:
  - print
  - log
  - send
  - write
```

### `sentinel.rules` — project-declared policy

Hard rules in a small DSL. Sources are origin kinds (`env`, `file`, `input`). VarRules name specific variables that should never be considered safe.

```
NEVER SOURCE: env -> print
NEVER SOURCE: file -> send
NEVER VAR: db_password -> write
```

`SourceRule` matches IR origin types. `VarRule` overrides the IR — any assignment to the named variable becomes `Tainted` regardless of RHS.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md#3-two-tier-rule-model) §3 for the full model.

---

## How it works (one paragraph)

Sentinel walks the AST in source order, builds a `SymbolicStore` that maps each variable to a value type (`Constant`, `EnvValue`, `Tainted`, `Derived`, `Unknown`), and threads a Z3 path condition through each statement. On `if`/`else`, it tracks both branches and merges them with `Implies` constraints. At each function call that matches a configured sink, it asks Z3 whether the current path is satisfiable — if not, the call is unreachable and the violation is silenced. Function returns of literal constants are summarized so that callers reason about them precisely.

For the deep dive (IR lattice, sequential analyzer, Z3 encoder, φ-merge, function summaries), see [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## Running tests

```sh
uv run python tests.py
```

The runner is hand-rolled (no pytest dependency). Each test is a one-line source + expected violation flag (or count). 30+ tests cover IR origins, DSL rules, flow-sensitive reorder, Z3 dead code, branch merge, and function summaries.

---

## CI

A starter GitHub Actions workflow is provided in [`.github/workflows/sentinel.yml`](./.github/workflows/sentinel.yml). Drop into any Python project with a `sentinel.rules` file at the root.

---

## Roadmap

See the phase table in [`ARCHITECTURE.md`](./ARCHITECTURE.md#2-phase-timeline). Currently shipping: AST taint, DSL, symbolic IR, Z3 path feasibility, φ-merge, function summaries. Next: loop widening, richer summaries, more property classes.

---

## License

See [`LICENSE`](./LICENSE).
