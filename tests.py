"""Hand-rolled test runner — no pytest dependency.

Two helpers:

  test(name, source, should_flag, rules=None)
      Asserts the source flags (or doesn't) — doesn't care about count.

  test_count(name, source, expected, rules=None)
      Asserts the exact violation count. Use for flow-sensitive cases
      where some sinks should fire and others should not.

`TEST_CONFIG` is fixed inside this file so tests don't depend on the
on-disk `config.yaml`.

Add tests grouped by the property they exercise — IR origins, DSL rules,
flow-sensitive reorder, Z3 path feasibility, branch merge.
"""

import ast

from config import Config
from dsl import SourceRule, VarRule
from taint import analyze

TEST_CONFIG = Config(
    secrets={"api_key", "password", "token", "secret"},
    sinks={"print", "log", "send", "write", "info", "debug", "warning", "error"},
)


def check(source: str):
    tree = ast.parse(source)
    return analyze(tree, TEST_CONFIG)


def check_with_rules(source: str, rules: list):
    tree = ast.parse(source)
    return analyze(tree, TEST_CONFIG, rules)


def test(name: str, source: str, should_flag: bool, rules: list = None):
    if rules is None:
        rules = []
    if rules:
        violations = check_with_rules(source, rules)
    else:
        violations = check(source)
    flagged = len(violations) > 0
    if flagged == should_flag:
        print(f"  ✓  {name}")
    else:
        expected = "violation" if should_flag else "no violation"
        print(f"  ✗  {name} — expected {expected}")


def test_count(name: str, source: str, expected: int, rules: list = None):
    if rules is None:
        rules = []
    if rules:
        violations = check_with_rules(source, rules)
    else:
        violations = check(source)
    got = len(violations)
    if got == expected:
        print(f"  ✓  {name}")
    else:
        print(f"  ✗  {name} — expected {expected} violation(s), got {got}")


print("\nRunning tests...\n")

# --- IR based: real sources → should flag ---
test("env var taint", "import os\nkey = os.environ.get('SECRET_KEY')\nprint(key)", True)
test(
    "env var propagation",
    "import os\nkey = os.environ.get('X')\ncopy = key\nprint(copy)",
    True,
)
test("user input", "key = input()\nprint(key)", True)
test("file read", "f = open('x').read()\nprint(f)", True)

# --- IR based: hardcoded values → should NOT flag ---
test("literal", "api_key = 'abc'\nprint(api_key)", False)
test("safe variable", "username = 'alice'\nprint(username)", False)
test("not printed", "import os\nkey = os.environ.get('X')", False)

# --- DSL source rules ---
test(
    "source rule env",
    "import os\nkey = os.environ.get('X')\nprint(key)",
    True,
    [SourceRule(source="env", sink="print")],
)

test(
    "source rule no flag",
    "key = 'abc'\nprint(key)",
    False,
    [SourceRule(source="env", sink="print")],
)

# --- DSL var rules ---
test(
    "var rule direct",
    "db_password = 'x'\nwrite(db_password)",
    True,
    [VarRule(source="db_password", sink="write")],
)

test(
    "var rule propagation",
    "db_password = 'x'\ncopy = db_password\nwrite(copy)",
    True,
    [VarRule(source="db_password", sink="write")],
)

test(
    "var rule no flag",
    "username = 'alice'\nwrite(username)",
    False,
    [VarRule(source="db_password", sink="write")],
)

# --- flow-sensitive: same var, two states ---
test_count(
    "reorder safe-then-tainted",
    "import os\nx = 'abc'\nprint(x)\nx = os.environ.get('K')\nprint(x)",
    1,
)

test_count(
    "reorder tainted-then-safe",
    "import os\nx = os.environ.get('K')\nprint(x)\nx = 'abc'\nprint(x)",
    1,
)

# --- function param via IR ---
test(
    "function param config.secrets name",
    "def f(api_key):\n    print(api_key)",
    True,
)

test(
    "function param safe name",
    "def f(username):\n    print(username)",
    False,
)

# --- Z3 path feasibility ---
test(
    "dead code if False",
    "import os\nkey = os.environ.get('X')\nif False:\n    print(key)",
    False,
)

test(
    "live code if True",
    "import os\nkey = os.environ.get('X')\nif True:\n    print(key)",
    True,
)

test(
    "impossible compound",
    "import os\nkey = os.environ.get('X')\nif x > 10 and x < 5:\n    print(key)",
    False,
)

test(
    "constrained var unreachable",
    "import os\nkey = os.environ.get('X')\nx = 5\nif x > 10:\n    print(key)",
    False,
)

test(
    "constrained var reachable",
    "import os\nkey = os.environ.get('X')\nx = 5\nif x > 0:\n    print(key)",
    True,
)

test_count(
    "else branch unreachable",
    "import os\nkey = os.environ.get('X')\nx = 5\nif x > 0:\n    print(key)\nelse:\n    print(key)",
    1,
)

# --- Phase 11b: env merge after branches ---
test(
    "var reassigned in branch becomes unknown",
    "import os\nkey = os.environ.get('X')\nx = 5\nif cond:\n    x = 100\nif x > 10:\n    print(key)",
    True,
)

test(
    "var untouched in branch keeps constraint",
    "import os\nkey = os.environ.get('X')\nx = 5\nif cond:\n    pass\nif x > 10:\n    print(key)",
    False,
)

test(
    "both branches assign — post merge unknown",
    "import os\nkey = os.environ.get('X')\nif cond:\n    x = 5\nelse:\n    x = 100\nif x > 50:\n    print(key)",
    True,
)

# --- Phase 11c: φ-merge precision ---
test(
    "both branches same value — merge keeps fact",
    "import os\nkey = os.environ.get('X')\nif cond:\n    x = 5\nelse:\n    x = 5\nif x > 10:\n    print(key)",
    False,
)

test(
    "both branches above threshold — merge proves unreachable",
    "import os\nkey = os.environ.get('X')\nif cond:\n    x = 100\nelse:\n    x = 200\nif x < 50:\n    print(key)",
    False,
)

test(
    "both branches below threshold — merge proves reachable",
    "import os\nkey = os.environ.get('X')\nif cond:\n    x = 5\nelse:\n    x = 10\nif x > 7:\n    print(key)",
    True,
)

# --- Phase 11d-i: function return summaries ---
test(
    "summary single return — unreachable",
    "import os\nkey = os.environ.get('X')\ndef threshold():\n    return 5\nx = threshold()\nif x > 10:\n    print(key)",
    False,
)

test(
    "summary single return — reachable",
    "import os\nkey = os.environ.get('X')\ndef threshold():\n    return 5\nx = threshold()\nif x > 0:\n    print(key)",
    True,
)

test(
    "summary multiple returns — all below threshold",
    "import os\nkey = os.environ.get('X')\ndef pick():\n    if c:\n        return 5\n    return 10\nx = pick()\nif x > 20:\n    print(key)",
    False,
)

test(
    "summary multiple returns — one above threshold",
    "import os\nkey = os.environ.get('X')\ndef pick():\n    if c:\n        return 5\n    return 100\nx = pick()\nif x > 50:\n    print(key)",
    True,
)

print()
