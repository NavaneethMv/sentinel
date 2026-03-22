# tests.py
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

print()
