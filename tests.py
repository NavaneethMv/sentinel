# tests.py
import ast
from taint import analyze
from config import Config

# a fixed test config so tests don't depend on sentinel.yaml
TEST_CONFIG = Config(
    secrets={"api_key", "password", "token", "secret"},
    sinks={"print", "log", "send", "write"}
)

def check(source: str):
    tree = ast.parse(source)
    return analyze(tree, TEST_CONFIG)   

def test(name: str, source: str, should_flag: bool):
    violations = check(source)
    flagged = len(violations) > 0

    if flagged == should_flag:
        print(f"  ✓  {name}")
    else:
        expected = "violation" if should_flag else "no violation"
        print(f"  ✗  {name} — expected {expected}")

# --- should flag ---
test("direct print",         "api_key = 'x'\nprint(api_key)",                    True)
test("taint propagation",    "api_key = 'x'\ncopy = api_key\nprint(copy)",       True)
test("f-string",             "api_key = 'x'\nprint(f'key: {api_key}')",          True)
test("concatenation",        "api_key = 'x'\nprint('k: ' + api_key)",            True)
test("function param",       "def f(api_key):\n    print(api_key)",              True)

# --- should NOT flag ---
test("safe variable",        "username = 'alice'\nprint(username)",              False)
test("secret not printed",   "api_key = 'x'\nx = api_key",                      False)

print()