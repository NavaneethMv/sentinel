# tests.py
from dsl import Rule
import ast
from taint import analyze
from config import Config

TEST_CONFIG = Config(
    secrets={"api_key", "password", "token", "secret"},
    sinks={"print", "log", "send", "write", "info", "debug", "warning", "error"},
)


def check_with_rules(source: str, rules: list[Rule]):
    tree = ast.parse(source)
    return analyze(tree, TEST_CONFIG, rules)


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


print("\nRunning tests...\n")

# --- should flag ---
test("direct print", "api_key = 'x'\nprint(api_key)", True)
test("taint propagation", "api_key = 'x'\ncopy = api_key\nprint(copy)", True)
test("f-string", "api_key = 'x'\nprint(f'key: {api_key}')", True)
test("concatenation", "api_key = 'x'\nprint('k: ' + api_key)", True)
test("function param", "def f(api_key):\n    print(api_key)", True)
test("method sink", "api_key = 'x'\nlogging.info(api_key)", True)
test("dict access", "data = {'api_key': 'abc'}\nprint(data['api_key'])", True)
test(
    "function return",
    "api_key = 'x'\ndef get_secret():\n    return api_key\nprint(get_secret())",
    True,
)
test(
    "local function secret",
    "def f():\n    api_key = 'x'\n    return api_key\nprint(f())",
    True,
)
test("dict taint", "api_key = 'x'\ndata = {'key': api_key}\nprint(data['key'])", True)
# --- should NOT flag ---
test("safe variable", "username = 'alice'\nprint(username)", False)
test("secret not printed", "api_key = 'x'\nx = api_key", False)

# --- DSL rules ---
test_rules = [Rule(source="my_custom_secret", sink="send")]
violations = check_with_rules(
    "my_custom_secret = 'x'\nsend(my_custom_secret)", test_rules
)
violations = check_with_rules(
    "my_custom_secret = 'x'\ncopy = my_custom_secret\nsend(copy)", test_rules
)
print(f"  {'✓' if violations else '✗'}  dsl rule propagation")
print(f"  {'✓' if violations else '✗'}  dsl rule")

print()
