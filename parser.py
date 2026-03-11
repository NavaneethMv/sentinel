import ast
import os

from config import load_config
from dsl import load_rules
from report import Report
from taint import analyze


def parse_file(file_name: str) -> None:
    with open(file_name) as f:
        source = f.read()

    config = load_config()
    tree = ast.parse(source)
    rules = load_rules("sentinel.rules") if os.path.exists("sentinel.rules") else []
    violations = analyze(tree, config, rules)
    report = Report(file_name, violations)
    report.print()
    return report
