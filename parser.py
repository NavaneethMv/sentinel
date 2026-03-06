import ast
from taint import analyze
from report import Report
from config import Config, load_config


def parse_file(file_name: str) -> None:
    with open(file_name, 'r') as f:
        source = f.read()
    
    config = load_config()
    tree = ast.parse(source)
    violations = analyze(tree, config)
    Report(file_name, violations).print()
