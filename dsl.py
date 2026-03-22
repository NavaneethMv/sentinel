from dataclasses import dataclass

from lark import Lark, Transformer


# source rule like envvar, file, network, etc. must never reach sink rule like log, console, file, network, etc.
@dataclass
class SourceRule:
    source: str
    sink: str


# var rule where api_key, password, etc. must never reach log, console, file, network, etc. - like users can specify
@dataclass
class VarRule:
    source: str
    sink: str


class RuleTransformer(Transformer):
    def source_rule(self, items):
        return SourceRule(source=str(items[0]), sink=str(items[1]))

    def var_rule(self, items):
        return VarRule(source=str(items[0]), sink=str(items[1]))

    def rule(self, items):
        return items[0]

    def start(self, items):
        return items


def load_rules(path: str) -> list:
    with open("grammer.lark") as f:
        grammer = f.read()

    with open(path) as f:
        rules = f.read()

    parser = Lark(grammer)
    tree = parser.parse(rules)
    return RuleTransformer().transform(tree)


if __name__ == "__main__":
    rules = load_rules("sentinel.rules")
    for r in rules:
        print(r)
