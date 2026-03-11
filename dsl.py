from dataclasses import dataclass

from lark import Lark, Transformer


@dataclass
class Rule:
    source: str
    sink: str


class RuleTransformer(Transformer):
    def rule(self, items):
        return Rule(source=str(items[0].children[0]), sink=str(items[1].children[0]))

    def start(self, items):
        return items


def load_rules(path: str) -> list[Rule]:
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
        print(f"Rule: {r.source} must never reach {r.sink}")
