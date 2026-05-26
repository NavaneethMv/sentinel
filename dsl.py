"""DSL parser for `sentinel.rules` (the hard/project-declared tier).

Two rule kinds:

- `NEVER SOURCE: <origin> -> <sink>` — `SourceRule`. Origin is `env`/`file`/`input`,
  matched against IR value types via `SOURCE_MAP` in `taint.py`.
- `NEVER VAR: <varname> -> <sink>` — `VarRule`. Names a specific variable that
  should be considered tainted; `build_store` flips its IR value to `Tainted`.

Grammar lives in `grammar.lark`. The Lark `Transformer` converts the parse
tree into `SourceRule` / `VarRule` dataclasses.

See ARCHITECTURE.md §3.2 (two-tier rule model).
"""

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
    with open("grammar.lark") as f:
        grammar = f.read()

    with open(path) as f:
        rules = f.read()

    parser = Lark(grammar)
    tree = parser.parse(rules)
    return RuleTransformer().transform(tree)


if __name__ == "__main__":
    rules = load_rules("sentinel.rules")
    for r in rules:
        print(r)
