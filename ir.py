from dataclasses import dataclass
from typing import Union

# --- Value types --- 
# every value in the program is one of these

@dataclass
class Constant:
    value: str          # a literal: "abc", "123"

@dataclass
class EnvValue:
    key: str            # os.environ.get("API_KEY")

@dataclass
class Tainted:
    reason: str         # known secret by name

@dataclass
class Derived:
    source: str         # came from another variable

@dataclass
class Unknown:
    pass                # we don't know what this is


# a Value is any of the above
Value = Union[Constant, EnvValue, Tainted, Derived, Unknown]


# --- IR for a single variable ---
@dataclass
class IRVar:
    name: str
    value: Value
    line: int


# --- The symbolic store ---
# maps variable names to what we know about their values

class SymbolicStore():
    def __init__(self):
        self.vars: dict[str, IRVar] = {}

    def set(self, name: str, value: Value, line: int):
        self.vars[name] = IRVar(name, value, line)

    def get(self, name: str) -> Value:
        return self.vars.get(name, Unknown()).value

    def copy(self) -> 'SymbolicStore':
        store = SymbolicStore()
        store.vars = self.vars.copy()
        return store

    def __repr__(self):
        return f"SymbolicStore({self.vars})"
    
    def is_tainted(self, name: str) -> bool:
        value = self.get(name)
        if isinstance(value, Tainted):
            return True
        if isinstance(value, Derived):
            return self.is_tainted(value.source)
        return False

    def dump(self):
        for name, var in self.vars.items():
            print(f"  {name} → {var.value}")
    
if __name__ == "__main__":
    store = SymbolicStore()

    store.set("api_key", Tainted(reason="name is a secret"), line=1)
    store.set("x", Derived(source="api_key"), line=2)
    store.set("msg", Constant("hello"), line=3)

    store.dump()
    print()
    print(f"api_key tainted: {store.is_tainted('api_key')}")
    print(f"x tainted:       {store.is_tainted('x')}")
    print(f"msg tainted:     {store.is_tainted('msg')}")