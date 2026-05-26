"""Violation dataclass and Report printer.

`Violation(var, sink, line)` — a single finding. `var` is the offending
variable name (or "secret" for non-Name args like f-strings); `sink` is
the function name that received the tainted value.

`Report.passed` is True iff there are zero violations. `main.py` reads it
to compute the process exit code.
"""

from dataclasses import dataclass


@dataclass
class Violation:
    var: str
    sink: str
    line: int


class Report:
    def __init__(self, file_name: str, violations: list[Violation]):
        self.file_name = file_name
        self.violations = violations
        self.passed = len(violations) == 0

    def print(self):
        print(f"\n{'=' * 40}")
        print(f"  Sentinel — {self.file_name}")
        print(f"{'=' * 40}")

        if not self.violations:
            print("  ✓ No violations found.\n")
        else:
            print(f"  ✗ {len(self.violations)} violation(s):\n")
            for v in self.violations:
                print(f"  [SECRET_LEAK] line {v.line}")
                print(f"    tainted value flows into '{v.sink}'\n")
