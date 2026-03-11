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
        self.passed = self.passed = len(violations) == 0

    def print(self):
        print(f"\n{'='*40}")
        print(f"  Sentinel — {self.file_name}")
        print(f"{'='*40}")

        if not self.violations:
            print("  ✓ No violations found.\n")
        else:
            print(f"  ✗ {len(self.violations)} violation(s):\n")
            for v in self.violations:
                print(f"  [SECRET_LEAK] line {v.line}")
                print(f"    tainted value flows into '{v.sink}'\n")
