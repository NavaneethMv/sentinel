"""CLI entry point for Sentinel.

Usage:
    sentinel scan <file_or_folder> ...

Expands directory arguments recursively (`*.py`) and dispatches each file to
`parser.parse_file`. Exit code 0 if no violations, 1 if any file reports
violations or no Python files were found.

The `[project.scripts]` table in `pyproject.toml` wires this module's `main`
function to the `sentinel` command, so `uv run sentinel scan ...` works.

See ARCHITECTURE.md §7 for the file map.
"""

import argparse
import sys
from pathlib import Path

from parser import parse_file


def find_files(targets: list[str]) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        path = Path(target)
        if path.is_file() and path.suffix == ".py":
            files.append(path)
        elif path.is_dir():
            files.extend(path.rglob("*.py"))
    return files


def cmd_scan(targets: list[str]) -> int:
    files = find_files(targets)
    if not files:
        print("sentinel: no Python files found in given targets", file=sys.stderr)
        return 1

    any_violations = False
    for f in files:
        report = parse_file(str(f))
        if not report.passed:
            any_violations = True

    return 1 if any_violations else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Security property checker for Python.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan files or directories for violations")
    scan.add_argument(
        "targets",
        nargs="+",
        help="Python files or directories to scan",
    )

    args = parser.parse_args()
    if args.cmd == "scan":
        sys.exit(cmd_scan(args.targets))


if __name__ == "__main__":
    main()
