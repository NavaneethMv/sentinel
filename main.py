import sys
from pathlib import Path

from parser import parse_file


def find_files(targets: list[str]) -> list[Path]:
    file_names = []
    for target in targets:
        path = Path(target)
        if path.is_file() and path.suffix == ".py":
            file_names.append(path)
        elif path.is_dir():
            file_names.extend(list(path.rglob("*.py")))
        else:
            continue

    return file_names


def main():
    targets = sys.argv[1:]

    if not targets:
        print("Usage: python main.py <file_or_folder> ...")
        sys.exit(1)

    files = find_files(targets)

    if not files:
        sys.exit(1)

    any_violations = False
    for f in files:
        report = parse_file(str(f))
        if not report.passed:
            any_violations = True

    sys.exit(1 if any_violations else 0)


if __name__ == "__main__":
    main()
