"""Command-line interface for the synthetic marker lab."""

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="compile the bundled catalog")
    scan = commands.add_parser("scan", help="scan one local regular file")
    scan.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    try:
        import yara
    except ImportError as exc:
        print(f"error: could not import yara-python: {exc}", file=sys.stderr)
        print(
            "Install it with: python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    from . import scanner

    try:
        rules = scanner.compile_catalog()
    except (OSError, yara.Error) as exc:
        print(f"error: catalog compilation failed: {exc}", file=sys.stderr)
        return 2

    if args.command == "check":
        print("Catalog compiled.")
        return 0

    try:
        names = scanner.match_names(rules, scanner.read_sample(args.file))
    except yara.TimeoutError:
        print("error: YARA scan timed out", file=sys.stderr)
        return 2
    except (OSError, scanner.InputError, yara.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for name in names:
        print(name)
    return 0 if names else 1


if __name__ == "__main__":
    sys.exit(main())
