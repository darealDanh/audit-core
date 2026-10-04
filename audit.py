#!/usr/bin/env python3
"""audit.py - verb dispatch for the audit suite."""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import audit_core  # noqa: E402


def cmd_selftest(_args: argparse.Namespace) -> int:
    print(f"audit_core {audit_core.__version__} ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit.py")
    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("selftest", help="verify the vendored core is importable")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"selftest": cmd_selftest}[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
