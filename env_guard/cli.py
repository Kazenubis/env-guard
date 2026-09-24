"""Command-line interface: `scan` and `install-hook`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from env_guard.hook import HookError, install_hook
from env_guard.rules import EntropyConfig
from env_guard.scanner import ScanError, ScanResult, scan_directory, scan_staged

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def format_text(result: ScanResult) -> str:
    """Human-readable report: one aligned row per finding plus a verdict line."""
    counts = result.counts()
    files = f"{result.files_scanned} file{'s' if result.files_scanned != 1 else ''}"
    if not result.findings:
        return f"No secrets found in {files}. Safe to commit."
    width = max(len(f.location()) for f in result.findings)
    rule_width = max(len(f.rule) for f in result.findings)
    rows = [f"{f.severity.upper():<7} {f.location():<{width}}  {f.rule:<{rule_width}}  {f.preview}"
            for f in result.findings]
    total = len(result.findings)
    summary = (f"\n{total} finding{'s' if total != 1 else ''} "
               f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low) in {files}.")
    verdict = " Commit blocked." if result.blocking else " Only low findings, not blocking."
    return "\n".join(rows) + summary + verdict


def format_json(result: ScanResult) -> str:
    """Machine-readable report."""
    return json.dumps(result.to_dict(), indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="env_guard",
                                     description="Catch secrets and risky files before you commit.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a folder, or only the staged files")
    scan.add_argument("path", nargs="?", default=".", help="project folder (default: .)")
    scan.add_argument("--staged", action="store_true", help="only scan files staged with git add")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--entropy-base64", type=float, default=EntropyConfig.base64_threshold,
                      metavar="BITS", help="entropy threshold for base64-like tokens (default: %(default)s)")
    scan.add_argument("--entropy-hex", type=float, default=EntropyConfig.hex_threshold,
                      metavar="BITS", help="entropy threshold for hex tokens (default: %(default)s)")
    scan.add_argument("--no-entropy", action="store_true", help="turn off the high-entropy check")

    hook = sub.add_parser("install-hook", help="write .git/hooks/pre-commit")
    hook.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    hook.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")
    return parser


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"env_guard: {root} is not a folder", file=sys.stderr)
        return EXIT_ERROR
    entropy = EntropyConfig(base64_threshold=args.entropy_base64, hex_threshold=args.entropy_hex,
                            enabled=not args.no_entropy)
    try:
        result = scan_staged(root, entropy) if args.staged else scan_directory(root, entropy)
    except ScanError as exc:
        print(f"env_guard: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(format_json(result) if args.format == "json" else format_text(result))
    return EXIT_FINDINGS if result.blocking else EXIT_CLEAN


def run_install_hook(args: argparse.Namespace) -> int:
    try:
        hook = install_hook(Path(args.path), force=args.force)
    except HookError as exc:
        print(f"env_guard: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Installed pre-commit hook at {hook.as_posix()}")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_scan(args) if args.command == "scan" else run_install_hook(args)


if __name__ == "__main__":
    sys.exit(main())
