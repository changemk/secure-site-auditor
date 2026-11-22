from __future__ import annotations

import argparse
import shutil
import sys

from .auditor import audit
from .report import render_html, render_text, save_report


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Passively review a website's public security posture.")
    command.add_argument("target", help="Domain or URL to audit")
    command.add_argument("--format", choices=("text", "json", "html"), default="text")
    command.add_argument("--output", help="Write the report to a file")
    command.add_argument("--timeout", type=float, default=10.0)
    command.add_argument(
        "--fail-below",
        type=int,
        metavar="SCORE",
        help="Exit with status 1 when the security score is below SCORE (0-100)",
    )
    return command


def main() -> int:
    args = parser().parse_args()
    if args.fail_below is not None and not 0 <= args.fail_below <= 100:
        print("Error: --fail-below must be between 0 and 100.", file=sys.stderr)
        return 2
    try:
        result = audit(args.target, timeout=args.timeout)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        path = save_report(result, args.output, args.format)
        print(f"Report saved to {path}")
    elif args.format == "html":
        print(render_html(result))
    elif args.format == "json":
        import json

        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(render_text(result, width=shutil.get_terminal_size((88, 24)).columns))
    return 1 if args.fail_below is not None and result.score < args.fail_below else 0


if __name__ == "__main__":
    raise SystemExit(main())
