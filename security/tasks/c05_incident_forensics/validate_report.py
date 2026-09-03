#!/usr/bin/env python3
"""Validate the exact C-05 four-line report format."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyze_incident import validate_report_text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        validate_report_text(args.report.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"invalid C-05 report: {error}", file=sys.stderr)
        return 1
    print("C-05 report format is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
