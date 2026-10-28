#!/usr/bin/env python3
"""Offline-only classifier for a libarchive diagnostic .ips report."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


def load_ips(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for match in re.finditer(r"\{", text):
            try:
                return json.loads(text[match.start() :])
            except json.JSONDecodeError:
                continue
    raise ValueError("the .ips file does not contain a readable JSON object")


def strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, (str, int, float, bool)):
        yield str(value)


def latest_state(log_path: Path | None) -> str | None:
    if log_path is None or not log_path.exists():
        return None
    state = None
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("state"):
            state = item["state"]
    return state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ips", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()

    report = load_ips(args.ips)
    haystack = "\n".join(strings(report)).lower()
    modules = {
        "libarchive": "libarchive" in haystack,
        "archive_read": "archive_read" in haystack,
        "joliet_parser_symbol": "build_pathname_utf16be" in haystack,
    }
    evidence = [
        line.strip()
        for line in haystack.splitlines()
        if any(token in line for token in ("exception", "termination", "signal", "reason"))
    ]
    state = latest_state(args.log)
    result = {
        "state": "CRASH_REPORT_AVAILABLE",
        "ips": str(args.ips),
        "app_last_state": state,
        "libarchive_or_archive_read_in_report": modules["libarchive"] or modules["archive_read"],
        "joliet_parser_symbol_in_report": modules["joliet_parser_symbol"],
        "exception_or_termination_evidence": evidence[:20],
        "interpretation": (
            "The .ips contains libarchive/archive_read evidence; compare the faulting image and PC manually."
            if modules["libarchive"] or modules["archive_read"]
            else "A .ips exists, but it does not identify libarchive."
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
