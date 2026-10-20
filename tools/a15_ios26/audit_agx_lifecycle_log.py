#!/usr/bin/env python3
"""Validate the structured AGX lifecycle JSONL contract offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = (
    "schema",
    "run_id",
    "session_id",
    "timestamp",
    "timestamp_monotonic_ns",
    "stage",
    "operation",
    "status",
    "return_code",
    "duration_ns",
    "resource_state",
    "close_reason",
    "detail",
)
CLOSE_OPERATIONS = {"munlock", "IOServiceClose", "IOObjectRelease"}


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"line {line_number}: invalid JSON: {error.msg}") from error
        if not isinstance(value, dict):
            raise ValueError(f"line {line_number}: event is not an object")
        events.append(value)
    return events


def audit_events(events: list[dict[str, Any]], run_id: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if not events:
        return {
            "state": "FAIL",
            "run_id": run_id,
            "session_ids": [],
            "events_checked": 0,
            "operations_checked": 0,
            "errors": ["journal is empty"],
        }

    available_run_ids = {event.get("run_id") for event in events}
    selected_run_id = run_id or events[-1].get("run_id")
    selected = [event for event in events if event.get("run_id") == selected_run_id]
    if not selected:
        errors.append(f"run_id {selected_run_id!r} is absent")

    previous_monotonic = None
    sessions: set[str] = set()
    operations_checked = 0
    for index, event in enumerate(selected):
        prefix = f"event {index}"
        missing = [field for field in REQUIRED_FIELDS if field not in event]
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")
            continue

        session_id = event["session_id"]
        if not isinstance(session_id, str) or not session_id:
            errors.append(f"{prefix}: session_id must be a non-empty string")
        else:
            sessions.add(session_id)

        monotonic = event["timestamp_monotonic_ns"]
        if not isinstance(monotonic, int) or isinstance(monotonic, bool) or monotonic < 0:
            errors.append(f"{prefix}: timestamp_monotonic_ns must be a non-negative integer")
        elif previous_monotonic is not None and monotonic < previous_monotonic:
            errors.append(f"{prefix}: monotonic timestamp regressed")
        else:
            previous_monotonic = monotonic

        duration = event["duration_ns"]
        if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
            errors.append(f"{prefix}: duration_ns must be a non-negative integer")

        resource_state = event["resource_state"]
        if resource_state is not None and not isinstance(resource_state, dict):
            errors.append(f"{prefix}: resource_state must be an object or null")

        return_code = event["return_code"]
        is_operation_result = return_code is not None or duration != 0
        if is_operation_result:
            operations_checked += 1
            if not isinstance(event["operation"], str) or not event["operation"]:
                errors.append(f"{prefix}: operation result has no operation name")
            if not isinstance(return_code, int) or isinstance(return_code, bool):
                errors.append(f"{prefix}: operation return_code must be an integer")
            if not isinstance(resource_state, dict):
                errors.append(f"{prefix}: operation result has no resource_state object")

        if event["operation"] in CLOSE_OPERATIONS:
            reason = event["close_reason"]
            if not isinstance(reason, str) or not reason:
                errors.append(f"{prefix}: {event['operation']} has no close_reason")

    if len(sessions) > 1:
        errors.append("selected run contains multiple session_id values")

    return {
        "state": "PASS" if not errors else "FAIL",
        "run_id": selected_run_id,
        "available_run_ids": sorted(value for value in available_run_ids if value is not None),
        "session_ids": sorted(sessions),
        "events_checked": len(selected),
        "operations_checked": operations_checked,
        "errors": errors,
        "scope": "offline JSONL contract validation; no device interaction",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path, help="Exported AGX lifecycle JSONL")
    parser.add_argument("--run-id", help="Select a run; default is the last run")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        report = audit_events(load_events(args.jsonl), args.run_id)
    except ValueError as error:
        report = {"state": "FAIL", "errors": [str(error)]}
    if args.compact:
        print(
            f"state: {report['state']}\n"
            f"run_id: {report.get('run_id')}\n"
            f"events_checked: {report.get('events_checked', 0)}\n"
            f"operations_checked: {report.get('operations_checked', 0)}\n"
            f"errors: {len(report.get('errors', []))}"
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["state"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
