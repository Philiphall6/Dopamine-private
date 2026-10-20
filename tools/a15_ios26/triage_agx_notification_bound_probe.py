#!/usr/bin/env python3
"""Triage the bounded iOS 26 notification-bind and selector-25 probe."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events, numbered
from triage_agx_zero_packet_probe import render_compact as render_zero_compact
from triage_agx_zero_packet_probe import triage as zero_triage


REVISION = "self-page-write-v1+agx-notification-vtable-v2+rtkit-mmio-disabled-v1"
LEGACY_REVISION = (
    "self-page-write-v1+agx-notification-bound-zero-packet-v1+"
    "rtkit-mmio-disabled-v1"
)
REVISIONS = frozenset((REVISION, LEGACY_REVISION))
REQUIRED = (
    ("titan.notification-binding", "START"),
    ("titan.notification-binding.array", "PASS"),
    ("titan.notification-binding.array-vtable-identity", "PASS"),
    ("titan.notification-binding.array-count", "PASS"),
    ("titan.notification-binding.queue-slot", "PASS"),
    ("titan.notification-binding.queue-derived-before", "PASS"),
    ("titan.notification-binding.queue-object-before", "PASS"),
    ("titan.notification-binding.empty", "PASS"),
    ("titan.notification-binding.create", "START"),
    ("titan.notification-binding.create", "PASS"),
    ("titan.notification-binding.user-map", "PASS"),
    ("titan.notification-binding.array-slots", "PASS"),
    ("titan.notification-binding.object", "PASS"),
    ("titan.notification-binding.object-repeat", "PASS"),
    ("titan.notification-binding.object-vtable-identity", "PASS"),
    ("titan.notification-binding.map", "PASS"),
    ("titan.notification-binding.map-vtable-identity", "PASS"),
    ("titan.notification-binding.map-address", "PASS"),
    ("titan.notification-binding.map-length", "PASS"),
    ("titan.notification-binding.registry", "PASS"),
    ("titan.notification-binding.bind", "START"),
    ("titan.notification-binding.bind", "PASS"),
    ("titan.notification-binding.queue-derived", "PASS"),
    ("titan.notification-binding.queue-derived-repeat", "PASS"),
    ("titan.notification-binding.queue-slot-repeat", "PASS"),
    ("titan.notification-binding.queue-object", "PASS"),
    ("titan.notification-binding.derived-vtable", "PASS"),
    ("titan.notification-binding.derived-vtable-repeat", "PASS"),
    ("titan.notification-binding.link", "PASS"),
    ("titan.notification-binding.object-final", "PASS"),
    ("titan.notification-binding", "PASS"),
    ("titan.notification-binding", "STOP"),
)


def _event(run: list[dict], stage: str, status: str) -> dict | None:
    return next((item for item in run if item["stage"] == stage and
                 item["status"] == status), None)


def _number(values: dict[str, str], key: str) -> int | None:
    try:
        return int(values[key], 0)
    except (KeyError, ValueError):
        return None


def triage(events: list[dict], run_id: str) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    entry = _event(run, "probe.entry", "START")
    entry_revision = fields(entry["detail"]).get("revision") if entry else None
    report = zero_triage(events, run_id, revision=(
        entry_revision if entry_revision in REVISIONS else REVISION
    ))
    sequence = [(event["stage"], event["status"]) for event in run]
    ordered = False
    try:
        position = 0
        for checkpoint in REQUIRED:
            position = sequence.index(checkpoint, position) + 1
        zero_start = sequence.index(("titan.zero-packet", "START"), position)
        ordered = zero_start >= position
    except ValueError:
        pass

    create_start = _event(run, "titan.notification-binding.create", "START")
    create_pass = _event(run, "titan.notification-binding.create", "PASS")
    bind_start = _event(run, "titan.notification-binding.bind", "START")
    bind_pass = _event(run, "titan.notification-binding.bind", "PASS")
    vtable_pass = _event(run, "titan.notification-binding.object-vtable-identity", "PASS")
    vtable_blocked = _event(run, "titan.notification-binding.object-vtable-identity", "BLOCKED")
    vtable_event = vtable_pass or vtable_blocked
    vtable = fields(vtable_event["detail"]) if vtable_event else {}
    empty = fields((_event(run, "titan.notification-binding.empty", "PASS") or {}).get(
        "detail", ""))
    registry = fields((_event(run, "titan.notification-binding.registry", "PASS") or {}).get(
        "detail", ""))
    link = fields((_event(run, "titan.notification-binding.link", "PASS") or {}).get(
        "detail", ""))
    stable = fields((_event(run, "titan.notification-binding", "PASS") or {}).get(
        "detail", ""))

    create_ok = bool(
        create_start and create_pass and
        sequence.count(("titan.notification-binding.create", "START")) == 1 and
        sequence.count(("titan.notification-binding.create", "PASS")) == 1 and
        numbered(create_start["detail"], "selector") == 14 and
        numbered(create_start["detail"], "entries") == 256 and
        numbered(create_start["detail"], "entry-size") == 32 and
        numbered(create_pass["detail"], "kr") == 0 and
        numbered(create_pass["detail"], "output-size") == 0x10 and
        fields(create_pass["detail"]).get("attempt") == "1/1"
    )
    bind_ok = bool(
        bind_start and bind_pass and
        sequence.count(("titan.notification-binding.bind", "START")) == 1 and
        sequence.count(("titan.notification-binding.bind", "PASS")) == 1 and
        numbered(bind_start["detail"], "selector") == 24 and
        numbered(bind_pass["detail"], "kr") == 0 and
        fields(bind_pass["detail"]).get("attempt") == "1/1"
    )
    relationship_ok = bool(
        empty.get("derived") == "0x0" and empty.get("object") == "0x0" and
        _number(registry, "length") == 0x2000 and
        _number(link, "derived") not in {None, 0} and
        link.get("notification") == link.get("expected") and
        stable.get("notification") == "same" and
        stable.get("selectors") == "14/24" and stable.get("attempts") == "1/1"
    )
    binding_ok = ordered and create_ok and bind_ok and relationship_ok
    create_attempts = sequence.count(("titan.notification-binding.create", "START"))
    bind_attempts = sequence.count(("titan.notification-binding.bind", "START"))
    vtable_mismatch = bool(
        create_ok and vtable_blocked and bind_attempts == 0 and
        report["selector25_call"]["attempts"] == 0 and
        vtable.get("unslid") not in {None, vtable.get("expected")}
    )
    report["notification_binding_ok"] = binding_ok
    report["selector14_attempts"] = create_attempts
    report["selector24_attempts"] = bind_attempts
    report["notification_queue_vtable"] = {
        "status": vtable_event["status"] if vtable_event else "MISSING",
        "observed": vtable.get("unslid", "missing"),
        "expected": vtable.get("expected", "missing"),
    }
    report["notification_id"] = numbered(create_pass["detail"], "id") if create_pass else None
    report["notification_derived"] = link.get("derived", "missing")

    call_status = report["selector25_call"]["status"]
    if binding_ok and report.get("zero_packet_observation_ok"):
        report["verdict"] = "agx_notification_bound_zero_packet_cleanup_observed"
    elif binding_ok and call_status == "BLOCKED":
        report["verdict"] = "agx_notification_binding_observed_packet_blocked"
    elif binding_ok:
        report["verdict"] = "agx_notification_binding_observed"
    elif vtable_mismatch:
        report["verdict"] = "notification_queue_vtable_mismatch_before_bind"
    else:
        report["verdict"] = "incomplete_or_blocked"
    report["limits"] = (
        "Exactly one selector-14 create, one selector-24 bind, and at most one "
        "selector-25 empty-record call are checked. No nonempty packet, GPU command, "
        "MMIO, physical write, protected-memory modification, bootstrap, or Sileo "
        "launch is proved."
    )
    return report


def render_compact(report: dict) -> str:
    notification_id = report["notification_id"]
    notification_text = "missing" if notification_id is None else str(notification_id)
    return (
        f"notification_binding: {'ok' if report['notification_binding_ok'] else 'incomplete'}\n"
        f"selector14: attempts={report['selector14_attempts']} id={notification_text}\n"
        f"selector24: attempts={report['selector24_attempts']} derived={report['notification_derived']}\n"
        f"notification_vtable: {report['notification_queue_vtable']['status']} "
        f"observed={report['notification_queue_vtable']['observed']} "
        f"expected={report['notification_queue_vtable']['expected']}\n"
        + render_zero_compact(report)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    events = load_events(args.jsonl.read_bytes())
    run_id = args.run_id or events[-1]["run_id"]
    report = triage(events, run_id)
    print(render_compact(report) if args.compact else json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
