#!/usr/bin/env python3
"""Classify exact-target self-page write evidence without promoting syscall success."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from triage_agx_metadata_probe import fields, load_events


REVISION = "self-page-write-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1"
REVISIONS = {
    REVISION,
    "self-page-write-v1+agx-uat-mode-v1+rtkit-mmio-disabled-v1",
    "self-page-write-v1+agx-gart-state-v1+rtkit-mmio-disabled-v1",
    "self-page-write-v1+agx-iouat-object-v1+rtkit-mmio-disabled-v1",
}
REQUIRED = (
    ("kernel.primitive", "PASS"),
    ("kernel-write.self-page", "START"),
    ("kernel-write.self-page.prepare", "START"),
    ("kernel-write.self-page.alias-read", "START"),
    ("kernel-write.self-page.prepare", "PASS"),
    ("kernel-write.self-page.attempt", "START"),
    ("kernel-write.self-page.observe", "START"),
    ("kernel-write.self-page.observe", "PASS"),
    ("kernel-write.self-page.restore", "START"),
    ("kernel-write.self-page.restore", "PASS"),
    ("kernel-write.self-page.cleanup", "START"),
    ("kernel-write.self-page.redirect", "START"),
    ("kernel-write.self-page.redirect", "PASS"),
    ("kernel-write.self-page", "PASS"),
)


def triage(events: list[dict], run_id: str) -> dict:
    run = [event for event in events if event["run_id"] == run_id]
    if not run or run_id == "unknown":
        raise ValueError("requested run_id is absent or unattributable")

    entry = next((event for event in run if event["stage"] == "probe.entry" and
                  event["status"] == "START"), None)
    entry_fields = fields(entry["detail"]) if entry else {}
    target_ok = (entry_fields.get("target") == "iPhone14,2" and
                 entry_fields.get("build") == "23A355")
    revision_ok = entry_fields.get("revision") in REVISIONS
    sequence = [(event["stage"], event["status"]) for event in run]
    position = 0
    ordered = True
    for checkpoint in REQUIRED:
        try:
            position = sequence.index(checkpoint, position) + 1
        except ValueError:
            ordered = False
            break

    proof_end = sequence.index(("kernel-write.self-page", "PASS")) + 1 if (
        "kernel-write.self-page", "PASS") in sequence else len(run)
    first_blocker = next((event for event in run[:proof_end] if event["status"] in
                          {"FAIL", "BLOCKED", "REJECTED"} and
                          not event["stage"].startswith(("hypervisor.", "agx.registry"))), None)
    attempt_started = ("kernel-write.self-page.attempt", "START") in sequence
    observed = ("kernel-write.self-page.observe", "PASS") in sequence
    restored = ("kernel-write.self-page.restore", "PASS") in sequence
    cleanup_failed = ("kernel-write.self-page.cleanup", "FAIL") in sequence
    if not target_ok or not revision_ok:
        verdict = "wrong_target_or_revision"
    elif ordered and not first_blocker and not cleanup_failed:
        verdict = "verified_app_page_kernel_alias_write"
    elif observed and (not restored or cleanup_failed):
        verdict = "change_observed_but_cleanup_unconfirmed"
    elif attempt_started and not first_blocker:
        verdict = "interrupted_after_attempt_checkpoint"
    elif first_blocker:
        verdict = "blocked_or_failed"
    else:
        verdict = "no_write_attempt_observed"

    return {
        "run_id": run_id,
        "target_ok": target_ok,
        "revision_ok": revision_ok,
        "verdict": verdict,
        "first_blocker": ({key: first_blocker[key] for key in
                           ("stage", "status", "detail")} if first_blocker else None),
        "last_checkpoint": {key: run[-1][key] for key in ("stage", "status", "detail")},
        "limits": "App-owned page kernel alias only; no physical write, protected-memory change, or SPTM bypass proven.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--run-id", help="defaults to the last probe.entry run")
    args = parser.parse_args()
    events = load_events(args.jsonl.read_bytes())
    run_id = args.run_id or next(
        (event["run_id"] for event in reversed(events) if event["stage"] == "probe.entry"),
        None,
    )
    if not run_id:
        parser.error("no probe.entry checkpoint")
    print(json.dumps(triage(events, run_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
