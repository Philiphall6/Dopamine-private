#!/usr/bin/env python3
"""Correlate safe AGX evidence while permanently denying MDSID submission."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from triage_agx_metadata_probe import load_events
from triage_agx_notification_bound_probe import triage as notification_triage


STATIC_ROUTE_STATUS = "MDSID_GXF_TTBR0_BINDING_PROVED_OFFLINE"
NO_GO_LIMITS = (
    "This report is an offline/read-only correlation gate. It never authorizes a "
    "nonempty MDSID record, GPU command, MMIO, physical or protected write, "
    "bootstrap, root replacement, or Sileo launch."
)


def assess(runtime: dict, static_audit: dict) -> dict:
    """Return a conservative combined verdict for already-collected evidence."""
    static_route_ok = static_audit.get("status") == STATIC_ROUTE_STATUS
    route_identity_ok = runtime.get("packet_route_identity_ok") is True
    empty_record_ok = (
        runtime.get("verdict") ==
        "agx_notification_bound_zero_packet_cleanup_observed"
    )
    evidence_complete = static_route_ok and route_identity_ok and empty_record_ok

    missing = []
    if not static_route_ok:
        missing.append("exact-image static MDSID-to-GXF TTBR0 binding is absent")
    if not route_identity_ok:
        missing.append("runtime command-buffer and firmware callback identities are absent")
    if not empty_record_ok:
        missing.append("bound notification plus empty-record cleanup is absent")

    remaining = [
        "nonempty MDSID record submission has not been observed",
        "MDSID parser behavior and its callback effects remain unobserved",
        "backend effects and final release before selector return are not fully bounded",
        "host wake trigger and root-frame acceptance/restoration remain unobserved",
        "power-lifecycle recovery remains unobserved",
    ]
    return {
        "state": (
            "STATIC_AND_EMPTY_ROUTE_EVIDENCED_NO_GO" if evidence_complete else
            "INCOMPLETE_EVIDENCE_NO_GO"
        ),
        "device_submission_authorized": False,
        "evidence": {
            "static_mdsid_ttbr0_binding": static_route_ok,
            "runtime_packet_route_identity": route_identity_ok,
            "runtime_notification_bound_empty_record_cleanup": empty_record_ok,
        },
        "missing_evidence": missing,
        "remaining_blockers": remaining,
        "next_action": (
            "offline analysis and independent review only; do not build or run a "
            "nonempty-MDSID IPA from this report"
        ),
        "limits": NO_GO_LIMITS,
    }


def triage(events: list[dict], run_id: str, static_audit: dict) -> dict:
    runtime = notification_triage(events, run_id)
    report = assess(runtime, static_audit)
    report["run_id"] = run_id
    report["runtime_verdict"] = runtime["verdict"]
    report["selector25"] = runtime["selector25_call"]
    return report


def render_compact(report: dict) -> str:
    evidence = report["evidence"]
    return "\n".join((
        f"run: {report['run_id']}",
        f"state: {report['state']}",
        f"static_mdsid_ttbr0: {evidence['static_mdsid_ttbr0_binding']}",
        f"packet_route_identity: {evidence['runtime_packet_route_identity']}",
        "notification_bound_empty_record: "
        f"{evidence['runtime_notification_bound_empty_record_cleanup']}",
        f"device_submission_authorized: {report['device_submission_authorized']}",
        f"remaining_blockers: {len(report['remaining_blockers'])}",
    )) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path, help="Exported device probe journal")
    parser.add_argument("--static-audit", required=True, type=Path,
                        help="Exact-image MDSID TTBR0 static-audit JSON")
    parser.add_argument("--run-id", help="Select a run; default is the last one")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    raw = args.jsonl.read_bytes()
    events = load_events(raw)
    static_raw = args.static_audit.read_bytes()
    report = triage(
        events,
        args.run_id or events[-1]["run_id"],
        json.loads(static_raw),
    )
    report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    report["static_audit_sha256"] = hashlib.sha256(static_raw).hexdigest()
    print(render_compact(report) if args.compact else json.dumps(report, indent=2,
                                                                  sort_keys=True))


if __name__ == "__main__":
    main()
