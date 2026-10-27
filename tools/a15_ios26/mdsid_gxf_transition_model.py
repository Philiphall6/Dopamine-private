#!/usr/bin/env python3
"""Model the MDSID -> GXF transition without constructing a device packet.

This module is deliberately semantic. It models lengths, control-flow gates,
backend preparation and cleanup outcomes, but it does not serialize bytes,
invoke IOKit, or emit an input suitable for an AGX client.
"""

from __future__ import annotations

from dataclasses import dataclass


IOGPU_SUBMISSION_RECORD_SIZE = 0x40
GXF_MESSAGE_SIZE = 0x30
MDSID_COMMAND = 0x10002


@dataclass(frozen=True)
class SyntheticScenario:
    """Abstract transition inputs; no packet contents are represented."""

    name: str
    submission_record_size: int = IOGPU_SUBMISSION_RECORD_SIZE
    gxf_message_size: int = GXF_MESSAGE_SIZE
    notification_bound: bool = True
    empty_command_header: bool = True
    backend_prepare_succeeds: bool = True
    parser_accepts: bool = True
    cleanup_release_succeeds: bool = True
    cleanup_clear_succeeds: bool = True


@dataclass(frozen=True)
class TransitionResult:
    scenario: str
    phases: tuple[str, ...]
    outcome: str
    cleanup: str
    rejection: str | None
    device_submission_performed: bool
    payload_serialized: bool
    firmware_execution_confirmed: bool
    physical_write: bool
    protected_memory_write: bool


def simulate_transition(scenario: SyntheticScenario) -> TransitionResult:
    """Run a safe, in-memory control-flow model for one synthetic scenario."""

    phases: list[str] = ["SCENARIO_ACCEPTED"]

    def result(outcome: str, cleanup: str, rejection: str | None = None):
        return TransitionResult(
            scenario=scenario.name,
            phases=tuple(phases),
            outcome=outcome,
            cleanup=cleanup,
            rejection=rejection,
            device_submission_performed=False,
            payload_serialized=False,
            firmware_execution_confirmed=False,
            physical_write=False,
            protected_memory_write=False,
        )

    if not scenario.notification_bound:
        phases.append("NOTIFICATION_PRECONDITION_REJECTED")
        return result(
            "REJECTED_BEFORE_BACKEND",
            "NOT_NEEDED",
            "notification binding absent",
        )

    if scenario.submission_record_size != IOGPU_SUBMISSION_RECORD_SIZE:
        phases.append("IOGPU_RECORD_REJECTED")
        return result(
            "REJECTED_BEFORE_BACKEND",
            "NOT_NEEDED",
            "submission record size is not 0x40",
        )

    if scenario.gxf_message_size != GXF_MESSAGE_SIZE:
        phases.append("GXF_MESSAGE_LAYOUT_REJECTED")
        return result(
            "REJECTED_BEFORE_PARSER",
            "NOT_NEEDED",
            "GXF message size is not 0x30",
        )

    phases.extend(("IOGPU_RECORD_VALIDATED", "QUEUE_DISPATCH_ENTERED"))
    phases.append("BACKEND_PREPARATION_STARTED")

    if not scenario.backend_prepare_succeeds:
        phases.append("BACKEND_PREPARATION_FAILED")
        return result("BACKEND_ERROR", "BACKEND_OBJECT_RELEASE_REQUIRED")

    phases.append("BACKEND_PREPARED")

    if scenario.empty_command_header:
        phases.extend(("EMPTY_RECORD_PATH_SELECTED", "PARSER_SKIPPED"))
        outcome = "ACCEPTED_NO_EXECUTION_PROOF"
    else:
        phases.append("NONEMPTY_RECORD_PATH_SELECTED")
        if not scenario.parser_accepts:
            phases.append("GXF_PARSER_REJECTED")
            outcome = "PARSER_ERROR"
        else:
            phases.append("GXF_PARSER_SIMULATED")
            outcome = "PARSE_PATH_REACHED_NO_EXECUTION_PROOF"

    phases.append("CLEANUP_STARTED")
    if not scenario.cleanup_release_succeeds:
        phases.append("BACKEND_RELEASE_FAILED")
        return result("CLEANUP_INCOMPLETE", "RELEASE_FAILED")

    phases.append("BACKEND_RELEASED")
    if not scenario.cleanup_clear_succeeds:
        phases.append("BACKEND_STATE_CLEAR_FAILED")
        return result("CLEANUP_INCOMPLETE", "STATE_CLEAR_FAILED")

    phases.append("CLEANUP_COMPLETE")
    return result(outcome, "SUCCESS")


def default_scenarios() -> tuple[SyntheticScenario, ...]:
    """Return the V12 scenario set without creating any packet bytes."""

    return (
        SyntheticScenario("empty-record-accepted"),
        SyntheticScenario("record-length-rejected", submission_record_size=0x30),
        SyntheticScenario("gxf-parser-reached", empty_command_header=False),
        SyntheticScenario(
            "backend-preparation-error",
            empty_command_header=False,
            backend_prepare_succeeds=False,
        ),
        SyntheticScenario(
            "parser-rejection",
            empty_command_header=False,
            parser_accepts=False,
        ),
        SyntheticScenario(
            "incomplete-release",
            cleanup_release_succeeds=False,
        ),
        SyntheticScenario("cleanup-success"),
    )
