#!/usr/bin/env python3
"""Pin the iOS 26 AGX RTBuddy-to-firmware power lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analyze_sptm_txm import MachOImage


KERNELCACHE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
STATIC_BASE = 0xfffffff007004000
RTBUDDY_IMAGE = "com.apple.AGXFirmwareKextG14PRTBuddy"
AGX_IMAGE = "com.apple.AGXG14P"
FIRMWARE_VTABLE = 0xfffffff007b19ab8

FIRMWARE_SLOTS = {
    0x620: (0x8011d7b1018461d0, 0xfffffff00884a1d0),
    0x670: (0x80111e2c01815594, 0xfffffff008819594),
    0x9c8: (0x8011ab470182aa00, 0xfffffff00882ea00),
    0x9d0: (0x80113b330182a9c8, 0xfffffff00882e9c8),
    0x9e0: (0x80118dac0182a8a4, 0xfffffff00882e8a4),
    0x9f0: (0x8011822d0182a708, 0xfffffff00882e708),
    0x9f8: (0x80115c4e0182a614, 0xfffffff00882e614),
    0xa00: (0x8011f4510182a604, 0xfffffff00882e604),
    0xa08: (0x8011c9e50182a520, 0xfffffff00882e520),
    0xa10: (0x80119a1d0182a474, 0xfffffff00882e474),
    0xa18: (0x8011d8570182a468, 0xfffffff00882e468),
}

RTBUDDY_EXPECTED = {
    # The transition wrapper calls powerTransitionStart before the gated change.
    0xfffffff0087d4580: ("cmp", "x1, #2"),
    0xfffffff0087d4590: ("cmp", "x20, #1"),
    0xfffffff0087d45ac: ("ldr", "x0, [x19, #0x160]"),
    0xfffffff0087d45b0: ("ldr", "w1, [x19, #0x110]"),
    0xfffffff0087d45c4: ("mov", "x17, #0xa08"),
    0xfffffff0087d45dc: ("blraa", "x8, x17"),
    # Completion uses the matching +0xa10 firmware slot.
    0xfffffff0087d46a4: ("cmp", "x20, #1"),
    0xfffffff0087d46ac: ("ldr", "x0, [x19, #0x160]"),
    0xfffffff0087d46c4: ("mov", "x17, #0xa10"),
    0xfffffff0087d46dc: ("blraa", "x8, x17"),
    # Gated state changes operate on the same firmware object at RTBuddy +0x160.
    0xfffffff0087d486c: ("ldr", "x0, [x0, #0x160]"),
    0xfffffff0087d48f4: ("cmp", "x21, #2"),
    0xfffffff0087d4900: ("cmp", "x20, #1"),
    0xfffffff0087d4910: ("ldr", "x0, [x19, #0x160]"),
    0xfffffff0087d4924: ("mov", "x17, #0x9c8"),
    0xfffffff0087d4934: ("mov", "w1, #0"),
    0xfffffff0087d49ec: ("cmp", "x21, #1"),
    0xfffffff0087d49f4: ("cmp", "x20, #1"),
    0xfffffff0087d4a54: ("add", "x8, x16, #0x9c8"),
    0xfffffff0087d4a5c: ("mov", "w1, #1"),
    0xfffffff0087d4aa8: ("cmp", "x21, #1"),
    0xfffffff0087d4ab0: ("cmp", "x20, #1"),
    0xfffffff0087d4ac4: ("ldr", "x0, [x19, #0x160]"),
    0xfffffff0087d4ad8: ("mov", "x17, #0x9e0"),
    0xfffffff0087d4b68: ("ldr", "x0, [x19, #0x160]"),
    0xfffffff0087d4b7c: ("mov", "x17, #0x9e0"),
    0xfffffff0087d4b90: ("mov", "w1, #1"),
}

AGX_EXPECTED = {
    # powerTransitionStart(role, entering) accepts only role zero and records state 1/2.
    0xfffffff00882e538: ("cbnz", "w1, #0xfffffff00882e5c8"),
    0xfffffff00882e554: ("mov", "x17, #0x9d0"),
    0xfffffff00882e568: ("mov", "w1, #1"),
    0xfffffff00882e590: ("add", "x9, x8, x9"),
    0xfffffff00882e598: ("cbnz", "w9, #0xfffffff00882e5dc"),
    0xfffffff00882e5a8: ("csel", "x9, x10, x9, ne"),
    0xfffffff00882e5b4: ("cinc", "w20, w20, ne"),
    0xfffffff00882e5c4: ("str", "w20, [x8, x9]"),
    # powerTransitionComplete clears the transition state and signals its event.
    0xfffffff00882e484: ("cbz", "w1, #0xfffffff00882e494"),
    0xfffffff00882e4a8: ("mov", "x17, #0x9d0"),
    0xfffffff00882e4d4: ("str", "wzr, [x10]"),
    0xfffffff00882e4d8: ("cbz", "w9, #0xfffffff00882e488"),
    0xfffffff00882e4e8: ("csel", "x9, x10, x9, eq"),
    # +0x9e0 stores the external power state and advances its generation.
    0xfffffff00882e8b8: ("strb", "w1, [x19, #0x598]"),
    0xfffffff00882e8c0: ("add", "w8, w8, #1"),
    0xfffffff00882e8c4: ("str", "w8, [x19, #0x59c]"),
    0xfffffff00882e940: ("ldr", "x0, [x19, #0x4a0]"),
    0xfffffff00882e954: ("mov", "x17, #0x3d0"),
}


def _require_instruction(image, address: int, expected: tuple[str, str]) -> None:
    instruction = image.instruction_at(address)
    actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
    if actual != expected:
        raise ValueError(f"instruction {address:#x}: expected {expected}, got {actual}")


def verify_power_lifecycle(rtb_image, agx_image) -> dict:
    for address, expected in RTBUDDY_EXPECTED.items():
        _require_instruction(rtb_image, address, expected)
    for address, expected in AGX_EXPECTED.items():
        _require_instruction(agx_image, address, expected)

    decoded_slots = {}
    for offset, (expected_encoding, expected_target) in FIRMWARE_SLOTS.items():
        slot = FIRMWARE_VTABLE + offset
        encoded = agx_image.read_u64(slot)
        target = None if encoded is None else STATIC_BASE + (encoded & 0xffffffff)
        if (encoded, target) != (expected_encoding, expected_target):
            raise ValueError(
                f"firmware slot +{offset:#x}: expected "
                f"{expected_encoding:#x} -> {expected_target:#x}, got {encoded} -> {target}"
            )
        decoded_slots[f"+{offset:#x}"] = f"{target:#x}"

    return {
        "rtbuddy_transition_wrapper": "0xfffffff0087d455c",
        "rtbuddy_power_state_change_gated": "0xfffffff0087d4848",
        "firmware_object_offset": "RTBuddy+0x160",
        "firmware_vtable": f"{FIRMWARE_VTABLE:#x}",
        "firmware_slots": decoded_slots,
        "state_transitions": {
            "0_or_2_to_1": ["powerTransitionStart", "+0x9c8(false)", "completion"],
            "1_to_0_or_2": ["powerTransitionStart", "+0x670", "+0x9c8(true)", "completion"],
            "external_state_update": "+0x9e0",
        },
        "direct_user_client_queue_registry_access": False,
        "queue_survival_runtime_observed": False,
    }


def audit(kernelcache: Path) -> dict:
    image_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    if image_hash != KERNELCACHE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {image_hash}")

    lifecycle = verify_power_lifecycle(
        MachOImage(kernelcache, RTBUDDY_IMAGE),
        MachOImage(kernelcache, AGX_IMAGE),
    )
    return {
        "status": "STATIC_AGX_FIRMWARE_POWER_LIFECYCLE_CLOSED_USERLAND_ASSERTION_PENDING",
        "build": "23A355",
        "kernelcache_sha256": image_hash,
        "power_lifecycle": lifecycle,
        "proven": [
            "the RTBuddy transition wrapper invokes firmware powerTransitionStart and completion slots",
            "powerStateChangeGated uses the same firmware object stored at RTBuddy+0x160",
            "the live runtime firmware vtable resolves every observed transition slot to the exact AGX implementation",
            "the direct transition path does not dereference the AGX user-client queue registry",
        ],
        "blocking_contracts": [
            {
                "id": "USERLAND_POWER_ASSERTION",
                "status": "UNPROVEN",
                "question": "Which bounded app-visible action requests the 0/2 to 1 transition deterministically?",
            },
            {
                "id": "OWNED_QUEUE_SURVIVAL",
                "status": "RUNTIME_OBSERVATION_REQUIRED",
                "question": "Does the owned queue, buffer registry, and context remain stable across one normal transition?",
            },
            {
                "id": "SELECTOR25_CORRECTED_ABI",
                "status": "DEVICE_PENDING",
                "question": "Does the exact 0x30 submit record pass the external-method contract?",
            },
        ],
        "decision": (
            "Build and run the corrected 0x30 selector-25 probe before adding a power-cycle probe. "
            "If selector 25 is accepted, the next bounded stage should observe one normal power "
            "transition while checking queue, buffer, context, and registered-root stability."
        ),
        "limits": (
            "Static analysis only. No device probe, packet submission, MMIO, physical write, "
            "protected-memory write, or SPTM call was performed."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.kernelcache)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
