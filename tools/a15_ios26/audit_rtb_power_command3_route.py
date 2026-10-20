#!/usr/bin/env python3
"""Pin the iOS 26 RTBuddy power-message route to GXF command 3 and TTBR0."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from analyze_agx_uppl_producer import analyze_gxf_command_producers
from analyze_sptm_txm import MachOImage
from analyze_titan import disassemble_gfx_text, parse_gfx_images
from audit_gxf_ttbr0_wake_route import IOS26_GFX_SHA256, verify_ios26_route


KERNELCACHE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
RTBUDDY_IMAGE = "com.apple.driver.RTBuddy"

HOST_EXPECTED = {
    # Install the RTBuddy state callback and its nested power-change callback.
    0xfffffff00a51f718: ("adrp", "x16, #0xfffffff00a51f000"),
    0xfffffff00a51f71c: ("add", "x16, x16, #0xbcc"),
    0xfffffff00a51f730: ("bl", "#0xfffffff00a51550c"),
    0xfffffff00a51552c: ("str", "x19, [x20, #0xc0]"),
    0xfffffff00a515534: ("strb", "w8, [x20, #0xd8]"),
    0xfffffff00a5155c0: ("ldr", "x8, [x19, #0xc0]"),
    0xfffffff00a5155c8: ("mov", "x1, x21"),
    0xfffffff00a5155cc: ("mov", "x2, x20"),
    0xfffffff00a5155d4: ("blraa", "x8, x17"),
    0xfffffff00a51fc3c: ("add", "x8, x16, #0x100"),
    0xfffffff00a51fc48: ("add", "x16, x16, #0xcd4"),
    0xfffffff00a51fc54: ("mov", "x1, x16"),
    0xfffffff00a51fc64: ("mov", "x5, #0"),
    0xfffffff00a51fc74: ("blraa", "x9, x17"),
    # The callback emits only for the observed active-power state.
    0xfffffff00a51fcec: ("ldr", "x1, [x1]"),
    0xfffffff00a51fcf0: ("ldr", "x8, [x2]"),
    0xfffffff00a51fcf4: ("cmp", "x1, #1"),
    0xfffffff00a51fcfc: ("cmp", "x8, #1"),
    0xfffffff00a51fda0: ("cmp", "x8, #1"),
    0xfffffff00a51fdac: ("bl", "#0xfffffff00a51fe54"),
    0xfffffff00a51fdc4: ("bl", "#0xfffffff00a51fe54"),
    # Map AP power states 0/1/3 to payloads 0x201/0x20/0.
    0xfffffff00a51fe6c: ("cmp", "x1, #3"),
    0xfffffff00a51fe74: ("cmp", "x1, #1"),
    0xfffffff00a51fe7c: ("cbnz", "x1, #0xfffffff00a51ff48"),
    0xfffffff00a51fe80: ("mov", "w20, #0x201"),
    0xfffffff00a51fe88: ("mov", "w20, #0x20"),
    0xfffffff00a51fe90: ("mov", "w20, #0"),
    # Encode RTKit class 0xb and send exactly one 64-bit message on endpoint 0.
    0xfffffff00a51fea4: ("mov", "x9, #0xb0000000000000"),
    0xfffffff00a51fea8: ("orr", "x8, x8, x9"),
    0xfffffff00a51feac: ("str", "x8, [sp, #8]"),
    0xfffffff00a51fec0: ("ldr", "x8, [x16, #0xe8]!"),
    0xfffffff00a51fec8: ("add", "x1, sp, #8"),
    0xfffffff00a51fed0: ("mov", "x2, #0"),
    0xfffffff00a51fed4: ("mov", "w3, #1"),
    0xfffffff00a51fee0: ("blraa", "x8, x17"),
    0xfffffff00a51feec: ("bl", "#0xfffffff00a5202d4"),
    # Generic RTBuddy power fanout reaches the installed callback.
    0xfffffff00a50c4c0: ("bl", "#0xfffffff00a515560"),
    0xfffffff00a50c574: ("bl", "#0xfffffff00a515560"),
    0xfffffff00a50ecf0: ("mov", "w1, #1"),
    0xfffffff00a50ecf4: ("mov", "w2, #1"),
    0xfffffff00a50ecf8: ("bl", "#0xfffffff00a515560"),
}

GFX_EXPECTED = {
    # RTKit message class dispatch.
    0xffffff800003e348: ("ubfx", "x8, x1, #0x34, #4"),
    0xffffff800003e34c: ("cmp", "w8, #0xf"),
    0xffffff800003e368: ("add", "x17, x17, #0xfc8"),
    0xffffff800003e36c: ("ldrsw", "x16, [x17, x16, lsl #2]"),
    0xffffff800003e370: ("adr", "x17, #0xffffff800003e370"),
    0xffffff800003e378: ("br", "x16"),
    # Jump-table class 0xb target: map payload, update state, schedule worker.
    0xffffff800003e404: ("ldr", "w19, [x20, #4]"),
    0xffffff800003e408: ("mov", "x0, x1"),
    0xffffff800003e40c: ("bl", "#0xffffff800003e730"),
    0xffffff800003e418: ("bl", "#0xffffff80000402f4"),
    0xffffff800003e424: ("cmp", "w8, w21"),
    0xffffff800003e42c: ("str", "w21, [x0, #4]"),
    0xffffff800003e438: ("str", "x20, [x0, #0x40]"),
    0xffffff800003e44c: ("bl", "#0xffffff800004035c"),
    # Payload mapper: 0x201 -> 8, 0x20 -> 0x21, zero -> helper.
    0xffffff800003e730: ("and", "w8, w0, #0xff"),
    0xffffff800003e740: ("cbz", "w8, #0xffffff800003e778"),
    0xffffff800003e74c: ("cmp", "w8, #0x20"),
    0xffffff800003e764: ("tst", "x0, #0x200"),
    0xffffff800003e768: ("mov", "w8, #8"),
    0xffffff800003e76c: ("mov", "w9, #3"),
    0xffffff800003e770: ("csel", "w0, w9, w8, eq"),
    0xffffff800003e778: ("b", "#0xffffff80000442f0"),
    0xffffff800003e77c: ("mov", "w0, #0x21"),
    # Non-0x10 state transitions call the command-3 constructor.
    0xffffff8000040aec: ("cmp", "w27, #0x10"),
    0xffffff8000040b00: ("bl", "#0xffffff8000040e5c"),
    0xffffff8000040ee4: ("mov", "w8, #3"),
    0xffffff8000040ee8: ("bl", "#0xffffff8000044560"),
}

GFX_CLASS_TABLE = 0xffffff8000002fc8
GFX_CLASS_BRANCH_BASE = 0xffffff800003e370
GFX_CLASS_OFFSETS = (
    0x120,
    0x74,
    0x74,
    0x74,
    0x74,
    0x0C,
    0xFC,
    0x120,
    0x74,
    0x74,
    0x84,
    0x94,
    0x74,
    0x74,
    0x74,
    0x120,
)


def _require_host_instruction(image, address: int, expected: tuple[str, str]) -> None:
    instruction = image.instruction_at(address)
    actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
    if actual != expected:
        raise ValueError(f"instruction {address:#x}: expected {expected}, got {actual}")


def _instruction_map(instructions: list[dict]) -> dict[int, tuple[str, str]]:
    return {
        item["address"]: (item["mnemonic"], item["op_str"])
        for item in instructions
    }


def verify_host_producer(image) -> dict:
    for address, expected in HOST_EXPECTED.items():
        _require_host_instruction(image, address, expected)
    return {
        "registration": "0xfffffff00a51f730 -> 0xfffffff00a51550c",
        "nested_callback": "0xfffffff00a51fbcc -> 0xfffffff00a51fcd4",
        "producer": "0xfffffff00a51fe54",
        "accepted_ap_states": [0, 1, 3],
        "payloads": {"0": "0x201", "1": "0x20", "3": "0x0"},
        "rtkit_class": "0xb",
        "endpoint": 0,
        "message_count": 1,
        "generic_fanout_callsites": [
            "0xfffffff00a50c4c0",
            "0xfffffff00a50c574",
            "0xfffffff00a50ecf8",
        ],
    }


def verify_gfx_power_ingress(image, instructions: list[dict]) -> dict:
    actual = _instruction_map(instructions)
    for address, expected in GFX_EXPECTED.items():
        observed = actual.get(address)
        if observed != expected:
            raise ValueError(
                f"instruction {address:#x}: expected {expected}, got {observed}"
            )

    offsets = struct.unpack("<16i", image.read(GFX_CLASS_TABLE, 16 * 4))
    if offsets != GFX_CLASS_OFFSETS:
        raise ValueError(
            f"GFX class jump table changed: expected {GFX_CLASS_OFFSETS}, got {offsets}"
        )
    class_b_target = GFX_CLASS_BRANCH_BASE + offsets[0xB]
    if class_b_target != 0xffffff800003e404:
        raise ValueError(f"GFX class 0xb target changed: {class_b_target:#x}")

    return {
        "receiver": "0xffffff800003e32c",
        "class_extract": "message[55:52]",
        "class_b_target": f"{class_b_target:#x}",
        "payload_state_map": {
            "0x201": 8,
            "0x20": "0x21",
            "0x0": "helper-derived",
        },
        "state_worker": "0xffffff8000040944",
        "command_3_constructor_callsite": "0xffffff8000040ee8",
    }


def _a000(path: Path):
    return next(image for image in parse_gfx_images(path) if image.label == "a000")


def audit(kernelcache: Path, gfx_path: Path) -> dict:
    kernel_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    if kernel_hash != KERNELCACHE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {kernel_hash}")
    gfx_hash = hashlib.sha256(gfx_path.read_bytes()).hexdigest()
    if gfx_hash != IOS26_GFX_SHA256:
        raise ValueError(f"iOS 26 GFX SHA-256 mismatch: {gfx_hash}")

    host = MachOImage(kernelcache, RTBUDDY_IMAGE)
    gfx = _a000(gfx_path)
    instructions = disassemble_gfx_text(gfx)
    producers = analyze_gxf_command_producers(gfx, instructions)

    return {
        "status": "STATIC_RTB_POWER_CLASS_B_TO_COMMAND3_CLOSED_USERLAND_TRIGGER_PENDING",
        "build": "23A355",
        "kernelcache_sha256": kernel_hash,
        "gfx_sha256": gfx_hash,
        "host_producer": verify_host_producer(host),
        "gfx_power_ingress": verify_gfx_power_ingress(gfx, instructions),
        "command3_to_ttbr0": verify_ios26_route(gfx, instructions, producers),
        "proven": [
            "RTBuddy installs the observed power-state callback chain",
            "AP power states 0, 1, and 3 map to class-0xb payloads 0x201, 0x20, and 0",
            "the host sends one class-0xb RTKit message on endpoint 0",
            "GXF class 0xb lands at the power-state handler",
            "the 0x201 payload maps to state 8 and the 0x20 payload maps to state 0x21",
            "a non-0x10 transition reaches the local command-3 constructor",
            "command 3 reloads TTBR0 from the registered current-context root",
        ],
        "blocking_contracts": [
            {
                "id": "USERLAND_POWER_TRANSITION_TRIGGER",
                "status": "UNPROVEN",
                "question": (
                    "Which bounded app-visible action deterministically causes the required "
                    "RTBuddy transition while the controlled AGX context stays alive?"
                ),
            },
            {
                "id": "MDSID_PACKET_RUNTIME_TRANSPORT",
                "status": "UNPROVEN",
                "question": (
                    "Can the corrected selector-25 ABI deliver the controlled MDSID write "
                    "without rejection or unsafe side effects?"
                ),
            },
            {
                "id": "ROOT_FRAME_ACCEPTANCE_AND_RESTORE",
                "status": "UNPROVEN",
                "question": (
                    "Will owned DRAM be accepted as the replacement root, and can the "
                    "registry entry and live TTBR0 be restored reliably?"
                ),
            },
        ],
        "decision": (
            "The internal host-to-firmware wake route is statically closed and does not "
            "depend on selector 25. Selector 25 is still needed for the controlled MDSID "
            "writes. Do not build another device probe until a bounded app-side power "
            "transition protocol and rollback observation are defined."
        ),
        "limits": (
            "Static analysis only. No device probe, packet submission, MMIO, physical "
            "write, protected-memory write, or SPTM call was performed."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=Path)
    parser.add_argument("--gfx", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.kernelcache, args.gfx)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
