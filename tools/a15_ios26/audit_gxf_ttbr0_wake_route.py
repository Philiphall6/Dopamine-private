#!/usr/bin/env python3
"""Pin the iOS 26 GXF command-3 to TTBR0 reload candidate and iOS 27 delta."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analyze_agx_uppl_producer import analyze_gxf_command_producers
from analyze_titan import disassemble_gfx_text, parse_gfx_images, parse_immediate_operand


IOS26_GFX_SHA256 = "3b245807d7a65241890e0d1d31566fed221082322de784779824a2e11464a98b"
IOS27_GFX_SHA256 = "e910ebea1f31c7053e231decaa87afce3ce52dbd114d61bafac7d064fa5a3d20"

IOS26_SYMBOLS = {
    "__mmu_gxf_enter": 0xFFFFFF80000009C0,
    "__rtk_mmu_gxf_dispatcher": 0xFFFFFF8000048464,
    "__rtk_mmu_switch_region_base_by_contextID": 0xFFFFFF80000486C8,
    "__rtk_mmu_uat_wake": 0xFFFFFF8000048A34,
    "__rtk_mmu_switch_region_base": 0xFFFFFF8000049170,
}

IOS27_SYMBOLS = {
    "__mmu_gxf_enter": 0xFFFFFF8000000A90,
    "__rtk_mmu_gxf_dispatcher": 0xFFFFFF8000048444,
    "__rtk_mmu_uat_wake": 0xFFFFFF800004886C,
    "__rtk_mmu_switch_region_base": 0xFFFFFF8000048FC8,
}

IOS26_EXPECTED = {
    # Local command-3 constructor and its leaf serializer.
    0xFFFFFF8000040EE4: ("mov", "w8, #3"),
    0xFFFFFF8000040EE8: ("bl", "#0xffffff8000044560"),
    0xFFFFFF8000044560: ("mov", "x0, sp"),
    0xFFFFFF8000044564: ("str", "w8, [sp]"),
    0xFFFFFF8000044568: ("b", "#0xffffff80000338a0"),
    0xFFFFFF80000338BC: ("bl", "#0xffffff80000009c0"),
    # Command 3 is the normal wake path; 0x20 is a separate direct path.
    0xFFFFFF80000484AC: ("cmp", "w21, #3"),
    0xFFFFFF80000484B0: ("b.ne", "#0xffffff800004858c"),
    0xFFFFFF80000484B4: ("bl", "#0xffffff8000048a34"),
    0xFFFFFF80000484F4: ("cmp", "w21, #0x20"),
    0xFFFFFF80000485C0: ("mov", "w2, #0"),
    0xFFFFFF80000485CC: ("b", "#0xffffff80000486c8"),
    # Registered context table: 16-byte entries and a masked root pointer.
    0xFFFFFF80000486F0: ("add", "x8, x8, #0x1e0"),
    0xFFFFFF80000486F4: ("ldr", "x23, [x8]"),
    0xFFFFFF8000048700: ("cbz", "x8, #0xffffff8000048814"),
    0xFFFFFF8000048710: ("cmp", "x8, #0x40"),
    0xFFFFFF8000048744: ("lsl", "x8, x24, #4"),
    0xFFFFFF8000048748: ("ldr", "x8, [x23, x8]"),
    0xFFFFFF800004874C: ("and", "x1, x8, #0x3ffffffc000"),
    0xFFFFFF8000048750: ("tbz", "w8, #0, #0xffffff80000487c8"),
    0xFFFFFF8000048758: ("ldrb", "w8, [x21, #0x638]"),
    0xFFFFFF8000048764: ("mov", "w0, #0"),
    0xFFFFFF8000048768: ("mov", "w2, #0x27"),
    0xFFFFFF800004876C: ("bl", "#0xffffff8000049170"),
    0xFFFFFF80000487F0: ("tbnz", "w22, #0, #0xffffff8000048764"),
    # Authorized wake fixes region=0 (TTBR0), uses current context, and auth=1.
    0xFFFFFF8000048A58: ("ldr", "w1, [x8, #0x1f8]"),
    0xFFFFFF8000048A5C: ("mov", "w0, #0"),
    0xFFFFFF8000048A60: ("mov", "w2, #1"),
    0xFFFFFF8000048A64: ("bl", "#0xffffff80000486c8"),
    # The selected root reaches TTBR0 and changes only T0SZ on this route.
    0xFFFFFF80000491D0: ("cbz", "w21, #0xffffff80000491e4"),
    0xFFFFFF80000491D4: ("msr", "ttbr1_el1, x20"),
    0xFFFFFF80000491E4: ("msr", "ttbr0_el1, x20"),
    0xFFFFFF8000049214: ("msr", "tcr_el1, x8"),
    # Mapper geometry used to derive the replacement low-root format.
    0xFFFFFF8000048E90: ("and", "w8, w8, #0x7ff"),
    0xFFFFFF8000048EDC: ("cmp", "x20, #0xe"),
    0xFFFFFF8000048EF4: ("and", "x8, x8, #0x3ffffffc000"),
    0xFFFFFF8000048F00: ("str", "x8, [x21, x22, lsl #3]"),
    0xFFFFFF8000049098: ("mov", "w1, #0x800"),
    # Bootstrap publishes the runtime table/count into state 0x581e0.
    0xFFFFFF8000034490: ("str", "x8, [x27, #0x1e0]"),
    0xFFFFFF8000034558: ("str", "xzr, [x27, #0x1e0]"),
    0xFFFFFF8000034564: ("str", "x9, [x26, #0x1e8]"),
}

IOS27_EXPECTED = {
    # Command 3 remains, but wake no longer resolves a registered root.
    0xFFFFFF8000048480: ("cmp", "w21, #3"),
    0xFFFFFF8000048484: ("b.eq", "#0xffffff8000048550"),
    0xFFFFFF8000048550: ("bl", "#0xffffff800004886c"),
    0xFFFFFF8000048888: ("bl", "#0xffffff8000048630"),
    0xFFFFFF800004888C: ("mov", "x0, x19"),
    0xFFFFFF8000048890: ("bl", "#0xffffff80000487f4"),
    # The generic low-level primitive still exists but is detached from wake.
    0xFFFFFF8000049028: ("cbz", "w21, #0xffffff800004903c"),
    0xFFFFFF800004902C: ("msr", "ttbr1_el1, x20"),
    0xFFFFFF800004903C: ("msr", "ttbr0_el1, x20"),
}

LOCAL_COMMANDS = [1, 2, 3, 0x10, 0x11, 0x12, 0x21]


def _instruction_map(instructions: list[dict]) -> dict[int, tuple[str, str]]:
    return {
        item["address"]: (item["mnemonic"], item["op_str"])
        for item in instructions
    }


def _require_instructions(
    instructions: list[dict], expected: dict[int, tuple[str, str]]
) -> None:
    actual = _instruction_map(instructions)
    for address, wanted in expected.items():
        observed = actual.get(address)
        if observed != wanted:
            raise ValueError(
                f"instruction {address:#x}: expected {wanted}, got {observed}"
            )


def _require_symbols(image, expected: dict[str, int]) -> None:
    for name, address in expected.items():
        observed = image.symbols.get(name)
        if observed != address:
            raise ValueError(f"symbol {name}: expected {address:#x}, got {observed}")


def _direct_branch_targets(instructions: list[dict], start: int, end: int) -> list[int]:
    targets = []
    for item in instructions:
        if not start <= item["address"] < end:
            continue
        if item["mnemonic"] not in {"b", "bl"}:
            continue
        target = parse_immediate_operand(item["op_str"])
        if target is not None:
            targets.append(target)
    return targets


def _verify_producers(producers: dict, forwarder: int, command3_callsite: int) -> dict:
    if producers.get("local_constant_commands") != LOCAL_COMMANDS:
        raise ValueError(
            f"unexpected local GXF commands: {producers.get('local_constant_commands')}"
        )
    if producers.get("command_0x20_local_producer_observed"):
        raise ValueError("a local command-0x20 producer unexpectedly appeared")
    if not producers.get("command_3_local_producer_observed"):
        raise ValueError("the local command-3 producer is missing")
    wrappers = producers.get("forwarding_wrappers", [])
    match = next((item for item in wrappers if item["address"] == forwarder), None)
    if match is None:
        raise ValueError(f"GXF forwarding wrapper {forwarder:#x} is missing")
    command3 = next(
        (
            item
            for item in match["callsites"]
            if item["command"] == 3 and item["callsite"] == command3_callsite
        ),
        None,
    )
    if command3 is None:
        raise ValueError("the expected forwarded command-3 callsite is missing")
    return {
        "commands": [f"{command:#x}" for command in LOCAL_COMMANDS],
        "command_3_callsite": f"{command3_callsite:#x}",
        "forwarder": f"{forwarder:#x}",
        "command_0x20_local_producer": False,
        "submit_wrapper_exact_pointer_references": producers.get(
            "submit_wrapper_exact_pointer_references", []
        ),
        "forwarder_exact_pointer_references": match["exact_pointer_references"],
    }


def verify_ios26_route(image, instructions: list[dict], producers: dict) -> dict:
    _require_symbols(image, IOS26_SYMBOLS)
    _require_instructions(instructions, IOS26_EXPECTED)
    producer_result = _verify_producers(
        producers,
        forwarder=0xFFFFFF8000044560,
        command3_callsite=0xFFFFFF8000040EE8,
    )
    return {
        "producer_census": producer_result,
        "dispatcher": {
            "command_3_calls_wake": True,
            "command_0x20_handler_present": True,
            "command_0x20_local_producer_present": False,
        },
        "registered_context": {
            "state_address": "0xffffff80000581e0",
            "table_pointer_offset": "0x0",
            "count_offset": "0x8",
            "current_uat_offset": "0x10",
            "current_context_id_offset": "0x18",
            "entry_size": "0x10",
            "maximum_entries": "0x40",
            "root_mask": "0x3ffffffc000",
            "valid_bit": 0,
            "authorization_state_offset": "0x638",
        },
        "authorized_wake": {
            "region_selector": 0,
            "translation_register": "TTBR0_EL1",
            "context_source": "current_context_id_global",
            "authorization_argument": 1,
            "t0sz": "0x27",
        },
        "low_root_geometry": {
            "virtual_address_bits": 0x40 - 0x27,
            "leaf_shift": 0xE,
            "index_mask": "0x7ff",
            "entry_count": 0x800,
            "entry_size": 8,
            "table_size": "0x4000",
            "levels_for_25_bit_low_va": 1,
            "derivation": "25 virtual bits = 14 page-offset bits + 11 root-index bits",
            "safe_construction_rule": (
                "clone the live 16K root and replace only the selected leaf PA bits; "
                "do not synthesize unverified attribute bits"
            ),
        },
    }


def verify_ios27_delta(image, instructions: list[dict], producers: dict) -> dict:
    _require_symbols(image, IOS27_SYMBOLS)
    _require_instructions(instructions, IOS27_EXPECTED)
    if "__rtk_mmu_switch_region_base_by_contextID" in image.symbols:
        raise ValueError("iOS 27 unexpectedly exports the by-context-ID switch")
    producer_result = _verify_producers(
        producers,
        forwarder=0xFFFFFF800004797C,
        command3_callsite=0xFFFFFF800004407C,
    )
    dispatcher = [
        item
        for item in instructions
        if 0xFFFFFF8000048444 <= item["address"] < 0xFFFFFF80000485E8
    ]
    if any(
        item["mnemonic"] == "cmp" and item["op_str"].lower() == "w21, #0x20"
        for item in dispatcher
    ):
        raise ValueError("iOS 27 unexpectedly retains direct command 0x20")
    wake_targets = _direct_branch_targets(
        instructions, 0xFFFFFF800004886C, 0xFFFFFF80000488B0
    )
    if IOS27_SYMBOLS["__rtk_mmu_switch_region_base"] in wake_targets:
        raise ValueError("iOS 27 wake unexpectedly calls the low-level TTBR switch")
    return {
        "producer_census": producer_result,
        "command_3_still_calls_wake": True,
        "command_0x20_handler_present": False,
        "by_context_id_switch_symbol_present": False,
        "wake_calls_low_level_ttbr_switch": False,
        "generic_low_level_ttbr_switch_still_present": True,
    }


def _a000(path: Path):
    return next(image for image in parse_gfx_images(path) if image.label == "a000")


def audit(ios26_gfx: Path, ios27_gfx: Path) -> dict:
    ios26_hash = hashlib.sha256(ios26_gfx.read_bytes()).hexdigest()
    ios27_hash = hashlib.sha256(ios27_gfx.read_bytes()).hexdigest()
    if ios26_hash != IOS26_GFX_SHA256:
        raise ValueError(f"iOS 26 GFX SHA-256 mismatch: {ios26_hash}")
    if ios27_hash != IOS27_GFX_SHA256:
        raise ValueError(f"iOS 27 GFX SHA-256 mismatch: {ios27_hash}")

    ios26 = _a000(ios26_gfx)
    ios27 = _a000(ios27_gfx)
    ios26_instructions = disassemble_gfx_text(ios26)
    ios27_instructions = disassemble_gfx_text(ios27)
    ios26_producers = analyze_gxf_command_producers(ios26, ios26_instructions)
    ios27_producers = analyze_gxf_command_producers(ios27, ios27_instructions)

    return {
        "status": "IOS26_ONLY_TTBR0_WAKE_ROOT_RELOAD_CANDIDATE",
        "ios26_build": "23A355",
        "ios27_build": "24A446",
        "ios26_gfx_sha256": ios26_hash,
        "ios27_gfx_sha256": ios27_hash,
        "ios26": verify_ios26_route(ios26, ios26_instructions, ios26_producers),
        "ios27_delta": verify_ios27_delta(
            ios27, ios27_instructions, ios27_producers
        ),
        "candidate_chain": [
            "read the live current-context ID and registered root entry",
            "clone the live 16K TTBR0 root into owned DRAM and alter one leaf PA",
            "replace only the selected registered root field while preserving metadata",
            "cause the normal command-3 UAT wake to reload TTBR0 from that entry",
            "test whether the existing MDSID write resolves a low VA through this TTBR0",
            "restore the original registry entry and original TTBR0 through the same wake path",
        ],
        "proven": [
            "local firmware command 3 is constructed and reaches UAT wake",
            "iOS 26 wake reloads TTBR0 from the registered current-context entry",
            "the selected root is masked, valid-bit checked, and bounded to 64 contexts",
            "the 25-bit low region uses one 16K table with 2048 eight-byte leaves",
            "iOS 27 removes both direct command 0x20 and the wake-to-context-root reload",
        ],
        "blocking_contracts": [
            {
                "id": "HOST_WAKE_TRIGGER",
                "question": (
                    "Which bounded userland-visible action deterministically produces the "
                    "statically identified RTBuddy class-0xb power transition while the "
                    "controlled context stays alive?"
                ),
                "status": "STATIC_PRODUCER_FOUND_USERLAND_TRIGGER_PENDING",
            },
            {
                "id": "MDSID_TTBR0_BINDING",
                "question": (
                    "Does the controlled MDSID target VA resolve through the reloaded "
                    "firmware TTBR0 rather than a separate GPU/UAT address space?"
                ),
                "status": "UNPROVEN",
            },
            {
                "id": "ROOT_FRAME_ACCEPTANCE_AND_RESTORE",
                "question": (
                    "Will owned DRAM be accepted as the replacement root, and can both "
                    "the registry entry and active TTBR0 be restored reliably?"
                ),
                "status": "UNPROVEN",
            },
        ],
        "decision": (
            "This is a concrete iOS-26-only physical-write candidate, not yet a "
            "working jailbreak chain. The RTBuddy class-0xb producer-to-command-3 "
            "route is pinned separately; offline work should next define a bounded "
            "app-side power-transition protocol and prove root acceptance and restore "
            "before another IPA is built."
        ),
        "limits": (
            "Static firmware analysis only. No device probe, packet submission, MMIO, "
            "physical write, protected-memory write, or SPTM call was performed."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ios26-gfx", type=Path, required=True)
    parser.add_argument("--ios27-gfx", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.ios26_gfx, args.ios27_gfx)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
