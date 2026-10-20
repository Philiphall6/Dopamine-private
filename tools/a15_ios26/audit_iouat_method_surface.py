#!/usr/bin/env python3
"""Pin the iOS 26 IOUAT BEE2-BEE7 surface, BEE6 constraints, and BEE7 root read."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analyze_sptm_txm import MachOImage


KERNELCACHE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
SPTM_SHA256 = "ed7781d2d82fe4818b85dd18c6b07dc172440eeecc2f7b33fc1e048313583f7c"
KERNEL_IMAGE = "com.apple.kernel"
KERNEL_STATIC_BASE = 0xfffffff007004000

IOUAT_FACTORY_VTABLE = 0xfffffff007aed3a0
BEE7_VTABLE_SLOT = IOUAT_FACTORY_VTABLE + 0x90
BEE7_VTABLE_ENCODING = 0x801163390175b844
BEE7_WRAPPER = 0xfffffff00875f844

METHOD_STRINGS = {
    "taskDied": 0xfffffff0070abac8,
    "prepareFWUnmap": 0xfffffff0070abd5d,
    "getTotalPageTableMemory": 0xfffffff0070abf11,
    "isPageFaultExpected": 0xfffffff0070abfa2,
    "getPageTablePhysicalBaseAddress": 0xfffffff0070ac036,
    "getPageTableEntry": 0xfffffff0070ac0df,
}

CALLER_EXPECTED = {
    # BEE2: taskDied(), no structure input or output.
    0xfffffff00875fe74: ("mov", "w1, #0xbee2"),
    0xfffffff00875fe78: ("mov", "x2, #0"),
    0xfffffff00875fe7c: ("mov", "x3, #0"),
    0xfffffff00875fe80: ("mov", "x4, #0"),
    0xfffffff00875fe84: ("mov", "x5, #0"),
    # BEE3: getTotalPageTableMemory(), eight-byte output.
    0xfffffff00875fbf4: ("mov", "w1, #0xbee3"),
    0xfffffff00875fbf8: ("mov", "x2, #0"),
    0xfffffff00875fbfc: ("mov", "x3, #0"),
    0xfffffff00875fc00: ("mov", "w5, #8"),
    # BEE4: isPageFaultExpected(), 0x10-byte input and one-byte output.
    0xfffffff00875fa88: ("mov", "w1, #0xbee4"),
    0xfffffff00875fa8c: ("mov", "w3, #0x10"),
    0xfffffff00875fa90: ("mov", "w5, #1"),
    # BEE5: getPageTableEntry(), eight-byte input and output.
    0xfffffff00875f788: ("mov", "w1, #0xbee5"),
    0xfffffff00875f78c: ("mov", "w3, #8"),
    0xfffffff00875f790: ("mov", "w5, #8"),
    # BEE6: prepareFWUnmap(address, length), 0x10-byte input and bool output.
    0xfffffff008761a58: ("stp", "x19, x21, [sp, #0x30]"),
    0xfffffff008761ac0: ("mov", "w1, #0xbee6"),
    0xfffffff008761ac4: ("mov", "w3, #0x10"),
    0xfffffff008761ac8: ("mov", "w5, #1"),
    0xfffffff008761acc: ("bl", "#0xfffffff008115494"),
    # BEE7: getPageTablePhysicalBaseAddress(index), four-byte input and
    # eight-byte output.
    0xfffffff00875f8ec: ("ldr", "x0, [x19, #0x20]"),
    0xfffffff00875f8f8: ("mov", "w1, #0xbee7"),
    0xfffffff00875f8fc: ("mov", "w3, #4"),
    0xfffffff00875f900: ("mov", "w5, #8"),
}

BEE7_DISPATCH_EXPECTED = {
    # BEE7 validates a four-byte index and an eight-byte output. Root zero
    # always uses the receiver; root one may use the alternate global object.
    0xfffffff008135070: ("mov", "w9, #0xbee7"),
    0xfffffff008135074: ("cmp", "x1, x9"),
    0xfffffff00813507c: ("mov", "w8, #4"),
    0xfffffff008135080: ("cbz", "x2, #0xfffffff0081358ac"),
    0xfffffff008135084: ("cmp", "x3, #4"),
    0xfffffff00813508c: ("cbz", "x19, #0xfffffff0081358ac"),
    0xfffffff008135090: ("cmp", "x5, #8"),
    0xfffffff008135098: ("ldr", "w8, [x2]"),
    0xfffffff0081350a4: ("ldr", "x10, [x9]"),
    0xfffffff0081350a8: ("cmp", "x10, #0"),
    0xfffffff0081350ac: ("ccmp", "w8, #1, #0, eq"),
    0xfffffff0081350b4: ("csel", "x21, x9, x0, eq"),
    0xfffffff0081350bc: ("ldr", "x0, [x21, #0x20]"),
    0xfffffff0081350c0: ("and", "w20, w8, #0xff"),
    0xfffffff0081350c8: ("mov", "x1, x20"),
    0xfffffff0081350cc: ("bl", "#0xfffffff0087b2dd8"),
    0xfffffff0081350d8: ("ldr", "x9, [sp, #0x48]"),
}

BEE7_PAPT_HELPER_EXPECTED = {
    # Translate the protected descriptor physical address through the same
    # 24-byte PAPT range format used by libjailbreak's sptm_phystokv().
    0xfffffff0087b2dd8: ("bti", "c"),
    0xfffffff0087b2de0: ("cmp", "w1, #1"),
    0xfffffff0087b2de4: ("b.hi", "#0xfffffff0087b2e58"),
    0xfffffff0087b2de8: ("cbz", "x2, #0xfffffff0087b2e58"),
    0xfffffff0087b2dec: ("adrp", "x8, #0xfffffff007af0000"),
    0xfffffff0087b2df0: ("ldr", "x8, [x8, #0x758]"),
    0xfffffff0087b2df4: ("add", "x8, x8, #8"),
    0xfffffff0087b2dfc: ("add", "x8, x8, #0x18"),
    0xfffffff0087b2e00: ("ldur", "x10, [x8, #-8]"),
    0xfffffff0087b2e04: ("subs", "x9, x0, x10"),
    0xfffffff0087b2e08: ("b.lo", "#0xfffffff0087b2dfc"),
    0xfffffff0087b2e0c: ("ldr", "w11, [x8, #8]"),
    0xfffffff0087b2e10: ("add", "x10, x10, x11, lsl #14"),
    0xfffffff0087b2e18: ("b.ls", "#0xfffffff0087b2dfc"),
    0xfffffff0087b2e1c: ("ldr", "x8, [x8]"),
    0xfffffff0087b2e20: ("add", "x9, x9, x8"),
    0xfffffff0087b2e24: ("ldrb", "w8, [x9]"),
    0xfffffff0087b2e28: ("cmp", "w1, #0"),
    0xfffffff0087b2e2c: ("mov", "w10, #0xf1"),
    0xfffffff0087b2e30: ("mov", "w11, #0xfa"),
    0xfffffff0087b2e34: ("csel", "w10, w11, w10, eq"),
    0xfffffff0087b2e38: ("tst", "w10, w8"),
    0xfffffff0087b2e3c: ("b.eq", "#0xfffffff0087b2e48"),
    0xfffffff0087b2e48: ("mov", "w8, #0"),
    0xfffffff0087b2e4c: ("add", "x9, x9, #8"),
    0xfffffff0087b2e50: ("ldr", "x9, [x9, w1, uxtw #3]"),
    0xfffffff0087b2e54: ("str", "x9, [x2]"),
}

BEE6_DISPATCH_EXPECTED = {
    0xfffffff00813525c: ("mov", "w8, #4"),
    0xfffffff008135260: ("cbz", "x2, #0xfffffff0081358ac"),
    0xfffffff008135264: ("cmp", "x3, #0x10"),
    0xfffffff00813526c: ("cbz", "x19, #0xfffffff0081358ac"),
    0xfffffff008135270: ("cmp", "x5, #1"),
    0xfffffff008135278: ("ldr", "x1, [x2]"),
    0xfffffff0081352ac: ("and", "x8, x20, #0x3fff"),
    0xfffffff0081352b4: ("cmp", "x8, x10"),
    0xfffffff0081352d8: ("ldr", "x8, [x20, #0x18]"),
    0xfffffff0081352dc: ("cmp", "x8, x9"),
    0xfffffff0081352e4: ("ldr", "x8, [x2, #8]"),
    0xfffffff0081352e8: ("ldr", "x0, [x20, #0x20]"),
    0xfffffff0081352ec: ("lsr", "x2, x8, #0xe"),
    0xfffffff0081352f0: ("bl", "#0xfffffff0087b34a4"),
    0xfffffff0081352f4: ("cmp", "w0, #1"),
    0xfffffff0081352fc: ("ldr", "x0, [x20, #0x20]"),
    0xfffffff008135300: ("bl", "#0xfffffff0087b34bc"),
    0xfffffff008135304: ("cmp", "w0, #1"),
    0xfffffff008135310: ("cmp", "w0, #2"),
    0xfffffff008135314: ("cset", "w9, eq"),
    0xfffffff008135318: ("strb", "w9, [x19]"),
}

PROTECTED_STUB_EXPECTED = {
    0xfffffff0087b34a4: ("bti", "c"),
    0xfffffff0087b34ac: ("movk", "x16, #7, lsl #32"),
    0xfffffff0087b34b4: ("movk", "x16, #6"),
    0xfffffff0087b34bc: ("bti", "c"),
    0xfffffff0087b34c4: ("movk", "x16, #7, lsl #32"),
    0xfffffff0087b34cc: ("movk", "x16, #7"),
}

SPTM_BEE6_EXPECTED = {
    # Begin: validate the protected state, preserve caller address/page count,
    # locate an existing tracked range, and publish it into protected state.
    0xfffffff0270a143c: ("mov", "x21, x2"),
    0xfffffff0270a1440: ("mov", "x22, x1"),
    0xfffffff0270a1458: ("bl", "#0xfffffff0270ae734"),
    0xfffffff0270a1474: ("mov", "x8, #-0x4000000000000"),
    0xfffffff0270a147c: ("cmp", "x9, x8"),
    0xfffffff0270a1488: ("lsl", "x1, x21, #0xe"),
    0xfffffff0270a1494: ("mov", "x0, x22"),
    0xfffffff0270a1498: ("mov", "x2, x20"),
    0xfffffff0270a149c: ("bl", "#0xfffffff0270aec2c"),
    0xfffffff0270a14a0: ("ldr", "x8, [sp, #0x38]"),
    0xfffffff0270a14a4: ("stp", "x8, xzr, [x20, #0x20]"),
    0xfffffff0270a14a8: ("str", "x21, [x20, #0x30]"),
    0xfffffff0270a14b4: ("mov", "w9, #4"),
    0xfffffff0270a14bc: ("caslb", "w10, w9, [x8]"),
    0xfffffff0270a14e8: ("bl", "#0xfffffff0270a1120"),
    # Range lookup: enforce 16 KiB alignment and containment in a tracked
    # lower/upper bound before returning the accepted start address.
    0xfffffff0270aec68: ("tst", "x0, #0x3fff"),
    0xfffffff0270aec70: ("cbz", "x1, #0xfffffff0270aed74"),
    0xfffffff0270aec74: ("and", "x10, x1, #0x3fff"),
    0xfffffff0270aec7c: ("sub", "x10, x1, #1"),
    0xfffffff0270aec80: ("adds", "x10, x0, x10"),
    0xfffffff0270aed30: ("cmp", "x0, x12"),
    0xfffffff0270aed34: ("b.lo", "#0xfffffff0270aedb4"),
    0xfffffff0270aed38: ("cmp", "x10, x13"),
    0xfffffff0270aed3c: ("b.hi", "#0xfffffff0270aedb4"),
    0xfffffff0270aed44: ("str", "x0, [x3]"),
    # Continue: walk only the saved range, mark eligible PTEs, invalidate,
    # and publish the completed range against the existing context ID.
    0xfffffff0270a1150: ("ldp", "x9, x22, [x0, #0x28]"),
    0xfffffff0270a1160: ("ldr", "x19, [x0, #0x20]"),
    0xfffffff0270a116c: ("add", "x20, x19, x9, lsl #14"),
    0xfffffff0270a11e4: ("orr", "x9, x9, #8"),
    0xfffffff0270a11e8: ("str", "x9, [x8]"),
    0xfffffff0270a125c: ("dsb", "oshst"),
    0xfffffff0270a1264: ("mov", "x1, x19"),
    0xfffffff0270a1268: ("mov", "x2, x20"),
    0xfffffff0270a1270: ("bl", "#0xfffffff02709fe80"),
    0xfffffff0270a1278: ("ldrh", "w9, [x21, #0x18]"),
    0xfffffff0270a127c: ("cmp", "x9, #0x40"),
    0xfffffff0270a12b0: ("str", "x19, [x8, #8]"),
    0xfffffff0270a12b4: ("str", "x20, [x8, #0x10]"),
    0xfffffff0270a12cc: ("mov", "w19, #2"),
    0xfffffff0270a130c: ("dsb", "osh"),
}

METHODS = (
    ("0xbee2", "taskDied", "0x0", "0x0", "lifecycle_cleanup"),
    ("0xbee3", "getTotalPageTableMemory", "0x0", "0x8", "read_only_counter"),
    ("0xbee4", "isPageFaultExpected", "0x10", "0x1", "read_only_predicate"),
    ("0xbee5", "getPageTableEntry", "0x8", "0x8", "read_only_pte_query"),
    ("0xbee6", "prepareFWUnmap", "0x10", "0x1", "constrained_existing_mapping_mutation"),
    ("0xbee7", "getPageTablePhysicalBaseAddress", "0x4", "0x8", "read_only_root_query"),
)


def require_instruction(image: MachOImage, address: int, expected: tuple[str, str]) -> None:
    instruction = image.instruction_at(address)
    actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
    if actual != expected:
        raise ValueError(f"instruction {address:#x}: expected {expected}, got {actual}")


def verify_kernel_surface(kernel: MachOImage) -> dict:
    for name, address in METHOD_STRINGS.items():
        if address not in kernel.find_string(name):
            raise ValueError(f"method string {name!r} missing at {address:#x}")
    for expected in (
        CALLER_EXPECTED,
        BEE6_DISPATCH_EXPECTED,
        BEE7_DISPATCH_EXPECTED,
        BEE7_PAPT_HELPER_EXPECTED,
        PROTECTED_STUB_EXPECTED,
    ):
        for address, instruction in expected.items():
            require_instruction(kernel, address, instruction)

    encoding = kernel.read_u64(BEE7_VTABLE_SLOT)
    target = None if encoding is None else KERNEL_STATIC_BASE + (encoding & 0xffffffff)
    if (encoding, target) != (BEE7_VTABLE_ENCODING, BEE7_WRAPPER):
        raise ValueError(
            f"BEE7 vtable slot {BEE7_VTABLE_SLOT:#x}: expected "
            f"{BEE7_VTABLE_ENCODING:#x} -> {BEE7_WRAPPER:#x}, got "
            f"{encoding!r} -> {target!r}"
        )

    return {
        "methods": [
            {
                "method": method,
                "name": name,
                "input_size": input_size,
                "output_size": output_size,
                "effect": effect,
            }
            for method, name, input_size, output_size, effect in METHODS
        ],
        "bee6_dispatch": {
            "caller": "0xfffffff0087619f8",
            "kernel_dispatch_case": "0xfffffff00813525c",
            "begin_stub": "table=7 entry=6 @ 0xfffffff0087b34a4",
            "continue_stub": "table=7 entry=7 @ 0xfffffff0087b34bc",
            "input": ["virtual_address", "length"],
            "length_to_pages": "length >> 14",
            "success_value": 2,
        },
        "bee7_root_mirror": {
            "iouat_vtable": f"{IOUAT_FACTORY_VTABLE:#x}",
            "vtable_slot": f"{BEE7_VTABLE_SLOT:#x}",
            "wrapper": f"{BEE7_WRAPPER:#x}",
            "wrapper_receiver_field": "IOUAT+0x20",
            "dispatcher": "0xfffffff008134e14",
            "dispatch_case": "0xfffffff008135070",
            "protected_descriptor_field": "dispatch-object+0x20",
            "papt_helper": "0xfffffff0087b2dd8",
            "papt_ranges_global": "0xfffffff007af0758",
            "papt_entry": {
                "size": "0x18",
                "physical_start": "0x0",
                "kernel_alias_start": "0x8",
                "page_count": "0x10",
                "page_shift": 14,
            },
            "descriptor_alias_expression": (
                "descriptor_pa - physical_start + kernel_alias_start"
            ),
            "descriptor_flags_offset": "0x0",
            "root_offsets": ["0x8", "0x10"],
            "root0_uses_receiver_unconditionally": True,
            "requires_sptm_call": False,
            "matches_libjailbreak_sptm_phystokv_layout": True,
            "read_only_recipe": [
                "dispatch_object = kread_ptr(iouat + 0x20)",
                "descriptor_pa = kread64(dispatch_object + 0x20)",
                "descriptor_alias = sptm_phystokv(descriptor_pa)",
                "root0 = kread64(descriptor_alias + 0x8)",
                "root1 = kread64(descriptor_alias + 0x10)",
            ],
            "classification": "ACTIVE_ROOT_DISCOVERY_STATICALLY_CLOSED_RUNTIME_PENDING",
        },
    }


def verify_sptm_prepare_fw_unmap(sptm: MachOImage) -> dict:
    for address, instruction in SPTM_BEE6_EXPECTED.items():
        require_instruction(sptm, address, instruction)

    return {
        "begin": "0xfffffff0270a1420",
        "continue": "0xfffffff0270a1120",
        "tracked_range_helper": "0xfffffff0270aec2c",
        "constraints": [
            "protected_uat_state_type_is_valid",
            "address_is_16k_aligned",
            "length_is_nonzero_and_16k_aligned",
            "address_plus_length_does_not_overflow",
            "requested_range_is_contained_in_an_existing_tracked_mapping",
            "walk_uses_the_mapping_pointer_returned_by_the_tracked_range_helper",
            "context_id_is_below_0x40_before_completion_is_published",
        ],
        "effects": [
            "mark_eligible_ptes_in_the_saved_mapping_range",
            "synchronize_and_invalidate_the_saved_range",
            "publish_completed_range_for_the_existing_context",
        ],
        "capabilities": {
            "mutates_existing_tracked_mapping": True,
            "accepts_arbitrary_untracked_range": False,
            "controls_physical_target": False,
            "replaces_translation_root": False,
            "creates_new_mapping": False,
        },
        "classification": "CONSTRAINED_EXISTING_MAPPING_OPERATION_NOT_ARBITRARY_PRIMITIVE",
    }


def audit(kernelcache: Path, sptm_path: Path) -> dict:
    kernel_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    if kernel_hash != KERNELCACHE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {kernel_hash}")
    sptm_hash = hashlib.sha256(sptm_path.read_bytes()).hexdigest()
    if sptm_hash != SPTM_SHA256:
        raise ValueError(f"SPTM SHA-256 mismatch: {sptm_hash}")

    result = verify_kernel_surface(MachOImage(kernelcache, KERNEL_IMAGE))
    result["bee6_sptm"] = verify_sptm_prepare_fw_unmap(MachOImage(sptm_path))
    result.update({
        "build": "23A355",
        "kernelcache_sha256": kernel_hash,
        "sptm_sha256": sptm_hash,
        "status": "STATIC_IOUAT_SURFACE_PINNED_BEE7_ROOT_DISCOVERY_CLOSED",
        "decision": (
            "BEE7 statically closes read-only discovery of both active root fields "
            "through the protected descriptor's PAPT alias; runtime confirmation is "
            "still pending. BEE6 is a real protected mutation route, but it only "
            "prepares an already tracked UAT mapping for firmware unmap and does not "
            "supply an arbitrary physical write, root replacement, or SPTM bypass."
        ),
        "limits": (
            "Static analysis only. No device probe, packet submission, MMIO, "
            "physical write, or protected-memory write was performed."
        ),
    })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=Path)
    parser.add_argument("--sptm", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.kernelcache, args.sptm)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
