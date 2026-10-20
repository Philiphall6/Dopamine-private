#!/usr/bin/env python3
"""Prove the 23A355 MDSID packet-to-GXF-TTBR0 write route offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from analyze_sptm_txm import MachOImage
from analyze_titan import disassemble_gfx_text, parse_gfx_images


KERNELCACHE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
GFX_SHA256 = "3b245807d7a65241890e0d1d31566fed221082322de784779824a2e11464a98b"
AGX_IMAGE = "com.apple.AGXG14P"
KERNEL_STATIC_BASE = 0xFFFFFFF007004000

FIRMWARE_VTABLE = 0xFFFFFFF007B19AB8
FIRMWARE_SEND_SLOT = FIRMWARE_VTABLE + 0x1B8
FIRMWARE_SEND_ENCODING = 0x80110CBF0183E040
FIRMWARE_SEND_TARGET = 0xFFFFFFF008842040
FIRMWARE_ADDRESS_SLOT = FIRMWARE_VTABLE + 0x210
FIRMWARE_ADDRESS_ENCODING = 0x801192500183DD6C
FIRMWARE_ADDRESS_TARGET = 0xFFFFFFF008841D6C

GXF_DISPATCH_TABLE = 0xFFFFFF8000002974
GXF_DISPATCH_ANCHOR = 0xFFFFFF8000003CB0
GXF_MDSID_PACKET_TYPE = 0xE
GXF_MDSID_HANDLER = 0xFFFFFF800000463C
GXF_T0SZ = 0x27


KERNEL_EXPECTED = {
    # processKernelCommand computes GPUVirtualAddress + buffer offset.
    0xFFFFFFF008804970: ("add", "x8, x16, #0x98"),
    0xFFFFFFF008804980: ("blraa", "x9, x17"),
    0xFFFFFFF008804984: ("ldr", "w8, [x21, #0x498]"),
    0xFFFFFFF008804988: ("add", "x9, x0, x20, lsl #2"),
    0xFFFFFFF0088049B8: ("add", "x10, x16, #0x210"),
    0xFFFFFFF0088049C0: ("add", "x1, x9, x8"),
    0xFFFFFFF0088049C4: ("mov", "w2, #0"),
    0xFFFFFFF0088049D0: ("blraa", "x11, x17"),
    0xFFFFFFF0088049D4: ("str", "x0, [sp, #0x20]"),
    # The exact runtime firmware implementation returns the address unchanged.
    FIRMWARE_ADDRESS_TARGET: ("bti", "c"),
    FIRMWARE_ADDRESS_TARGET + 4: ("mov", "x0, x1"),
    FIRMWARE_ADDRESS_TARGET + 8: ("ret", ""),
    # Packet type 0x0e, target +4, value +0xc, ID +0x14.
    0xFFFFFFF008804A9C: ("mov", "w8, #0xe"),
    0xFFFFFFF008804AA0: ("str", "w8, [sp, #0x80]"),
    0xFFFFFFF008804AA4: ("strb", "w20, [sp, #0x94]"),
    0xFFFFFFF008804AA8: ("ldr", "x8, [sp, #0x20]"),
    0xFFFFFFF008804AAC: ("stur", "x8, [sp, #0x84]"),
    0xFFFFFFF008804AB0: ("stp", "w22, w23, [sp, #0x8c]"),
    0xFFFFFFF008804B5C: ("add", "x2, sp, #0x80"),
    # The callback selects device+0x4a0 and virtual slot +0x1b8.
    0xFFFFFFF0087F1C6C: ("ldr", "x0, [x22, #0x4a0]"),
    0xFFFFFFF0087F1C90: ("mov", "x17, #0x1b8"),
    0xFFFFFFF0087F1C94: ("add", "x16, x16, x17"),
    0xFFFFFFF0087F1CD0: ("braa", "x16, x17"),
    # Final firmware sender reaches the common 0x30-byte ring copier.
    FIRMWARE_SEND_TARGET + 0x68: ("mov", "x0, x20"),
    FIRMWARE_SEND_TARGET + 0x70: ("bl", "#0xfffffff00881bb58"),
    0xFFFFFFF00881BD04: ("mov", "w8, #0x30"),
    0xFFFFFFF00881BD08: ("umull", "x8, w0, w8"),
    0xFFFFFFF00881BD20: ("ldp", "q0, q1, [x21]"),
    0xFFFFFFF00881BD24: ("ldr", "q2, [x21, #0x20]"),
    0xFFFFFFF00881BD28: ("stp", "q1, q2, [x9, #0x10]"),
    0xFFFFFFF00881BD2C: ("str", "q0, [x9]"),
}


GFX_EXPECTED = {
    # Ring consumer: 0x30-byte entries, packet type at +0, bounded switch.
    0xFFFFFF8000003C6C: ("mov", "w11, #0x30"),
    0xFFFFFF8000003C70: ("umaddl", "x20, w9, w11, x10"),
    0xFFFFFF8000003C74: ("ldr", "w9, [x20]"),
    0xFFFFFF8000003C8C: ("sub", "w16, w9, #4"),
    0xFFFFFF8000003C90: ("cmp", "w16, #0x30"),
    0xFFFFFF8000003CAC: ("ldrsw", "x16, [x17, x16, lsl #2]"),
    0xFFFFFF8000003CB8: ("br", "x16"),
    # Type 0x0e handler consumes the exact kernel packet fields.
    GXF_MDSID_HANDLER: ("ldrb", "w21, [x20, #0x14]"),
    GXF_MDSID_HANDLER + 4: ("ldur", "x22, [x20, #4]"),
    GXF_MDSID_HANDLER + 8: ("ldr", "w23, [x20, #0xc]"),
    GXF_MDSID_HANDLER + 0xC: ("ldr", "w9, [x20, #0x10]"),
    0xFFFFFF80000046D4: ("str", "w23, [x22]"),
}


def _require_kernel_instructions(image, expected=KERNEL_EXPECTED) -> None:
    for address, wanted in expected.items():
        instruction = image.instruction_at(address)
        observed = (
            None
            if instruction is None
            else (instruction.mnemonic, instruction.op_str)
        )
        if observed != wanted:
            raise ValueError(
                f"kernel instruction {address:#x}: expected {wanted}, got {observed}"
            )


def _instruction_map(instructions: list[dict]) -> dict[int, tuple[str, str]]:
    return {
        item["address"]: (item["mnemonic"], item["op_str"])
        for item in instructions
    }


def _require_gfx_instructions(instructions: list[dict], expected=GFX_EXPECTED) -> None:
    actual = _instruction_map(instructions)
    for address, wanted in expected.items():
        observed = actual.get(address)
        if observed != wanted:
            raise ValueError(
                f"GFX instruction {address:#x}: expected {wanted}, got {observed}"
            )


def _decode_kernel_slot(image, slot: int, encoding: int, target: int) -> None:
    observed = image.read_u64(slot)
    decoded = None if observed is None else KERNEL_STATIC_BASE + (observed & 0xFFFFFFFF)
    if (observed, decoded) != (encoding, target):
        raise ValueError(
            f"firmware vtable slot {slot:#x}: expected {encoding:#x} -> "
            f"{target:#x}, got {observed!r} -> {decoded!r}"
        )


def verify_kernel_route(image) -> dict:
    _require_kernel_instructions(image)
    _decode_kernel_slot(
        image,
        FIRMWARE_ADDRESS_SLOT,
        FIRMWARE_ADDRESS_ENCODING,
        FIRMWARE_ADDRESS_TARGET,
    )
    _decode_kernel_slot(
        image,
        FIRMWARE_SEND_SLOT,
        FIRMWARE_SEND_ENCODING,
        FIRMWARE_SEND_TARGET,
    )
    return {
        "command": "MDSID update (0x10002)",
        "target_expression": "IOGPUMemoryMap.GPUVirtualAddress + dsid*4 + IOGPUState.buffer_offset",
        "target_transform": {
            "slot": f"{FIRMWARE_ADDRESS_SLOT:#x}",
            "target": f"{FIRMWARE_ADDRESS_TARGET:#x}",
            "effect": "identity: returns x1 unchanged",
        },
        "packet": {
            "type": f"{GXF_MDSID_PACKET_TYPE:#x}",
            "size": "0x30",
            "target_offset": "0x4",
            "value_offset": "0xc",
            "dsid_offset": "0x14",
        },
        "transport": {
            "firmware_send_slot": f"{FIRMWARE_SEND_SLOT:#x}",
            "firmware_send_target": f"{FIRMWARE_SEND_TARGET:#x}",
            "ring_entry_size": "0x30",
            "full_packet_copy": True,
        },
    }


def verify_gfx_route(image, instructions: list[dict]) -> dict:
    _require_gfx_instructions(instructions)
    table_index = GXF_MDSID_PACKET_TYPE - 4
    offset = struct.unpack(
        "<i", image.read(GXF_DISPATCH_TABLE + table_index * 4, 4)
    )[0]
    target = (GXF_DISPATCH_ANCHOR + offset) & ((1 << 64) - 1)
    if target != GXF_MDSID_HANDLER:
        raise ValueError(
            f"GXF packet {GXF_MDSID_PACKET_TYPE:#x} dispatches to {target:#x}, "
            f"expected {GXF_MDSID_HANDLER:#x}"
        )
    return {
        "ring_entry_size": "0x30",
        "packet_type": f"{GXF_MDSID_PACKET_TYPE:#x}",
        "dispatch_table": f"{GXF_DISPATCH_TABLE:#x}",
        "dispatch_target": f"{target:#x}",
        "field_binding": {
            "target": "packet+0x4 -> x22",
            "value": "packet+0xc -> w23",
            "dsid": "packet+0x14 -> w21",
        },
        "terminal_effect": "str w23, [x22]",
    }


def verify_binding(kernel_image, gfx_image, gfx_instructions: list[dict]) -> dict:
    kernel = verify_kernel_route(kernel_image)
    gfx = verify_gfx_route(gfx_image, gfx_instructions)
    low_va_bits = 0x40 - GXF_T0SZ
    low_va_limit = 1 << low_va_bits
    return {
        "status": "MDSID_GXF_TTBR0_BINDING_PROVED_OFFLINE",
        "kernel_route": kernel,
        "gfx_route": gfx,
        "address_space_binding": {
            "translation_owner": "GXF CPU store",
            "tcr_t0sz": f"{GXF_T0SZ:#x}",
            "low_va_bits": low_va_bits,
            "ttbr0_window": f"0x0..{low_va_limit - 1:#x}",
            "rule": (
                "a target VA below 2^(64-T0SZ) is translated through the active "
                "GXF TTBR0_EL1 loaded by the command-3 wake route"
            ),
            "kernel_target_range_check_after_identity_transform": False,
        },
        "closed_blocker": "MDSID_TTBR0_BINDING",
        "remaining_blockers": [
            "HOST_WAKE_TRIGGER",
            "ROOT_FRAME_ACCEPTANCE_AND_RESTORE",
        ],
    }


def _a000(path: Path):
    return next(image for image in parse_gfx_images(path) if image.label == "a000")


def audit(kernelcache: Path, gfx: Path) -> dict:
    kernel_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    gfx_hash = hashlib.sha256(gfx.read_bytes()).hexdigest()
    if kernel_hash != KERNELCACHE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {kernel_hash}")
    if gfx_hash != GFX_SHA256:
        raise ValueError(f"GFX SHA-256 mismatch: {gfx_hash}")
    gfx_image = _a000(gfx)
    result = verify_binding(
        MachOImage(kernelcache, AGX_IMAGE),
        gfx_image,
        disassemble_gfx_text(gfx_image),
    )
    result.update(
        {
            "build": "23A355",
            "kernelcache_sha256": kernel_hash,
            "gfx_sha256": gfx_hash,
            "limits": (
                "Exact-image static analysis only. No device probe, packet submission, "
                "MMIO, physical write, protected-memory write, or SPTM call was performed."
            ),
        }
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernelcache", type=Path, required=True)
    parser.add_argument("--gfx", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.kernelcache, args.gfx)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
