#!/usr/bin/env python3
"""Verify the minimal AGX 3D packet route from parsing to context allocation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from analyze_sptm_txm import MachOImage


IMAGE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
SPTM_SHA256 = "ed7781d2d82fe4818b85dd18c6b07dc172440eeecc2f7b33fc1e048313583f7c"
AGX_IMAGE = "com.apple.AGXG14P"
IOGPU_IMAGE = "com.apple.iokit.IOGPUFamily"
KERNEL_IMAGE = "com.apple.kernel"
STATIC_BASE = 0xfffffff007004000

PACKET_SIZE = 0x550
PREFIX_ID_OFFSET = 0x0
COMMAND_SIZE_OFFSET = 0x4
GENERIC_OFFSET = 0x8
GENERIC_SIZE = 0xc0
NESTED_LENGTH_OFFSET = 0xa4
KIND_OFFSET = 0xa8
PAYLOAD_OFFSET = 0xc8
PAYLOAD_SIZE = 0x488
PAYLOAD_SENTINEL_OFFSET = 0x388
PACKET_SENTINEL_OFFSET = PAYLOAD_OFFSET + PAYLOAD_SENTINEL_OFFSET

PACKET_ID = 0x10000
PACKET_KIND_3D = 2
RESOURCE_FREE_SENTINEL = 0xffffffff

DESCRIPTOR_VTABLE = 0xfffffff007b227f0
CONTEXT_SLOT_OFFSET = 0x90
CONTEXT_SLOT_ENCODING = 0x8011bed3017d45f0
CONTEXT_SLOT_TARGET = 0xfffffff0087d85f0


AGX_EXPECTED = {
    0xfffffff00885b240: ("adds", "x9, x8, #8"),
    0xfffffff00885b254: ("ldr", "x8, [x8]"),
    0xfffffff008858a9c: ("adds", "x19, x8, #0xc0"),
    0xfffffff008858ac8: ("mov", "w2, #0xc0"),
    0xfffffff008858b14: ("ldr", "w8, [x0, #0xac]"),
    0xfffffff0088055dc: ("ldr", "w8, [sp, #0x30]"),
    0xfffffff0088055e0: ("cmp", "w8, #0x10, lsl #12"),
    0xfffffff0088057f8: ("cmp", "w8, #2"),
    0xfffffff0088057fc: ("b.ne", "#0xfffffff008805b64"),
    0xfffffff00880587c: ("bl", "#0xfffffff0088177e0"),
    0xfffffff0088058dc: ("bl", "#0xfffffff0088064e0"),
    0xfffffff008817808: ("adds", "x9, x8, #0x488"),
    0xfffffff008817864: ("ldr", "x11, [x8, #0x388]"),
    0xfffffff008817870: ("str", "x11, [x0, #0x98]"),
    0xfffffff0088178a8: ("mov", "w8, #1"),
    0xfffffff0088066a4: ("bl", "#0xfffffff00880b228"),
    0xfffffff0088066a8: ("tbz", "w0, #0, #0xfffffff008806880"),
    0xfffffff008806718: ("ldr", "x0, [x19, #0x840]"),
    0xfffffff008806720: ("bl", "#0xfffffff009f3025c"),
    0xfffffff008867ef4: ("ldr", "w8, [x3]"),
    0xfffffff008867ef8: ("cmn", "w8, #1"),
    0xfffffff008867f20: ("mov", "w8, #1"),
    0xfffffff00880c140: ("ldr", "w8, [x20, #0x98]"),
    0xfffffff00880c144: ("cbz", "w8, #0xfffffff00880c23c"),
    0xfffffff00880c23c: ("mov", "w0, #1"),
    0xfffffff0087d867c: ("ldrb", "w8, [x19, #0x222]"),
    0xfffffff0087d86e8: ("bl", "#0xfffffff0087f04a4"),
    0xfffffff0087d86ec: ("str", "w0, [x19, #0x1c4]"),
}

IOGPU_EXPECTED = {
    0xfffffff009f4bdac: ("ldr", "w8, [x1, #4]"),
    0xfffffff009f4bdbc: ("cmp", "w8, #8"),
    0xfffffff009f4bdf4: ("blraa", "x8, x17"),
    0xfffffff009f3031c: ("str", "x20, [x10]"),
    0xfffffff009f30328: ("stlr", "w8, [x9]"),
    0xfffffff009f30358: ("b", "#0xfffffff009f335e8"),
    0xfffffff009f338a4: ("bl", "#0xfffffff009f2faac"),
    0xfffffff009f2fb04: ("ldr", "x19, [x10]"),
    0xfffffff009f2fb1c: ("ldr", "w8, [x8, #0x158]"),
    0xfffffff009f2fb74: ("ldr", "x8, [x16, #0x90]!"),
    0xfffffff009f2fb88: ("movk", "x17, #0xbed3, lsl #48"),
    0xfffffff009f2fb8c: ("blraa", "x8, x17"),
}

PROTECTED_AGX_EXPECTED = {
    0xfffffff0087d86c4: ("mov", "w9, #0xeed0"),
    0xfffffff0087d86c8: ("add", "x0, x8, x9"),
    0xfffffff0087f0608: ("add", "x8, x16, #0x128"),
    0xfffffff0087f0614: ("mov", "x1, x24"),
    0xfffffff0087f0618: ("mov", "x2, x23"),
    0xfffffff0087f0624: ("blraa", "x9, x17"),
    0xfffffff00887b970: ("str", "w20, [x9]"),
    0xfffffff00887b984: ("tbz", "w9, #0, #0xfffffff00887b99c"),
    0xfffffff00887b988: ("ldr", "x0, [x8, #0x10]"),
    0xfffffff00887b98c: ("mov", "x1, x20"),
    0xfffffff00887b990: ("mov", "w2, #0"),
    0xfffffff00887b994: ("bl", "#0xfffffff008760e44"),
}

AGX_REMOVAL_EXPECTED = {
    # The GART slot removes the old protected registration before publishing
    # the replacement context ID in the per-kind field.
    0xfffffff00887b91c: ("ldr", "w8, [x19, #0x1e8]"),
    0xfffffff00887b92c: ("ldr", "w8, [x19, #0x1f4]"),
    0xfffffff00887b944: ("ldr", "x0, [x8, #0x10]"),
    0xfffffff00887b948: ("bl", "#0xfffffff008760f88"),
    0xfffffff00887b970: ("str", "w20, [x9]"),
    # Allocation holds allocator+8, consumes allocator+0x40/+0x48, and only
    # drops the lock after the GART callback and bookkeeping complete.
    0xfffffff0087f04e0: ("ldr", "x0, [x0, #8]"),
    0xfffffff0087f04e4: ("bl", "#0xfffffff007fe12ac"),
    0xfffffff0087f057c: ("ldr", "x9, [x19, #0x40]"),
    0xfffffff0087f0584: ("str", "w10, [x19, #0x48]"),
    0xfffffff0087f0624: ("blraa", "x9, x17"),
    0xfffffff0087f0a2c: ("ldr", "x0, [x19, #8]"),
    0xfffffff0087f0a30: ("bl", "#0xfffffff007fe2080"),
    # Destruction uses device+0xeed8, the same allocator lock, invokes the
    # GART removal, then pushes the ID to device+0xef10 before unlocking.
    0xfffffff008867234: ("ldr", "x8, [x0, #0x10]"),
    0xfffffff008867238: ("add", "x20, x8, #0xe, lsl #12"),
    0xfffffff00886723c: ("ldr", "x0, [x20, #0xed8]"),
    0xfffffff008867240: ("bl", "#0xfffffff007fe12ac"),
    0xfffffff0088672f4: ("blraa", "x9, x17"),
    0xfffffff00886733c: ("ldr", "x8, [x20, #0xf10]"),
    0xfffffff008867348: ("str", "w9, [x20, #0xf18]"),
    0xfffffff008867364: ("str", "w21, [x10]"),
    0xfffffff0088676d4: ("ldr", "x0, [x20, #0xed8]"),
    0xfffffff0088676d8: ("bl", "#0xfffffff007fe2080"),
}

KERNEL_EXPECTED = {
    0xfffffff008760e5c: ("stur", "w1, [x29, #-0x14]"),
    0xfffffff008760ec4: ("ldr", "x0, [x19, #0x20]"),
    0xfffffff008760ed4: ("mov", "w1, #0xbee0"),
    0xfffffff008760ed8: ("mov", "w3, #4"),
    0xfffffff008760ee4: ("mov", "x17, #0x5070"),
    0xfffffff0081350e0: ("mov", "w8, #4"),
    0xfffffff0081350e8: ("cmp", "x3, #4"),
    0xfffffff0081350f4: ("ldr", "w22, [x2]"),
    0xfffffff008135118: ("ldr", "x0, [x0, #0x20]"),
    0xfffffff00813511c: ("and", "w1, w22, #0xffff"),
    0xfffffff008135120: ("bl", "#0xfffffff0087b3504"),
    0xfffffff0087b350c: ("movk", "x16, #7, lsl #32"),
    0xfffffff0087b3514: ("movk", "x16, #0xa"),
}

KERNEL_REMOVAL_EXPECTED = {
    0xfffffff008761004: ("mov", "w1, #0xbee1"),
    0xfffffff008761008: ("mov", "x2, #0"),
    0xfffffff00876100c: ("mov", "x3, #0"),
    0xfffffff008761010: ("mov", "x4, #0"),
    0xfffffff008761014: ("mov", "x5, #0"),
    0xfffffff00876101c: ("blraa", "x8, x17"),
    0xfffffff008134eb4: ("mov", "x8, #0"),
    0xfffffff008134ed8: ("ldr", "x0, [x0, #0x20]"),
    0xfffffff008134edc: ("bl", "#0xfffffff0087b351c"),
    0xfffffff0087b3524: ("movk", "x16, #7, lsl #32"),
    0xfffffff0087b352c: ("movk", "x16, #0xb"),
}

SPTM_EXPECTED = {
    0xfffffff0270a00b0: ("mov", "x19, x1"),
    0xfffffff0270a00c0: ("and", "w8, w19, #0xffff"),
    0xfffffff0270a00c4: ("cmp", "w8, #0x40"),
    0xfffffff0270a00cc: ("ldrh", "w8, [x0, #0x18]"),
    0xfffffff0270a00d0: ("mov", "w9, #0xffff"),
    0xfffffff0270a0110: ("strh", "w19, [x0, #0x18]"),
    0xfffffff0270a0124: ("ldp", "x12, x14, [x11]"),
    0xfffffff0270a012c: ("tbnz", "w15, #0, #0xfffffff0270a02b4"),
    0xfffffff0270a0130: ("ldrb", "w12, [x0]"),
    0xfffffff0270a0138: ("tst", "w12, w14"),
    0xfffffff0270a0164: ("tst", "w12, #0xe"),
    0xfffffff0270a018c: ("str", "x12, [x11]"),
    0xfffffff0270a0194: ("str", "x13, [x9, #8]"),
}

SPTM_REMOVAL_EXPECTED = {
    0xfffffff02709fac4: ("mov", "w1, #2"),
    0xfffffff02709fac8: ("mov", "w2, #5"),
    0xfffffff02709facc: ("bl", "#0xfffffff0270ae734"),
    0xfffffff02709fad0: ("ldrh", "w20, [x0, #0x18]"),
    0xfffffff02709fad4: ("cmp", "w20, #0x40"),
    0xfffffff02709faf4: ("ldr", "w8, [x8]"),
    0xfffffff02709faf8: ("cbnz", "w8, #0xfffffff02709fce0"),
    0xfffffff02709fb50: ("tbz", "w9, #0, #0xfffffff02709fd3c"),
    0xfffffff02709fb58: ("tbz", "w9, #0, #0xfffffff02709fd3c"),
    0xfffffff02709fb8c: ("ldur", "x8, [x29, #-0x40]"),
    0xfffffff02709fb90: ("str", "x8, [x10]"),
    0xfffffff02709fb94: ("dsb", "oshst"),
    0xfffffff02709fbe8: ("lsl", "x8, x8, #0x30"),
    0xfffffff02709fbec: ("tlbi", "aside1os, x8"),
    0xfffffff02709fbf0: ("dsb", "osh"),
    0xfffffff02709fc08: ("mov", "w8, #0xffff"),
    0xfffffff02709fc0c: ("strh", "w8, [x0, #0x18]"),
}


def build_minimal_packet() -> bytes:
    packet = bytearray(PACKET_SIZE)
    struct.pack_into("<I", packet, PREFIX_ID_OFFSET, PACKET_ID)
    struct.pack_into("<I", packet, COMMAND_SIZE_OFFSET, PACKET_SIZE)
    struct.pack_into("<I", packet, NESTED_LENGTH_OFFSET, PAYLOAD_SIZE)
    struct.pack_into("<I", packet, KIND_OFFSET, PACKET_KIND_3D)
    struct.pack_into("<I", packet, PACKET_SENTINEL_OFFSET, RESOURCE_FREE_SENTINEL)
    return bytes(packet)


def validate_minimal_packet(packet: bytes) -> dict:
    if len(packet) != PACKET_SIZE:
        raise ValueError(f"packet size: expected {PACKET_SIZE:#x}, got {len(packet):#x}")
    expected = {
        PREFIX_ID_OFFSET: PACKET_ID,
        COMMAND_SIZE_OFFSET: PACKET_SIZE,
        NESTED_LENGTH_OFFSET: PAYLOAD_SIZE,
        KIND_OFFSET: PACKET_KIND_3D,
        PACKET_SENTINEL_OFFSET: RESOURCE_FREE_SENTINEL,
    }
    for offset, value in expected.items():
        actual = struct.unpack_from("<I", packet, offset)[0]
        if actual != value:
            raise ValueError(f"packet field {offset:#x}: expected {value:#x}, got {actual:#x}")
    allowed = set()
    for offset in expected:
        allowed.update(range(offset, offset + 4))
    unexpected = next((index for index, value in enumerate(packet)
                       if value and index not in allowed), None)
    if unexpected is not None:
        raise ValueError(f"unexpected nonzero packet byte at {unexpected:#x}")
    return {
        "size": f"{len(packet):#x}",
        "prefix_id": f"{PACKET_ID:#x}",
        "kind": PACKET_KIND_3D,
        "payload_offset": f"{PAYLOAD_OFFSET:#x}",
        "payload_size": f"{PAYLOAD_SIZE:#x}",
        "resource_free_sentinel_offset": f"{PACKET_SENTINEL_OFFSET:#x}",
        "resource_free_sentinel": f"{RESOURCE_FREE_SENTINEL:#x}",
    }


def require_instruction(image: MachOImage, address: int, expected: tuple[str, str]) -> None:
    instruction = image.instruction_at(address)
    actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
    if actual != expected:
        raise ValueError(f"instruction {address:#x}: expected {expected}, got {actual}")


def verify_route(agx: MachOImage, iogpu: MachOImage) -> dict:
    for address, expected in AGX_EXPECTED.items():
        require_instruction(agx, address, expected)
    for address, expected in IOGPU_EXPECTED.items():
        require_instruction(iogpu, address, expected)

    slot = DESCRIPTOR_VTABLE + CONTEXT_SLOT_OFFSET
    encoding = agx.read_u64(slot)
    target = None if encoding is None else STATIC_BASE + (encoding & 0xffffffff)
    if (encoding, target) != (CONTEXT_SLOT_ENCODING, CONTEXT_SLOT_TARGET):
        raise ValueError(f"3D context slot {slot:#x}: got {encoding} -> {target}")

    return {
        "parser": {
            "chunk_size_field": "+0x4",
            "prefix_id": f"{PACKET_ID:#x}",
            "generic_header_size": f"{GENERIC_SIZE:#x}",
            "kind": PACKET_KIND_3D,
            "kind_parser": "0xfffffff0088177e0",
            "deep_setup": "0xfffffff00880b228",
        },
        "lifecycle": {
            "descriptor_factory": "0xfffffff0088064e0",
            "ring_insert": "0xfffffff009f3025c",
            "ring_worker": "0xfffffff009f335e8",
            "descriptor_dispatch": "0xfffffff009f2faac",
            "context_slot": f"{slot:#x}",
            "context_slot_encoding": f"{encoding:#x}",
            "context_slot_target": f"{target:#x}",
            "dynamic_context_allocator": "0xfffffff0087f04a4",
        },
        "resource_contract": {
            "optional_lists_may_be_empty": True,
            "first_resource_id_uses_minus_one_sentinel": True,
            "sentinel_gate": "0xfffffff008867ed8",
        },
    }


def verify_protected_registration(
    agx: MachOImage,
    kernel: MachOImage,
    sptm: MachOImage,
) -> dict:
    for address, expected in PROTECTED_AGX_EXPECTED.items():
        require_instruction(agx, address, expected)
    for address, expected in KERNEL_EXPECTED.items():
        require_instruction(kernel, address, expected)
    for address, expected in SPTM_EXPECTED.items():
        require_instruction(sptm, address, expected)

    return {
        "agx_context_allocator": "0xfffffff0087f04a4",
        "agx_gart_register_context": "0xfffffff00887b8c4",
        "runtime_mode_one_target": "0xfffffff008760e44",
        "kernel_method": "0xbee0",
        "kernel_input_size": "0x4",
        "kernel_context_mask": "0xffff",
        "protected_stub": "table=7 entry=10",
        "sptm_handler": "0xfffffff0270a009c",
        "sptm_guards": [
            "context_id_below_0x40",
            "descriptor_context_id_is_0xffff",
            "both_global_context_slots_are_empty",
            "descriptor_type_is_uat_eligible",
        ],
        "packet_controls_context_id": False,
        "packet_controls_translation_roots": False,
        "effect": "registers driver-selected context ID against pre-existing typed roots",
    }


def verify_protected_removal(
    agx: MachOImage,
    kernel: MachOImage,
    sptm: MachOImage,
) -> dict:
    for address, expected in AGX_REMOVAL_EXPECTED.items():
        require_instruction(agx, address, expected)
    for address, expected in KERNEL_REMOVAL_EXPECTED.items():
        require_instruction(kernel, address, expected)
    for address, expected in SPTM_REMOVAL_EXPECTED.items():
        require_instruction(sptm, address, expected)

    return {
        "agx_gart_context_slot": "0xfffffff00887b8c4",
        "agx_context_release": "0xfffffff008867218",
        "runtime_mode_one_target": "0xfffffff008760f88",
        "kernel_method": "0xbee1",
        "kernel_input_size": "0x0",
        "protected_stub": "table=7 entry=11",
        "sptm_handler": "0xfffffff02709faac",
        "context_id_source": "protected_descriptor_plus_0x18",
        "sptm_guards": [
            "context_id_below_0x40",
            "per_context_outstanding_state_is_zero",
            "both_global_context_slots_are_present",
            "descriptor_type_is_uat_eligible",
            "context_is_not_current_global_context",
        ],
        "sptm_effects": [
            "clear_both_global_context_slot_valid_bits",
            "publish_before_tlb_invalidate_with_dsb_oshst",
            "invalidate_context_asid",
            "complete_invalidation_with_dsb_osh",
            "reset_descriptor_context_id_to_0xffff",
        ],
        "allocator_base": "device_plus_0xeed0",
        "allocator_lock": "device_plus_0xeed8",
        "free_id_stack": "device_plus_0xef10",
        "free_id_count": "device_plus_0xef18",
        "remove_precedes_id_publish": True,
        "remove_precedes_free_id_push": True,
        "allocation_and_release_share_lock": True,
        "early_reuse_mismatch": False,
    }


def audit(kernelcache: Path, sptm_path: Path) -> dict:
    image_hash = hashlib.sha256(kernelcache.read_bytes()).hexdigest()
    if image_hash != IMAGE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {image_hash}")
    sptm_hash = hashlib.sha256(sptm_path.read_bytes()).hexdigest()
    if sptm_hash != SPTM_SHA256:
        raise ValueError(f"SPTM SHA-256 mismatch: {sptm_hash}")
    packet = build_minimal_packet()
    agx = MachOImage(kernelcache, AGX_IMAGE)
    result = verify_route(agx, MachOImage(kernelcache, IOGPU_IMAGE))
    kernel = MachOImage(kernelcache, KERNEL_IMAGE)
    sptm = MachOImage(sptm_path)
    result["protected_registration"] = verify_protected_registration(agx, kernel, sptm)
    result["protected_removal"] = verify_protected_removal(agx, kernel, sptm)
    result.update({
        "build": "23A355",
        "kernelcache_sha256": image_hash,
        "sptm_sha256": sptm_hash,
        "minimal_packet": validate_minimal_packet(packet),
        "minimal_packet_sha256": hashlib.sha256(packet).hexdigest(),
        "status": "STATIC_3D_SPTM_REGISTER_REMOVE_LIFECYCLE_CONFIRMED_RUNTIME_PENDING",
        "limits": (
            "This proves a legitimate AGX context-registration and serialized removal "
            "route. It closes the simple early-ID-reuse mismatch, but does not prove "
            "protected-memory mutation, an SPTM bypass, a physical-write primitive, "
            "or a jailbreak. No device probe ran."
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
