#!/usr/bin/env python3
"""Check the exact 23A355 AGX ProbeConfig address/map dataflow offline."""

from __future__ import annotations

import argparse
import hashlib
import pathlib

import lief
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from disassemble_fileset import mapped_bytes


TARGET_KC_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
CONFIG_BASE = 0xFFFFFFF00AB5EA88
KERNEL_STATIC_BASE = 0xFFFFFFF007004000
IOMEMORYMAP_VTABLE = 0xFFFFFFF007AB4820
A0_META_VTABLE = 0xFFFFFFF007B1E048
BASE_META_VTABLE = 0xFFFFFFF007B1EE48
BASE_INSTANCE_VTABLE = 0xFFFFFFF007B1E0D0


def instructions(binary, start: int, size: int) -> dict[int, tuple[str, str]]:
    code = mapped_bytes(binary, start, size)
    if code is None:
        raise ValueError(f"AGX instruction span not mapped: 0x{start:x}")
    return {item.address: (item.mnemonic, item.op_str) for item in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, start)}


def check(binary, kernel) -> None:
    exec_segment = next((segment for segment in binary.segments if segment.name == "__TEXT_EXEC"), None)
    if exec_segment is None:
        raise ValueError("AGX executable segment missing")
    target_calls = {0xFFFFFFF008816B74: [], 0xFFFFFFF008850900: [], 0xFFFFFFF0088508C8: []}
    for item in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
        bytes(exec_segment.content), exec_segment.virtual_address
    ):
        if item.mnemonic == "bl":
            target = int(item.op_str[1:], 16)
            if target in target_calls:
                target_calls[target].append(item.address)
    direct_callers = target_calls[0xFFFFFFF008816B74]
    if direct_callers != [0xFFFFFFF008851A8C]:
        raise ValueError(f"unexpected direct callers of A0 map setup: {direct_callers}")
    if target_calls[0xFFFFFFF008850900] or target_calls[0xFFFFFFF0088508C8]:
        raise ValueError("unexpected direct caller of AGX register writer/reader")

    blocks = (
        (0xFFFFFFF008816BC8, 0x18),
        (0xFFFFFFF008816CE0, 0x10),
        (0xFFFFFFF008816ED4, 0x20),
        (0xFFFFFFF008816F4C, 0x4),
        (0xFFFFFFF008816F50, 0x1C),
        (0xFFFFFFF008816FC4, 0x20),
        (0xFFFFFFF008816FE4, 0x148),
        (0xFFFFFFF0088174A0, 0x8),
        (0xFFFFFFF0088175EC, 0x8),
    )
    found = {}
    for start, size in blocks:
        found.update(instructions(binary, start, size))
    found.update(instructions(kernel, 0xFFFFFFF0086EB8E4, 0x38))

    expected = {
        0xFFFFFFF008816BC8: ("adrp", "x24, #0xfffffff00ab5e000"),
        0xFFFFFFF008816BD4: ("add", "x23, x23, #0xa88"),
        0xFFFFFFF008816BDC: ("b.eq", "#0xfffffff0088171cc"),
        0xFFFFFFF008816CE0: ("mov", "w25, #2"),
        0xFFFFFFF008816CE4: ("strb", "w25, [x23, #8]"),
        0xFFFFFFF008816ED4: ("mov", "w1, #0"),
        0xFFFFFFF008816ED8: ("strb", "wzr, [x23, #0xc]"),
        0xFFFFFFF008816EDC: ("mov", "w8, #1"),
        0xFFFFFFF008816F4C: ("strb", "w8, [x23, #0xd]"),
        0xFFFFFFF008816F50: ("ldrb", "w8, [x23, #8]"),
        0xFFFFFFF008816F54: ("sub", "w8, w8, #1"),
        0xFFFFFFF008816F58: ("cmp", "w8, #2"),
        0xFFFFFFF008816F5C: ("cset", "w8, lo"),
        0xFFFFFFF008816F64: ("and", "w9, w9, #0xfffffffc"),
        0xFFFFFFF008816F68: ("cinc", "w9, w9, lo"),
        0xFFFFFFF008816FC4: ("mov", "w10, #0xeb"),
        0xFFFFFFF008816FC8: ("and", "w9, w9, w10"),
        0xFFFFFFF008816FCC: ("orr", "w8, w8, w9"),
        0xFFFFFFF008816FE0: ("strb", "w8, [x23, #0x11]"),
        0xFFFFFFF008816FE4: ("ldr", "x8, [x23, #0x18]"),
        0xFFFFFFF008817000: ("mov", "x17, #0x3c8"),
        0xFFFFFFF008817020: ("bl", "#0xfffffff0086eb8e4"),
        0xFFFFFFF008817024: ("str", "x0, [x23, #0x18]"),
        0xFFFFFFF008817028: ("ldrb", "w1, [x23, #0xd]"),
        0xFFFFFFF00881705C: ("mov", "x17, #0x3c8"),
        0xFFFFFFF00881707C: ("bl", "#0xfffffff0086eb8e4"),
        0xFFFFFFF008817080: ("str", "x0, [x23, #0x20]"),
        0xFFFFFFF0088170A0: ("tbz", "w8, #0, #0xfffffff00881712c"),
        0xFFFFFFF0088170A8: ("ldrb", "w1, [x23, #0xc]"),
        0xFFFFFFF0088170BC: ("mov", "x17, #0x3d0"),
        0xFFFFFFF0088170DC: ("str", "x0, [x23, #0x30]"),
        0xFFFFFFF0088170E0: ("cbz", "x0, #0xfffffff008817400"),
        0xFFFFFFF0088170E8: ("tbz", "w8, #2, #0xfffffff00881712c"),
        0xFFFFFFF0088170F0: ("ldrb", "w1, [x23, #0xd]"),
        0xFFFFFFF008817104: ("mov", "x17, #0x3d0"),
        0xFFFFFFF008817124: ("str", "x0, [x23, #0x38]"),
        0xFFFFFFF008817128: ("cbz", "x0, #0xfffffff008817550"),
        0xFFFFFFF0088174A0: ("add", "x0, x0, #0"),
        0xFFFFFFF0088175F0: ("add", "x0, x0, #0x79"),
        0xFFFFFFF0086EB904: ("mov", "x1, #0"),
        0xFFFFFFF0086EB908: ("mov", "x2, #0"),
        0xFFFFFFF0086EB90C: ("mov", "w3, #0"),
    }
    for address, wanted in expected.items():
        actual = found.get(address)
        if actual != wanted:
            raise ValueError(f"0x{address:x}: expected {wanted}, got {actual}")

    literals = {
        0xFFFFFFF0070F9000: b"Could not map GPU reg range",
        0xFFFFFFF0070F9079: b"Could not map Fender reg range",
    }
    for address, wanted in literals.items():
        value = mapped_bytes(binary, address, 128)
        if value is None or wanted not in value.split(b"\0", 1)[0]:
            raise ValueError(f"missing AGX map failure literal at 0x{address:x}")

    entry = mapped_bytes(kernel, IOMEMORYMAP_VTABLE + 0x78, 8)
    if entry is None or int.from_bytes(entry, "little") != 0x801134F6016DC5DC:
        raise ValueError("unexpected IOMemoryMap slot 0x78 chained pointer")
    accessor = KERNEL_STATIC_BASE + (int.from_bytes(entry, "little") & 0xFFFFFFFF)
    if instructions(kernel, accessor, 12) != {
        accessor: ("bti", "c"),
        accessor + 4: ("ldr", "x0, [x0, #0x28]"),
        accessor + 8: ("ret", ""),
    }:
        raise ValueError("IOMemoryMap slot 0x78 no longer returns fAddress")

    follow = instructions(binary, 0xFFFFFFF0088171E4, 0x30)
    read = instructions(binary, 0xFFFFFFF0088508CC, 0x10)
    write = instructions(binary, 0xFFFFFFF008850900, 0x124)
    expected_follow = {
        0xFFFFFFF0088171E4: ("ldr", "x0, [x23, #0x30]"),
        0xFFFFFFF0088171F8: ("ldr", "x8, [x16, #0x78]!"),
        0xFFFFFFF008817208: ("blraa", "x8, x17"),
        0xFFFFFFF00881720C: ("str", "x0, [x20, #0x310]"),
    }
    expected_read = {
        0xFFFFFFF0088508CC: ("ldr", "x8, [x0, #0x310]"),
        0xFFFFFFF0088508D0: ("add", "x8, x8, #0x11, lsl #12"),
        0xFFFFFFF0088508D4: ("add", "x8, x8, #0x108"),
        0xFFFFFFF0088508D8: ("ldr", "x8, [x8]"),
    }
    expected_write = {
        0xFFFFFFF008850924: ("mov", "x19, x0"),
        0xFFFFFFF008850928: ("ldr", "x10, [x0, #0x3b8]"),
        0xFFFFFFF00885092C: ("ldr", "x8, [x0, #0x3c0]"),
        0xFFFFFFF008850954: ("mov", "w9, #0"),
        0xFFFFFFF0088509C4: ("add", "w25, w9, #1"),
        0xFFFFFFF008850A0C: ("mov", "x25, x9"),
        0xFFFFFFF008850A10: ("mov", "x9, x8"),
        0xFFFFFFF008850A14: ("ldr", "x8, [x19, #0x310]"),
        0xFFFFFFF008850A18: ("add", "x10, x24, x8"),
        0xFFFFFFF008850A1C: ("str", "w9, [x10, #0xf20]"),
    }
    for actual, expected in ((follow, expected_follow), (read, expected_read), (write, expected_write)):
        for address, wanted in expected.items():
            if actual.get(address) != wanted:
                raise ValueError(f"0x{address:x}: expected {wanted}, got {actual.get(address)}")
    writer_start = 0xFFFFFFF008850900
    first_mmio_store = 0xFFFFFFF008850A1C
    writer_prefix = mapped_bytes(binary, writer_start, first_mmio_store + 4 - writer_start)
    if writer_prefix is None:
        raise ValueError("AGX writer prefix not mapped")
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    decoded_prefix = list(disassembler.disasm(writer_prefix, writer_start))
    if not decoded_prefix or decoded_prefix[-1].address != first_mmio_store:
        raise ValueError("AGX writer prefix does not end at the expected MMIO store")
    argument_registers = {f"{width}{index}" for width in ("x", "w") for index in range(1, 8)}
    argument_reads = [
        (item.address, item.reg_name(register))
        for item in decoded_prefix
        for register in item.regs_access()[0]
        if item.reg_name(register) in argument_registers
    ]
    if argument_reads:
        raise ValueError(f"AGX writer now reads an incoming x1-x7 argument: {argument_reads}")
    setup = instructions(binary, 0xFFFFFFF008850958, 0x10)
    if setup.get(0xFFFFFFF008850960) != ("mov", "w24, #0xe0") or setup.get(
        0xFFFFFFF008850964
    ) != ("movk", "w24, #1, lsl #16"):
        raise ValueError("AGX sample write offset setup changed")

    a0_meta_init = instructions(binary, 0xFFFFFFF008856524, 0x40)
    expected_a0_meta = {
        0xFFFFFFF008856524: ("adrp", "x0, #0xfffffff00ab5e000"),
        0xFFFFFFF008856528: ("add", "x0, x0, #0x528"),
        0xFFFFFFF008856530: ("add", "x1, x1, #0xc9b"),
        0xFFFFFFF008856548: ("adrp", "x16, #0xfffffff007b1e000"),
        0xFFFFFFF00885654C: ("add", "x16, x16, #0x38"),
        0xFFFFFFF008856550: ("add", "x16, x16, #0x10"),
        0xFFFFFFF008856560: ("str", "x16, [x0]"),
    }
    for address, wanted in expected_a0_meta.items():
        if a0_meta_init.get(address) != wanted:
            raise ValueError(f"A0 metaclass initializer changed at 0x{address:x}")
    if mapped_bytes(binary, A0_META_VTABLE - 0x18, 0x18) != bytes(0x18):
        raise ValueError("A0 metaclass vtable boundary changed")

    base_ctor = instructions(binary, 0xFFFFFFF0088583F4, 0x198)
    expected_base_ctor = {
        0xFFFFFFF0088583F4: ("adrp", "x0, #0xfffffff007b24000"),
        0xFFFFFFF0088583F8: ("add", "x0, x0, #0x840"),
        0xFFFFFFF0088583FC: ("mov", "w1, #0x7bb8"),
        0xFFFFFFF008858400: ("movk", "w1, #1, lsl #16"),
        0xFFFFFFF008858404: ("bl", "#0xfffffff0085fb7bc"),
        0xFFFFFFF008858438: ("adrp", "x20, #0xfffffff00ab5e000"),
        0xFFFFFFF00885843C: ("add", "x20, x20, #0x640"),
        0xFFFFFFF008858440: ("mov", "x1, x20"),
        0xFFFFFFF008858444: ("bl", "#0xfffffff009f4396c"),
        0xFFFFFFF008858450: ("str", "xzr, [x0, #0x310]"),
        0xFFFFFFF008858570: ("adrp", "x16, #0xfffffff007b1e000"),
        0xFFFFFFF008858574: ("add", "x16, x16, #0xc0"),
        0xFFFFFFF008858578: ("add", "x16, x16, #0x10"),
        0xFFFFFFF008858588: ("str", "x16, [x0]"),
    }
    for address, wanted in expected_base_ctor.items():
        if base_ctor.get(address) != wanted:
            raise ValueError(f"base AGX instance constructor changed at 0x{address:x}")
    if mapped_bytes(binary, BASE_INSTANCE_VTABLE - 0x18, 0x18) != bytes(0x18):
        raise ValueError("base AGX instance vtable start boundary changed")
    if mapped_bytes(binary, 0xFFFFFFF007B1EE30, 0x18) != bytes(0x18):
        raise ValueError("base AGX instance vtable end boundary changed")
    base_instance_methods = {
        0x2A8: 0xFFFFFFF008851A7C,
        0x7B8: 0xFFFFFFF008850900,
        0x7C0: 0xFFFFFFF0088508C8,
    }
    for offset, target in base_instance_methods.items():
        raw = mapped_bytes(binary, BASE_INSTANCE_VTABLE + offset, 8)
        if raw is None or KERNEL_STATIC_BASE + (int.from_bytes(raw, "little") & 0xFFFFFFFF) != target:
            raise ValueError(f"base AGX instance vtable method at +0x{offset:x} changed")

    setup_entry = instructions(binary, 0xFFFFFFF008851A7C, 0x54)
    expected_setup_entry = {
        0xFFFFFFF008851A7C: ("pacibsp", ""),
        0xFFFFFFF008851A8C: ("bl", "#0xfffffff008816b74"),
        0xFFFFFFF008851A90: ("mov", "x19, x0"),
        0xFFFFFFF008851A9C: ("ldrb", "w8, [x20, #0x11]"),
        0xFFFFFFF008851AA0: ("tbz", "w8, #4, #0xfffffff008851ad0"),
        0xFFFFFFF008851ACC: ("strb", "w8, [x20, #0x11]"),
    }
    for address, wanted in expected_setup_entry.items():
        if setup_entry.get(address) != wanted:
            raise ValueError(f"base AGX setup dispatch changed at 0x{address:x}")

    a0_literal = b"AGXAcceleratorG14P_A0"
    a0_name = mapped_bytes(binary, 0xFFFFFFF007100C9B, len(a0_literal))
    if a0_name != a0_literal:
        raise ValueError("A0 AGX class literal changed")
    base_name = mapped_bytes(binary, 0xFFFFFFF007100CD7, 18)
    if base_name != b"AGXAcceleratorG14P":
        raise ValueError("base AGX class literal changed")
    base_init = instructions(binary, 0xFFFFFFF00885875C, 0x38)
    expected_base_init = {
        0xFFFFFFF008858760: ("add", "x1, x1, #0xcd7"),
        0xFFFFFFF008858778: ("adrp", "x16, #0xfffffff007b1e000"),
        0xFFFFFFF00885877C: ("add", "x16, x16, #0xe38"),
        0xFFFFFFF008858780: ("add", "x16, x16, #0x10"),
        0xFFFFFFF008858790: ("str", "x16, [x0]"),
    }
    for address, wanted in expected_base_init.items():
        if base_init.get(address) != wanted:
            raise ValueError(f"base AGX vtable initializer changed at 0x{address:x}")
    if mapped_bytes(binary, BASE_META_VTABLE - 0x18, 0x18) != bytes(0x18):
        raise ValueError("base AGX metaclass vtable boundary changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=pathlib.Path)
    args = parser.parse_args()
    if hashlib.sha256(args.kernelcache.read_bytes()).hexdigest() != TARGET_KC_SHA256:
        raise ValueError("unexpected kernelcache SHA-256")
    lief.logging.disable()
    container = lief.parse(str(args.kernelcache))
    address = 0xFFFFFFF008816ED4
    binary = next(
        (item for item in container.filesets if mapped_bytes(item, address, 4) is not None),
        None,
    )
    if binary is None or getattr(binary, "fileset_name", "") != "com.apple.AGXG14P":
        raise ValueError("AGXG14P fileset entry not found")
    if not any(
        segment.name == "__DATA"
        and segment.virtual_address <= CONFIG_BASE
        and CONFIG_BASE + 0x40 <= segment.virtual_address + segment.virtual_size
        for segment in binary.segments
    ):
        raise ValueError("ProbeConfig fields not inside AGXG14P __DATA")
    kernel_address = 0xFFFFFFF0086EB8E4
    kernel = next(
        (item for item in container.filesets if mapped_bytes(item, kernel_address, 4) is not None),
        None,
    )
    if kernel is None or getattr(kernel, "fileset_name", "") != "com.apple.kernel":
        raise ValueError("kernel fileset entry not found")
    check(binary, kernel)
    print(f"PASS AGX ProbeConfig __DATA base=0x{CONFIG_BASE:x}")
    print("count=2 selects descriptor 0 as GPU and descriptor 1 as Fender")
    print("candidate physical fields: +0x18 GPU, +0x20 Fender")
    print("fresh-provider count=2 forces GPU map bit 0; Fender map uses bit 2")
    print("map results: +0x30 GPU, +0x38 Fender")
    print("IOMemoryMap slot 0x78 returns fAddress; GPU map VA saved at AGX object +0x310")
    print("base AGX G14P instance vtable links setup and +0x310 reader/writer; sample offsets: read +0x11108, write +0x11000")
    print("A0/base metaclass tables are distinct from the base instance table; A0 runtime presence unresolved")
    print("base-instance method is the only direct AGXG14P call into this map setup function")
    print("base-instance setup entry calls map routine before its later flag-4 check; runtime dispatch unobserved")
    print("AGX register writer uses fixed map offset +0x11000; no x1-x7 argument read before first store or direct BL caller in AGXG14P")
    print("requested null map returns branch to verification failures")
    print("offline static control flow only; no runtime MMIO access or protected-range write proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
