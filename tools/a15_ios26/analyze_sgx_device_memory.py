#!/usr/bin/env python3
"""Resolve the captured A15 sgx register windows without touching the device."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import struct

from analyze_devicetree import Node, parse_node, walk


TARGET_DT_SHA256 = "c7d59f0364cdb504ee32881142b03dadcea85fe5808de7dd69e63bea7a9d5725"


def u32_property(node: Node, name: str) -> int:
    value = node.properties[name]
    if len(value) != 4:
        raise ValueError(f"{name}: expected one 32-bit cell")
    return struct.unpack("<I", value)[0]


def u64_pairs(value: bytes, name: str) -> list[tuple[int, int]]:
    if len(value) % 16:
        raise ValueError(f"{name}: incomplete two-cell address/size pair")
    return list(struct.iter_unpack("<QQ", value))


def resolve_reg(
    reg: list[tuple[int, int]], ranges: list[tuple[int, int, int]]
) -> list[tuple[int, int]]:
    """Resolve direct-child reg pairs through one 2/2/2-cell parent ranges table."""
    resolved = []
    for address, length in reg:
        if not length or address + length > 1 << 64:
            raise ValueError("invalid reg extent")
        matches = [
            parent + address - child
            for child, parent, size in ranges
            if size and child <= address and address + length <= child + size
        ]
        if len(matches) != 1:
            raise ValueError(f"reg 0x{address:x}/0x{length:x} resolves to {len(matches)} ranges")
        resolved.append((matches[0], length))
    return resolved


def io_ranges(value: bytes) -> list[tuple[int, int, int, str]]:
    if len(value) % 24:
        raise ValueError("pmap-io-ranges: incomplete record")
    return [
        (address, length, wimg, struct.pack(">I", signature).decode("ascii", errors="replace"))
        for address, length, wimg, signature in struct.iter_unpack("<QQII", value)
    ]


def intersection(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int] | None:
    start = max(a[0], b[0])
    end = min(a[0] + a[1], b[0] + b[1])
    return (start, end - start) if start < end else None


def analyze(blob: bytes) -> tuple[list[tuple[int, int]], list[list[tuple[int, int, int, str]]]]:
    root, end = parse_node(blob)
    if any(blob[end:]):
        raise ValueError("nonzero trailing DeviceTree data")
    nodes = dict(walk(root))
    parent = nodes["/device-tree/arm-io"]
    sgx = nodes["/device-tree/arm-io/sgx"]
    defaults = nodes["/device-tree/defaults"]
    if root.properties.get("model", b"").rstrip(b"\0") != b"iPhone14,2":
        raise ValueError("unexpected target model")
    if sgx.properties.get("compatible", b"").rstrip(b"\0") != b"gpu,t8110":
        raise ValueError("unexpected sgx compatible")
    if (u32_property(parent, "#address-cells"), u32_property(parent, "#size-cells")) != (2, 2):
        raise ValueError("unsupported arm-io cell layout")
    if (u32_property(root, "#address-cells"), u32_property(root, "#size-cells")) != (2, 2):
        raise ValueError("unsupported root cell layout")
    raw_ranges = parent.properties["ranges"]
    if len(raw_ranges) % 24:
        raise ValueError("arm-io ranges: incomplete 2/2/2-cell entry")
    ranges = list(struct.iter_unpack("<QQQ", raw_ranges))
    resolved = resolve_reg(u64_pairs(sgx.properties["reg"], "sgx.reg"), ranges)
    deny = [item for item in io_ranges(defaults.properties["pmap-io-ranges"]) if item[3] == "DENY"]
    overlaps = [
        [(hit[0], hit[1], item[2], item[3]) for item in deny if (hit := intersection(reg, item[:2]))]
        for reg in resolved
    ]
    return resolved, overlaps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("devicetree", type=pathlib.Path)
    args = parser.parse_args()
    blob = args.devicetree.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != TARGET_DT_SHA256:
        raise ValueError(f"unexpected DeviceTree SHA-256: {digest}")
    resolved, overlaps = analyze(blob)
    for index, ((address, length), hits) in enumerate(zip(resolved, overlaps)):
        print(f"sgx.reg[{index}] candidate physical=0x{address:x} length=0x{length:x}")
        for hit, size, wimg, signature in hits:
            print(f"  overlaps {signature} physical=0x{hit:x} length=0x{size:x} wimg=0x{wimg:x}")
    print("offline geometry only; no runtime descriptor, map, or MMIO access proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
