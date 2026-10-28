#!/usr/bin/env python3
"""Build deterministic, valid ISO9660/Joliet control images for V5.

The images are ordinary archives.  They deliberately stay below the 1024-byte
UTF-16BE pathname buffer used by the observed caller; they are not exploit
payloads and are never submitted automatically by CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
from dataclasses import dataclass, field
from pathlib import Path


SECTOR = 2048
FIRST_DIRECTORY_SECTOR = 30
PATH_TABLE_L_SECTOR = 24
PATH_TABLE_L_OPTIONAL_SECTOR = 25
PATH_TABLE_M_SECTOR = 26
PATH_TABLE_M_OPTIONAL_SECTOR = 27
DIRECTORY_DATE = bytes((126, 10, 28, 0, 0, 0, 0))


@dataclass
class FileEntry:
    name: str
    ascii_name: str
    payload: bytes
    extent: int = 0


@dataclass
class Directory:
    name: str
    ascii_name: str
    parent: "Directory | None" = None
    ascii_extent: int = 0
    joliet_extent: int = 0
    children: list["Directory"] = field(default_factory=list)
    files: list[FileEntry] = field(default_factory=list)


def both_endian(value: int, size: int) -> bytes:
    if size == 2:
        return value.to_bytes(2, "little") + value.to_bytes(2, "big")
    if size == 4:
        return value.to_bytes(4, "little") + value.to_bytes(4, "big")
    raise ValueError(size)


def put_both(block: bytearray, offset: int, value: int, size: int) -> None:
    block[offset : offset + size * 2] = both_endian(value, size)


def joliet_name(value: str) -> bytes:
    encoded = value.encode("utf-16-be")
    if len(encoded) > 255:
        raise ValueError(f"Joliet identifier too long: {value!r}")
    return encoded


def directory_record(name: bytes, extent: int, size: int, is_directory: bool) -> bytes:
    padding = 1 if len(name) % 2 == 0 else 0
    length = 33 + len(name) + padding
    if length > 255:
        raise ValueError(f"directory record too large: {length}")
    record = bytearray(length)
    record[0] = length
    record[1] = 0
    record[2:10] = both_endian(extent, 4)
    record[10:18] = both_endian(size, 4)
    record[18:25] = DIRECTORY_DATE
    record[25] = 2 if is_directory else 0
    record[26] = 0
    record[27] = 0
    record[28:32] = both_endian(1, 2)
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    if padding:
        record[-1] = 0
    return bytes(record)


def directory_bytes(directory: Directory, joliet: bool) -> bytes:
    directory_extent = directory.joliet_extent if joliet else directory.ascii_extent
    parent_extent = (
        directory.parent.joliet_extent if joliet else directory.parent.ascii_extent
    ) if directory.parent else directory_extent
    records = [
        directory_record(b"\x00", directory_extent, SECTOR, True),
        directory_record(b"\x01", parent_extent, SECTOR, True),
    ]
    for child in directory.children:
        name = joliet_name(child.name) if joliet else child.ascii_name.encode("ascii")
        child_extent = child.joliet_extent if joliet else child.ascii_extent
        records.append(directory_record(name, child_extent, SECTOR, True))
    for file_entry in directory.files:
        name = joliet_name(file_entry.name) if joliet else file_entry.ascii_name.encode("ascii")
        records.append(directory_record(name, file_entry.extent, len(file_entry.payload), False))
    data = b"".join(records)
    if len(data) > SECTOR:
        raise ValueError(f"directory does not fit in one sector: {directory.name}")
    return data + bytes(SECTOR - len(data))


def flatten_directories(root: Directory) -> list[Directory]:
    result: list[Directory] = []
    queue = [root]
    while queue:
        current = queue.pop(0)
        result.append(current)
        queue[0:0] = current.children
    return result


def path_table_bytes(root: Directory, joliet: bool, big_endian: bool) -> bytes:
    directories = flatten_directories(root)
    indexes = {id(directory): index + 1 for index, directory in enumerate(directories)}
    output = bytearray()
    for directory in directories:
        if directory is root:
            name = b"\x00"
            parent_index = 1
        else:
            name = joliet_name(directory.name) if joliet else directory.ascii_name.encode("ascii")
            parent_index = indexes[id(directory.parent)]
        output.append(len(name))
        output.append(0)
        extent = directory.joliet_extent if joliet else directory.ascii_extent
        output.extend(extent.to_bytes(4, "big" if big_endian else "little"))
        output.extend(parent_index.to_bytes(2, "big" if big_endian else "little"))
        output.extend(name)
        if len(name) % 2:
            output.append(0)
    return bytes(output)


def root_record(root: Directory, joliet: bool) -> bytes:
    extent = root.joliet_extent if joliet else root.ascii_extent
    return directory_record(b"\x00", extent, SECTOR, True)


def descriptor(
    kind: int,
    volume_id: str,
    root: Directory,
    total_sectors: int,
    path_table_size: int,
    joliet: bool,
) -> bytes:
    block = bytearray(SECTOR)
    block[0] = kind
    block[1:6] = b"CD001"
    block[6] = 1
    block[8:40] = b"DOPAMINE V5 CONTROL".ljust(32, b" ")
    block[40:72] = volume_id.encode("ascii").ljust(32, b" ")[:32]
    put_both(block, 80, total_sectors, 4)
    put_both(block, 120, 1, 2)
    put_both(block, 124, 1, 2)
    put_both(block, 128, SECTOR, 2)
    put_both(block, 132, path_table_size, 4)
    l_sector = PATH_TABLE_L_OPTIONAL_SECTOR if joliet else PATH_TABLE_L_SECTOR
    m_sector = PATH_TABLE_M_OPTIONAL_SECTOR if joliet else PATH_TABLE_M_SECTOR
    block[140:144] = l_sector.to_bytes(4, "little")
    block[144:148] = (0).to_bytes(4, "little")
    block[148:152] = m_sector.to_bytes(4, "big")
    block[152:156] = (0).to_bytes(4, "big")
    block[156:190] = root_record(root, joliet)
    block[190:318] = b"Dopamine-private V5".ljust(128, b" ")
    block[318:446] = b"libarchive control archive".ljust(128, b" ")
    block[446:574] = b"Dopamine-private".ljust(128, b" ")
    block[574:702] = b"CVE-2026-112522 diagnostic".ljust(128, b" ")
    block[702:739] = b"2026102800000000".ljust(37, b"0")
    return bytes(block)


def assign_extents(root: Directory) -> list[FileEntry]:
    directories = flatten_directories(root)
    for index, directory in enumerate(directories):
        directory.ascii_extent = FIRST_DIRECTORY_SECTOR + index
        directory.joliet_extent = FIRST_DIRECTORY_SECTOR + len(directories) + index
    files = [file_entry for directory in directories for file_entry in directory.files]
    next_sector = FIRST_DIRECTORY_SECTOR + len(directories) * 2
    for file_entry in files:
        file_entry.extent = next_sector
        next_sector += max(1, math.ceil(len(file_entry.payload) / SECTOR))
    return files


def build_iso(root: Directory, volume_id: str) -> tuple[bytes, list[str], int]:
    files = assign_extents(root)
    directories = flatten_directories(root)
    joliet_l = path_table_bytes(root, joliet=True, big_endian=False)
    joliet_m = path_table_bytes(root, joliet=True, big_endian=True)
    ascii_l = path_table_bytes(root, joliet=False, big_endian=False)
    ascii_m = path_table_bytes(root, joliet=False, big_endian=True)
    path_table_size = len(joliet_l)
    if len(joliet_l) != len(joliet_m):
        raise AssertionError("Joliet path tables differ in size")
    total_sectors = max(
        FIRST_DIRECTORY_SECTOR + len(directories) * 2,
        *(file.extent + max(1, math.ceil(len(file.payload) / SECTOR)) for file in files),
    ) + 1
    image = bytearray(total_sectors * SECTOR)
    image[16 * SECTOR : 17 * SECTOR] = descriptor(1, volume_id, root, total_sectors, len(ascii_l), False)
    svd = bytearray(descriptor(2, volume_id, root, total_sectors, path_table_size, True))
    svd[88:120] = b"%/E".ljust(32, b" ")
    image[17 * SECTOR : 18 * SECTOR] = svd
    terminator = bytearray(SECTOR)
    terminator[0] = 255
    terminator[1:6] = b"CD001"
    terminator[6] = 1
    image[18 * SECTOR : 19 * SECTOR] = terminator
    image[PATH_TABLE_L_SECTOR * SECTOR : PATH_TABLE_L_SECTOR * SECTOR + len(ascii_l)] = ascii_l
    image[PATH_TABLE_L_OPTIONAL_SECTOR * SECTOR : PATH_TABLE_L_OPTIONAL_SECTOR * SECTOR + len(joliet_l)] = joliet_l
    image[PATH_TABLE_M_SECTOR * SECTOR : PATH_TABLE_M_SECTOR * SECTOR + len(ascii_m)] = ascii_m
    image[PATH_TABLE_M_OPTIONAL_SECTOR * SECTOR : PATH_TABLE_M_OPTIONAL_SECTOR * SECTOR + len(joliet_m)] = joliet_m
    for directory in directories:
        offset = directory.ascii_extent * SECTOR
        image[offset : offset + SECTOR] = directory_bytes(directory, joliet=False)
        offset = directory.joliet_extent * SECTOR
        image[offset : offset + SECTOR] = directory_bytes(directory, joliet=True)
    for file_entry in files:
        offset = file_entry.extent * SECTOR
        image[offset : offset + len(file_entry.payload)] = file_entry.payload
    expected_paths: list[str] = []
    for directory in directories:
        components: list[str] = []
        current: Directory | None = directory
        while current is not None and current.parent is not None:
            components.append(current.name)
            current = current.parent
        prefix = "/".join(reversed(components))
        for file_entry in directory.files:
            expected_paths.append(f"{prefix + '/' if prefix else ''}{file_entry.name}")
    return bytes(image), expected_paths, total_sectors


def make_control_a() -> Directory:
    root = Directory("", "ROOT")
    root.files = [
        FileEntry("README.TXT", "README.TXT", b"V5 simple ISO9660 Joliet control\n"),
        FileEntry("CHECKSUM.TXT", "CHECKSUM.TXT", b"ordinary archive control\n"),
    ]
    return root


def make_control_b() -> Directory:
    root = Directory("", "ROOT")
    level1 = Directory("LEVEL-1", "LEVEL1", root)
    level2 = Directory("LEVEL-2", "LEVEL2", level1)
    level3 = Directory("LEVEL-3", "LEVEL3", level2)
    level3.files = [FileEntry("DEEP.TXT", "DEEP.TXT", b"nested Joliet control\n")]
    root.children = [level1]
    level1.children = [level2]
    level2.children = [level3]
    root.files = [FileEntry("ROOT.TXT", "ROOT.TXT", b"multi-level control\n")]
    return root


def repeated_name(prefix: str, fill: str, count: int = 96) -> str:
    return (prefix + fill * count)[:count]


def make_control_c() -> Directory:
    root = Directory("", "ROOT")
    levels: list[Directory] = []
    parent = root
    for index, fill in enumerate("ABCD", 1):
        directory = Directory(repeated_name(f"L{index}", fill), f"L{index}", parent)
        parent.children = [directory]
        levels.append(directory)
        parent = directory
    parent.files = [FileEntry(repeated_name("F", "X") + ".TXT", "LONGFILE.TXT", b"long-path control\n")]
    return root


def controls() -> list[tuple[str, str, Directory]]:
    return [
        ("V5-A-simple.iso", "V5_SIMPLE", make_control_a()),
        ("V5-B-multilevel.iso", "V5_MULTI", make_control_b()),
        ("V5-C-long-safe-path.iso", "V5_LONG", make_control_c()),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "Resources" / "v5-controls")
    args = parser.parse_args()
    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)
    manifest: list[dict[str, object]] = []
    for filename, volume_id, root in controls():
        image, expected_paths, sectors = build_iso(root, volume_id)
        path = args.output / filename
        path.write_bytes(image)
        manifest.append(
            {
                "file": filename,
                "bytes": len(image),
                "sectors": sectors,
                "sha256": hashlib.sha256(image).hexdigest(),
                "expected_paths": expected_paths,
                "max_expected_utf16be_bytes": max((len(path.encode("utf-16-be")) for path in expected_paths), default=0),
                "malformed_payload": False,
            }
        )
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
