#!/usr/bin/env python3
"""Dependency-free structural validator for the V5 ISO9660/Joliet controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


SECTOR = 2048


def both(block: bytes, offset: int, size: int) -> tuple[int, int]:
    left = int.from_bytes(block[offset : offset + size], "little")
    right = int.from_bytes(block[offset + size : offset + size * 2], "big")
    if left != right:
        raise AssertionError(f"dual-endian mismatch at {offset:#x}: {left} != {right}")
    return left, right


def record(data: bytes, offset: int) -> tuple[dict[str, object], int]:
    length = data[offset]
    if length == 0:
        return {"terminator": True}, SECTOR - (offset % SECTOR)
    if length < 34 or offset + length > len(data):
        raise AssertionError(f"invalid directory record at {offset:#x}")
    name_length = data[offset + 32]
    name_start = offset + 33
    name_end = name_start + name_length
    if name_end > offset + length:
        raise AssertionError("directory name exceeds record")
    padding = 1 if name_length % 2 == 0 else 0
    expected_length = 33 + name_length + padding
    if length != expected_length:
        raise AssertionError(f"record length {length} != expected {expected_length}")
    if padding and data[offset + length - 1] != 0:
        raise AssertionError("non-zero ISO9660 padding byte")
    extent = int.from_bytes(data[offset + 2 : offset + 6], "little")
    extent_be = int.from_bytes(data[offset + 6 : offset + 10], "big")
    size = int.from_bytes(data[offset + 10 : offset + 14], "little")
    size_be = int.from_bytes(data[offset + 14 : offset + 18], "big")
    if extent != extent_be or size != size_be:
        raise AssertionError("directory record endian mismatch")
    return {
        "length": length,
        "extent": extent,
        "size": size,
        "flags": data[offset + 25],
        "name_bytes": data[name_start:name_end],
    }, length


def parse_directory(data: bytes, extent: int, joliet: bool, seen: set[int], prefix: str = "") -> list[dict[str, object]]:
    if extent in seen:
        raise AssertionError(f"directory loop at sector {extent}")
    seen.add(extent)
    start = extent * SECTOR
    end = start + SECTOR
    if end > len(data):
        raise AssertionError("directory extends beyond ISO")
    entries: list[dict[str, object]] = []
    offset = start
    while offset < end:
        parsed, consumed = record(data, offset)
        if parsed.get("terminator"):
            break
        name_bytes = parsed["name_bytes"]
        if name_bytes == b"\x00":
            name = "\x00"
        elif name_bytes == b"\x01":
            name = "\x01"
        else:
            name = name_bytes.decode("utf-16-be" if joliet else "ascii", errors="strict")
        parsed["name"] = name
        parsed["path"] = prefix
        if name not in ("\x00", "\x01"):
            data_end = parsed["extent"] * SECTOR + parsed["size"]
            if data_end > len(data):
                raise AssertionError(f"entry {name!r} points past end of ISO")
            entries.append(parsed)
            if parsed["flags"] & 2:
                child_prefix = f"{prefix}/{name}" if prefix else name
                entries.extend(parse_directory(data, parsed["extent"], joliet, seen, child_prefix))
        offset += consumed
    return entries


def parse_path_table(data: bytes, offset: int, size: int, joliet: bool, big_endian: bool) -> list[str]:
    table = data[offset : offset + size]
    if len(table) != size:
        raise AssertionError("path table outside ISO")
    names: list[str] = []
    cursor = 0
    while cursor < len(table):
        if cursor + 8 > len(table):
            raise AssertionError("truncated path table entry")
        name_len = table[cursor]
        extent_start = cursor + 2
        extent = int.from_bytes(table[extent_start : extent_start + 4], "big" if big_endian else "little")
        parent = int.from_bytes(table[extent_start + 4 : extent_start + 6], "big" if big_endian else "little")
        if extent * SECTOR >= len(data) or parent == 0:
            raise AssertionError("invalid path table extent or parent")
        name_start = cursor + 8
        name_end = name_start + name_len
        if name_end > len(table):
            raise AssertionError("path table name outside table")
        raw = table[name_start:name_end]
        if raw == b"\x00":
            names.append("/")
        else:
            names.append(raw.decode("utf-16-be" if joliet else "ascii", errors="strict"))
        cursor = name_end + (name_len % 2)
    return names


def validate(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) % SECTOR:
        raise AssertionError("ISO is not sector aligned")
    pvd = data[16 * SECTOR : 17 * SECTOR]
    svd = data[17 * SECTOR : 18 * SECTOR]
    terminator = data[18 * SECTOR : 19 * SECTOR]
    if pvd[0:7] != b"\x01CD001\x01":
        raise AssertionError("missing PVD")
    if svd[0:7] != b"\x02CD001\x01" or svd[88:91] != b"%/E":
        raise AssertionError("missing Joliet SVD")
    if terminator[0:7] != b"\xffCD001\x01":
        raise AssertionError("missing volume descriptor terminator")
    if pvd[881] != 1 or pvd[882] != 0 or any(pvd[1395:]):
        raise AssertionError("invalid PVD file-structure or reserved fields")
    if svd[881] != 1 or svd[882] != 0 or any(svd[1395:]):
        raise AssertionError("invalid SVD file-structure or reserved fields")
    sectors = len(data) // SECTOR
    pvd_sectors, _ = both(pvd, 80, 4)
    svd_sectors, _ = both(svd, 80, 4)
    if pvd_sectors != sectors or svd_sectors != sectors:
        raise AssertionError("volume size does not match image")
    path_size, _ = both(svd, 132, 4)
    l_location = int.from_bytes(svd[140:144], "little")
    m_location = int.from_bytes(svd[148:152], "big")
    l_names = parse_path_table(data, l_location * SECTOR, path_size, True, False)
    m_names = parse_path_table(data, m_location * SECTOR, path_size, True, True)
    if l_names != m_names:
        raise AssertionError("Joliet path tables differ")
    pvd_path_size, _ = both(pvd, 132, 4)
    pvd_l_location = int.from_bytes(pvd[140:144], "little")
    pvd_m_location = int.from_bytes(pvd[148:152], "big")
    pvd_l_names = parse_path_table(data, pvd_l_location * SECTOR, pvd_path_size, False, False)
    pvd_m_names = parse_path_table(data, pvd_m_location * SECTOR, pvd_path_size, False, True)
    if pvd_l_names != pvd_m_names:
        raise AssertionError("ISO9660 path tables differ")
    pvd_root, _ = record(pvd, 156)
    parse_directory(data, int(pvd_root["extent"]), False, set())
    root, _ = record(svd, 156)
    root_entries = parse_directory(data, int(root["extent"]), True, set())
    paths = sorted(str(entry["path"] + "/" + entry["name"]).lstrip("/") for entry in root_entries if not (entry["flags"] & 2))
    max_utf16be = max((len(path_value.encode("utf-16-be")) for path_value in paths), default=0)
    result: dict[str, object] = {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sectors": sectors,
        "joliet": True,
        "path_table_entries": len(l_names),
        "entries": len(root_entries),
        "paths": paths,
        "max_path_utf16be_bytes": max_utf16be,
        "malformed_payload": False,
    }
    verifier = shutil.which("isovfy")
    if verifier:
        completed = subprocess.run([verifier, str(path)], capture_output=True, text=True, check=False)
        result["isovfy_available"] = True
        result["isovfy_returncode"] = completed.returncode
        if completed.returncode != 0:
            raise AssertionError(f"isovfy failed: {completed.stderr or completed.stdout}")
    else:
        result["isovfy_available"] = False
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path(__file__).parent / "Resources" / "v5-controls")
    args = parser.parse_args()
    manifest_path = args.directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else []
    manifest_by_file = {item["file"]: item for item in manifest}
    results = []
    for path in sorted(args.directory.glob("*.iso")):
        result = validate(path)
        expected = manifest_by_file.get(path.name)
        if expected:
            if result["sha256"] != expected["sha256"] or result["paths"] != sorted(expected["expected_paths"]):
                raise AssertionError(f"manifest mismatch for {path.name}")
        results.append(result)
    if len(results) != 3:
        raise AssertionError(f"expected three V5 controls, found {len(results)}")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
