#!/usr/bin/env python3
"""Offline structural checks for the embedded, benign ISO control file."""

from __future__ import annotations

import hashlib
from pathlib import Path


SECTOR = 2048


def main() -> int:
    iso = Path(__file__).parent / "Resources" / "control.iso"
    data = iso.read_bytes()
    assert data, "control ISO is empty"
    assert len(data) % SECTOR == 0, "ISO size is not sector aligned"

    descriptors = [data[index * SECTOR:(index + 1) * SECTOR] for index in range(16, 32)]
    assert any(block[0:7] == b"\x01CD001\x01" for block in descriptors), "missing primary volume descriptor"
    assert any(block[0] == 2 and block[1:6] == b"CD001" and b"%/E" in block[88:120] for block in descriptors), "missing Joliet descriptor"
    assert any(block[0:7] == b"\xffCD001\x01" for block in descriptors), "missing volume descriptor terminator"
    assert b"LIBARCHIVE_CTL" in data, "control volume identifier missing"

    print({
        "path": str(iso),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "iso9660": True,
        "joliet": True,
        "malformed_payload": False,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
