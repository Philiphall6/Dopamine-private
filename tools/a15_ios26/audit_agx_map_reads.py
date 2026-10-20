"""Audit retained AGX map-field reads without touching a device."""

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_DEVICE_VTABLE = 0xFFFFFFF007B21C50
EXPECTED_BASE_INSTANCE_VTABLE = 0xFFFFFFF007B1E0D0


def audit_capture(capture):
    if capture.get("machine") != "iPhone14,2" or capture.get("productVersion") != "26.0.1":
        raise ValueError("capture is not from the pinned iPhone14,2 / iOS 26.0.1 target")

    findings = []
    for connection in capture.get("connections", []):
        for plan in connection.get("kernelReadPlans", []):
            if plan.get("name") != "AGXMappedAddresses":
                continue
            reads = [read for read in plan.get("reads", []) if int(read["offset"], 0) == 0x310]
            if not reads:
                findings.append("AGXMappedAddresses has no +0x310 read")
                continue
            if (
                plan.get("root") == "IOGPUDevice"
                and plan.get("object") == connection.get("IOGPUDevice")
                and int(connection.get("IOGPUDeviceUnslidVtable", "0"), 0) == EXPECTED_DEVICE_VTABLE
            ):
                findings.append(
                    "WRONG-RECEIVER: +0x310 was read on IOGPUDevice, "
                    "not the AGXAcceleratorG14P service instance; its value cannot establish AGX map state"
                )
            else:
                findings.append(
                    "UNVERIFIED-RECEIVER: +0x310 read lacks a validated "
                    "AGXAcceleratorG14P instance/vtable identity"
                )
    if capture.get("serviceClass") == "AGXAcceleratorG14P":
        findings.append(
            "BASE-SERVICE: reported AGXAcceleratorG14P class agrees with the static map path; "
            "class alone does not establish a live map"
        )
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.captures:
        raw = path.read_bytes()
        capture = json.loads(raw)
        findings = audit_capture(capture)
        print(f"{path.name} sha256={hashlib.sha256(raw).hexdigest()}")
        print(f"  static AGX base instance vtable=0x{EXPECTED_BASE_INSTANCE_VTABLE:x}")
        for finding in findings or ["NO AGXMappedAddresses plan in capture"]:
            print(f"  {finding}")


if __name__ == "__main__":
    main()
