# A15 / iOS 26: notification map ABI correction

Target: iPhone14,2, iOS 26.0.1, build 23A355.

## Device observation

The private notification-vtable v2 run completed one selector-14 creation and
validated the returned `IOGPUNotificationQueue` vtable at
`0xfffffff007e479a8`. The returned object exposed an `IOMemoryMap` at `+0x18`.
Its address at `+0x28` matched the selector-14 user address, and its length at
`+0x30` was `0x2454`.

The prior guard used `0x2000`, which is the input payload size from 256 entries
of 32 bytes. It stopped before selector 24 and selector 25. No MDSID record,
GPU MMIO, physical write or protected-memory write was performed. The owned
connection closed cleanly.

## Revised contract

`self-page-write-v1+agx-notification-map-v3+rtkit-mmio-disabled-v1` separates
the two values:

1. `0x2000`: required writable payload capacity.
2. `0x2454`: exact driver `IOMemoryMap` length for the owned notification queue.

The revision retains one selector-14 creation, one selector-24 bind and at most
one selector-25 all-zero record. It does not use MDSID or advance to power,
root, physical-memory, SPTM, bootstrap or Sileo work.
