# A15 iOS 26 AGX Shared-Buffer Tracking V6

Date: 2026-10-20
Branch: `codex/a15-ios26-private-research`
Target: iPhone14,2 / A15 / iOS 26.0.1 / 23A355

## Scope

V6 adds passive snapshots around the existing shared AGX buffer observation.
It does not add a selector, a GPU command, a nonempty MDSID record, MMIO, a
physical or protected write, SPTM/PAPT changes, or bootstrap installation.
The existing single bounded selector-25 empty-record call is unchanged.

## Finding From The Previous Log

The earlier `titan.zero-packet.buffer-preflight` result reported
`first-nonzero=0x100` and stopped before selector 25. The source shows that
the bounded alias check intentionally uses `output.address + 0x100`, copies a
temporary 0x20-byte pattern there, and restores it only in the centralized
cleanup path. Therefore the old result is consistent with the probe's own
temporary mutation; it does not identify AGX or firmware as the writer.

V6 records the buffer before and after that mutation and around selectors 6,
14 and 24. A change after `ALIAS_AFTER_WRITE` and before cleanup would be a
new observation requiring review; the snapshots alone still do not attribute
the writer.

## Code Changes

Modified `Application/Dopamine/Exploits/Titan/exploit/titan.m`:

- Added a 16 KiB snapshot tracker with a previous-snapshot comparison.
- Added SHA-256, nonzero-byte count, first nonzero offset, changed-byte count
  and first changed offset.
- Replaced the raw shared-buffer address in snapshot details with a short
  SHA-256-derived address token.
- Added read-only checkpoints at `BUFFER_CREATED`, `BUFFER_INITIALIZED`,
  `ALIAS_BEFORE`, `ALIAS_AFTER_WRITE`, `QUEUE_BEFORE`, `QUEUE_AFTER`,
  `NOTIFICATION_BEFORE`, `NOTIFICATION_AFTER`, `BIND_BEFORE`, `BIND_AFTER`
  and `PREFLIGHT_FINAL`.
- Added `ALIAS_AFTER_RESTORE`; it is `NOT_TESTED` when the temporary write was
  not reached.
- Kept cleanup centralized and passed the tracker through the existing call
  chain without adding an IOKit operation.

Snapshot details contain `result=PASS`, `checkpoint`, `address-token`,
`size`, `sha256`, `nonzero-count`, `first-nonzero`, `changed-bytes`,
`first-changed`, `previous` and `read-only=yes`. The generic checkpoint
writer supplies the existing session ID and monotonic timestamp fields.

## Offline Tests

Added `tools/a15_ios26/test_agx_buffer_tracking_v6.py`. It models the
snapshot contract for a zero buffer, a byte at offset `0x100`, multiple
nonzero regions, temporary write and restoration, identical snapshots,
invalid or unavailable input, no mutation during capture and address
tokenization.

Local results for this revision:

- `python tools/a15_ios26/check_research_integration.py`: `OK`;
- focused V6/V2 tests: `20 tests`, `OK`;
- `git diff --check`: `PASS`;
- Objective-C/Xcode compilation on this Windows host: `NOT_TESTED`.

## Runtime Diagnostic Evidence

The supplied `A15DIAG` UI log is a separate diagnostic result. It confirms
exact target identity, SPTM artifact presence and arm64e as `PASS`; PPL
bypass and exploit loading/execution as `NOT_TESTED`; runtime kernel
read/write as `BLOCKED`; Titan command buffers as `BLOCKED` in diagnostic
mode; privilege elevation, bootstrap and protected component as
`NOT_TESTED`; report write as `PASS`; and the final result as `BLOCKED`,
`jailbreak-not-performed`.

This proves that the in-app diagnostic logging path is active. It is not a
V6 device run and it is not evidence of a functional jailbreak.

## Open Hypotheses

1. High confidence: `0x100` in the previous preflight was the intentional
   temporary alias mutation because the source writes that offset before the
   queue path.
2. Open: whether selectors 6, 14 or 24 modify the shared buffer. V6 can show
   a transition but cannot attribute it without an independent causal test.
3. Open: whether the firmware context persists after queue and notification
   setup. The lifecycle log keeps power and firmware persistence at
   `NOT_TESTED`; `ready=1` is not proof.
4. Open: independent destruction of child buffer, queue and notification
   objects after `IOServiceClose`.

## Required Device Observation

For a manually selected build, preserve the JSONL events for all V6
checkpoints and compare their SHA-256 and changed-byte fields. Stop on any
unexpected change, failed restoration, invalid snapshot or cleanup failure.
Do not retry automatically and do not promote a nonempty record or bootstrap
from these observations.

## Limits

The snapshot helper reads a known user mapping after the existing mapping and
protection checks. It has no fault-recovery mechanism for an asynchronously
invalid mapping, so an inaccessible-buffer case is covered offline by the
contract model and reported as `NOT_TESTED` before the production read. No
V6 run on the iPhone, no new IPA and no jailbreak validation are claimed.
