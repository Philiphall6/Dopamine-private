# A15 / iOS 26: linked empty-record acceptance

Target: iPhone14,2, iOS 26.0.1, build 23A355.

## Provenance

| Field | Value |
| --- | --- |
| Source commit | `a91336d4f2a3e3ae9dd52d2bc43b72e852f39c87` |
| Private Actions run | `39392906389` (`success`) |
| IPA SHA-256 | `9DAFDD799ED35053DEA7281850AD3EAEE64FE237CC3D5026E90686A0D2174C26` |
| Revision | `self-page-write-v1+agx-notification-map-v3+rtkit-mmio-disabled-v1` |
| Safety mode | `no-gfx-mmio` |

## One bounded run

The device created one owned notification queue with selector 14 and bound it
once with selector 24. The resulting derived state was present at
`queue+0x428`; the queue slot at `+0x430` retained the same owned notification
object. The notification vtable and map contract were both validated first.

The single selector-25 invocation then accepted an all-zero owned `0x40` record
with `kr=0x0`. Pre/post observations show the pool digest, user buffer, command
buffer, notification binding, firmware object and registered buffer stayed
stable. The queue's `dispatch` and `command-index` counters changed from `0` to
`1`; all other tracked state remained at its clean value. The owned AGX
connection closed successfully and the phone did not restart.

## What this establishes

- The normal notification prerequisite is required and works on 23A355.
- The accepted linked empty-record route consumes one record and returns through
  its immediate cleanup path.
- The earlier `0xe00002bc` outcome was the missing-notification prerequisite,
  not a selector-25 record-size failure.

## What remains excluded

No MDSID or other nonempty record was submitted. No GPU MMIO, physical or
protected-memory write, power transition, root replacement, SPTM work,
bootstrap deployment or Sileo installation occurred. The final `titan.run FAIL
return=-1` line is a deliberate bounded-probe stop after the successful stage.

The next step is offline-only: inspect the exact nonempty MDSID parser and
cleanup boundary. The exact-image audit confirms a static MDSID route but does
not yet establish complete runtime effects or final deallocation timing, so it
does not authorize a device submission.
