# A15 iOS 26.0.1: owned AGX queue identity probe

## Evidence and hypothesis

The prior iPhone14,2 / 23A355 run observed an app-owned G14P client,
selector-12 buffer ID 1, and a user-writable mapping whose 0x20 changed
bytes were independently visible through a kernel DRAM alias. The bytes
were restored. This is not a physical write or a protected-memory change.

The exact kernelcache maps command-queue creation to selector 6 and packet
submission to selector 25. Selector 25 rejects a missing queue before the
buffer parser. The next falsifiable link is therefore whether a queue
created on the same client is registered under the returned ID, has the
expected AGXCommandQueue identity, points back to that client's device and
table, and coexists with the original registered buffer.

## Bounded device test

Revision `self-page-write-v1+agx-own-queue-v1+rtkit-mmio-disabled-v1`
retains the prior exact-device and exact-build gate, ClearSword self-page
write/restoration, AGX object gates, and restored shared-buffer alias test.
After verifying the queue registry and structure sizes, it makes one
selector-6 call with a zeroed 0x408-byte input and 0x10-byte output. It
then checks the returned queue ID against the same client's registry,
repeats object reads, compares the exact-image queue vtable, table and
device backreferences, returned token, ready byte, and buffer identity.
All steps persist checkpoints to `a15-ios26-active-probe.jsonl`.

Queue creation is **stateful**: exact-image static analysis shows resource
setup before the returned ID. Thus the test is not read-only. It performs
no selector-25 packet submission, GPU command-buffer submission, IPC-right
copy, GFX MMIO read, physical write, or deliberate protected-memory
mutation. The previous GFX SError panic remains unattributed, so its MMIO
read stays disabled. Only the user installs and launches the IPA, once.

The local triager `tools/a15_ios26/triage_agx_owned_queue_probe.py`
requires ordered exact-target checkpoints, restored aliases, same-client
queue/buffer identity, connection close, and no forbidden later stage. A
blocked gate, missing checkpoint, or reboot is not a success. Offline
integration and unit tests pass (177 tests).

## Interpretation boundary

The observed same-client queue and buffer establish a necessary
object-identity link, not buffer consumption by the parser. The specific
selector-25 path has pre-parser backend and resource effects that are not
bounded for a device test. Kernel read, the controlled kernel-virtual
write to an app-owned page, physical write, and protected-memory change
remain distinct. No SPTM/TXM bypass or code injection is inferred.

## Trial status

Branch `codex/a15-own-queue-v1-20261019`, commit `dd97a72`, was pushed to
the public fork. macOS CI run `39234080749` completed successfully on that
exact commit. The downloaded `outputs/agx-own-queue-v1-ci-dd97a72/Dopamine.ipa`
is 55,501,964 bytes with SHA-256
`8793350aa91511ed4921102a49470fab0729677e94f65521ad02cb014ab1b579`.
Its app plist carries the exact revision and its Titan framework contains
the queue-create, identity, and connection-close checkpoint strings. The
old app-container log
was copied before installation to
`outputs/device/a15-own-queue-v1-20261019/before.jsonl` (SHA-256
`866f225a37fa67d8e03da811f49a6e2aba91edbbc3405c2e582c7d54f24768ff`).
## First device trial and exact-size correction

The user installed `dd97a72` and ran it once without reboot. The
post-run journal was pulled twice with identical 397,893-byte contents
and SHA-256
`e179690b8d86169ad56a94abba2d8bf4889936892159644070ad308b950a87b5`.
Its first 352,084 bytes match the pre-run file exactly. The added run ID
`5FDDD069-9B19-479F-A85D-CCE7E0490627` has 178 checkpoints. Self-page
kernel-virtual write/restoration, AGX service/mux/factory identity, the
own-client shared-buffer alias, and the queue registry/device identity
gates all passed. Selector 6 then returned `0xe00002c2`, with no queue
ID or token. Connection close and probe cleanup passed. No forbidden
stage, packet submission, or reboot was observed.

Apple's [IOKit header](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/IOKit/IOReturn.h)
defines `0xe00002c2` as `kIOReturnBadArgument`.
The exact-image selector-6 wrapper reads the supplied structure size at
`0xfffffff009f1a618`, the device's expected size from `+0x278` at
`0xfffffff009f1a61c`, and compares them at `0xfffffff009f1a620` and
`0xfffffff009f1a624`. The equality branch precedes the queue factory.
The IOGPU base initializer stores `0x408` at `device+0x278`, but the G14P
initializer overrides it with `0x410` at `0xfffffff0087e734c` to
`0xfffffff0087e7350`. The first IPA sent `0x408`, so an input-size
rejection before allocation is the strongest explanation. The live
`device+0x278` value was not logged in that run; the inference is to be
tested, not treated as a direct observation.

The G14P queue initializer reads the additional eight bytes at input
`+0x408`; zero selects no optional bits in the audited path. Commit
`0720986` adds a read-and-match gate for live `device+0x278 == 0x410`
and sends a zeroed 0x410-byte input once. It keeps all later stages
disabled. The exact-image audit now validates 381 instruction anchors in
`outputs/agx-own-queue-input-contract-2026-10-19.json`; 179 offline
tests and the integration guard pass. CI run `39237016964` succeeded on
the exact `0720986` commit. The downloaded
`outputs/agx-own-queue-v2-ci-0720986/Dopamine.ipa` is 55,501,984 bytes,
SHA-256
`405c00dcec226b73aad901a2d406b216f1d3041674b694856e28b24071b3400a`.
The embedded app revision, `no-gfx-mmio` safety mode, and Titan
`titan.own-queue.input-size` / `input=0x410` checkpoint strings were
verified.

## Second device trial: same-client queue observed

The user installed the v2 IPA and ran it once on USB iPhone14,2, iOS
26.0.1, build 23A355, without reboot. Before the run, the persistent
journal was copied to
`outputs/device/a15-own-queue-v2-20261019/before.jsonl` (397,893 bytes,
SHA-256 `e179690b8d86169ad56a94abba2d8bf4889936892159644070ad308b950a87b5`).
The post-run file was pulled twice with identical 449,461-byte contents
and SHA-256
`bf2154628ebf11b6a6d5681e832d1bac90b5e40c6db2848aa71886ca126a7664`.
Its first 397,893 bytes match the baseline exactly. The single added run
`73263D5E-22A4-4757-B24B-7DCCFE45B36E` has 202 checkpoints.

The live device `+0x278` value is `0x410`, confirming the v1 size
mismatch. One selector-6 call with a zeroed 0x410-byte input returned
`kr=0`, queue ID 1, and token `0xefdc8755`. The queue's repeated object
reads match; its vtable unslides to the audited AGXCommandQueue vtable.
The queue table and device backreferences point to the same client's
objects, the token matches, the ready byte is 1, and the previously
registered buffer remains at ID 1 in its separate buffer array.
The connection closed and cleanup passed. The triager reports
`owned_queue_and_buffer_observed`, `queue_identity_ok=true`, no first
blocker, no missing/out-of-order checkpoint, and no forbidden stage.
The final `titan.run FAIL return=-1` is the probe's deliberate stop after
these checks; it does not negate the queue result.

This establishes a same-client AGX queue/buffer identity link. It does
not show selector-25 invocation, buffer-ID parsing, GPU packet execution,
physical writing, protected-memory modification, code injection, or a
SPTM/TXM bypass. The next concrete blocker is the selector-25 path's
stateful backend/resource work before the buffer getter; an apparently
rejected packet would not independently prove safe parser reachability.
The previous GFX MMIO read remains disabled.
