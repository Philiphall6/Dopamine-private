# A15 / 23A355: blockers after the owned AGX queue trial

Scope: iPhone14,2, iOS 26.0.1, build 23A355. This note separates live
observations from exact-image static deductions. It does not enable a new
device-side experiment.

## Live evidence

The user ran the `0720986` diagnostic IPA once without reboot. Two USB
copies of the post-run JSONL are byte-identical (449,461 bytes, SHA-256
`bf2154628ebf11b6a6d5681e832d1bac90b5e40c6db2848aa71886ca126a7664`)
and extend the 397,893-byte baseline exactly. Run
`73263D5E-22A4-4757-B24B-7DCCFE45B36E` contains 202 checkpoints.
ClearSword read the kernel header. A 0x20-byte kernel-virtual alias write
changed an app-owned page, matched through the app mapping, and was
restored. AGX selector 12 registered an app-writable buffer; selector 6
returned queue ID 1 on the same client after the live size gate read
`device+0x278 == 0x410`. Queue object, token, table/device backreferences,
ready byte, and buffer registry were checked. The client closed and the
probe deliberately returned `-1` before later Titan stages.

| Boundary | Status on this target | Evidence needed to advance |
|---|---|---|
| Kernel read | Observed | Already sufficient for bounded object census. |
| Kernel-virtual write | Observed only on an app-owned page, then restored | A separate target-specific readback would be needed for any claim about a kernel-owned object. |
| Own AGX buffer and queue | Observed on one client | This proves identity, not packet consumption. |
| AGX parser consumption | Not reached | Show that an accepted request selects the registered buffer and its bytes, with pre-parser effects independently bounded. |
| Physical write | Not observed | Independent physical-target observation and readback, not merely a kernel alias or user mapping. |
| Protected-memory change / SPTM / TXM | Not reached | An accepted protected operation and independent protected-state observation; none follows from kernel access alone. |

## Exact-image selector-25 gate

The new `tools/a15_ios26/audit_agx_submit_boundary.py` checks the retained
kernelcache SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
It builds instruction-level control-flow graphs for the 155-instruction
batch routine and 197-instruction processor. On normal-return local paths,
the queue-state write at `0xfffffff009f492a0` dominates the processor
call at `0xfffffff009f49398`; the backend virtual call at
`0xfffffff009f4960c` and its success gate at `0xfffffff009f49618`
dominate the parser dispatch at `0xfffffff009f49680`. The backend-failure
branch skips that dispatch. The report is
`outputs/agx-submit-boundary-cfg-2026-10-19.json`.

Decision: abandon a selector-25 **parser-only** phone probe. A request
rejected before the backend says nothing about buffer consumption; a
request reaching the parser has already crossed stateful effects.
The graph does not establish the returned backend object's runtime
identity, its complete effects, GPU execution, or an alternative safe
ingress. The static class route is narrowed below, but complete effects
for the live queue type remain unbounded. Only then should a new device
experiment be considered.

The exact G14P vtable conditionally resolves the device factory to
`AGXBlockFence` and that class's `+0x90` preparation slot to
`0xfffffff0087f5ca8`. Its disassembly contains lock calls and at least
four distinct pool-bitmap stores (`0xfffffff0087f5d34`,
`0xfffffff0087f5dc4`, `0xfffffff0087f5e44`, and
`0xfffffff0087f5edc`) before its return. The expanded audit checks the
PAC-encoded vtable entries and a 268-instruction local graph: the object
state write at `0xfffffff0087f5cc8` and indirect call at
`0xfffffff0087f5ce4` each dominate the return, while the four pool
write sites are reachable but conditional. These are static candidate
effects, not evidence that this object or every store occurs in the live
selector-25 path. They rule out describing the pre-parser backend as a
passive validation step. The downstream effects are still unbounded, so
this candidate does not clear the phone-test gate.

The same image resolves the early `AGXBlockFence::prepare` indirect call
one step further. Its GOT entry at `0xfffffff007b15d20` decodes to the
IOGPUFamily table at `0xfffffff007e439e8`; the `+0xa0` slot decodes to
`0xfffffff009f21f00`. The audit pins both chained encodings and the load
instructions. That target calls a base initializer at
`0xfffffff009f21bc0` on every normal-return local path, and its success
path contains object-state stores, authenticated callbacks, an allocation,
and another setup call. This narrows one static target; it does not prove
the live object type, the callbacks' targets, or complete side effects.
The selector-25 phone-test gate therefore remains closed.

The initializer's base helper has one more statically resolvable call:
IOGPUFamily GOT `0xfffffff007e40920` points to a kernel table at
`0xfffffff007aeee60`; its `+0x78` slot targets
`0xfffffff0085fad18`, a three-instruction method that returns `1`.
The helper's subsequent success path stores object fields and invokes
two additional setup calls. The exact-image audit pins this third-hop
encoding and disassembly. Resolving one benign callback does not bound
the rest of the initialization, pool writes, or live submission path.

The v2 journal connects this static route to the owned queue more
specifically. It observed queue vtable `0xfffffff007b17550`, queue
`+0x538` pointing to the validated G14P device, and device vtable
`0xfffffff007b1e0d0`. In the selector-25 entry, the client table at
`+0x120` supplies a queue lookup; the returned queue enters the batch
routine, whose processor reads `queue+0x538` and calls the device
vtable slot `+0x5c0` (`0xfffffff007b1e690`). That slot statically
decodes to the `AGXBlockFence` factory. This is a conditional route for
the observed queue identity, not evidence that selector 25 ran or that
its returned backend object's type was measured. The factory reads a
metaclass global initialized in this image with the `AGXBlockFence`
name and a `0x158` class size. Its `+0x68` allocation slot constructs
an instance with the vtable whose `+0x90` preparation slot is the
stateful candidate above. This establishes the intended static class
chain, but the actual returned pointer, initialization path and effects
remain unobserved on this device.

The local `AGXBlockFence::prepare` graph also has a possible path that
clears bitmap bits for pool reservations, stores addresses at object
`+0x130` and `+0x138`, and returns without traversing its local
rollback stores. Other branches do restore bitmap state. The audit pins
the relevant store and branch instructions and rejects a changed path.
It does not establish which branch runs on this phone or whether a later
stage releases the reservations. The existence of this pre-parser
stateful path reinforces the decision against a parser-only IPA.

## Queue packet method and older selector

The observed queue vtable `0xfffffff007b17550` has an authenticated
`+0x118` entry resolving to the G14P override at
`0xfffffff008803254`. That override calls the same queue's `+0x160`
method first. The `+0x160` target clears queue `+0x5f0` and, if its ready
byte at `+0x5e8` is set, returns success; the v2 trial measured ready=1,
but it did **not** invoke this method. On the success branch, the override
calls a separate virtual `queue+0x670` method, writes queue state at
`+0x800`, `+0x802`, and `+0x5d8`, and only then tail-dispatches through
G14P GOT `0xfffffff007b15d40` to IOGPUFamily table
`0xfffffff007e46b28`, slot `+0x128`. That slot resolves to the known base
packet processor `0xfffffff009f4be9c`. The virtual call's target and
complete effects remain unresolved; these are static branch facts, not
observations of packet consumption.

Both older selector-0 table entries target `0xfffffff009f1c684`, which
calls the same batch routine at `0xfffffff009f49254` as modern selector
25. Their live dispatch availability is unobserved, and neither static
entry bypasses the batch's pre-parser state write or backend gate. This
rules out the proposed **parser-only shortcut through selector 0** on the
checked path, but does not prove there is no other entry in the image.
The exact-image pointers and instructions are pinned in the expanded
`outputs/agx-submit-boundary-cfg-2026-10-19.json` audit.

The `queue+0x670` object can be narrowed statically. The queue
initializer allocates `0x17c0` bytes, calls a constructor installing the
vtable at `0xfffffff007b17410`, and stores the result at `+0x670`.
The class registration names this type `AGXCommandBuffer` with the same
size. Its `+0x78` initializer receives the queue's device and table,
storing the device at command-buffer `+0x18`; its `+0x98` callback
resolves to `0xfffffff0087fd300`. That callback advances a ring index,
clears command entries, writes counters in the associated table, and invokes an
additional virtual `+0x210` method on an object reached via the device.
The exact-image audit pins the class string, initializer and callback
slots, constructor wiring, and selected writes. The callback target is
therefore not a passive buffer read on this static route. Its runtime
invocation, the downstream virtual target, and the full device effects
remain unobserved; GPU submission is not claimed.

One more static hop reaches `device+0x4a0`: device vtable `+0x880`
resolves to a factory using the `AGXArmFirmwareASC` metaclass. The
device initializer stores that factory's result at `+0x4a0`, and the
command-buffer callback loads that field before its `+0x210` virtual
call. The class registration size is `0x1be0`; its allocator installs
a base vtable whose `+0x210` slot resolves to the kernel
`__cxa_pure_virtual` assertion stub. This is **not** a prediction that
the live callback panics: the final object identity and effective
vtable at the time of packet processing were not measured, and later
initialization or replacement may change the target. It prevents a
confident static claim about the callback's downstream effects. The
audit pins the factory, class string, allocation and base slot while
marking the effective target unresolved.
The immediately following initializer call reloads the G14P **device**
vtable and invokes its `+0x858` slot with the device as receiver. It is
not, by itself, a vtable replacement on the object just stored at
`device+0x4a0`. The exact-image audit pins this local distinction; it
does not rule out later replacement, a different live object, or an
inactive packet path.
The class metadata also names `AGXArmFirmware` as the parent of
`AGXArmFirmwareASC`. Its metaclass allocator returns null directly;
the device factory instead selects the ASC allocator. Thus the parent
does not supply a concrete alternative `+0x210` implementation on this
checked factory path. This still does not establish that the callback
is reached, that the field is unchanged when reached, or that the
static ASC vtable is the effective one in a live submission.
The ASC allocator itself installs that same base vtable after its
parent initialization call. The other two direct references to the
vtable base found in this fileset are destructor paths; neither is
evidence of a different live callback target. This narrows the static
route, but does not prove the absence of later replacement through an
indirect call or another image.

## Other routes

| Route | Current blocker | Decision |
|---|---|---|
| Historical Titan IPC handoff | XNU 12377 PAC/SMR and changed port layout invalidate the legacy right-copy assumptions. The own AGX client does not transfer backboardd's rights. | Keep legacy copy disabled; require a separately validated Darwin 25 design. |
| GFX / RTKit MMIO | Earlier GFX SError panic provenance is unresolved. A mapped register address is not a safe read. | Keep live MMIO disabled. |
| SPTM UAT producer | Static descriptor and option policy are mapped, but caller-controlled `segments_page` and `map_options` ingress is unproved; frame-class checks remain. | No protected request on device. |
| Stage-2 / Hypervisor | Userland framework, symbols, entitlement, and virtualization property were absent on the exact device; typed guest frames are a separate SPTM interface. | Not a substitute for Titan's physical-write step. |
| UPPL / pmap alternative | No reachable weak UPPL writer; the public pmap PoC has no independent page-table refcount or protected-write measurement. | Do not promote either to a primitive. |

The strongest demonstrated chain is kernel read, a reversible
kernel-virtual write to an app-owned page, an AGX shared buffer, and a
same-client command queue. It stops before buffer parsing, physical
writing, and protected-memory authority. No injection is claimed.

## Final audit disposition

**No-go for a packet-submission IPA on the current evidence.** Queue
creation is repeatably observed, but the first packet's intermediate
callback has stateful effects and its effective firmware target is not
measured. The selector-25 backend can also change state before the
parser and has a possible reservation path without local rollback.
Consequently a parser-only or protected-write trial cannot be described
as bounded by this audit. The exact-image findings above are a stopping
decision, not a claim that the chain is complete or that a live callback
would necessarily panic.

A later decision would need independent evidence for the runtime
firmware object and callback target, the complete pre-parser effects,
actual buffer consumption, and a separately measured physical write.
SPTM/TXM authority would require its own protected-state observation.
None of these is supplied by the v2 journal. Keep GFX MMIO and the
legacy IPC-right copy disabled; do not label the existing diagnostic IPA
as a jailbreak or request another phone run on its basis.
