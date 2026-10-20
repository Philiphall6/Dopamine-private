# A15 iOS 26.0.1: own AGX shared-buffer alias probe

## Baseline and hypothesis

The 2026-10-19 `eed8d43` device run validated the G14P service, GART,
`AGXUATMux`, and its factory-result object on iPhone14,2 / 23A355. It did
not establish that a user-controlled buffer reaches that object. The exact
kernelcache's IOGPU user-client selector 12 accepts two scalar inputs and
returns a 16-byte address/size/ID record. Static tracing links that ID to
the client buffer registry. These are offline findings, not live proof.

Falsifiable hypothesis: on this exact build, opening the app's own G14P
connection with type 1 and calling selector 12 with `(0x4000, 0)` returns a
writable, app-mapped 16 KiB buffer. Its returned ID names an
`IOGPUBaseBuffer` in that client's registry, whose map object reports the
same user address. After pinning, a 0x20-byte change through the user
mapping should be visible through the corresponding kernel DRAM alias.

## Bounded test

Revision `self-page-write-v1+agx-shared-alias-v1+rtkit-mmio-disabled-v1`
first repeats the existing ClearSword app-page write/restoration and the
read-only G14P/GART/mux/factory identity gates. It then opens only its own
G14P connection. Port type/state, wrapper and client vtables, returned
address/length/ID, VM read-write permission, registry array bounds,
buffer/descriptor/map vtables, and map-address equality must all pass
before any user byte is changed. A failed gate stops the run.

The test pins the page, compares 0x20 bytes from the user mapping and
kernel DRAM alias, changes those bytes through the **user** mapping,
independently reads the alias, restores the original bytes, verifies
restoration, and redirects the ClearSword read target before releasing the
page and connection. It does not call a GPU command selector, consume a
packet, copy an IPC right, touch GFX MMIO, or invoke SPTM/TXM. No mutation
is attempted through the physical address or kernel alias in this stage.
Checkpoints are persisted in `a15-ios26-active-probe.jsonl`.

The offline integration check and synthetic log triage are in
`tools/a15_ios26/check_research_integration.py` and
`tools/a15_ios26/triage_agx_shared_alias_probe.py`. The latter requires an
ordered run on the exact target, stable object linkages, both alias reads,
restoration, redirect, and absence of protected/GFX stages before reporting
`registered_user_dram_alias_observed`. A blocked or absent checkpoint is a
negative or incomplete observation, not a success.

## Interpretation boundary

The strongest possible positive result here is an app-writable AGX buffer
registered under its own client ID and backed by bytes also readable via a
kernel DRAM alias. That is distinct from the earlier kernel-virtual write
to a separate app-owned page. Neither result is a physical write or a
protected-memory modification. The next unresolved boundary would be a
specific packet/selector lookup that consumes this ID and reads these
bytes, followed separately by evidence of an accepted IOUAT mapping and
any SPTM/TXM effect. None is inferred from an alias match alone.

The earlier GFX SError panic remains unattributed. Its MMIO read is still
disabled. Only the user installs the IPA and starts a single device run.

## Device result (2026-10-19)

The user installed CI build `4f3cc28` and ran it once on the USB-verified
iPhone14,2 / 23A355, reporting no reboot. The append-only JSONL was pulled
twice from the app container; both copies have SHA-256
`866F225A37FA67D8E03DA811F49A6E2ABA91EDBBC3405C2E582C7D54F24768FF`.
Its first 309,692 bytes are identical to the preceding device log. The
42,392-byte addition contains one run ID
`751C4F93-262F-4370-8B5A-3BD78C9AF775` and 164 checkpoints. The triager
reports `registered_user_dram_alias_observed` with complete order, no
blocker, and no forbidden stage.

The type-1 G14P client opened and matched the expected vtable. Selector 12
returned `(address=0x108cd8000, size=0x4000, id=1)` with effective user VM
protection `0x3`. The client's `+0x120` table and `+0x78` registry array
resolved slot 1 to buffer `0xffffffe786aa8700`, stable on repeat. The
buffer's `+0x28` and `+0x40` fields named the same descriptor; its `+0x48`
map reported the returned user address and 0x4000 length. Array, buffer,
descriptor, and map vtables matched exact-image constants. The 0x20-byte
change through the **user** mapping independently matched the kernel DRAM
alias; restoration and ClearSword target redirect both passed.

No parser or packet lookup was called. The remaining concrete question is
whether a valid packet resolves this same ID/object and consumes those
changed bytes through its kernel mapping, while all packet bounds and
resource-type checks pass. An alias match alone cannot answer that, nor
prove physical writing or a protected-memory effect.

## Selector-25 boundary recheck

The exact-image IOGPU external-method table maps queue creation to index
`6`, shared-memory creation to `12`, notification creation to `14`,
notification attachment to `24`, and submission to `25`. Titan's historical
header uses `7`, `13`, `15`, `25`, and `26` respectively. The live selector
12 return confirms at least the shared-memory index on this build; the
other exact-image table entries remain static observations. Reusing Titan's
old wrappers verbatim would target different methods. Opening our own
G14P client removes the need to copy a backboardd IPC right for this one
buffer test, but does not establish equivalent queue/device state or a
working Titan command chain.

At static selector-25 target `0xfffffff009f1acec`, the exact instructions
require a four-scalar form (`[x21+0x28] == 4`), check the structure and
length, look up a queue through the client table at `+0x120` (call at
`0xfffffff009f1ae40`), compare a field from the returned object, and only then call the packet
routine at `0xfffffff009f1ae74`. An intentionally invalid/no-queue request
would stop before the parser and reveal nothing about the buffer ID. A
request that passes those gates may submit work; no proof yet bounds its
GPU/GFX effects. Therefore no selector-25 device experiment is enabled by
this result. The next offline task is to pin a valid, minimal packet format
and a pre-submission observation point for same-object/byte consumption;
without both, the parser link remains untested.

## Static/live consumer-type join

The live buffer-vtable checkpoint normalizes the registered object at
`0xffffffe786aa8700` to `0xfffffff007e44048`. The exact-image audit
independently identifies that same IOGPU base-buffer vtable. Its `+0x80`
slot (`0xfffffff007e440c8`) decodes to `0xfffffff009f25130`, the getter
used by the static packet path after an ID-based object lookup. This joins
the observed buffer *type* to the statically compatible consumer method;
it does not show that a packet looked up ID 1 in this run.

The getter first obtains a kernel mapping from the buffer's `+0x28`
descriptor and then adds the buffer's `+0x50` slice offset. The live test
validated `+0x28` descriptor identity and an independent DRAM alias, but
did not read `+0x30` (cached kernel mapping) or `+0x50` (slice offset),
and did not invoke the getter. Those remain distinct runtime checks.
The separate Stage-2/Hypervisor preflight remains blocked by the absent
framework/API, device-tree virtualization property, and entitlements; it
does not bridge this AGX packet or SPTM boundary. The historical Titan IPC
transfer is likewise not rescued by opening an own client: the latter
proves ownership of this buffer only, not the backboardd queue/device state.

## Selector-25 pre-parser boundary (offline)

The exact `23A355` image now has an audited sequence for the active
submission method. Selector 25 checks the four-scalar contract, looks up
a queue at `0xfffffff009f1ae40`, and branches around the batch routine
when that lookup returns null. It also compares a queue field before
calling the batch routine at `0xfffffff009f1ae74`. A rejected/no-queue
request therefore cannot test the buffer parser.

On the route that reaches the parser, the batch routine sets queue state
at `0xfffffff009f492a0`, enters its locking/backend path, and calls a
backend virtual method at `0xfffffff009f4960c` before the parser dispatch
at `0xfffffff009f49680`. The parser then looks up an input buffer ID at
`0xfffffff009f4bed0` and calls the selected object's `+0x80` getter at
`0xfffffff009f4bff8` on the continuing path. This order closes a static
control-flow question, not a runtime observation: the effects of the
backend call are not bounded, and no selector-25 invocation was made.

The conditional service-vtable factory at `0xfffffff007b1e768` resolves
to an `AGXCommandQueue` allocation path. A second factory slot at
`0xfffffff007b1e690` resolves to `AGXBlockFence`; its `+0x90` preparation
slot resolves to `0xfffffff0087f5ca8`. That method initializes fields,
takes a lock, and has a conditional resource-pool bitmap update at
`0xfffffff0087f5d34`. These identities are grounded in class registration
strings, metaclass allocators, and installed vtables in the exact image.
They remain conditional on the unobserved live queue/device virtual
dispatch. The bitmap update is not proved to happen on every accepted
request, and this does not establish GPU command execution.

The audit records these exact instructions and five factory/preparation
entries in `outputs/agx-shared-alias-submission-boundary-2026-10-19.json`;
all 170 offline tests pass. For the known active selector-25 route there is no
evidenced parser-only device test. A passive buffer-field observation
could further check the cached map and slice offset, but it would still
not prove packet consumption. GFX MMIO remains disabled.

## Queue creation is not a passive probe (offline)

Selector 6 follows the AGX service's `+0x698` queue factory, then calls
the queue's `+0xd8` initializer before registry insertion at
`0xfffffff009f1a6e0` and the output-pair store at
`0xfffffff009f1a710`. The exact-image queue initializer resolves to
`0xfffffff0088041e8`. It calls the device's `+0xd20` setup method,
allocates resource arrays, and calls the queue's `+0x160` method with
argument zero. That method resolves to `0xfffffff0087ff07c`: on its
initialization path it allocates and sets up resources, stores an object
at queue `+0x8e0`, calls a finalization helper at
`0xfffffff0087ff384`, and only then marks the queue ready at
`0xfffffff0087ff390`. No packet parser call is needed for these effects.

The audit pins three virtual targets and the ordering in the same JSON
artifact (370 instruction anchors). These are static, conditional paths:
the live queue type, resource-allocation outcome, and downstream device
effects were not observed or fully bounded. Creating a queue would provide
an ID, but is not a read-only identity check. No selector-6 device call or
new IPA was made. The remaining live buffer-consumption edge therefore
cannot be inferred from a no-queue rejection or from queue creation alone.
