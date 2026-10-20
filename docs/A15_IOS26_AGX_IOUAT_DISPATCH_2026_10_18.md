# A15 / 23A355: AGX map dispatch to IOUAT or AGXUAT (offline)

This pass used only the retained `kernelcache.bin`, SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
It also checked `devicetree.raw`, SHA-256
`c7d59f0364cdb504ee32881142b03dadcea85fe5808de7dd69e63bea7a9d5725`.
`tools/a15_ios26/audit_agx_uat_dispatch.py` pins the image, 197 instruction
anchors, three encoded AGX and six IOGPUFamily indirect-function entries,
18 modern external-method entries, two older selector-0 entries, and two
packet-buffer getter candidates,
one candidate IOGPUFamily array-provider entry, one kernel buffer-address
getter candidate, one kernel initializer entry,
and four authenticated kernel callback
candidates. Its JSON evidence is
`../../outputs/iphone-system/uat-map-dispatch-v1.json` relative to this
worktree. No device action or MMIO access occurred. The GFX/RTKit MMIO read
remains disabled after the unattributed GFX SERROR.

## New control-flow result

- In `com.apple.AGXG14P`, `0xfffffff008857f1c` reads bit 0 from the input
  AGX object's `+0xdae0` state and `0xfffffff008857f28` stores that bit to
  global `0xfffffff00ab61150`. This is a runtime mode value, not a constant
  established for the target iPhone.
- The AGX map path at `0xfffffff00887a8a4` takes its options from incoming
  `x2`. At `0xfffffff00887acc0`, mode bit set calls kernel
  `0xfffffff008761094` (`IOUAT` map); mode bit clear calls AGX-local
  `0xfffffff00889472c` (`AGXUAT` map). A second call path at
  `0xfffffff00887c3dc` has the same polarity. Encoded indirect-function
  entries at `0xfffffff007b1c670` and `0xfffffff007b1c5a8` decode, using
  kernel static base `0xfffffff007004000`, to the two AGX caller routines.
  These entries establish their presence in indirect dispatch data, not that
  a particular user-client selector reaches them.
- The `IOUAT` route checks `0x4000` alignment for length and virtual address,
  asks a descriptor's authenticated virtual method for physical segments,
  allocates a segment array, and writes records with `0x28`-byte stride.
  It then loads an object from `IOUAT+0x20` and invokes
  `0xfffffff0081152ec`, which dispatches through that object's authenticated
  vtable slot `+0x30`, using PAC discriminator `0x325e`.
- Four kernel callback entries have that discriminator and slot: `uat`,
  `t8110dart`, `ans2_sart`, and `nvme`. Their names and encoded target
  pointers are checked in the exact image. The `uat` entry at
  `0xfffffff007a7d820` decodes to `0xfffffff008136508`. That function calls
  `0xfffffff0087b3474`, whose stub sets table ID 7 and entry ID 4 before
  branching to the protected dispatcher.
- The `IOUAT` initializer at `0xfffffff00875ea20` takes a provider in `x3`.
  An authenticated indirect entry at `0xfffffff007aed448` resolves to that
  initializer. The AGX-reachable factory at `0xfffffff00875f2c8` loads that
  table's `+0xa8` slot and calls it with `x3=0` at
  `0xfffffff00875f3b8`/`0xfffffff00875f3c4`.
  It stores a non-null provider at `IOUAT+0x20`. When `x3` is null, it calls
  `0xfffffff00811520c` with the `uat` table header; that helper stores the
  table in the allocated object and the object at `IOUAT+0x20`. The map
  routine later reads the same field. Thus the **AGX factory's default
  branch** connects the IOUAT map callback to SPTM table 7, entry 4,
  subject to successful initialization.
- AGX calls the factory at `0xfffffff00887c95c` only on its mode-set path,
  stores the returned IOUAT object at state `+0x10`, and publishes that
  state at `+0x2e8`. Its later map path loads the state and its `+0x10`
  IOUAT object before calling `0xfffffff008761094`. This is a conditional
  static route, not evidence that mode was set or a map ran on the iPhone.
- The second AGX mapper saves its incoming descriptor object from `x1` and
  forwards it as `x1` to IOUAT. No caller-to-user-client provenance or
  control of that descriptor's physical segments follows from this alias.
- An upstream `IOGPUFamily` resource routine at `0xfffffff009f14a5c`
  receives an optional kernel object in `x2`. The non-null path calls its
  authenticated `+0xd8` method and branches away on a nonzero result. On
  success it forwards that object as `x3` through a `+0xf0` virtual call.
  The compatible `IOGPUFamily` method at `0xfffffff009f16e1c` preserves
  `x3` while walking a resource list and directly calls
  `0xfffffff009f52274` with it. This wrapper forwards `x3` through a
  `+0xe8` PAC call compatible with AGX method `0xfffffff0088792ac`.
  That AGX method passes the object to a `+0xd0` PAC call compatible with
  its second mapper. The exact table entries and discriminators are pinned,
  but the runtime object types selecting them are not observed.
- The exact `IOGPUFamily` image narrows one source of that routine's `x2`.
  Its immediate upstream framing method at `0xfffffff009f4bd6c` checks an
  8-byte minimum, 4-byte alignment, length overflow, and buffer end before
  calling the command handler through PAC. Another packet method at
  `0xfffffff009f4be9c` obtains a driver buffer address through a virtual
  method, checks record offsets, and passes bounded begin/end pointers to
  that framer. Encoded entries at `0xfffffff007e46c00` and
  `0xfffffff007e46c08` match the framing and command methods. This locates
  the request format inside a driver packet buffer; it does not yet prove
  which user-client API fills that buffer.

  The packet processor is reachable from the method at
  `0xfffffff009f1c684` through `0xfffffff009f49254`,
  `0xfffffff009f4956c`, and a PAC virtual call whose encoded
  `+0x118` entry at `0xfffffff007e46c50` resolves to
  `0xfffffff009f4be9c`. The method dispatcher at
  `0xfffffff009f1d4b0` accepts selector indices 0 through 13 and
  indexes two `0x18`-stride tables, selected by a client mode byte.
  **Index 0 in both older method tables** decodes to `0xfffffff009f1c684`.
  This method rejects a length above `0x40` or a null input pointer,
  then calls `0xfffffff00811c320` to copy a small input structure to
  its stack. The helper validates a user address range, temporarily
  clears PAN around the copy, and restores it afterward. On success,
  the method looks up a driver object by handle and forwards the copied
  structure and length to the packet path. This is a static packet route;
  invoking these older table entries through a live user client is not
  established.

  A separate `externalMethod` dispatcher at `0xfffffff009f1d3f8`
  gates on client `+0x100` bit 0, accepts indices through `0x37`, and
  selects one of two `0x18`-stride tables using client `+0x103` bit 0.
  Both tables place `s_new_command_queue` at **index 6**
  (`0xfffffff009f1a524`) and `s_submit_command_buffers` at **index 25**
  (`0xfffffff009f1acec`). The latter looks up a handle in the client
  table at `+0x120` and directly calls packet submission
  `0xfffffff009f49254` at `0xfffffff009f1ae74` after argument checks.
  This gives a more precise static external-method-to-packet edge,
  but does not prove the larger packet buffer's writable origin or a
  live call on the phone. The historical Titan header declares queue
  creation as 7 and submission as 26; in this exact image those entries
  resolve to `0xfffffff009f1a890` and `0xfffffff009f1afc0`, respectively.
  Its other three selectors are also one higher than the compatible
  exact-image table entries: 13 vs 12 for shared memory, 15 vs 14 for
  notification queue, and 25 vs 24 for setting a notification queue.
  These three correspondences are inferred from scalar and output
  contracts, not confirmed by symbol names. Both mode tables agree.
  The active probe stopped before either Titan selector call, so this
  mismatch is not an observed explanation for its current stop.

  The packet processor looks up a buffer object by ID in a driver table
  at `+0x490`, then obtains its buffer pointer through authenticated
  slot `+0x80` with PAC discriminator `0x8807`. Two matching entries
  decode to `0xfffffff009f24914` and `0xfffffff009f25130`;
  the latter calls the former and adds an object-local `+0x50` slice
  offset. The former tests an object at `+0x30` and, on one branch,
  calls that object's authenticated `+0x78` method for an address. The
  sole matching entry in the kernel image at `0xfffffff007ab4898` decodes
  to `0xfffffff0086e05dc`, which returns the object's field `+0x28`.
  This is a narrower buffer-address candidate set, but the
  runtime object type, effective byte alias, and user writability remain
  unproved.

  The same client object table is loaded at user-client `+0x120` during
  submission-object setup. An authenticated `+0xd8` call is compatible
  with `0xfffffff009f48aec`, which stores that table at submission object
  `+0x490`. The parser later uses that field for three IDs at copied
  structure offsets `+0`, `+4`, and `+8`; an earlier submission step also
  reads a handle at `+0x20`. The shared lookup at `0xfffffff009f17f10`
  rejects index zero or an index beyond the table count, loads an already
  registered object from the indexed array, and increments its reference
  count. Thus this route selects existing driver objects, rather than
  accepting an arbitrary kernel pointer from the copied structure.
  Runtime selection of the setup target and the concrete type accepted by
  the parser still require separate proof.

  A compatible shared-memory registration path is now visible upstream.
  External-method index 12 forwards the client table at `+0x120` to
  `0xfffffff009f3866c`. That routine obtains an object through a PAC
  factory call on table `+0x50`, registers it in the table's `+0x78`
  array via `0xfffffff009f17f08`, and returns both an ID and an address.
  The address routine `0xfffffff009f251c0` takes a mapping object from
  buffer `+0x48` and invokes its authenticated `+0x78` address getter.
  During buffer initialization, `0xfffffff009f24f70` creates a backing
  object stored at `+0x40`, copies that **same pointer** to `+0x28`, and
  stores a task-specific mapping at `+0x48`. The separate kernel-address
  getter can create a mapping at `+0x30` from the same backing object.
  Thus the registration and common backing-object pointer are static
  evidence; the factory's live class, mapping permissions, effective
  byte alias, and whether the parser selects this object are not yet
  established.

  The command handler's switch reads the command word from the
  request; signed jump-table slot 16 resolves to `0xfffffff009f4a7cc`.
  That branch requires at least 12 payload bytes after the initial 8-byte
  header, then checks `12 + 16 * record_count` against the available payload.
  It passes `request+0x14` to `0xfffffff009f2a6a4`. The loop there reads
  16-byte records: a flag byte, an index at `+4`, and two range words at
  `+8`/`+12`, with overflow and bounds branches. Depending on the flag, it
  supplies either `null` or an object loaded from a driver array as `x2`
  to a `+0x108` PAC dispatch compatible with `0xfffffff009f14a5c`.
  The array comes from an authenticated `+0xe8` method on a kernel object;
  another caller of the same `+0x108` slot reads its object from a kernel
  array at `+0x90`. This is evidence for **record/index control**, not a
  demonstrated ability to supply arbitrary descriptor bytes or physical
  segments. The array producer's runtime type and the actual target of each
  virtual call remain unresolved.
- A class-compatible `+0xe8` entry at `0xfffffff007e478e8` decodes to
  `0xfffffff009f54fec`. This candidate accepts only 4K, 16K, or 64K
  granules, checks alignment against a parent length at object `+0x30`,
  and lazily constructs an array by calling `0xfffffff009f19600` for each
  granule with a parent object from `+0x88`, slice offset, and granule size.
  It caches the array in the object. The call site's cast metadata is
  adjacent to this candidate's vtable, but subclasses or other runtime
  types could override the slot. The parent object's creation and backing
  segments are not yet traced. This is a stronger candidate for the next
  boundary, not proof of the provider used on the device.
- The alternative `AGXUAT` route at `0xfffffff00889472c` carries the
  caller's options to a PAC-authenticated virtual map callback after
  alignment/segment handling. A potential table-entry write inside that
  callback is not equivalent to an observed physical or protected write.
- The exact static DeviceTree has none of the properties named `gpu-iouat`
  in `/chosen` or `gpu` / `gpu_iouat` in `/arm-io/sgx`. The kernel's IOUAT
  bootstrap references these names, but the absence in this retained tree
  does not establish the runtime IORegistry values or AGX mode bit.

## Live cross-check (2026-10-19)

The user's `eed8d43` run on iPhone14,2 / 23A355 observes the G14P service,
`AGXGartG14`, and `AGXUATMux` pointer chain with exact unslid vtables.
The initialized mode global is `1` on two reads. The mux `+0x10`
factory-result field is non-null and stable, and its object's unslid vtable
is the exact-image factory value `0xfffffff007aed3a0` on two reads.
The persistent JSONL is
`outputs/device/a15-iouat-object-v1-20261019/after.jsonl` (SHA-256
`2FAA7538CEA433F28BB2D999B165CA2E4032D1A0D276673429A369EE15B527F9`).
This removes the null-factory alternative for that sampled state, but
does not show a map invocation or an accepted descriptor. The mismatch
between the service source byte `0` and global mode `1` remains unattributed.

The next evidence sequence is: an actual client/table/registered-buffer
identity; effective user-map write permission and one bounded byte shared
with the kernel-side buffer address; the same registered object retrieved
by the packet lookup; and only then the validated input-to-mapper path.
Failure of any earlier condition rejects this proposed ingress without a
GPU submission or protected request. No physical write, protected-memory
change, or SPTM/TXM call is implied by the factory-object observation.

## Falsifiable hypothesis and next check

Hypothesis: on iPhone14,2/23A355, a buffer created through compatible
external-method index 12 is returned with a writable task mapping, can be
resolved by index 25 through the same client table, and supplies command 16
bytes to the packet parser. The next minimal **offline** test is to trace
the PAC factory target at table `+0x50` / slot `+0xa8` and the arguments
and mapping flags passed to `0xfffffff0086dfc84`; check whether the
kernel mapping at `+0x30` exposes the same bytes. Then identify the runtime
`+0xe8` array producer and the origin of its parent object at `+0x88`.
Test whether the
`+0xd8` validation and descriptor virtual method
preserve any caller-controlled physical segment choice. Reject this ingress
hypothesis if the returned mapping is read-only, the kernel mapping has
different bytes, or the packet path rejects the created object. The 2026-10-19
run now observes the AGX mode and a matching factory-result object; it does
not resolve the buffer's concrete virtual targets, content control,
client-state gate, or live selector reachability. The buffer-factory and
mapping-option portions of this original offline test are further audited in
`A15_IOS26_UAT_INGRESS_BOUNDARY_2026_10_18.md`; effective runtime byte
aliasing remains unobserved.

The previously observed ClearSword kernel primitive remains separate from
this path. The later device run did prove a restored 0x20-byte kernel-virtual
write to an app-owned page; this audit and the IOUAT object observation do
not establish a physical write or protected-memory change.
