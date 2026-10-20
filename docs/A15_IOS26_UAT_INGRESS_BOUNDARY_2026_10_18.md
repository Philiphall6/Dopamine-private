# A15 / 23A355: UAT ingress boundary (offline)

No device action was performed for this pass. The GFX/RTKit MMIO read remains
disabled after the unattributed GFX SERROR.

## What is already established

- The SHA-256 `ED7781D2D82FE4818B85DD18C6B07DC172440EEECC2F7B33FC1E048313583F7C`
  23A355 SPTM image registers UAT table ID 7 at `0xfffffff0270180d0`.
  Its authenticated 16-byte entry 4 points to `acquire_uat_segments_page`
  (`0xfffffff0270a1d58`); entry 5 points to `sptm_uat_map_continue`
  (`0xfffffff0270a1590`). The producer has no direct `BL` caller in the
  extracted SPTM text; its table registration is the known dispatch edge.
- The 21B91 table also has ID 7, but its seven-entry UAT table places the
  analogous producer at index 2. The 23A355 table has 13 entries. This is a
  selector-layout change, not evidence of a new userland entry point.
- The 23A355 producer receives `segments_page`, `num_segments`, and
  `map_options` in `x2`/`x3`/`x4`, acquires the descriptor page as
  `XNU_DEFAULT`, and calls the continuation. Frame-domain and mapping-class
  checks still apply to leaves. These facts are from the exact-image
  `agx-uppl-producer.json` and `sptm-txm-static-report-v10.json` outputs.

## New upstream ownership cross-check

The local XNU source checkout is `xnu-12377.1.9` (`f6217f8`). In
`osfmk/arm64/sptm/pmap/pmap_data.c`, `pmap_cpu_data_array_init()` reserves
`MAX_CPUS * PMAP_IOMMU_SCRATCH_SIZE` from `avail_start`. The per-CPU
initializer derives a physical slice from `sptm_cpu_iommu_scratch_start`
and stores `phystokv(iommu_scratch)` in `sptm_pcpu->sptm_iommu_scratch`.
The adjacent source comment describes this memory as the EL2 IOMMU drivers'
buffer for passing data into SPTM. This identifies a kernel/driver-owned
staging surface, **not** an app-supplied descriptor page. The source does not
show that this particular scratch buffer is the page consumed by UAT entry 4
on 23A355; that link remains to be traced in the exact kernelcache.

## Falsifiable next link

The exact 23A355 kernelcache now supplies a conditional static upstream
route: AGX mode-set setup calls an IOUAT factory, which passes a null provider
to an authenticated initializer; its default `uat` callback calls the
ID-7/entry-4 protected stub. See
`A15_IOS26_AGX_IOUAT_DISPATCH_2026_10_18.md`. Runtime mode and reachability
remain unobserved.

Trace one exact `com.apple.AGXG14P` call path from a reachable user-client
selector to the identified IOUAT map routine. The exact image identifies
external-method index 25 in both IOGPUFamily tables as a packet submission
entry; it resolves a registered queue handle and calls the packet submit
routine after argument checks. A separate older method-table index 0 also
reaches that routine after copying at most `0x40` user bytes, but its live
use is unobserved. The historical Titan header's index 26 for submission
targets another method on 23A355; the active probe stopped before that call.
A driver packet parser bounds record offsets, its
framer checks length and alignment, and `IOGPUFamily` command 16 reads 16-byte request
records, checks their count and length, then uses record flags and indices to
choose a kernel object or null for the resource method's `x2`. The object
array is returned by an authenticated driver method, not embedded in those
records. A class-compatible provider builds such an array in 4K/16K/64K
granules from an existing parent object at `+0x88`; its runtime selection
and that parent's origin remain unproved. The resource method validates a non-null object through another
virtual method before forwarding it toward AGX. The command handler's
packet buffer's backing and writable provenance, and the array producer's
concrete runtime type are still unknown. Two PAC-compatible getters can
produce the packet buffer address; one adds an object-local slice offset.
The packet processor first resolves that object by ID from a driver table,
and its PAC `+0x118` process dispatch matches the exact parser entry.
The base getter calls a PAC `+0x78` candidate that returns an object field
at `+0x28`; the object's allocation and user mapping remain unproved.
Compatible shared-memory index 12 registers an object in that table's
`+0x78` array and returns an address through a mapping at object `+0x48`.
Its initializer stores the same backing-object pointer at `+0x40` and
`+0x28`; a separate kernel mapping can be built at `+0x30`. This connects
registration and backing provenance statically, but not the live factory
type, mapping permissions, effective byte alias, or parser acceptance.
The client table at `+0x120` is itself assigned by a PAC-authenticated
device `+0x588` factory. Compatible IOGPU and AGX entries lead to a table
initializer that creates the `+0x78` registry. A client-initializer input
stored at `+0x128` is forwarded as context. The downstream kernel mapping
routine reads that argument at `+0x28`, consistent with the exact-build
`task.map` offset. This supports a task-pointer interpretation but does not
identify the live task or the permissions of its mapping.
At the registered-buffer factory's PAC `+0xa8` call, the IOGPU base entry
forces mapping options `1`. The AGX override checks the second input scalar:
`2` passes `0x1001`, while any other value uses a base-table `+0xb8`
fallback. The base-table fixup decodes to `0xfffffff007e44fa0`; its `+0xb8`
slot is exactly the IOGPU entry that forces `1`. The buffer initializer
forwards this value to its mapping call. In local XNU 12377,
`iokit/IOKit/IOMapTypes.h` defines `kIOMapAnywhere = 1` and
`kIOMapReadOnly = 0x1000`; `IOMemoryDescriptor.cpp` only requests a write
memory reference when the latter bit is absent. Thus the AGX special branch
requests a read-only mapping and the base branch requests one without the
read-only flag. The exact-image audit pins these instruction/PAC edges, not
the resulting runtime permissions or user-to-parser byte propagation.
The backing call has the six-argument/tag shape of
`IOBufferMemoryDescriptor::inTaskWithOptions` in local XNU 12377. The
initializer passes the client task as `inTask` when option `0x1000` is clear,
and `NULL` when set; it fixes the backing options at `0x10060`, capacity at
the first caller scalar, alignment at `1`, kernel tag at `0`, and user tag
at `0x64`. XNU's `IOBufferMemoryDescriptor.h` decodes `0x10060` as
`kIOMemoryKernelUserShared | kIOMemoryPageable | kIOMemoryPurgeable`.
This strengthens the base path's user/kernel sharing provenance, while the
special AGX path starts with an unmapped allocation and asks for a separate
read-only user mapping. Neither the allocation's runtime success nor an
effective writable alias has been observed on the device.
In `IOBufferMemoryDescriptor.cpp`, a successful pageable allocation with
non-null `inTask` sets `mapTask = inTask`, creates a task mapping with
`kIOMapAnywhere` (no read-only bit), and makes that mapping the buffer
address. This is a conditional XNU contract, not a 23A355 runtime result.
The exact-image factory obtains its metaclass pointer from
`0xfffffff00aa9eb98`, which lies in the kernel's zero-fill `__common`
section. A further exact-image trace identifies its static class: the
registration at `0xfffffff0086d4bb0` passes that same global as `x0`,
the file-backed string `IOBufferMemoryDescriptor` at
`0xfffffff0070a53e1` as `x1`, and size `0xe8` as `w3` to the metaclass
constructor at `0xfffffff0085f7d6c`. The backing factory at
`0xfffffff0086d515c` loads this global and calls its allocation slot.
Thus the static factory class is established, while the zero-fill runtime
value, allocation success, virtual initializer result, and effective user
permissions remain unobserved. The metaclass allocation slot
`0xfffffff007ab3750` decodes to `0xfffffff0086d46b0`, which installs the
object vtable at `0xfffffff007aecbf8`. Its initializer slot `+0x128`
decodes to `0xfffffff0086d3bf4`. On the path with a non-null client task,
that initializer passes the task as `x4` to descriptor setup at
`0xfffffff0086e6be8`, with a range count of `1` in `w2`. This is distinct
from the task-mapping call below and does not prove descriptor setup succeeds.
After descriptor setup, the fixed backing options `0x10060` are filtered
by `0x1fffff00` and then `0xf0000fff`; the resulting task-map option is
`1` exactly. The code passes the selected task to
`0xfffffff0086dfc84`, retains the returned mapping object, and checks it
for null. Its authenticated `+0x78` getter resolves to
`0xfffffff0086e05dc`, which reads the mapping address at `+0x28`;
the initializer stores that value at descriptor `+0xb8`. This closes the
static address-provenance edge that the XNU source suggested. The known
`kIOMapReadOnly` bit `0x1000` is not requested on this call, but actual
permissions, allocation success, and propagation of caller edits into
parser bytes remain unobserved.
The two mapping routes now have a common static descriptor identity. The
initializer stores the returned `IOBufferMemoryDescriptor` in buffer
`+0x40`, copies that pointer into `+0x28`, and creates the user map at
`+0x48` through `0xfffffff0086dfc84`. When the base packet getter needs
an address, it lazily invokes buffer `+0x28`'s authenticated `+0xe8`
method and caches the resulting map at `+0x30`. The exact descriptor
vtable slot at `0xfffffff007aecce0` decodes to `0xfffffff0086e0abc`;
that method adds `kIOMapAnywhere` and tails into the same mapping helper.
The base getter reads the `+0x30` map's authenticated `+0x78` address,
while the external-method output reads that getter on the `+0x48` map.
XNU 12377's `IOMemoryDescriptor::map` and `createMappingInTask` have the
same source-level shape. The two maps are distinct objects, but their
static descriptor input is one object. No live bytes were compared, and
neither effective aliasing nor write permission is established by this
disassembly alone. A minimal falsifier is to mutate one bounded byte in
the returned user map and observe that byte through the registered
buffer's kernel-side address before command submission, with both map
creation and address-getter checkpoints recorded. This test has not run.
The registry path is now pinned more tightly. The table initializer
creates its `+0x78` array via `0xfffffff009f17d5c`. Its constructor
installs vtable `0xfffffff007e41030`; slot `+0x78` decodes to
`0xfffffff009f17ed4`, which writes the newly created buffer pointer
into the selected array slot. The shared-memory call passes that pointer
as the insert argument and returns the resulting nonzero ID. On the
packet side, the ID is read from the input, the same table's `+0x78`
array is searched, and the bounded lookup loads its `ID * 8` slot and
performs an atomic reference-count operation. This establishes a
conditional static object round trip, not that a live packet carries
the returned ID unchanged, that the ID remains allocated, or that the
base-buffer getter is the runtime target. The minimal falsifier for this
edge is equality of the registered object pointer and the parser lookup
result under the same table and ID, before any submission; not run.
The IOGPU base constructor installs vtable `0xfffffff007e44048`; its
`+0x80` entry is `0xfffffff007e440c8`, whose PAC-compatible target is the
packet processor's address getter `0xfffffff009f25130`. That getter calls
the base address method and adds buffer `+0x50` as a slice offset. This
closes a static type-compatibility edge for the base buffer, but does not
show that a valid live packet selects it or that its bytes are caller-writable.
The submission setup passes the user-client's table at `+0x120` to a
PAC-compatible initializer that stores it at object `+0x490`. The parser's
IDs are bounded indices into that table, not raw kernel pointers.
Record the copied or transformed input fields, allocation/type of the
physical descriptor page, and every length/options check. A route exists only
if the exact 23A355 path carries demonstrably caller-controlled descriptor
bytes into the protected request after those checks. Merely finding the
per-CPU scratch pointer, the SPTM endpoint, or a GPU map is insufficient.
The next falsifiable evidence boundary is the actual mode-zero buffer
allocation, mapping permissions, byte alias, and authenticated address
getter used by packet processing. If the live path selects a different
backing object, or the mode-zero mapping has
additional write restrictions, this proposed user-to-parser edge fails.
If the producer is populated only from driver-created state, abandon this
specific user-controlled-UAT hypothesis. Do not invoke a protected request
or touch MMIO to answer the offline provenance question.

No controlled kernel write, physical write, or protected-memory modification
is established by this cross-check. The observed ClearSword primitive is a
separate kernel-access result and cannot fill the missing ingress edge.
