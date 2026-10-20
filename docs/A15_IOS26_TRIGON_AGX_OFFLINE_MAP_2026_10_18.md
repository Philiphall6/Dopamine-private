# A15 / 23A355: offline Trigon AGX address map

Scope: iPhone14,2, A15, iOS 26.0.1, build 23A355. This is a comparison of
recorded target ranges with historical Trigon source constants. It performs no
device access and establishes no kernel write, physical write, or SPTM/TXM
modification.

## Sources and confidence

- Target DeviceTree: `outputs/iphone-system/live-usb/devicetree.img4`
  (SHA-256 `e56146e871749c7ffbf6e7e1db170edb32fa7d1504502e1997316f318bb6d49d`,
  matching `outputs/iphone-system/live-usb/manifest.json`), parsed from
  `outputs/iphone-system/unpacked/devicetree.raw`. Its root identifies
  `iPhone14,2`, `D63AP`, and `EmbeddedDeviceTrees-11156.2.8`.
- Target `gfx-asc` IODeviceMemory results:
  `tools/a15_ios26/live-layout-iphone14_2-23A355.json`, corroborated by
  `docs/A15_IOS_26_0_1_RESEARCH.md`. Descriptor 1 has a validated existing
  kernel `IOMemoryMap`; descriptor 0 has only a non-null mapping collection,
  not an enumerated/validated mapping. Neither has been dereferenced here.
- Trigon arm64e implementation: `alfiecg24/Trigon` commit
  `82d802e119c268fc8984e8d2a89a0c05b2be5a3d`, especially
  [`agx.c`](https://github.com/alfiecg24/Trigon/blob/82d802e119c268fc8984e8d2a89a0c05b2be5a3d/Trigon/Exploit/agx.c#L15-L19)
  and [`info.c`](https://github.com/alfiecg24/Trigon/blob/82d802e119c268fc8984e8d2a89a0c05b2be5a3d/Trigon/Exploit/info.c#L128-L139).
  These are historical constants, **not** measurements of the 23A355 device.
- [Trigon part 3](https://alfiecg.uk/2026/10/17/Trigon.html) limits the exploit
  to iOS 16.5 and below and says MMIO needed by its AGX cache-injection route
  became protected by `pmap-io-ranges` in iOS 16.6. This is a historical
  limitation, not a measurement of the exact 23A355 policy table.

## Target ranges

All ranges below use inclusive end addresses. The endpoint of descriptor 0 is
`0x206400000 + 0x6c000 - 1 = 0x20646bfff`; an earlier report had incorrectly
written `0x20646ffff`.

| Source | Physical range | Length | Demonstrated access |
| --- | --- | ---: | --- |
| `gfx-asc` descriptor 0 | `0x206400000..0x20646bfff` | `0x6c000` | Descriptor observed; mapping collection present, not enumerated |
| `gfx-asc` descriptor 1 (GFX IORVBAR) | `0x206050000..0x206050007` | `0x8` | Existing kernel map validated; register **not read** |

The `arm-io` DeviceTree parent maps child offsets beginning at physical
`0x200000000`. Its `sgx` child (`compatible=gpu,t8110`) declares offset
`0x4000000`, length `0x4000000`, i.e. physical
`0x204000000..0x207ffffff`. This **contains** all five historical Trigon
debug/ECC/wrapper addresses below. The DeviceTree declaration proves address
ownership, not a kernel or user mapping, register compatibility, or write
permission. The `sgx` node also declares a nested
`0x204d00000..0x204d1ffff` region.

The same DeviceTree has a 1,536-byte `pmap-io-ranges` property in
`/device-tree/defaults`. It decodes into 64 24-byte records using XNU's
`pmap_io_range_t` layout (`addr:u64`, `len:u64`, `wimg:u32`,
`signature:u32`), documented in `work/xnu-apple/osfmk/arm64/sptm/pmap/pmap_data.h`.
Two records are relevant here:

| Signature | Physical range | `wimg` | Historical Trigon addresses contained |
| --- | --- | ---: | --- |
| `DENY` | `0x206000000..0x20604ffff` | `0x4007` | `CPU_UTTDBG` |
| `DENY` | `0x206110000..0x2063fffff` | `0x4007` | `L2C_ERR_STS`, `L2C_RAM_CFG`, `ASC_DBG_SECURE_DEBUG_DIS`, `ASC_DBG` and `+0x8` |

These are the only two `DENY` signatures among the 64 records. `DENY` is the
stored four-character signature, decoded in four-character-code order rather
than raw little-endian byte order. XNU's `pmap_cache_attributes()` returns
the matching record's `wimg` for physical addresses outside its managed-page
range, except `SKIO`; it does not itself make the `DENY` access decision. The low six bits of
`0x4007` are the WIMG value `0x7`; the significance of its `0x4000` bit and
the full SPTM enforcement semantics are not established by the local XNU
sources or this DeviceTree parsing alone. The geometry
is nevertheless striking: the observed GFX IORVBAR is at `0x206050000`,
immediately after the first `DENY` range; `gfx-asc` descriptor 0 starts at
`0x206400000`, immediately after the second. Neither existing `gfx-asc`
descriptor includes Trigon's debug registers.

The offline check against `work/xnu-apple` commit `f6217f8`
(`xnu-12377.1.9`) confirms the distinction: `pmap_find_io_attr()` returns
the matching record for an I/O physical address, and
`pmap_cache_attributes()` can use its `wimg` value. Neither function creates
an `IOMemoryMap` or proves that a caller can read or write that register.
The raw DeviceTree table has 64 records; the five historical AGX debug/ECC
addresses above all match one of the two `DENY` records, while the validated
GFX IORVBAR and descriptor-0 start match neither. Static string presence in
the kernel image does not establish a runtime `sgx` alias.

## Exact kernelcache fileset and direct references

The unpacked kernelcache from the same USB preboot capture is
`outputs/iphone-system/unpacked/kernelcache.bin` (SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`).
It is an `MH_FILESET` with 248 entries. Its `com.apple.AGXG14P` entry starts
at file offset `0xf0cc0`; its `__TEXT_EXEC` spans file offsets
`0x17d2760..0x18910b7`. The kernel entry starts at `0x8000`.

In `AGXG14P`, the literal `/arm-io/gfx-asc` is at file offset `0xfbded`
(unslid VA `0xfffffff0070ffded`). A direct ARM64 `ADRP`/`ADD` reference at
`0xfffffff00884eb1c`/`0xfffffff00884eb20` loads that literal. The adjacent
instructions combine it with `IODeviceTree:` using a `%s%s` format, look up
the resulting registry path, and request the `compatible` property. This
observed sequence is a DeviceTree metadata lookup, **not** evidence that the
driver maps the broad `sgx` range or the Trigon debug registers.

The literal `/arm-io/sgx` is in the kernel entry at file offset `0xa81b6`
(unslid VA `0xfffffff0070ac1b6`). Its direct `ADRP`/`ADD` reference is at
`0xfffffff008760af0`/`0xfffffff008760af4`, in the code path associated with
`iouat_bootstrap` and adjacent `gpu_iouat` strings. That path concerns GPU
address translation setup; it is not an observed AGX debug-register mapping.
The direct-reference scan does not exclude indirect references or runtime
mapping. None of the exact 64-bit physical constants `0x206040000`,
`0x206150040`, `0x206050000`, or `0x206400000` appears as a literal in this
kernelcache; DeviceTree-derived addresses need not appear as literals.

## Static AGX provider-to-map path

The fileset's embedded `AGXG14P` personalities (XML near file offsets
`0x37960ba` and `0x37963fc`) declare `IOProviderClass=AppleARMIODevice`,
include `gpu,t8110` in `IONameMatch`, and name
`AGXAcceleratorG14P`/`AGXAcceleratorG14P_A0`. The exact DeviceTree `sgx`
node has `compatible=gpu,t8110` and two `reg` pairs:
`(0x4000000, 0x4000000)` and `(0x4d00000, 0x20000)`, relative to the
`arm-io` parent. This ties the personality to the `sgx` provider more
strongly than a kernelcache string reference alone.

In `AGXG14P` `__TEXT_EXEC`, the function at unslid
`0xfffffff008851a7c` calls `0xfffffff008816b74` while preserving its
incoming service-provider argument. An encoded vtable entry at unslid
`0xfffffff007b1e378` points to the caller. It belongs to the **instance**
vtable at `0xfffffff007b1e0d0`, installed by the
`AGXAcceleratorG14P` constructor at `0xfffffff008858570`. That constructor
uses the class metadata at `0xfffffff00ab5e640`, whose registration at
`0xfffffff008858754` names `AGXAcceleratorG14P`; it also initializes the
instance field `+0x310` to zero before installing the vtable. This connects
the map path to the base class reported in the retained live captures,
although execution of this method on the phone remains unobserved. The callee
casts the provider argument using an
`AppleARMIODevice` metaclass reference: its chained pointer at file offset
`0xb11c28` resolves into `AppleARMPlatform`'s metaclass storage, whose
initializer uses the literal `AppleARMIODevice`. The function stores the
accepted provider and calls a virtual count method at slot `0x3c0`
(`0xfffffff008816e9c`), then uses slot `0x3d0` twice at
`0xfffffff0088170bc` and `0xfffffff008817104` with an index and zero
mapping options. The return values are saved as map pointers. The matching
kernel implementation at `0xfffffff00867e770` gets a device-memory
descriptor and maps it; this is consistent with XNU 12377.1.9
`IOService::mapDeviceMemoryWithIndex` in `iokit/Kernel/IOService.cpp`.
PAC-authenticated vtable dispatch and the argument/return-value sequence
make this a **static map-attempt path**, not a demonstrated runtime map.

For a provider reporting two `IODeviceMemory` entries, the AGX branch at
`0xfffffff008816ed4` assigns index 0 to the GPU resource and index 1 to
the Fender resource. It first obtains the physical start of each selected
descriptor, then conditionally tries the corresponding maps according to
configuration flags. The DeviceTree contains two `reg`
pairs, but it has not been shown that the live `AppleARMIODevice` publishes
exactly two descriptors or that descriptor 0 retains the full declared
`0x204000000..0x207ffffff` range. The separately observed `gfx-asc`
descriptors cannot answer that question. A scan of this kext's
PAC-discriminated slot-`0x3d0` call sites found only these two instances;
the same call shape also occurs in other, unrelated drivers. The `AGXG14P`
literal `registers` is passed to a property setter at
`0xfffffff008878738`, not evidence of a register map.

An offline assertion over the SHA-256-pinned kernelcache and DeviceTree
confirmed the two `sgx` `reg` pairs, the embedded personality match, the
chained metaclass references, and both authenticated slot-`0x3d0` calls.
It performed no runtime mapping or device access.

## XNU resource-resolution contract and bounded check

The local XNU 12377.1.9 source supplies a more specific explanation for the
two `reg` pairs. `IOPlatformDevice::getResources()` calls the platform
expert's `getNubResources()` (`iokit/Kernel/IOPlatformExpert.cpp`). The
`IODTPlatformExpert` implementation returns early if device memory is already
present; otherwise it calls `IODTResolveAddressing(nub, "reg", NULL)`. That
resolver (`iokit/Kernel/IODeviceTreeSupport.cpp`) iterates the `reg` entries,
translates each through parent `ranges`, constructs one
`IODeviceMemory::withRange(phys, len)` for each successfully resolved entry,
and publishes the resulting array as `gIODeviceMemoryKey`.
`IODeviceMemory::withRange()` merely creates an `IOMemoryDescriptor` for the
physical extent (`iokit/Kernel/IODeviceMemory.cpp`); it does not read or write
the device. `IOService::getDeviceMemoryCount()` reads the published array,
while `IOService::mapDeviceMemoryWithIndex()` attempts to map one descriptor
and can return null (`iokit/Kernel/IOService.cpp`). Notably,
`IODTPlatformExpert::getNubResources()` returns success even if no descriptor
was constructed, so that return code alone is not a useful proof.

`tools/a15_ios26/analyze_sgx_device_memory.py` applies the direct-child
two-address/two-size-cell translation to the SHA-256-pinned decompressed
target DeviceTree (SHA-256
`c7d59f0364cdb504ee32881142b03dadcea85fe5808de7dd69e63bea7a9d5725`).
It checks that each `sgx.reg` extent fits exactly one `arm-io.ranges` entry;
this is a deliberately narrower offline model than XNU's general resolver.
Its result is:

| Candidate descriptor | Resolved physical range | Intersections with `DENY` records |
| --- | --- | --- |
| `sgx.reg[0]` | `0x204000000..0x207ffffff` | `0x206000000..0x20604ffff`, `0x206110000..0x2063fffff` |
| `sgx.reg[1]` | `0x204d00000..0x204d1ffff` | None |

Five synthetic unit tests cover translation, crossing and ambiguous parent
windows, record decoding, and overlap boundaries; all pass. The exact target
DeviceTree invocation also completes with the table above. This makes the
*candidate* descriptor geometry reproducible, but not the live
`AppleARMIODevice` array: that runtime provider may prepublish or alter
resources, `withRange()` may fail, and the subsequent map may fail. The AGX
personality and vtable path support a plausible connection, not proof that
the live provider reports two descriptors or a usable index-0 map.

## Exact AGX ProbeConfig state and failure branches

`tools/a15_ios26/check_agx_probeconfig_map.py` checks the pinned kernelcache
instructions and literals. In the two-resource branch, the AGX code stores
index 0 at `ProbeConfig+0xc` and index 1 at `ProbeConfig+0xd`. Its calls at
`0xfffffff008817018` and `0xfffffff008817074` fetch each descriptor via
the provider's slot `0x3c8`, then call the kernel wrapper at
`0xfffffff0086eb8e4`. That wrapper dispatches the descriptor's virtual
slot `0x98` with `(0, NULL, 0)`, consistent with XNU's
`IOMemoryDescriptor::getPhysicalAddress()` implementation, **not** with a
mapping or physical-memory read. AGX saves the returned physical starts at
`ProbeConfig+0x18` (GPU/index 0) and `+0x20` (Fender/index 1).

The `ProbeConfig` storage is in AGXG14P `__DATA`, at unslid
`0xfffffff00ab5ea88`; these offsets are static for the pinned image, not
runtime addresses until the kernel slide is applied. Conditional calls to
provider slot `0x3d0` request `mapDeviceMemoryWithIndex` for GPU index 0
and Fender index 1, gated by bits 0 and 2 of `ProbeConfig+0x11`
respectively. Their results are stored at `ProbeConfig+0x30` and
`+0x38`. If a requested GPU map returns null, the branch at
`0xfffffff0088170e0` goes to a verification-failed path with the literal
`Could not map GPU reg range`; the corresponding Fender branch at
`0xfffffff008817128` uses `Could not map Fender reg range`. This establishes
explicit failure handling in the exact AGX code, but neither call is known
to execute on the research phone in this configuration.

For the **fresh-provider** initialization branch specifically, the code
stores mode `2` at `ProbeConfig+0x8`. When the resource count is two, the
following flag calculation turns `(mode - 1) < 2` into bit 0 of
`ProbeConfig+0x11`, after clearing the old low bits. The later mask `0xeb`
retains bit 0. Thus a two-descriptor fresh-provider path requests the GPU
index-0 map; it is not optional on that path. The Fender bit 2 still depends
on other configuration. A different resource count, reuse of an already
initialized provider, or runtime side effects are not resolved by this
static proof.

The new offline checker passed against SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
It verifies the two selected indices, the physical-address stores, both
map-result stores and null branches, the kernel wrapper call shape, and the
failure strings. It does not claim that the descriptor starts match the
DeviceTree, that either map exists at runtime, or that MMIO is accessible.
The retained `outputs/iphone-system/*usb-syslog.jsonl` files contain no
`Could not map GPU reg range`, `Could not map Fender reg range`,
`AGXk Verification failed`, or `ProbeConfig` match. This absence is not a
runtime success result: the relevant initialization may not have run, and
those captures are not a complete AGX trace.

### AGX's ordinary use of the mapped address

The exact kernelcache provides a further static connection beyond a map
attempt. The `IOMemoryMap` vtable at unslid `0xfffffff007ab4820` has a
chained slot-`0x78` entry resolving to `0xfffffff0086e05dc`. That three-
instruction kernel function returns the field at map-object offset `0x28`;
XNU's `IOMemoryMap` layout identifies it as `fAddress`, and
`getVirtualAddress()` returns that field
(`iokit/IOKit/IOMemoryDescriptor.h:914-920`,
`iokit/Kernel/IOMemoryDescriptor.cpp:5627-5641`). After a non-null GPU
index-0 map, AGX calls this slot at `0xfffffff0088171f8` and stores the
returned virtual address at its object offset `+0x310` at
`0xfffffff00881720c`. This shows that the mapping result is wired into
the driver's own address state; it does not show that this branch executed
on the phone.

The `AGXAcceleratorG14P` instance vtable at `0xfffffff007b1e0d0` has
offsets `+0x2a8`, `+0x7b8`, and `+0x7c0` resolving respectively to the
setup method at `0xfffffff008851a7c`, a writer at
`0xfffffff008850900`, and a reader at `0xfffffff0088508c8`. The reader
loads the object field `+0x310` and reads from virtual offset `0x11108`.
The writer loads the same field and stores a word at offset `0x11000`
(`0x100e0 + 0xf20`). These are **static AGX MMIO code paths**, not observed
device accesses or controlled writes. If the live map starts at the
DeviceTree's candidate `0x204000000`, their candidate physical addresses
are `0x204011108` and `0x204011000`, neither inside a `DENY` record.
Thus ordinary AGX operation may use the index-0 map without establishing
access to Trigon's protected offsets around `0x206000000` and
`0x206110000`. The updated exact-image checker verifies the chained
vtable targets, accessor, stores, and these two sample uses. It does not
exclude other AGX paths or establish runtime map geometry.
The setup entry's direct branch at `0xfffffff008851a8c` calls the map
routine before the entry's subsequent flag-bit-4/SoC handling. The exact-
image checker now pins this order. It establishes the order **if** the
virtual setup entry is dispatched; it does not establish that dispatch on
the device.

### Fixed-offset AGX writer is not an arbitrary-write primitive

The exact-image check of the base-class method at `0xfffffff008850900`
finds its first MMIO store at `0xfffffff008850a1c`. The destination is
the virtual map base stored in the AGX instance at `+0x310`, plus fixed
offset `0x11000`; its stored word is
assembled from object fields, bitmaps, and loop state. Capstone's register
access data shows no read of incoming `x1`-`x7` arguments before that
store. There is no direct `BL` caller of this writer or its paired reader
inside the `AGXG14P` fileset; their instance-vtable slots remain the
identified dispatch surface. This rules out treating this routine's mere
presence as an argument-controlled arbitrary-address write. It does **not**
rule out indirect influence over earlier object state, callers in another
fileset, or other AGX write paths. Nor does it prove that the live map exists
or that this store executed. The fixed candidate address is outside the
DeviceTree `DENY` records, so this particular store does not itself reach
the Trigon protected ranges.

### Correction of the retained live `+0x310` observation

The earlier USB capture
`outputs/iphone-system/live-usb/titan-live-agx-mapped-addresses-v4.json`
(SHA-256 `2d1ad90fb3e6496f35a9d7e3927a54d8c2b9be8d480ebe9aa3226f7637e74573`)
reported zero for `gpu_reg_va` at `+0x310`. Its `AGXMappedAddresses`
read plan explicitly uses `root=IOGPUDevice`, with `object` equal to that
connection's `IOGPUDevice` pointer. The object's unslid vtable is
`0xfffffff007b21c50`, not the static
`AGXAcceleratorG14P` instance vtable `0xfffffff007b1e0d0`. The `+0x310` store
traced above uses the AGX setup method's receiver, preserved as `x20`
through the map path. The old read therefore addresses a **different class
of object**. Its zero cannot establish that the AGX GPU map or virtual
address is null.

The same wrong-root read occurs in retained `titan-live-ascwrap-v5.json`
(SHA-256 `3225e4355e9491e7cbfdc2b33457385020bdbba2d25d451c778fd58b41bc5728`)
and `titan-live-rtbuddy-v7-initial.json`
(SHA-256 `cbadd0fb8b504ff2761929265174b67196b435b26e08b547e2f841a765b3cf0e`).
`tools/a15_ios26/audit_agx_map_reads.py` checks the object-root and vtable
identity in those JSONs offline, rather than interpreting the field name as
proof of its owner's type. None of the three captures reads the base-class
AGX instance's `+0x310`; its runtime map
state remains **unmeasured**, not proven present. `serviceName` in the
capture identifies the registry service selected for a connection, not the
class of the object used by the nested `kernelReadPlans` read.

### Corrected base-class dispatch gate

The v4 live capture reports `serviceClass=AGXAcceleratorG14P`, without
`_A0`. The current local `work/FilzaJailedDS-34306/FilzaTitanProbe.m`
implementation obtains this field via `IOObjectGetClass()` after
`IOServiceMatching("AGXAccelerator")`; however, that source now emits probe
version 9 and is not a binary-proven copy of the version-4 implementation.
The embedded AGXG14P personalities both list `gpu,t8110` in
`IONameMatch` and the same `IOProviderClass=AppleARMIODevice`, so their
matching strings alone do not decide which object executes the setup path.
The earlier comparison at offsets `+0x330/+0x840/+0x848` was invalid:
`0xfffffff007b1e048` and `0xfffffff007b1ee48` are **metaclass** vtable
pointers, not corresponding instance vtables. The long instance table starts
at `0xfffffff007b1e0d0` after a three-zero-word boundary and ends at the
next such boundary at `0xfffffff007b1ee30`. The constructor using the
base-class metadata stores that table and initializes `+0x310`; its entries
at `+0x2a8/+0x7b8/+0x7c0` link the map setup, writer, and reader. The
SHA-pinned offline checker now asserts the boundaries, constructor, class
literal, and entries. This removes the alleged A0-only blocker, but it does
not show that the live base-class object has a non-null map. XNU's
`IOService` matching checks whether a client already consumes the personality's
`IOMatchCategory` on a given provider (`iokit/Kernel/IOService.cpp`, around
the `copyClientWithCategory()` check). The two AGX personalities use the same
`IOAcceleratorES` category. If the captured base service and the A0
personality compete for the same live `sgx` provider, an already-selected
base client is evidence against a parallel A0 client on *that provider*.
The capture does not identify the provider object or perform an A0 service
enumeration, so this remains a conditional inference, not an absence proof.

All 51 retained target probe JSONs in `outputs/iphone-system/live-usb/`
that have a scalar `serviceClass` report `AGXAcceleratorG14P` on
`iPhone14,2`/`26.0.1`. They span six recorded kernel-base values, but are
not 51 independent boot experiments. None reports `_A0`; the probes select
one `AGXAccelerator` service and do not enumerate all such services. The
SHA-pinned code check finds exactly one direct `BL` in AGXG14P
`__TEXT_EXEC` to the analyzed map-setup routine
`0xfffffff008816b74`: the call at `0xfffffff008851a8c` from the
base-instance method. The reported live service class therefore agrees with
the static map path. It does not prove that the method ran, that a map
survived, or that a protected subrange can be accessed.

## What a non-null AGX map would and would not prove

XNU 12377's `IOService::mapDeviceMemoryWithIndex()` calls `range->map(options)`
(`iokit/Kernel/IOService.cpp:8505`). `IOMemoryDescriptor::map()` requests a
kernel-task mapping of the descriptor's **full** length
(`iokit/Kernel/IOMemoryDescriptor.cpp:5815`). On a new physical-descriptor
mapping, `makeMapping()` calls `doMap()` and returns null when that call fails
(`IOMemoryDescriptor.cpp:5958,6039`). A compatible existing map can instead
be reused (`:6013`), so a non-null result need not represent a fresh mapping
operation on that invocation.

For the physical `IODeviceMemory::withRange()` used by the DeviceTree
resolver, `doMap()` goes through `memoryReferenceMap()` and, when its device
pager is present, `populateDevicePager()` (`IOMemoryDescriptor.cpp:5055,5117`).
The physical-descriptor reference path sets up that pager and marks a
single-range descriptor contiguous (`:735-770`). Population covers the
physical segment via `device_pager_populate_object()`; for a kernel map it
then calls `vm_fault()` at the **start** of the mapping to resolve an early
pmap entry (`:5305-5377`). This is map-time VM work, not a CPU read of the
MMIO register. The source does not show a separate `vm_fault()` for every
page in the 64 MiB segment. The two `DENY` intersections start at offsets
`0x2000000` and `0x2110000` from `sgx.reg[0]`, far beyond that initial
fault address. Therefore even a non-null `ProbeConfig+0x30` would establish
at most a surviving map object, **not** that either `DENY` subrange has a
usable page translation or tolerates a register read/write.

The visible pmap path also makes an attempted *new* map a potentially
non-benign experiment. `pmap_enter_pte()` passes the PTE to `sptm_map_page()`
(`osfmk/arm64/sptm/pmap/pmap.c:5690,5763`). In the non-managed-physical-page
branch, XNU panics on an unexpected SPTM return other than the documented
success/valid/flush-pending cases (`:6229-6259`). This source path does not
show that either `DENY` range will be rejected, or that the target ever
reaches that branch, but it rules out treating an explicit map attempt as
automatically read-only or harmless. The relevant runtime I/O table comes
from `SPTMArgs`, and the `0x4000` bit in the DeviceTree records has no
defined meaning in the visible `pmap_io_range_t` flag list. We must inspect
**existing** map metadata only; no new mapping or MMIO access is authorized
by this offline result.

The `DENY` label is a DeviceTree 4CC signature, not by itself a demonstrated
access result. XNU's SPTM pmap code takes its runtime I/O attribute table
from `SPTMArgs->sptm_pmap_io_ranges`
(`osfmk/arm64/sptm/pmap/pmap_data.c`), and its visible cache-attribute path
does not establish the hardware/SPTM rule for a dereference. Neither the
source-level resolver nor the offline overlap check justifies reviving the
MMIO read that was disabled after the unattributed GFX SError.

## Trigon register comparison

| Historical Trigon name | Physical address | `sgx` DeviceTree | `pmap-io-ranges` | Existing `gfx-asc` map | Role in Trigon source |
| --- | ---: | --- | --- | --- | --- |
| `CPU_UTTDBG` | `0x206040000` | Inside | `DENY` | Outside | Halt/unhalt debug wrapper |
| `L2C_ERR_STS` | `0x206140008` | Inside | `DENY` | Outside | ECC state |
| `L2C_RAM_CFG` | `0x206140108` | Inside | `DENY` | Outside | Cache RAM configuration |
| `ASC_DBG_SECURE_DEBUG_DIS` | `0x206150020` | Inside | `DENY` | Outside | Secure debug control on A15+ |
| `ASC_DBG` | `0x206150040` | Inside | `DENY` | Outside | Cacheline injection port (`+0x8` also used) |
| A15 AGX PMGR | `0x23b7003c8` | Outside | No matching record | Outside | Power state/control; lies in the `pmgr` DeviceTree ranges |

Trigon's A15 `gDeviceInfo.iorvbar` is `0x210050000`, whereas the observed
`gfx-asc` IORVBAR here is `0x206050000`. Trigon uses its value to derive a
kernel physical base; these must not be treated as the same register or used to
infer that Trigon's other constants are correct for 23A355.

## Route decision

The **existing** GFX IORVBAR map cannot directly serve Trigon's AGX cache
injection: it covers only eight bytes, and neither observed `gfx-asc`
descriptor includes the required registers. The exact DeviceTree does place
the historical addresses inside `sgx`, but also records them inside `DENY`
`pmap-io-ranges`. A declared register window is not an accessible mapping.

The corrected static **base-class** path makes a map attempt for its
GPU-matched provider plausible, including index 0 if its published
descriptor count is two. The retained captures report this same base-class
service. This resolves the earlier class-identity mismatch, but does **not**
establish a surviving `sgx` `IOMemoryMap`, the physical range
actually exposed by that map, or successful access inside either `DENY`
subrange. The next concrete gate is to prove those descriptor and map
attributes without dereferencing MMIO. The old `IOGPUDevice+0x310=0` result
does not close this gate. A bounded, read-only runtime check should identify
the live base-class AGX service object and its provider, then record
the device-memory count, both physical extents, the `ProbeConfig` flag byte
at `+0x11`, the **service instance's** `+0x310` field, and the corresponding physical-start
and map-result fields at `+0x18/+0x20` and `+0x30/+0x38` using validated
small metadata reads. If
the count or index-0 extent differs from the offline result, this particular
AGX route is refuted. A null index-0 map would be a meaningful failure only
if the fresh-provider two-descriptor path ran and the flag still required the
GPU map attempt; otherwise it could reflect a different configuration or
initialization path. A map covering the broad window would
still **not** prove that SPTM permits an access inside either `DENY` range.
Cache attributes, secure-debug state, historical-register validity on this
build, and a controlled write with readback remain separate gates. The prior
GFX SError has uncertain provenance, so live MMIO reads and writes remain
disabled.

## Minimal class gate prepared, not yet run

The next probe revision adds an `agx.registry` census before XPF or the
ClearSword/Titan stages, behind the exact iPhone14,2 / 23A355 target gate.
It iterates the IOService plane, records each `AGXAccelerator*` service's
class, registry ID, and immediate parent class/name/ID, then writes a
bounded `SUMMARY` and `STOP` to the persistent A15 JSONL. This census
does not open a user client, map memory, submit GPU commands, or touch MMIO.
The remainder of the existing active probe is unchanged, so its overall
launch must **not** be described as read-only. No IPA containing this
revision has been built, installed, or run on the device yet.

The falsifiable question for this census is whether the previously reported
`AGXAcceleratorG14P` service is attached to the live `sgx` provider and
whether any A0 service also exists. `complete=yes`, `class-failures=0`,
`iterator-valid=yes`, `base>0`, and a parent named `sgx` would establish
the service/provider relationship for that run. It would justify a separate,
metadata-only validation of that exact service instance; it would not
establish an MMIO translation, accessible `DENY` registers, kernel write,
physical write, or protected-memory modification.
The persistent `agx.registry` checkpoints would localize a failure before
the subsequent active stages, but an iPhone panic still needs a separately
captured panic log and matching run ID/timestamp before attribution.

## Bounded instance metadata stage prepared, not yet run

The current source revision `agx-service-census-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1`
retains the pre-XPF registry census and replaces the active Titan local GPU
queue-selector step with `titan.agx-map-metadata`. After the exact target gate,
ClearSword, and patchfinder, it obtains the `AGXAccelerator` service handle,
requires userland class `AGXAcceleratorG14P`, validates the unslid
`IOMachPort` wrapper vtable (`0xfffffff007abcb18`) before following its
object pointer, and validates the unslid service *instance* vtable
(`0xfffffff007b1e0d0`) before reading `+0x310`. It then reads only scalar
fields of the static `ProbeConfig` at `0xfffffff00ab5ea88` plus the runtime
kernel slide: mode, GPU/Fender indexes, flags, physical starts, and map-result
pointers. Each exact read has a persistent checkpoint. The stage does not
dereference a map-result pointer or mapped address, open a GPU user client,
invoke a queue selector, copy an IPC right, or read/write MMIO. It always
stops Titan after the metadata check. The whole launch is **not** read-only:
the preceding ClearSword primitive is still active.
The decisive service and configuration fields are read a second time;
`stability PASS` is required before a summary is accepted. This rejects
obvious concurrent changes, though it is not an atomic snapshot of the
driver state.
The wrapper reference is the unslid value of the earlier validated 23A355
`gfx-asc` wrapper capture (`0xfffffff04b314b18 - 0x43858000`); it is an
identity gate, not permission to follow a mismatched object.

A successful run needs the same exact target/build, complete `agx.registry`
census, both vtable identity `PASS` checkpoints, all scalar-read `PASS`
checkpoints, `stability PASS`, and a final `titan.agx-map-metadata PASS`
followed by `STOP`.
A class/vtable mismatch blocks interpretation of subsequent offsets. A zero
`service+0x310` or GPU map-result pointer would narrow the map hypothesis,
but would not by itself prove the setup method ran; mode, indexes, flags,
and the fresh-provider two-descriptor contract must be checked together.
Nonzero values establish metadata only, not an accessible MMIO translation
or a controlled write. No IPA containing this revision has been built,
installed, or run on the iPhone.

## Persistent-log triage prepared

`tools/a15_ios26/triage_agx_metadata_probe.py` reads a saved
`Documents/a15-ios26-active-probe.jsonl` copy offline. It selects the last
`run_id` by default (`--run-id` selects another), reports the input SHA-256,
and requires the exact target/build/revision plus ordered census, primitive,
identity, scalar, repeat-read, stability, summary, and stop checkpoints.
It correlates the AGX service registry ID with the census match and its
`sgx` parent. Hypervisor preflight `BLOCKED` events and the intentional
outer `titan.run FAIL` after the metadata `STOP` are not treated as the
first failure. An unexpected return to local GPU selection, IORVBAR,
RTKit, IPC census, or command-buffer stages invalidates a new-revision run.

Example after exporting the app's JSONL, without accessing the phone:

```powershell
py tools/a15_ios26/triage_agx_metadata_probe.py path\to\a15-ios26-active-probe.jsonl
```

`metadata_matches_static_candidate` is only a metadata-consistency
verdict. It does not validate the referenced `IOMemoryMap`, establish a
hardware/SPTM permission for `DENY`, or demonstrate a controlled write.
The existing October 16 JSONL is correctly rejected as an earlier
revision; it cannot satisfy the new run's gates.
