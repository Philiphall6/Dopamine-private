# A15 / iOS 26.0.1 Research Worklog

This file is the durable handoff for the `iPhone14,2` / `23A355` research
branch. It records confirmed evidence, unresolved hypotheses, generated
artifacts, verification, and the next bounded task. Conversation history is
not treated as the source of truth.

## Scope and Safety Boundary

- Target: `iPhone14,2` (A15), iOS 26.0.1, build `23A355`.
- Current phase: offline GFX/SPTM/TXM comparison and bounded diagnostic code.
- Not enabled: unrestricted physical write, privilege elevation, trust-cache
  installation, bootstrap preparation, or a general jailbreak path.
- Runtime-derived addresses and credentials are not recorded here.

## 2026-10-16: AGX / SPTM Producer Boundary Correction

### Completed

- Added `analyze_agx_uppl_producer.py` for a symmetric, offline comparison of
  the exact `21B91` and `23A355` AGX/SPTM images plus the `23A355` GFX slices.
- Decoded every RTKit PatchBay descriptor by its four-byte tag, declared value
  width, and inline default.
- Classified direct references, writers, relocations, chained fixups, and the
  Mach-O symbol flags for `__rtk_uppl_client_dispatch`.
- Compared `AGXFirmwareKextG14RTBuddy::requestFirmwareBinary` and the SPTM
  microPPL handoff anchors on both builds.
- Reconstructed the shared handoff layout on both builds and linked the
  `23A355` GFX PatchBay PPL-shared base to its direct firmware consumer.
- Recovered the protected UAT map-continuation frame checks and per-type
  mapping-policy lookup on `23A355`.
- Recovered the exact `21B91` predecessor despite its older symbol/API shape,
  and compared its direct frame-type switch with the `23A355` table policy.

### Confirmed Findings

1. The microPPL handoff magic remains `0x4b1d000000000002` on both builds.
   The existence of the handoff is therefore not the iOS 26 novelty.
2. The iOS 17 AGX firmware-provider method copies the core configuration and
   returns success for its accepted role, while retaining an assertion path
   for unsupported input. The iOS 26 method is an unconditional
   `Unimplemented` stub with the added `AGFIFirmwareRole` argument.
3. PatchBay supplies `BtpG` (GPTBAT base), `StpG` (GPTBAT size), `BlpP`
   (PPL-shared base), and `S2xG` (PPL-shared L2 physical address). No PatchBay
   descriptor names or targets the UPPL dispatch object.
4. In both `23A355` GFX slices, `__rtk_uppl_client_dispatch` is a zeroed,
   16-byte weak definition (`n_desc=0x80`) in `__DATA,__gxf_data`. It has one
   direct reader, no direct writer, no section relocation, no image
   relocation, and no chained fixup.
5. The prior statement that this proved runtime population was too strong.
   The corrected status is **zero weak default; producer unresolved**. The
   exact A15 payload may leave the UPPL route inactive unless an external
   protected producer is demonstrated.
6. `23A355` SPTM explicitly parses dynamic `%s-data-base` and `%s-data-size`
   properties for `gfx`, checks page alignment, and carries the diagnostic
   anchor `uat_register_gfx_data_segment`. This is a real producer-side bridge
   for the protected GFX data segment, but it does not yet prove that SPTM
   replaces the two UPPL words.
7. The shared SPTM/GFX handoff layout is symmetrical: SPTM magic at `+0x0`,
   GFX peer magic at `+0x8`, status at `+0x18`, 65 records at `+0x20` with
   stride `0x18`, ownership/state byte at `+0x638`, and auxiliary word at
   `+0x640`. SPTM initializes the final fields to `1` and `0`; GFX writes the
   peer magic and clears `+0x638` during bootstrap.
8. Both `23A355` GFX slices directly consume PatchBay's PPL-shared base. This
   proves the shared handoff, but not an UPPL handler-table producer.
9. The iOS 26 SPTM initializer stores dynamic GFX segment records at driver
   state `+0xb8`, stride `0x10`, with physical base at `+0x0` and page count
   at `+0x8`. It registers them through the protected-frame helper using
   selector `1`; the shared handoff uses selector `2`. The helper's exact
   compatibility branches map existing protected region type `2` to selector
   `1` and type `0x16` to selector `2`.
10. `sptm_uat_map_continue` at `0xfffffff0270a1590` acquires page-table
    frames as type `0x17`. Its mapping path reaches
    `iommu_register_mapping` at `0xfffffff0270caa58`, which passes `0x42` as a
    wildcard selector, reads the actual frame type from metadata `+0x2`, and
    then consults the per-type record table at `0xfffffff02701d720`. Its
    `0x60`-byte records contain the allowed-domain bitmap at `+0x8` and the
    maximum mapping class at `+0x10`. Segment registration is therefore not
    equivalent to permission to map arbitrary protected pages.
11. The reverse chain now reaches the UAT request producer. Endpoint 4 at
    `0xfffffff0270a1d58` acquires the segment-descriptor frame as type `0xb`
    and calls map continuation at `0xfffffff0270a1ef0`; endpoint 5 is the
    continuation function itself. Both belong to UAT dispatch ID `7`.
12. The chain reconnects structurally to GFX through the shared UAT/handoff
    state and the direct GXF dispatcher, but no static call edge yet proves
    that GXF command `0x10` invokes SPTM endpoint 4 or 5. The UPPL branch also
    remains separate and unresolved.
13. The type-`2` policy record has a zero allowed-domain bitmap and maximum
    mapping class `0`. Selector-1 `gfx-data` registration is therefore not a
    direct UAT leaf-mapping capability. The frame types with a nonzero domain
    bitmap or mapping class are `0`, `0xb`, `0xe`, `0xf`, `0x10`, `0x19`,
    `0x22`, `0x23`, `0x24`, `0x25`, and `0x3b`.
14. The immediate GFX firmware constructor for command `0x10` is the
    unsymbolized function at `0xffffff80000339f8`. It writes the command at
    `0xffffff8000033a08` and submits it through the GXF wrapper from
    `0xffffff8000033a28`. The envelope contains command `0x10` at `+0x0` and
    a payload pointer at `+0x8`; the payload stores original arguments `x1`,
    `x0`, `x2`, and `w3` at `+0x0`, `+0x8`, `+0x10`, and `+0x18`.
15. The firmware route reaches `__mmu_gxf_enter`, the direct GXF dispatcher,
    and `__rtk_mmu_map`, but no branch, endpoint ID, packet translation, or
    common protocol links it directly to SPTM UAT endpoints 4/5. The kernel
    `gfx-handoff-base` initializer at `0xfffffff008892a3c` builds the shared
    handoff but not the command packet; the local `RTBuddy64` fileset contains
    only two trampolines. The demonstrated relation is architectural, not a
    direct packet transfer.
16. Exact `21B91` uses `iommu_frame_acquire` at `0xfffffff0070882a8`, not
    `iommu_frame_acquire_type`. Its `sptm_uat_map_continue` at
    `0xfffffff00706fd5c` page-masks the leaf address with
    `0xfffffffff000` and calls `iommu_register_mapping` at
    `0xfffffff00706ff30` with legacy mode `0` or `1`.
17. The `21B91` registrar at `0xfffffff007088760` reads the actual frame type
    from metadata `+0x2` and has accepting branches only for
    `XNU_DEFAULT (0xb)` and `XNU_IO (0x19)`. This is a direct switch, not the
    authenticated per-domain/per-class table used by `23A355`.
18. The `21B91` request function at `0xfffffff0070703b4` saves the same five
    input registers as the iOS 26 producer and tail-calls map continuation at
    `0xfffffff007070484`. Its copy helper at `0xfffffff00706f68c` validates
    the segment-descriptor page as `XNU_DEFAULT (0xb)`. The structural
    producer role is therefore symmetric even though the protected policy
    generation changed.

### Route Consequence

The elevation research should no longer assume that handler indices can be
discovered by observing an inevitable UPPL registration. The direct GXF route
and the SPTM/GFX shared handoff are proven, but the handoff is not new. The
iOS 26-specific route now runs through dynamic GFX segment registration into
the protected-frame registry and then through independent frame-type, domain,
and mapping-type checks. The reverse pass now reaches UAT dispatch ID `7`, the
endpoint-4 request producer, the shared handoff, and the known GXF side. The
type-`2` `gfx-data` record is not directly mappable under that policy. GXF
command `0x10` and SPTM endpoints 4/5 are now classified as separate
interfaces over the same UAT/handoff architecture; a direct edge or common
packet format was not observed. The next offline targets are the kernel/RTKit
caller provenance of the unsymbolized GXF constructor and ownership/naming of
the frame types that actually permit mapping. The weak UPPL object remains a
separate unresolved branch.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 33 tests
  passed.
- `python -m py_compile tools/a15_ios26/analyze_agx_uppl_producer.py
  tools/a15_ios26/analyze_titan.py
  tools/a15_ios26/compare_gfx_security.py`: passed.
- Generated producer-boundary reports:
  `outputs/iphone-system/agx-uppl-producer/agx-uppl-producer.{json,md}`.
- Regenerated `titan-static-report.{json,md}` and the six-build
  `gfx-security-comparison.{json,md}` with the corrected producer status.

| Generated artifact | SHA-256 |
|---|---|
| `agx-uppl-producer/agx-uppl-producer.json` | `38B900761EFC0E62144932FB642B8DDB2CAF08858AB03D1547B375566A6E9D9B` |
| `agx-uppl-producer/agx-uppl-producer.md` | `C83E5136A2D0469B28B64EE252BF5F84D91AF20D4865E61C7F0FA08068BFEB0C` |
| `titan-static-report.json` | `2A8BBE2F8F5F05E15B7F79796067438F4D9E85DCBC4208036AC6DB43D8BE702C` |
| `titan-static-report.md` | `18D96EE3FF989A62F4B34D7510E4E4C74E22D5FB6EF80BC0E2BD112575D1BE48` |
| `gfx-differential/gfx-security-comparison.json` | `A353190DFFE0AE029B83BDC812F2C18FB052E6C4AEFA7D8747DB0791EE33F17E` |
| `gfx-differential/gfx-security-comparison.md` | `6EE23F7DFB6799DB3291568A05B822575B2726CC94AC021C174AA0E866F2A7CF` |

## 2026-10-16: GXF / UPPL Entry Analysis

### Completed

- Extended `analyze_titan.py` with a static GXF/UPPL/MMU contract analyzer.
- Extended `compare_gfx_security.py` with a symmetric dispatch and mapping
  comparison for every GFX firmware slice.
- Added unit coverage for immediate decoding and bounded range-guard
  classification.
- Regenerated `gfx-security-comparison.json` and
  `gfx-security-comparison.md` from the six exact A15 firmware payloads.
- Exact `23A355` GFX payload SHA-256:
  `3B245807D7A65241890E0D1D31566FED221082322DE784779824A2E11464A98B`.

### Confirmed Findings

1. Builds through `22B5045g` route the GXF entry directly to
   `__rtk_mmu_gxf_dispatcher`.
2. `23A355` adds a two-bit route at `__rtk_mmu_gxf_dispatcher_entry`:
   bit 0 selects `__rtk_mmu_gxf_dispatcher`; bit 1 selects
   `__rtk_uppl_client_dispatcher`. The bit-0 branch is tested first, so it wins
   if both bits are set.
3. The UPPL packet is at least `0x28` bytes: a 32-bit handler index at `+0x0`
   and four 64-bit arguments at `+0x8`, `+0x10`, `+0x18`, and `+0x20`.
   Dispatch checks the index, rejects a null handler, and transfers with
   authenticated `BRAAZ`. The observed rejection statuses are `0x80000003`
   for an out-of-bounds index and `0x8000000b` for a null handler.
4. The packaged `23A355` dispatch state contains a zero handler count and zero
   table pointer. The 16-byte `__rtk_uppl_client_dispatch` object is a weak
   data symbol; its only direct text reference in GFX is the dispatcher and no
   local writer or table signer was found. Runtime population is not proven;
   this payload cannot map an index to `map`, `unmap`, or `update_mapping`
   without inventing evidence.
5. The direct GXF `map` path includes a separate bounded range guard before
   entering `__rtk_mmu_map`. The mapping handlers themselves call
   `_mmu_get_tt_info` to validate translation-region bounds but do not contain
   that separate ingress guard.
6. `_mmu_get_tt_info`, `_mmu_get_page_table`, and the public mapping facades
   are structurally equivalent across `22A3354`, `22B5045g`, and `23A355` for
   the observed range checks.
7. `23A355` adds attribute class `0x8000`, translated to descriptor value
   `0x419`. Older compared builds expose classes `0`, `0x100`, `0x200`,
   `0x400`, `0x800`, `0x2000`, and `0x4000`.
8. `23A355` adds a context-switch guard in
   `__rtk_mmu_switch_region_base_by_contextID`: it reads state byte `+0x638`
   and conditionally requires bit 0 of argument `x2`.
9. The direct GXF commands remain `0x10` map, `0x11` update, and `0x12` unmap.
   Their observed handler contracts are map `(physical page, virtual page,
   page count, attributes)`, update `(virtual page, page count, attributes)`,
   and unmap `(virtual page, page count)`, with `0x4000`-byte pages.

## 2026-10-16: SPTM UAT Endpoint Expansion

### Completed

- Extended `analyze_sptm_txm.py` to decode null-terminated IOMMU endpoint
  tables with their authenticated chained handlers and referenced anchors.
- Regenerated symmetric v10 reports for exact `21B91` and `23A355` images.
- Added a unit test for the `0x10`-byte endpoint record and null terminator.

### Confirmed Findings

1. The UAT registration identity is unchanged: dispatch table ID `7`, domain
   permission mask `0x2` on both builds.
2. The UAT endpoint table grows from 7 handlers on `21B91` to 13 handlers on
   `23A355`.
3. `21B91` exposes anchored endpoints for init state, map table, prepare
   firmware unmap begin, unmap begin, set context ID, and get info. One entry
   has no exact `sptm_*` string anchor.
4. `23A355` exposes init and destroy state, map and unmap table, map continue,
   prepare firmware unmap begin and continue, unmap begin and continue, set
   and remove context ID, and get info. One entry at index 4 has no exact
   `sptm_*` string anchor; the reverse call-graph pass now identifies it as
   the request producer that calls index 5 / `sptm_uat_map_continue`.
5. The `23A355` UAT table is at `0xfffffff0270180d0`, uses `0x10`-byte
   records, contains 13 authenticated chained function pointers, and is
   followed by a null record.
6. SPTM's UAT code directly references validation for virtual ranges, context
   IDs, map options, physical addresses, table descriptors, and map segments.

### Symmetric Counts

| Driver | iOS 17.1.1 / 21B91 | iOS 26.0.1 / 23A355 |
|---|---:|---:|
| SART | 2 | 3 |
| NVMe | 3 | 9 |
| UAT | 7 | 13 |
| t8110dart table 3 | 9 | 17 |
| t8110dart table 4 | 1 | 4 |

### Interpretation Boundary

The new UPPL path is a useful static control-flow marker, but it is not a
demonstrated active route. The weak zero default has no observed local writer,
relocation, fixup, or PatchBay descriptor. The missing evidence is whether an
external protected producer replaces it at all on A15, which caller can select
bit 1, and what the `+0x638`, `x2[0]`, and attribute class `0x8000` guards mean.
Physical-page type checking is no longer wholly unknown: the `23A355` UAT
map-continuation path requires type `0x17` for page-table frames. Mapping
registration passes wildcard selector `0x42`, then reads the actual frame type
and applies its domain bitmap and maximum mapping-class policy.

The SPTM UAT endpoint table is a separate registered dispatch table. Its
expansion is strong evidence of a richer protected mapping lifecycle, but no
static reference yet proves that it populates GFX's zeroed
`__rtk_uppl_client_dispatch` state. Endpoint index 4 remains unnamed because
it has no direct `sptm_*` anchor, but its role as the request producer is now
established by its direct call to endpoint 5 rather than inferred from table
order.

## 2026-10-16: GXF Producer and Handoff Queue Provenance

### Completed

- Extended `analyze_agx_uppl_producer.py` to recover the direct GXF map
  constructor, its serialized caller, first-order producer functions, exact
  pointer references, and the handoff queue consumer contract.
- Correlated restricted frame-policy bitmaps with the named IOMMU descriptor
  IDs recovered from the same SPTM image.
- Regenerated the v5 AGX/UPPL producer report for both packaged GFX slices.

### Confirmed Findings

1. In slice `a000`, direct GXF map command `0x10` is constructed at
   `0xffffff80000339f8`, submitted through `0xffffff80000338a0`, and enters
   GXF through `__mmu_gxf_enter` at `0xffffff80000009c0`.
2. The constructor has one direct caller, the serialized wrapper at
   `0xffffff8000035334`. That wrapper is called twice by
   `__rtk_arm_start_bootstrap_area` at `0xffffff80000344f8` and
   `0xffffff800003450c`, immediately before the firmware installs its
   `TTBR0_EL1`, `TCR_EL1`, and `SCTLR_EL1` configuration. A second caller at
   `0xffffff800003d44c` belongs to an internal memory-map path.
3. The same structural route is independently present in slice `b000` with
   shifted addresses. Neither slice contains an exact data pointer to the
   constructor or a direct named RTKit message/endpoint ingress in this call
   chain. This is a local firmware mapping API, not evidence of a translated
   SPTM endpoint-4/5 packet.
4. The shared handoff is an explicit 65-entry flush queue. Context IDs are
   bounded to `0..0x40`; records start at `+0x20`, use stride `0x18`, and hold
   state at `+0x0` plus two payload values at `+0x8/+0x10`.
5. `__rtk_mmu_uat_flush_request` consumes and acknowledges those records.
   `__rtk_mmu_uat_idle` sets owner byte `+0x638`; `__rtk_mmu_uat_wake`
   clears it. The owner byte is therefore lifecycle state, not a frame type or
   an SPTM authorization result.
6. `XNU_CPUTRACE_PA_BUFFER (0x22)` and `XNU_CPUTRACE_VA_BUFFER (0x23)` use
   domain bitmap `0x84`, permitting domains 2 and 7. Domain 7 is the named
   `uat` IOMMU descriptor. `TXM_SEP_SECURE_CHANNEL (0x3b)` uses bitmap
   `0x120`, permitting domain 5 (`SART`) and unresolved domain 8. These are
   CPU-trace and SEP integration policies, not AGX leaf candidates.
7. The same 65-record queue contract and `+0x638` idle/wake owner byte are
   confirmed in both slices of every available comparison GFX image from
   `21D61` through `22B5045g`. This is not an exact `21B91` GFX comparison,
   but it rules out the queue layout itself as the iOS 26-specific delta.

### Frame-Type Names and Retype Callbacks

The authenticated SPTM frame-type name table at `0xfffffff027019228` removes
the remaining ambiguity around the restricted policy rows:

1. `0x22` is `XNU_CPUTRACE_PA_BUFFER`. Its retype-in and retype-out callbacks
   are both no-op `BTI c; RET` stubs.
2. `0x23` is `XNU_CPUTRACE_VA_BUFFER`. Its retype-in callback conditionally
   clears the halfword at frame metadata `+0x4` when the old type is `0x11`;
   its retype-out callback is the function anchored by
   `xnu_generic_retype_out`.
3. `0x3b` is `TXM_SEP_SECURE_CHANNEL`. Its callbacks are no-op stubs.
4. The table also identifies `0x17` as `XNU_IOMMU`, `0x19` as `XNU_IO`, and
   `0x1a` as `XNU_PROTECTED_IO`.

### Consequence

The route no longer has an undefined gap between the GFX handoff and command
construction. More importantly, the apparent `0x22/0x23` AGX branch was a
false lead: domain 7 permission belongs to the CPU-trace/UAT integration, not
to unidentified GPU leaf frames. The direct producer is now identified as
`acquire_uat_segments_page`. It acquires the descriptor page as
`XNU_DEFAULT (0x0b)`, copies validated segment records, and forwards
`num_segments` plus `map_options` to `sptm_uat_map_continue`.

On `23A355`, the leaf path masks the physical address with
`0xfffffffff000` and derives a requested mapping class of `1` or `2`. The
domain-7 table permits
`XNU_IO (0x19)` for both classes but does not permit
`XNU_PROTECTED_IO (0x1a)`. This corrects the earlier open-ended
`XNU_IO`/`XNU_PROTECTED_IO` branch. Exact `21B91` instead uses a direct
`XNU_DEFAULT`/`XNU_IO` allow switch and legacy modes `0/1`; those values must
not be relabeled as iOS 26 classes `1/2`. A new IPA is not justified until
offline segment provenance identifies which permitted leaf type is actually
used by the legitimate AGX path.

### Exact Next Task

1. Trace the segment physical-address provenance from
   `acquire_uat_segments_page` into the leaf registration call.
2. Decode the `map_options` lookup completely and associate each legitimate
   AGX segment kind with mapping class `1` or `2`.
3. Trace the exact legacy mode `0/1` branch meaning on `21B91` and compare its
   reference-accounting side effects with the iOS 26 class table.
4. Acquire an exact `21B91` GFX image only if byte-exact queue comparison is
   still needed; the nearest iOS 17 images already match the queue contract.
5. Keep the zero weak UPPL table as a separate branch unless a direct writer,
   relocation, fixup, or protected producer is recovered.
6. Keep this phase offline; do not emit or send a live UPPL/SPTM mapping
   request.

### HackTricks Orientation Review

The HackTricks iOS exploitation index is useful as a broad checklist, but it
does not change the current route:

1. Its physical-UAF/IOSurface material concerns obtaining kernel read/write.
   The current chain has already crossed that stage with ClearSword, so it
   does not answer the remaining SPTM frame-policy question.
2. Its PPL stale-TLB example describes an older PPL-specific vulnerability.
   It is not evidence that the same invalidation or accounting flaw exists in
   the higher-privilege SPTM boundary on `23A355`.
3. Its BinDiff workflow supports versioned kernelcache comparison, but our
   symmetric method must also include `sptm`, `txm`, and GFX firmware. A
   kernel-only diff would miss the exact frame-name, retype-callback, and UAT
   policy evidence recovered here.
4. The page contains broad mitigation summaries and approximate timelines,
   not build-specific proof. Apple confirms the architectural boundary:
   SPTM and TXM protect user and kernel page tables even against kernel write,
   and replace PPL on A15 or later. Therefore HackTricks is retained as an
   orientation source, not as evidence of an A15/iOS 26 bypass.

### arXiv and Public-Source Cross-Check

The 2025 paper *Modern iOS Security Features -- A Deep Dive into SPTM, TXM,
and Exclaves* independently supports the descriptor-and-rule-set model used by
the analyzer. Its main static sample is an iPhone 16 on iOS 18.4, with dynamic
work on an SRD running iOS 18.5 and an M4 iPad on iPadOS 17.5.1. It is not an
A15/23A355 offset source.

Useful symmetric facts from the paper are:

1. SPTM is the sole authority for frame retyping and mapping policy.
2. `XNU_DEFAULT -> XNU_IOMMU` and `XNU_IOMMU -> XNU_DEFAULT` are explicit
   lifecycle transitions in its iOS 18.4 baseline.
3. The iOS 18.4 frame table leaves `0x22/0x23` reserved, while the recovered
   23A355 table names those slots as the two CPU-trace buffer types. This is a
   concrete version delta and a warning against carrying numeric types across
   releases without the authenticated name table.
4. The paper's normal CPU `sptm_map_page` rule set is not the proprietary UAT
   `iommu_register_mapping` policy recovered here. The two must remain
   separate in the report.

The Tin-Z starter pack is retained only as an introductory diagram. It uses
generic page-type names, models GXF as ordinary EL2, and says there is no
public iOS 17 SPTM bypass; that state claim conflicts with the published Titan
range. It contributes no build-specific UAT selector, frame type, or callback.

The `cloverfield11/ios26-hypervisor-research` repository documents a separate
Stage-2 virtualization route on A16/iOS 26.4.1. It currently contains a README
and two commits, not a reproducible artifact bundle. Its Stage-2 frame types
are useful as another example of SPTM-gated mapping policy, but the repository
explicitly reports no bypass and does not connect guest VM dispatch to the
23A355 UAT/GPU path.

The local A15/23A355 artifacts independently confirm that this Stage-2 route
is present on the current target too. `devicetree.raw` contains
`has-virtualization` at file offset `0x36bf8`, with a four-byte value
`01 00 00 00`. SPTM reads that property through the xref at
`0xfffffff0270c3a74` and stores the resulting flag at
`0xfffffff027085820`; the same image names frame types `0x1f` and `0x20` as
`XNU_STAGE2_ROOT_TABLE` and `XNU_STAGE2_PAGE_TABLE`. Neither type appears in
the recovered UAT leaf allow set, so this confirms a separate SPTM service,
not an alternate UAT permission or a bypass.

The separation is visible in code as well: the exact image anchors guest
root acquisition at `0xfffffff0270d9d68`, guest entry at
`0xfffffff0270d9efc`, guest exit at `0xfffffff0270da1b8`, guest dispatch at
`0xfffffff0270dadfc`, and guest VA-to-IPA translation at
`0xfffffff0270db164`. The UAT policy rows for Stage-2 types `0x1f/0x20` have
zero allowed-domain bitmap and zero maximum mapping class. A bug in this VM
surface would be a separate vulnerability hypothesis; static availability
and an entitlement gate alone do not produce a host Stage-1 write primitive.

The v8 producer report now recovers the Stage-2 gate and state machine rather
than relying on names alone. The flag at `0xfffffff027085820` has exactly three
static readers: `cpu_root_table_retype_in` (`0xfffffff0270c81a8`),
`genter_dispatch_entry` (`0xfffffff0270cc4e8`), and `sptm_surt_alloc`
(`0xfffffff0270d5558`). The low-level GENTER path branches at
`0xfffffff02708caac` into `genter_dispatch_entry`. Dispatch target `0x1b`
selects service `0xc` and transitions `STATE_XNU -> STATE_XNU_GUEST`; target
`0x1c` selects service `0xd` and transitions `STATE_XNU_GUEST ->
STATE_SPTM_CALLED_BY_XNU`. Both entries use the same state-transition handler
at `0xfffffff02708c23c`. This bounds the guest route without identifying an
UAT permission edge or a bypass.

The v9 report continues from those transitions into the SPTM endpoint registry
and typed-page lifecycle. The static registry slot at `0xfffffff0270856e8`
selects table `0` at `0xfffffff02701c910`; `sptm_dispatch` bounds it to 50
endpoints. The guest subset is `0x18` (`sptm_guest_va_to_ipa`), `0x19`
(`sptm_guest_stage1_tlb_op`), `0x1a` (inferred Stage-2 TLB operation from its
root acquisition and `sptm_broadcast_tlbi` call), `0x1b`
(`sptm_guest_dispatch`), and `0x1c` (`sptm_guest_exit`). `sptm_guest_enter`
has no endpoint slot and is called only internally.

The same extraction proves that a guest root is not a caller-supplied arbitrary
page. `acquire_stage2_root_pt` requires `0x4000` alignment, the tracked SPTM
physical range, a valid in-flight reference, and exact frame type `0x1f`.
Endpoint `1` is `sptm_retype`; its root callback validates the geometry,
requires the virtualization gate for attribute index `1`, checks the encoded
VMID with `(vmid & 0xff01) == 1`, and atomically rejects duplicate VMIDs. Root
retype-out requires zero mapping references, executes `TLBI VMALLS12E1IS`,
and clears the VMID bitmap. Type `0x20` accepts only page-table subtype values
below `4`, and retype-out requires both mapping and nested reference counts to
be zero. This closes the easy Stage-2-shortcut hypothesis without exercising
any protected service.

Integrated with the live chain, this result defines a later contract rather
than a replacement path. The current on-device frontier remains the bounded
`backboardd` IPC census after ClearSword, Titan patchfinding, and IORVBAR
resolution have passed. IPC entry copy, GFX command-buffer submission,
unrestricted physical write, and protected-memory mutation remain unreached.
If those stages are eventually satisfied, Stage-2 still requires the typed
`0x1f/0x20` frame lifecycle, unique VMID ownership, and guarded GENTER state
transitions. Nothing in the recovered table grants the missing UAT leaf
permission or turns guest translation into a host Stage-1 write primitive.

The active IPC branch now has a v3 source revision. Apple's adjacent
`xnu-12377.1.9` layout confirms that each table entry is `0x18` bytes with the
signed object pointer at `+0x0` and `ie_bits` at `+0x8`. It also confirms that
the port header uses byte-sized `io_type` plus a three-bit `io_state`, replacing
the legacy bit-31 active marker and low-ten-bit type consumed by Titan's old
scan. The exact-target census now snapshots the complete entry before and
after following it, requires capability rights and an in-space object state,
and keeps the `IOMachPort` plus user-client vtables as the final attribution
checks. This revision remains read-only and still stops before IPC right copy
or GFX submission. GitHub Actions run `38871258849` built source commit
`30579d2c1b3cb32b2697be95fea188e91ed3806a` successfully, and package
inspection confirmed the v3 markers plus the explicit pre-copy stop. The
resulting `Dopamine-A15-iOS26-ipc-census-v3-30579d2.ipa` has SHA-256
`74EBB99892BDD649957748B64A31B05E07E07025686F3B2B3C6A57D5491C122B`.

The exact target ran this v3 build on 2026-10-16. The table decode was stable:
`0xc000` bytes, 2,048 complete entries, 1,649 entries with rights, zero
unstable snapshots, and stable final table/PID checks. The modern header split
produced 547 state-1 and 1,102 state-2 objects. Type `36` contained 85
`IOMachPort` wrappers and exactly two objects with the expected IOGPU
user-client vtable. The census stopped before IPC right copy and GFX
submission, and the device did not reboot. Because both exact matches occurred
after the 64-line generic-candidate cap, the follow-up v4 source adds a separate
bounded `MATCH` marker while preserving the same read-only execution boundary.
GitHub Actions run `38879780175` built source commit
`d55d66724ba09d82727f97d106de1ff740fcdeb3` successfully. Package inspection
confirmed `ipc-census-v4`, the exact `MATCH` records and counters, and the
explicit pre-copy stop. The resulting
`Dopamine-A15-iOS26-ipc-census-v4-d55d667.ipa` is 55,473,398 bytes with
SHA-256 `1F518E8F11F3815E896B51FDCA632C98F805304C435C59BF209D27F656BB36AB`.
The exact target ran v4 on 2026-10-16 without rebooting. It emitted exact
matches at IPC indices `537` and `1009`, with object addresses
`0xffffffdf5e176b30` and `0xffffffdf5e176ca0`. Both resolved to runtime vtable
`0xfffffff04b36fa10` (unslid `0xfffffff007b17a10`). The scan reported 2,048
entries, 1,669 rights, zero unstable snapshots, 85 type-36 IOKit connections,
two logged matches, no truncated match, and stable final table/PID checks. The
next bounded source revision profiles only the seven read-only downstream
fields needed to compare the two user clients; the pre-copy stop remains in
place.
GitHub Actions run `38881947358` built that v5 source at commit
`bfd9c4f2752422ce2001c1842bf401f552e98a7b` successfully. Package inspection
confirmed the `PROFILE`, `PROFILE-COMPARE`, profile counters, v5 revision, and
explicit pre-copy stop. The resulting
`Dopamine-A15-iOS26-ipc-profile-v5-bfd9c4f.ipa` is 55,474,513 bytes with
SHA-256 `97C911785BAD3E78417AAFF8EA3E4B62528CE53A008ECC89B9D6F536356E96E9`.
The exact target ran v5 on 2026-10-16 without rebooting. Both exact matches
produced complete `valid=0x7f` profiles. Index `537` used device
`0xffffffdf5e4e4600`, namespace `0xffffffe20f7794c0`, and handles
`0xffffffe042a2a000`; index `1009` used device `0xffffffdf5e4e4800`,
namespace `0xffffffe20f77a4c0`, and handles `0xffffffe042a18000`. Both clients
shared GPU `0xffffffe431bdc000`, device vtable `0xfffffff04b379c50`, and GPU
vtable `0xfffffff04b3760d0`; both MDSID-map fields were null. The final
`PROFILE-COMPARE` therefore reported `same-device=no`, `same-gpu=yes`,
`same-gpu-vtable=yes`, `same-namespace=no`, and `same-handles=no`. The scan
covered all 2,048 entries with no unstable snapshot and stopped before
`task_copy_ipc_entry`. The USB capture
`ipc-profile-v5-usb-2026-10-16.log` has SHA-256
`0C91FC6ABB960F3ABEBA005FD479E41A0F60A2BAD45A97431DA1AF7F9279FD3C`.
The subsequent source-only audit against Apple XNU tags `xnu-10002.41.9` and
`xnu-12377.1.9` is in `docs/TITAN_IPC_COPY_DARWIN25_AUDIT.md`. It proves that
the historical `ip_kobject + 0x10` no-senders handoff now lands in
`ip_pdrequest`, while XNU 12377 reads the authenticated `ip_nsrequest` union at
`ip_kobject`. The old `ipc_object` bit operations are also incompatible with
Darwin 25's typed/state header and signed label pointer. The active copy path
remains blocked. A defense-in-depth gate was also added at the start of
`task_copy_ipc_entry`: iOS 26 or XNU major 12377 and later returns before the
first legacy target-port read or write.

GitHub Actions run `38887531277` built the guarded v5 source at commit
`79b75bb81b4fc3e8f5a112c8d3a1b924e0cfff67` successfully. Package inspection
confirmed the existing `ipc-census-v5`, `PROFILE-COMPARE`, and explicit
pre-copy stop markers, plus the new Darwin 25 legacy-copy refusal in
`Frameworks/Titan.framework/Titan`. The resulting
`Dopamine-A15-iOS26-ipc-profile-v5-guard-79b75bb.ipa` is 55,474,629 bytes with
SHA-256 `9A423151A27EBAFC2C3C4E4F0942886B95FC51928E592501F80EE01F60F8F752`.
No device run was required for this source-only guard. It was nevertheless
installed and run on the exact target on 2026-10-16. The guarded build again
completed ClearSword, the IORVBAR traversal, and the full read-only IPC census.
The decoded backboardd table had allocation `0x10000`, 2,730 entries, and a
`0x10`-byte tail. Exact IOGPU user-client matches remained at indices `537` and
`1009`; both profiles were complete (`valid=0x7f`) and retained the same shared
GPU but distinct device, namespace, and handles relationship. The final census
reported 1,940 rights, zero unstable snapshots, 86 type-36 connections, two
exact matches, and stable table/PID checks. It stopped at the explicit
read-only boundary before `task_copy_ipc_entry`, so the Darwin 25 refusal was
not reached and no write or right transfer occurred.

A same-day Calif/Hexacon demonstration reportedly showed a private untethered
jailbreak on iPhone 18 Pro with iOS 27.0.1. The public conference page confirms
Calif's opening keynote but currently publishes no chain details, artifacts,
or SPTM/TXM mechanism. `docs/CALIF_HEXACON_IOS27_SIGNAL.md` records the signal,
its provenance, and the unanswered questions. It does not change the current
A15 route.

A public-source refresh on 2026-10-16 found no released iOS 26/A15 SPTM
bypass, TXM injection path, or Darwin 25 replacement for Titan's historical
IPC-right transfer. Apple does document two controlled alternatives: the
Security Research Device can boot custom SPTM/TXM firmware, and the Private
Cloud Compute Virtual Research Environment can boot a custom SPTM/TXM/kernel
set. These are useful for validating monitor contracts without weakening the
bounded A15 probe, but neither demonstrates a production-device bypass or
portability to iPhone14,2 build 23A355.

Dataflow Forensics' less-indexed public `SPTM - The Last Bits` post independently
identifies UAT as dispatch table `7` on iOS 26 and explains that calls use the
`0x70000000#` family. Its earlier iOS 17 round-two post records UAT as subsystem
`7` with 13 services. This corroborates the analyzer's independent dispatch
attribution, but neither post publishes a Stage-2 or UAT bypass.

A fresh schema reproduction is recorded in
`docs/SPTM_SCHEMA_VERIFICATION_2026_10_16.md`. The iOS 17 and iOS 26
SPTM/TXM reports are structurally identical to v10 after normalizing only
their input path strings; the regenerated AGX/UAT report is byte-for-byte
identical to the prior producer report. This confirms that the public
`ios26-hypervisor-research` route is a separate typed Stage-2 API, not the
missing AGX/UAT authorization edge: frame types `0x1f/0x20` retain zero direct
UAT-domain permission on the exact A15/23A355 sample.

The public Stage-2 result has nevertheless been adapted into a new measurable
branch instead of being treated only as a negative result. The exact-target
probe now runs `hypervisor-preflight-v1` before XPF. It checks the user-space
Hypervisor framework and four entry-point symbols, introspects the three
Hypervisor entitlement names on the current process, and reads the three HV
sysctls. It then records an explicit read-only stop without invoking any
`hv_*` function. The first device run will therefore locate this alternate
route's real boundary at framework visibility, entitlement, or kernel support
without changing Titan's IPC and protected-write boundaries.

Commit `dfe6098` was built successfully by GitHub Actions run `38895885958`.
The packaged executable contains the revision, checkpoint, entitlement,
sysctl, and resolved-symbol markers. Its embedded XML entitlements were parsed
directly from the Mach-O code-signature superblob (slot 5); none of the three
Hypervisor entitlement keys is granted. The stable local artifact is
`outputs/iphone-system/Dopamine-A15-iOS26-hypervisor-preflight-v1-dfe6098.ipa`
(55,477,131 bytes, SHA-256
`098214EF81C2F2CC1D139F2AAAEB4E36CFE959AC73BC6A3AB90EE3734EECEBE0`).
This confirms that a device result will measure the ordinary app's actual
boundary rather than a signing-time entitlement supplied for the experiment.

The first exact-device run of `hypervisor-preflight-v1` on 2026-10-16 reached
the expected stop. `Hypervisor.framework` and all four resolved `hv_*` symbols
were absent; the three entitlement queries returned absent;
`kern.hv_vmm_present` returned zero; and reads of `kern.hv_support` and
`kern.hv_disable` were rejected with `EPERM`. No Hypervisor function was
invoked. Titan remained independently stable: the IPC table contained 2,730
entries, the exact IOGPU clients remained at indices `537` and `1009`, and
both profiles remained complete. Two object headers were outside the IPC
space and were also the only `io-state=0` entries, while the table and PID
stability checks still passed.

The next bounded adaptation is `hypervisor-preflight-v2`. It preserves the
same no-VM boundary while reporting filesystem and `dlopen` results for public,
private, and `libsystem_hypervisor` locations; reading the live
`IODeviceTree:/product/has-virtualization` property; enumerating a maximum of
8,192 IORegistry entries for virtualization-related names/classes; and
checking loaded dyld image names. It never opens an IOKit user client. This
separates an absent public ABI from a private runtime service that remains
observable on the exact device.

Commit `e9118ee` built successfully in GitHub Actions run `38898440663`.
Package inspection found every v2 path, dyld, device-tree, and IORegistry
checkpoint in the executable. The embedded XML entitlement blob again
contained no Hypervisor key. The stable local artifact is
`outputs/iphone-system/Dopamine-A15-iOS26-hypervisor-preflight-v2-e9118ee.ipa`
(55,481,421 bytes, SHA-256
`7D9313F680187201DFF6988C29F4B17A83D27FDA1253CAEEBC331F6FA15CED16`).

The USB host path was then made reproducible with the 2026-10-11 Windows
build of `libimobiledevice`. Pairing and identity checks confirmed the live
target as `iPhone14,2`, iOS `26.0.1`, build `23A355`, `arm64e`. The Dopamine
container was opened through its installed, signature-qualified bundle ID and
the append-only checkpoint log was copied to
`outputs/device/a15-ios26-active-probe-20261016.jsonl`. Its 13 recorded runs
confirm the same stable boundary: ClearSword KRW, IORVBAR resolution, and both
IOGPU profiles pass; the exact-target branch stops before
`task_copy_ipc_entry`.

The next adaptation is `rtkit-metadata-v1`. It uses the already validated
IORVBAR mapping to read the GFX reset-vector register, validates the physical
range and 16 KiB alignment, resolves an existing kernel alias with `phystokv`,
and reads exactly one 16 KiB bootstrap page through
`clearsword_kreadbuf_exact`. It then requires a unique
`0x7777777777777700` marker, validates the historical text/data metadata
layout, and rereads the marker window for stability. The probe stops after
reporting the metadata. It does not call `kmap`, copy firmware, transfer an
IPC right, open/call an IOKit user client, or write memory. This creates a new
observable RTKit path before the blocked command-buffer setup without claiming
an injection or bypass.

In parallel, `Indegosblade/pmap-tte-remove` was reviewed at commit
`78ccf6e`. Its advertised overflow count is derived from the PoC's mapping
count rather than a measured L3 page-table count. The published A17 output
classifies the modified user sentinel `0x41414141414141bb` as a kernel PTE.
The exact Darwin 25 XNU source accounts for the reference count on each
specific leaf table. This branch is therefore recorded as an unverified claim
and was not added to the active device probe.

### 2026-10-16 15:06 CEST device reboot

The `rtkit-metadata-v1` IPA from commit `f5fe035` built in Actions run
`38903304606` and was handed to the user for installation. The USB host
confirmed `iPhone14,2`, iOS `26.0.1`, build `23A355` before the attempted
scan. The device disconnected and reconnected. A retained panic report at
`outputs/device/crashes-20261016/panic-full-2026-10-16-150638.0002.ips`
records `GFX SERROR` from `kernel_task`, `l2c_err_adr
0x2400000206050000`, and Dopamine in the foreground. The low address bits
correspond to the `0x206050000` physical IORVBAR descriptor discovered in
the prior read-only probe.

The post-reboot HouseArrest copy of
`Documents/a15-ios26-active-probe.jsonl` still has only 14 runs; its newest
`probe.entry` is at 14:33:56 CEST and ends at `titan.command-buffers FAIL`.
There is no 15:06 `probe.entry` or `titan.rtkit-metadata` checkpoint. The
installed app's exact binary revision was not independently verified, so the
panic cannot yet be attributed to the new MMIO read. Do not repeat the scan
or treat this as a metadata pass. First verify the installed binary and
obtain a pre-panic checkpoint through a path that does not depend on a live
GFX register read.

### Verification

- `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"`: 49 tests
  passed.
- In-memory `compile()` check for `analyze_agx_uppl_producer.py`,
  `analyze_titan.py`, `analyze_sptm_txm.py`, and
  `check_research_integration.py`: passed.
- `python tools/a15_ios26/check_research_integration.py`: passed; the active
  diagnostic remains exact-target and privilege/bootstrap stages stay blocked.
- `git diff --check`: passed (line-ending warnings only).
- Generated report root:
  `outputs/iphone-system/gfx-differential/` outside the Git worktree.
- Symmetric SPTM/TXM v10 reports:
  `outputs/iphone-system/sptm-txm-static-report-v10.{json,md}` and
  `outputs/iphone-system/ios17_1_1-symmetric/sptm-txm-static-report-v10.{json,md}`.

| Generated artifact | SHA-256 |
|---|---|
| `gfx-differential/gfx-security-comparison.json` | `A353190DFFE0AE029B83BDC812F2C18FB052E6C4AEFA7D8747DB0791EE33F17E` |
| `gfx-differential/gfx-security-comparison.md` | `6EE23F7DFB6799DB3291568A05B822575B2726CC94AC021C174AA0E866F2A7CF` |
| `sptm-txm-static-report-v10.json` | `498757C670945373111A06727843CF73E785D985C924D165101400C09A90BBBE` |
| `sptm-txm-static-report-v10.md` | `80E58C6FFB4CAA83A8B427FA07F4A94B2304B2391F9BB5EF7DF42805458E4AEE` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.json` | `FF4B1B8AF5819404D8271DB340A253B619612C7BFD45C6365E65BD5EF2FBCC23` |
| `ios17_1_1-symmetric/sptm-txm-static-report-v10.md` | `5D6DADB165E0B4B7AF39B77BCEBC05B41193F28478BF14673986BCCA793005D4` |
| `agx-uppl-producer/agx-uppl-producer.json` | `D1280C523ECFEEC08564AADD4AC8CCBD7B774A1E30F02BC5DE65A1C8DFFDCB6A` |
| `agx-uppl-producer/agx-uppl-producer.md` | `D0FEF4A3845B9D45FC01BEF825982F930E91785A87A295581B5B54CE49724BBA` |

### 2026-10-16 offline UAT selector reassessment

`docs/A15_IOS26_ROUTE_REASSESSMENT_2026_10_16.md` records the current route
decisions and the GFX-panic attribution limit. The AGX/SPTM analyzer now
validates the exact 23A355 selector instructions and decodes the 16-byte UAT
option table from the retained SPTM image. Four selectors request mapping
class 1, seven request class 2, and five are rejected by that selector gate.
This narrows map-option semantics, but no external provenance of the segment
page or options has been established. It is not a controlled-write result.

The new offline report is preserved at
`outputs/iphone-system/uat-options-v1/agx-uppl-producer.{json,md}` outside the
worktree. No device probe, MMIO read, IPC-right transfer, or protected request
was run for this reassessment.

The pre-existing MMIO-disabled commit also completed its CI build in Actions
run `38906834273`. The downloaded IPA at
`outputs/iphone-system/mmio-disabled-v1/Dopamine.ipa` is 55,483,303 bytes,
SHA-256 `510CF5B3B4D5263BC735F92411F9FCEF3C0FE1282CB98EB2B545DCF4FD0CB354`.
Package inspection confirms the no-GFX-MMIO Info.plist marker and the Titan
stop string; no installation or device run followed.

### 2026-10-18 AGX instance-vtable correction (offline)

The first AGX/Trigon map pass misidentified metaclass vtable pointers as
instance vtables. The SHA-256-pinned 23A355 kernelcache shows that the
`AGXAcceleratorG14P` instance constructor uses class metadata at
`0xfffffff00ab5e640`, zeroes its `+0x310` field, and installs the instance
vtable at `0xfffffff007b1e0d0`. That table's `+0x2a8/+0x7b8/+0x7c0`
entries resolve to the analyzed map-setup method and the two ordinary AGX
MMIO-use methods. The class reported in retained device captures therefore
agrees with this static path; an A0 instance is **not** a prerequisite.
`check_agx_probeconfig_map.py`, the USB read-root audit, and the Trigon
offline map report now enforce/state the corrected ownership. The old
`IOGPUDevice+0x310=0` read remains wrong-root evidence and does not settle
the AGX service instance's field. No new IPA was built or run, no live AGX
mapping was observed, and the GFX MMIO read remains disabled pending panic
attribution. Kernel reading, controlled kernel writing, physical writing,
and protected-memory modification remain distinct unproven steps here.

### 2026-10-18: bounded AGX service-instance metadata stage

Prepared source revision `agx-service-census-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1`
for iPhone14,2/23A355. The active Titan branch now stops after validating
the AGX service's `IOMachPort` wrapper and base-class instance vtables and
reading only `service+0x310` and selected `ProbeConfig` scalars via exact
kernel reads. The legacy local GPU queue-selector code remains in the tree
but is not invoked by this branch. No map pointer or mapped address is
dereferenced; GFX/RTKit MMIO remains disabled. Persistent per-field
checkpoints distinguish identity, exact-read, and metadata failures. This
source is not a live result and cannot demonstrate a kernel, physical, or
SPTM-protected write. No IPA has been built or installed for this revision.
The exact-image checker additionally pins the base-instance setup entry's
direct call into the map routine before its later flag handling. The
metadata stage now repeats its decisive scalars and blocks the final
summary on observed drift; this is a consistency check, not an atomic
snapshot or evidence that setup executed on the phone.
The base-class AGX writer at `0xfffffff008850900` was also traced to its
first MMIO store. It targets fixed map offset `+0x11000`, reads no incoming
`x1`-`x7` argument before that store, and has no direct `BL` caller in the
`AGXG14P` fileset. This is not an observed or arbitrary controlled write;
indirect state influence and other dispatch paths remain open questions.

### 2026-10-18: deterministic triage for the next AGX metadata run

Added `tools/a15_ios26/triage_agx_metadata_probe.py` and synthetic tests.
The tool pins the JSONL SHA-256 and one `run_id`, rejects target/revision
mismatches and missing or reordered identity/stability/stop checkpoints,
and correlates the service's registry ID with the census provider. It
does not infer a valid MMIO map or controlled write from nonzero pointers.
The retained October 16 multi-run JSONL is classified as an old revision,
with `titan.command-buffers` as its specific first failure; no new live
capture or IPA build occurred.

### 2026-10-18: offline UAT ingress ownership cross-check

`docs/A15_IOS26_UAT_INGRESS_BOUNDARY_2026_10_18.md` separates the already
registered 23A355 UAT table-ID-7 entry-4 producer from its still-unproven
external caller. XNU 12377.1.9 reserves a per-CPU IOMMU scratch buffer for
EL2 drivers to pass data into SPTM, but that source does not prove it is the
descriptor page consumed by this exact UAT endpoint. The remaining offline
test is a selector-to-descriptor provenance trace in the 23A355 kernelcache.
No phone action, MMIO access, or write was performed for this cross-check.

### 2026-10-18: exact-image AGX/IOUAT map bifurcation

`docs/A15_IOS26_AGX_IOUAT_DISPATCH_2026_10_18.md` records a newly pinned
23A355 branch: an AGX-state bit selects either the kernel `IOUAT` segment
producer or the AGX-local `AGXUAT` mapper. The IOUAT route allocates
0x28-byte segment records and calls a PAC-authenticated virtual map slot;
the runtime callback selection, branch value, and user-client provenance
remain unproven. Four PAC-compatible callback entries were identified;
the `uat` candidate calls a protected stub for SPTM table ID 7, entry 4.
The IOUAT initializer stores a caller-provided `x3` at `IOUAT+0x20` when
non-null; otherwise it constructs the `uat` provider there. AGX's mode-set
setup calls an IOUAT factory that passes `x3=0`, stores its result at state
`+0x10`, then publishes that state at `+0x2e8`; a later AGX map reads those
fields. This proves a conditional AGX-to-SPTM static route, not that the
device selected or executed it. The exact static DeviceTree lacks the named
IOUAT enablement properties, which does not settle runtime state. The
initializer has an authenticated indirect table entry. The second AGX mapper
forwards its incoming kernel descriptor in `x1` to IOUAT unchanged; its
creation and user-client provenance remain untraced. A PAC-compatible
IOGPUFamily chain was identified upstream: an optional `x2` kernel object
passes a virtual `+0xd8` check, is forwarded through the resource list and
IOGPU wrapper as `x3`, then reaches an AGX virtual mapper as a descriptor
candidate. Its runtime object type and selector origin are still unknown.
Fifteen focused tests and the exact-image audits pass. No device action, MMIO
access, or write was performed.

### 2026-10-18: IOGPU command-16 object provenance (offline)

Extended `audit_agx_uat_dispatch.py` to pin 113 instruction anchors, the
`IOGPUFamily` command-handler table entry, and its signed jump-table slot 16.
The upstream packet path obtains a driver buffer address through a virtual
method, checks record offsets, and frames each command with 8-byte minimum,
4-byte alignment, overflow, and end-of-buffer guards.
The exact image shows a length-checked array of 16-byte request records at
`request+0x14`. A record's flag and index choose either null or an object
from an array returned by a PAC-authenticated driver method; the selected
object is passed through a `+0x108` virtual call compatible with the known
resource mapper. A class-compatible `+0xe8` provider candidate lazily builds
the array in 4K/16K/64K granules from a parent object at `+0x88`, after
an alignment check. This replaces the vague `x2` origin with a concrete
record/index-to-kernel-object candidate, but does not prove that arbitrary
descriptor bytes or physical segments are controllable. The handler's
user-client ingress, runtime virtual targets, parent object's origin, AGX mode, and
factory execution remain unobserved. The exact-image audit and unit tests
pass. No phone action, MMIO access, or write was performed.

### 2026-10-18: selector-0 packet ingress and buffer getter candidates (offline)

The 23A355 `IOGPUFamily` dispatcher indexes two 0x18-stride tables with
selector indices 0 through 13. Index 0 in both tables resolves to the same
method, which bounds a user copy to 0x40 bytes, resolves a driver object by
handle, and calls the packet path. The kernel copy helper validates the user
range and brackets the copy with PAN changes. This closes the static
selector-to-packet edge, not the packet buffer's writable provenance. The
packet processor resolves its buffer object by ID from a driver table. Its
authenticated `+0x80` getter has two matching table
entries; one candidate adds an object-local `+0x50` slice offset to the
other's result. A sole PAC-compatible kernel `+0x78` getter candidate
returns its object's `+0x28` field. Runtime type, allocation, and buffer
control remain unobserved. The exact-image audit now pins 142 instruction anchors, five IOGPU indirect
entries including the PAC packet-process edge, and the two selector
entries plus two getter candidates. No phone action, MMIO access, or new
kernel/physical/protected write occurred.

### 2026-10-18: IOGPU object-table ownership and handle bounds (offline)

The exact-image audit now pins 156 instructions and six IOGPU indirect
entries. A PAC-compatible submission-object initializer receives the
user-client object table from `+0x120` and stores it at submission object
`+0x490`. The packet processor reads three IDs from its small copied input
and uses the table's buffer-object array to resolve them. Its shared lookup
rejects zero/out-of-range indices, loads a registered pointer from the
array, and retains the object. This invalidates the hypothesis that these
copied ID fields directly supply arbitrary kernel pointers or packet-body
bytes. The table's object registration, backing allocation, user mapping,
and runtime virtual target remain unresolved. No device action, MMIO access,
or new kernel/physical/protected write occurred.

### 2026-10-18: modern external-method selector correction (offline)

The prior index-0 packet edge belongs to older 0..13 method tables; its
live user-client routing was not established. The exact-image dispatcher at
`0xfffffff009f1d3f8` instead gates on client state, bounds the index at
`0x37`, and selects one of two 0x18-stride external-method tables. Both
tables put `s_new_command_queue` at index 6 and
`s_submit_command_buffers` at index 25. The latter directly reaches the
packet submission routine after a registered queue lookup. The historical
Titan header uses 7 and 26 for these two calls, which select different
methods on 23A355. This is a reproducible offline selector-contract
divergence, not the cause of the current phone stop: the active probe ends
before a Titan selector call. Three other header selectors also have
compatible exact-image argument layouts one index lower: shared memory
12, notification queue 14, and set notification 24. These are contract
inferences rather than symbol-confirmed names. The updated exact-image
audit pins 175 instructions and 18 external-method entries. Buffer backing and user
writability remain the next provenance boundary; no phone or MMIO action
was taken and no new write was demonstrated.

### 2026-10-18: shared-memory registration and dual mapping (offline)

Exact-image external-method index 12 forwards the client object table to
`0xfffffff009f3866c`. Its factory result is registered in table `+0x78`,
which the packet processor later uses for buffer-ID lookup, and the method
returns both an ID and an address from a mapping at buffer `+0x48`.
Initialization stores one backing-object pointer at both buffer `+0x40`
and `+0x28`; a separate kernel mapping can be cached at `+0x30` from that
same object. The audit now pins 197 instructions, with focused registration
and backing-alias tests. This narrows the provenance gap but does not prove
the factory's runtime type, a writable user mapping, byte aliasing, or
acceptance of this object by the command parser. No phone or MMIO action
was taken and no new kernel, physical, or protected write was observed.

### 2026-10-18: shared-buffer factory and mapping-option split (offline)

The 23A355 user-client table at `+0x120` is assigned from an authenticated
device factory; compatible IOGPU and AGX entries reach a table initializer
that creates the buffer registry at `+0x78`. The context forwarded from
client `+0x128` reaches a kernel mapping routine that reads its `+0x28`
field, consistent with `task.map`. The shared-buffer factory has
two PAC-compatible implementations. IOGPU forces mapping option `1`; the
AGX override sends second-scalar value `2` through option `0x1001` and all
other values through a base-table slot that resolves to the IOGPU option-`1`
method. Local XNU 12377 defines `0x1000` as `kIOMapReadOnly`, so the
special branch requests read-only mapping. The base IOGPU buffer constructor
installs a vtable whose `+0x80` slot resolves to the packet address getter,
closing a static type-compatibility edge. The exact-image audit now pins
225 instructions, seven table-factory PAC entries, both buffer-factory
entries, the AGX base-table fallback, and that getter slot; 109 offline tests pass. This is
an option-level finding only. Effective user-map permissions, runtime
factory choice, byte aliasing, and parser acceptance remain unobserved.
No device run, MMIO read, or controlled kernel/physical/protected write
occurred.

### 2026-10-18: backing allocation signature and task choice (offline)

The exact kernel backing routine matches the six-argument tagged overload
of XNU 12377 `IOBufferMemoryDescriptor::inTaskWithOptions`: its wrapper
stores two VM tags and forwards task, options, capacity, and alignment to an
authenticated initializer. The IOGPU buffer initializer passes the client
task when the map option lacks `0x1000`, or `NULL` when that bit is present.
Backing options are fixed at `0x10060`, corresponding in XNU to
kernel/user sharing, pageable memory, and purgeable memory; alignment is
`1`, kernel tag `0`, user tag `0x64`. The audit now pins 237 instructions;
111 offline tests pass. This narrows the byte-provenance gap but does not
establish successful allocation, actual write permission, byte aliasing,
packet acceptance, or any controlled kernel/physical/protected write.
No device action or MMIO read occurred.

The matching XNU source maps a successful pageable buffer into a non-null
`inTask` with `kIOMapAnywhere` and retains that task mapping as its buffer
address. That contract makes the base branch a concrete candidate for a
user-editable shared buffer. However, the exact-image metaclass pointer
loaded by the backing factory is in zero-fill kernel `__common` at
`0xfffffff00aa9eb98`; its runtime value cannot be read from the file.
The audit checks that this address belongs to a zero-byte `__common`
section. Static class registration, allocation success, effective
permissions, and parser-byte aliasing are separate edges; the static class
is resolved in the next entry.

### 2026-10-18: backing metaclass resolved in exact kernel (offline)

The initializer at `0xfffffff0086d4bb0` calls the metaclass constructor
with global `0xfffffff00aa9eb98`, the file-backed class string
`IOBufferMemoryDescriptor` at `0xfffffff0070a53e1`, and object size
`0xe8`. The factory at `0xfffffff0086d515c` loads that same global for
its authenticated allocation call. This closes the *static class identity*
gap left by the zero-fill global. The metaclass allocation slot resolves to
`0xfffffff0086d46b0`, which installs the object vtable; its `+0x128`
initializer resolves to `0xfffffff0086d3bf4`. That initializer passes the
non-null task into descriptor setup with one range; a later call creates
the task mapping with option `1`.
The audit now pins 264 instructions and two additional PAC entries; 113
offline tests pass. It does not observe the runtime pointer, successful
allocation, effective writable task mapping, byte alias to the packet
parser, or any controlled kernel/physical/protected write. No phone action
or MMIO read occurred.

### 2026-10-18: backing task-map address provenance (offline)

The exact 23A355 initializer continues beyond descriptor setup: for fixed
backing options `0x10060`, its two masks reduce the mapping options to
`1`, clearing the otherwise unexplained `0x10000` bit. It passes the
selected task to `0xfffffff0086dfc84`, stores and null-checks the mapping
object, then invokes its authenticated `+0x78` address getter. That getter
reads mapping `+0x28`, and the result is stored at buffer descriptor
`+0xb8`. This pins a static path to a task-mapping address and shows that
the known `kIOMapReadOnly` bit `0x1000` is absent from that call. The audit
now pins 277 instructions; 114 offline tests pass. No runtime mapping
permission, user-to-parser byte propagation, controlled kernel write,
physical write, or protected-memory modification has been observed.
No device action or GFX MMIO read occurred.

### 2026-10-18: dual-map descriptor identity (offline)

The base buffer initializer stores one `IOBufferMemoryDescriptor` at
`+0x40` and `+0x28`, and creates its user map at `+0x48` from `+0x40`.
The base packet address getter lazily constructs `+0x30` from `+0x28`.
That virtual `+0xe8` slot is pinned to exact-image
`0xfffffff0086e0abc`, which adds map option `1` and calls the same
`0xfffffff0086dfc84` mapping helper. XNU 12377 describes this as
mapping the descriptor into the kernel task. Thus both mapping routes
have the same static descriptor input, though their map objects differ.
The audit pins 286 instructions and this additional PAC entry; 115
offline tests pass. Runtime byte aliasing, effective write permission,
parser acceptance, controlled kernel write, physical write, and
protected-memory modification remain unobserved. No phone action or
GFX/RTKit MMIO read occurred.

### 2026-10-18: registry object round trip (offline)

The exact IOGPU table creates a `+0x78` array. Its constructor installs
vtable `0xfffffff007e41030`, whose insertion slot `+0x78` resolves to
`0xfffffff009f17ed4`. The shared-memory creator passes its new buffer
pointer to that insertion and returns the assigned ID. The packet parser
reads an input ID, resolves the same table's `+0x78` array, checks the
index, loads the pointer from the indexed slot, and applies an atomic
reference-count operation. This closes the conditional static
registration-to-lookup pointer flow. It does not establish that a live
packet uses the returned ID before reclamation or replacement, or that
the selected object is the base buffer with a writable task mapping.
The exact-image audit now pins 297 instructions and the array insertion
PAC entry; 116 offline tests pass. No kernel write, physical write, or
protected-memory modification was observed. No device action or
GFX/RTKit MMIO read occurred.

### 2026-10-18: bounded ClearSword self-page write test prepared (not run)

The historical `clearsword_kwritebuf` returns zero even when its inner
`early_kwritebuf` silently returns after `setsockopt` failure. Its return
value alone cannot be treated as write evidence. An exported strict 0x20-byte
writer now rejects invalid sizes and alignment and propagates socket errors.
The exact-target active probe resolves this writer from the loaded ClearSword
framework. It allocates and pins one app-owned 16K page, translates a 0x20-byte
region to its kernel virtual alias, and requires a strict pre-read matching
the app bytes before any mutation. A persisted checkpoint precedes the single
0x20-byte change; a strict kernel-alias read and an app-mapping comparison
must both match the changed pattern. A second strict write restores the
original bytes, again checked through both aliases. Before releasing the
page, the probe redirects ClearSword's socket to the previously verified
kernel Mach-O header and checks its magic again. If that redirect fails, the
page remains pinned until process exit so the socket is not left pointing at
freed memory. The app mapping is restored on every controlled exit. Failure
stops before Titan.
No IPC right copy, AGX command, GFX/RTKit MMIO read, or protected-page target
was added.

This experiment is falsifiable: an error from the strict writer, a mismatch
on either readback, or an interrupted checkpoint sequence does **not** prove
a controlled write. Even a fully passing run would establish only a kernel
virtual write to the direct-map alias of an app-owned data page, not an
arbitrary kernel-object overwrite, a physical-write primitive, an SPTM/TXM
bypass, or injection. The new JSONL triage tool enforces that distinction.
Its synthetic interruption and failure tests pass, and the actual strict C
writer passes a host-compiled socket-mock contract test. The integration
checker and 123 offline tests pass. No iPhone USB device was detected during
this preparation; no IPA for this revision has been built, installed, or run.
The first concrete next checkpoint is a signed build plus USB identity
verification of iPhone14,2/23A355 before one device run. The unattributed
GFX SError still forbids re-enabling the RTKit MMIO read.

### 2026-10-18: self-page probe CI artifact built (device run pending)

Public fork branch `Philiphall6/Dopamine:codex/a15-self-page-write-v1-20261018`
contains app commit `b38b7ec35f6b80cd844002054f19d43c3ec5f97f`. GitHub
Actions run `39159009409` completed the macOS build and uploaded the
`Dopamine` artifact. The extracted
`outputs/self-page-write-v1-ci-b38b7ec/Dopamine.ipa` is 55,494,420 bytes, SHA-256
`DDE6DF42276603001AFB566878B60CD6FEF88836C1D4274B58D7FB11B26501FA`.
Its Info.plist declares
`self-page-write-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1` and
`no-gfx-mmio`; the archive contains the app,
ClearSword, Titan, and the strict read/write symbol strings. The 123 offline
tests and integration check pass. The user will install this IPA; it has not
been installed or run by this agent. The PC had no Apple USB device at the
last check. There is still no on-device controlled-write observation, no
physical-write proof, and no protected-memory modification.

### 2026-10-19: live self-page write and AGX metadata (one run)

The host confirmed the connected USB device as `iPhone14,2`, iOS `26.0.1`,
build `23A355`, and queried the installed, signature-qualified Dopamine app.
Its `A15ProbeRevision` is
`self-page-write-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1` and its
safety mode is `no-gfx-mmio`. The pre-run log was copied before the user
launched the probe once. The post-run app-container JSONL is
`outputs/device/a15-self-page-write-v1-after-20261019.jsonl`, SHA-256
`FEABAF05977DE2A1AE2319AEF3782D1DF1EF055931B7FB3FC44EFD88573D5E28`.
Run ID `AAF2B273-F5D5-451D-9C90-18DDF54C8EDE` terminated without reboot.

For that single run, the strict pre-read matched the initial app-owned page,
the 0x20-byte ClearSword kernel-alias write returned success, and both the
kernel-alias read and independent app mapping matched the changed pattern.
A second strict write restored the original bytes, verified through both
aliases; the socket was redirected to the verified kernel header before the
page was released. The offline triage verdict is
`verified_app_page_kernel_alias_write`. This is reproducible checkpoint
evidence for one controlled **kernel-virtual write to an app-owned data page**,
not an arbitrary kernel-object write, physical-write primitive, protected
memory modification, or SPTM/TXM bypass.

The same run found one live `AGXAcceleratorG14P` service under `sgx`, not an
`AGXAcceleratorG14P_A0` service. Its instance vtable and scalar ProbeConfig
metadata passed exact-image and repeated-read checks: mode `2`, GPU index
`0`, fender index `1`, flags `0xf`, GPU physical base `0x204000000`, and
fender physical base `0x204d00000`. The AGX triage now accepts this combined
probe revision and returns `metadata_matches_static_candidate`; 124 offline
tests pass. The ProbeConfig mode byte is **not** the AGX runtime IOUAT
dispatch bit, so it cannot establish that the SPTM table-7/entry-4 route ran.
Titan intentionally stopped after metadata, before any GPU selector, command
submission, IPC transfer, MMIO read, or protected request. The unattributed
GFX SError continues to bar the prior MMIO read.

### 2026-10-19: exact AGX runtime UAT-mode provenance (offline)

The exact 23A355 AGX image pins the observed G14P instance vtable's `+0x618`
entry to the mode initializer at `0xfffffff008857ee4`. That method reads
instance `+0xdb08`, masks bit 0, and stores it at `0xfffffff00ab61150`.
The same method stores `1` at `0xfffffff00ab61160` after this mode write;
the probe also requires that initialization byte to be stably `1`, avoiding
an uninitialized-zero route claim.
The map path reads this same global to select IOUAT versus AGXUAT. This is a
concrete connection between the live instance identity and the previously
conditional IOUAT route, but the device's actual bit has not yet been read.

Revision `self-page-write-v1+agx-uat-mode-v1+rtkit-mmio-disabled-v1` adds a
bounded read-only double-check of source, global, and initialization flag. It reports a route only
when all three bytes are stable and linked; disagreement stops the probe. The
exact-image audit, 135 offline tests, and integration check pass. See
`docs/A15_IOS26_AGX_RUNTIME_MODE_PROBE_2026_10_19.md`. No new device run or
protected-memory operation has occurred for this revision.

The public research branch advanced through `e3f11cf` to `0e0d52d`; only
the three app-source files needed by this probe were committed. GitHub Actions
run `39212576616` compiled `0e0d52d` successfully. Its artifact is
`outputs/agx-uat-mode-v1-ci-0e0d52d/Dopamine.ipa`, SHA-256
`6AD4B655EBE6EDBCE402348291E54BF8BA1D02B42D048E11B9982EA1C291FF64`.
ZIP integrity and the embedded revision, `no-gfx-mmio` marker, self-page
checkpoint, and new AGX mode/initialization checkpoints were checked. The
prior `e3f11cf` CI run was cancelled before producing an IPA because the
initialization-byte guard was added. The corrected IPA has not been installed
or run by this agent. The exact-image audit now pins 305 instructions, the
G14P vtable entry, and the single AGX-image write site for each mode byte;
135 offline tests and the integration check pass.

### 2026-10-19: live UAT-mode byte disagrees with service source

The user installed and ran the `0e0d52d` IPA once on the verified exact
target; the phone did not reboot. The persistent post-run JSONL is
`outputs/device/a15-uat-mode-v1-after-20261019.jsonl`, SHA-256
`DCFF653A1600935B327BBA7A8F4221EA8665A6E2927B2F518200E39B8EC7A599`.
Its 986-line pre-run prefix is unchanged and exactly 89 checkpoints were
appended under run ID `E451E4DF-FF17-45F7-B33C-E2286A328CB5`.

ClearSword passed and the app-owned 0x20-byte self-page kernel-alias mutation,
dual readback, restoration, and socket redirect all passed again. This is a
kernel-virtual write to an app-owned page only. The validated G14P service
object read `+0xdb08=0` twice; the audited AGX map-dispatch global read `1`
twice and its initializer marker read `1` twice. The first blocker was
`titan.agx-uat-mode.stability:BLOCKED` because the source and global did not
match. The method audited in the exact image would select IOUAT if called
while the global remains `1`, but no map call or IOUAT object was observed.
The source provenance hypothesis is falsified for the current service state;
another initializer instance versus later source mutation is unresolved.
No SPTM/TXM call, physical write, protected-memory modification, GPU command,
IPC transfer, or GFX MMIO read occurred. The previous GFX SError remains
unattributed and its MMIO read stays disabled.

Offline triage now reports the stable conditional branch bit separately from
the unproved instance link, and recognizes the combined revision for the
self-page proof. All 26 focused triage tests pass. The next concrete blocker
is a validated live IOUAT state/factory field and accepted ingress, not the
availability of a kernel-virtual writer by itself.
The audited state initializer stores to its own `x0+0x2e8`; the live registry
service has not been proven to be that `x0`. A service-relative state read is
therefore not yet a valid next on-device probe.

### 2026-10-19: static service-to-GART-to-state link

The exact-image audit now pins the G14P service vtable's `+0x6f8` GART
factory path, the `AGXGartG14` class tag and vtable, the service-start store
at `service+0xee80`, and the GART setup store at `GART+0x2e8`. This corrects
the earlier unjustified service-relative `+0x2e8` shortcut. The new bounded
revision validates the GART vtable before following its state field, with
persistent checkpoints and no GFX MMIO or active map call. Its state type
remains unconfirmed. The static candidate is not yet a device observation,
and neither it nor the app-owned-page kernel-virtual write implies a physical
or protected-memory write. The first device blocker to test is whether
`service+0xee80` contains a stable live `AGXGartG14` pointer.

The offline audit of kernelcache SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`
passes, as do 147 offline unit tests and the active-probe integration check.
Only the three app-source files were committed to the already-authorized
public research branch as `449016e`. GitHub Actions run `39216523358`
compiled that exact commit successfully. The downloaded artifact is
`outputs/agx-gart-state-v1-ci-449016e/Dopamine.ipa`, SHA-256
`C30A01FFB51F97AC41CF76863BAD47008BF3531FCA49D7EE5AFF148485394594`.
ZIP integrity, the embedded revision and `no-gfx-mmio` marker, and GART
checkpoint strings in `Titan.framework` passed inspection. This build has
not been installed or run on the device by the agent; no GART runtime result
is claimed.

### 2026-10-19: live GART chain and bounded factory-field follow-up

The user installed and ran `449016e` once on the USB-verified iPhone14,2 /
23A355. The post-run JSONL at
`outputs/device/a15-gart-state-v1-20261019/after.jsonl` has SHA-256
`1553B2C094D18D37D2DD93D2E16394AD092E119366DE8EF43C1E749AADED4ADB`.
Its baseline prefix is unchanged and 97 new checkpoints carry only run ID
`91500365-97B0-42B6-9F3D-6C46F72DFC31`. A second pull was byte-identical.
The user reported no reboot. The GART pointer at service `+0xee80`, GART
vtable `0xfffffff007b1c4d8`, state pointer at GART `+0x2e8`, and state
vtable `0xfffffff007b22ae0` were each stable across repeated reads.
Offline class-tag and constructor checks on the exact kernelcache identify
that state vtable as `AGXUATMux`. No state `+0x10` read or map call occurred.

The next revision checks the exact mux vtable, then double-reads the mode
and initialization marker. Only a stable `1/1` follows the `+0x10`
factory-result field and validates the expected factory vtable
`0xfffffff007aed3a0`; any mismatch stops. The offline auditor and 159 tests
pass. A positive result would identify an object only, not an accepted
mapping, physical write, protected-memory change, or SPTM/TXM bypass. GFX
MMIO remains disabled pending attribution of the earlier SError panic.

The app changes were pushed to the previously authorized public branch as
`b939bcb` and `eed8d43`; only the three relevant app-source files were
published. GitHub Actions run `39220113885` was cancelled after the mode
attribution guard was added. Run `39221012920` compiled `eed8d43`
successfully. The downloaded IPA is
`outputs/agx-iouat-object-v1-ci-eed8d43/Dopamine.ipa`, SHA-256
`F3F92ABFCFBDDDF7696542F342CDCA81C972CA3D51A4FA41B28C1218395DCB34`.
ZIP CRC, embedded revision, `no-gfx-mmio`, and the new checkpoint strings
were verified. The connected device still reports iPhone14,2 / 26.0.1 /
23A355 over USB. The IPA has not been installed or run by the agent; the
factory field has no live observation yet.

### 2026-10-19: live IOUAT factory object observed

The user installed and ran `eed8d43` once on iPhone14,2 / 26.0.1 /
23A355 without a reboot. The persistent log is
`outputs/device/a15-iouat-object-v1-20261019/after.jsonl`, SHA-256
`2FAA7538CEA433F28BB2D999B165CA2E4032D1A0D276673429A369EE15B527F9`.
Its 279,909-byte pre-run prefix is byte-identical to the saved baseline;
113 new checkpoints belong to run ID
`9FF6E3D7-BF8C-44C2-8A63-3390AFE71F0F`. A second USB pull was
byte-identical. Offline triage reports `iouat_factory_object_observed` with
no missing, reordered, or forbidden checkpoint.

The validated G14P service `0xffffffe1c17bc000` led through GART
`0xffffffeb1e0fc000` (unslid vtable `0xfffffff007b1c4d8`) to
`AGXUATMux` `0xffffffe78605fdc0` (unslid vtable
`0xfffffff007b22ae0`). The global mode and initialized marker each read
`1` twice. The mux `+0x10` field read `0xffffffeb1e204c00` twice, and
its unslid vtable matched the exact-image factory value
`0xfffffff007aed3a0` twice. This closes the previously unobserved live
factory-result link. It does not show that a mapping method accepted a
descriptor or that user-controlled bytes reached the IOUAT path.

The separate 0x20-byte kernel-virtual write to an app-owned page passed,
was independently read through the app mapping, and was restored. No
physical write, protected-memory change, SPTM/TXM call, GPU submission,
IPC transfer, or GFX MMIO access occurred. `titan.run FAIL return=-1` is
the deliberate bounded stop after the object reads, with cleanup passing.
The next falsifiable boundary is the runtime identity and permissions of a
registered shared-memory buffer, equality of its user and kernel byte
aliases, and whether the packet lookup retrieves that same object. Static
index and vtable matches alone cannot satisfy those observations. The
earlier GFX SError remains unattributed, so MMIO stays disabled.

### 2026-10-19: own AGX shared-buffer alias probe prepared

The next bounded revision is documented in
`docs/A15_IOS26_AGX_SHARED_ALIAS_2026_10_19.md`. It tests the first live
user-byte ingress boundary after the observed IOUAT factory object: exact
G14P client identity, selector 12 output, buffer registry ID and map
identity, then one 0x20-byte mutation through the app's own mapping with
kernel-alias observation and restoration. It does not submit GPU commands,
touch MMIO, or request a protected mapping. A positive alias match would
still not prove packet consumption, physical writing, or SPTM/TXM bypass.

The three relevant app files were committed and pushed to the authorized
public branch as `4f3cc28`. GitHub Actions run `39227019706` compiled that
commit successfully. The downloaded IPA is
`outputs/agx-shared-alias-v1-ci-4f3cc28/Dopamine.ipa`, SHA-256
`B54F1392607E118FA9E2B32DC1FAD5A3E5A371B125D1DA8D13F06CEEE03CF2BB`.
ZIP CRC, embedded revision, `no-gfx-mmio` safety marker, and Titan checkpoint
strings were verified. Offline integration and 167 tests passed. This
revision has not been installed or run on the iPhone by the agent.

### 2026-10-19: live registered AGX buffer alias observed

The user installed `4f3cc28` and ran the probe once on the USB-verified
iPhone14,2 / 23A355. The user reported no reboot. The persistent log was
pulled from Dopamine's container to
`outputs/device/a15-shared-alias-v1-20261019/after.jsonl`, SHA-256
`866F225A37FA67D8E03DA811F49A6E2ABA91EDBBC3405C2E582C7D54F24768FF`.
It contains the unchanged 309,692-byte prior prefix and 42,392 new bytes.
A second USB pull was byte-identical. The new run ID is
`751C4F93-262F-4370-8B5A-3BD78C9AF775` with 164 checkpoints; the
offline triager reports `registered_user_dram_alias_observed`, no missing
or out-of-order checkpoint, no first blocker, and no forbidden stage.

The exact G14P service opened type 1 successfully. Its own client vtable
matched the expected runtime address. Selector 12 returned a 16 KiB user
mapping at `0x108cd8000` with registry ID `1` and effective VM protection
`0x3` (read/write). Client `+0x120` led to a registry array at table
`+0x78`; slot `1` stably named buffer `0xffffffe786aa8700`. Its
`+0x28` and `+0x40` descriptor pointers were equal, and its `+0x48`
map object reported the same user address and 16 KiB length. The vtables
for the array, base buffer, descriptor, and map matched their exact-image
values. After pinning, the 0x20-byte user-memory change was observed through
the derived kernel DRAM alias (`dual-alias-match=yes`), then both original
bytes and the ClearSword read target were verified restored.

This establishes caller-controlled bytes in an AGX-registered buffer and
an observable kernel alias. The write in this stage was a **user-mapping**
write; the earlier separate self-page test remains the only deliberately
verified kernel-virtual write in these staged proofs. Neither is a physical-write primitive or a protected
memory modification. There was no packet submission, parser lookup, GPU
command, GFX MMIO read, IPC transfer, or SPTM/TXM call. The next concrete
blocker is demonstrating that an accepted packet lookup retrieves this
same buffer ID/object and consumes the changed bytes through its kernel
mapping. Static compatibility of the lookup does not prove that runtime
edge. The earlier GFX panic cause remains unresolved, so MMIO stays off.

The exact-image method table uses indexes `6/12/14/24/25` for the relevant
queue/shared-memory/notification/attachment/submission methods; Titan's
historical wrappers use `7/13/15/25/26`. Selector 12 is now confirmed live
for the shared-memory method. The selector-25 disassembly requires a valid
four-scalar request and queue lookup before packet processing, so a rejected
no-queue call cannot demonstrate buffer consumption. No selector-25 device
call was made; its submission effects are not yet bounded.

The new static/live join compares the live buffer's normalized vtable
`0xfffffff007e44048` with the exact-image audit: its `+0x80` getter slot
decodes to `0xfffffff009f25130`, the packet path's compatible address
getter. This strengthens type compatibility, but the run did not call that
getter or look up ID 1 from a packet. The buffer's runtime `+0x30` cached
kernel map and `+0x50` slice offset were not read. The own-client result
does not transfer backboardd's queue/device rights, and the independent
Hypervisor preflight remains blocked at its API/device/entitlement gates.

### 2026-10-19: selector-25 parser-only test rejected offline

The exact-image audit now pins 370 instruction anchors around selector 25,
its batch routine, and the packet processor. Selector 25 looks up a queue
at `0xfffffff009f1ae40`; a missing queue branches past the batch call.
On the continuing path, the batch routine writes queue state at
`0xfffffff009f492a0`, uses its locking/backend path, and makes a backend
virtual call at `0xfffffff009f4960c` before parser dispatch at
`0xfffffff009f49680`. The parser's buffer-ID lookup at
`0xfffffff009f4bed0` precedes the selected buffer's `+0x80` getter call
at `0xfffffff009f4bff8`. Thus a rejected selector-25 call cannot prove
buffer consumption, while a call that reaches the getter is not yet
bounded against GPU/backend effects. This is a static ordering result,
not a device execution. No new IPA or live packet test was made; GFX MMIO
remains disabled. The audit artifact is
`outputs/agx-shared-alias-submission-boundary-2026-10-19.json`, and 170
offline tests pass.

The conditional service-vtable factories are now attributed to
`AGXCommandQueue` (`0xfffffff007b1e768` -> `0xfffffff0087dc520`) and
`AGXBlockFence` (`0xfffffff007b1e690` -> `0xfffffff0087e4280`) by their
exact-image class registrations, allocators, and installed vtables. The
fence's `+0x90` preparation method (`0xfffffff0087f5ca8`) initializes
fields and locks, with a conditional pool-bitmap update at
`0xfffffff0087f5d34`. This narrows the pre-parser backend effect, but
neither the live queue identity nor any selector-25 execution was observed;
it does not prove a bitmap update on every path or GPU execution. The
expanded audit records five factory/preparation entries, and 170 offline
tests pass.

### 2026-10-19: queue creation is also stateful (offline)

The exact-image selector-6 path allocates an AGXCommandQueue, invokes
its `+0xd8` initializer, registers it at `0xfffffff009f1a6e0`, and
returns the registry ID and queue `+0x558` value at `0xfffffff009f1a710`. The initializer
resolves to `0xfffffff0088041e8`, calls a device setup virtual method,
allocates resource arrays, and calls queue `+0x160` with argument zero.
That method resolves to `0xfffffff0087ff07c` and, on its initialization
path, allocates and sets up resources, stores one at queue `+0x8e0`, calls a
finalization helper, then marks the queue ready. Three new virtual targets
and the pre-return ordering are pinned in the audit artifact. No live
queue identity or device-side effect is established. Creating a queue
is therefore not a passive identity probe; no selector-6 call or IPA was
made. The buffer-consumption edge remains unobserved, and GFX MMIO is off.

### 2026-10-19: bounded own-client queue IPA ready

The prior shared-buffer run established a registered app-owned buffer and
restored user-byte/DRAM-alias agreement, but not a queue on that client.
Commit `dd97a72` adds one exact selector-6 queue-creation call after the
existing identity and restoration gates. It compares the returned ID's
AGXCommandQueue object, table/device backreferences, token, ready byte,
and original buffer registry. It does not invoke selector 25 or the GFX
MMIO path. Queue creation itself allocates resources and is stateful.

Public-fork macOS CI run `39234080749` passed on `dd97a72`. The IPA at
`outputs/agx-own-queue-v1-ci-dd97a72/Dopamine.ipa` has SHA-256
`8793350aa91511ed4921102a49470fab0729677e94f65521ad02cb014ab1b579`;
its app revision and Titan checkpoints were checked in the archive. The
USB device is iPhone14,2 / 23A355. Its pre-install journal is preserved
at `outputs/device/a15-own-queue-v1-20261019/before.jsonl` with SHA-256
`866f225a37fa67d8e03da811f49a6e2aba91edbbc3405c2e582c7d54f24768ff`.
All 177 offline tests and the integration guard pass. The user installs
the IPA and launches the one device test; no new live result is claimed
until the post-run journal is copied and triaged. Even a same-client
queue/buffer match would not prove packet parsing, physical writing,
protected-memory modification, or SPTM/TXM bypass.

### 2026-10-19: queue v1 rejected at input-size gate; v2 in CI

One `dd97a72` run on the exact USB device ended without reboot. The
post-run JSONL is 397,893 bytes, SHA-256
`e179690b8d86169ad56a94abba2d8bf4889936892159644070ad308b950a87b5`,
and exactly extends the 352,084-byte baseline. Run
`5FDDD069-9B19-479F-A85D-CCE7E0490627` repeats the restored
self-page and AGX shared-buffer observations. The own-client queue
registry/device gates pass; selector 6 returns `0xe00002c2`
(`kIOReturnBadArgument`) before an ID is returned. The connection closes
and cleanup passes. No packet or MMIO stage ran.

Exact-image disassembly explains the likely mismatch: the selector-6
wrapper requires a structure of at least 0x408 bytes and equal to
`device+0x278`; the base class stores 0x408 but G14P overrides that
field to 0x410. The v1 call sent 0x408. The live field value was not
measured in v1, so this is a falsifiable explanation, not a claimed
runtime read. G14P reads the extra eight bytes at input `+0x408` as
options. Commit `0720986` gates on the live 0x410 value and sends a
zeroed 0x410-byte input; selector 25 remains off. CI run `39237016964`
passed on `0720986`. The v2 IPA has SHA-256
`405c00dcec226b73aad901a2d406b216f1d3041674b694856e28b24071b3400a`;
the revision and Titan checkpoint strings were verified in the archive.
The exact-image audit has 381 anchors and all 179 offline tests pass.
The subsequent v2 device result is recorded below. See
`docs/A15_IOS26_AGX_OWN_QUEUE_2026_10_19.md`.

### 2026-10-19: queue v2 succeeds on the exact iPhone

The user installed v2 and ran it once on USB iPhone14,2 / 23A355,
without a reboot. `outputs/device/a15-own-queue-v2-20261019/before.jsonl`
is the 397,893-byte v1 post-run journal (SHA-256
`e179690b8d86169ad56a94abba2d8bf4889936892159644070ad308b950a87b5`).
Two copies of the v2 post-run journal are byte-identical, 449,461 bytes,
SHA-256 `bf2154628ebf11b6a6d5681e832d1bac90b5e40c6db2848aa71886ca126a7664`,
and retain the exact baseline prefix. The one added run ID is
`73263D5E-22A4-4757-B24B-7DCCFE45B36E` with 202 checkpoints.

The live G14P device `+0x278` reads `0x410`. Selector 6 returns `kr=0`,
queue ID 1 and token `0xefdc8755`. Repeated object and vtable reads,
queue table/device backreferences, token, ready byte, and the distinct
buffer registry all match the same client. Connection close and cleanup
pass. The triager verdict is `owned_queue_and_buffer_observed` with no
first blocker or forbidden stage. The v1 `0x408` rejection is therefore
explained by the measured input-size contract.
The terminal `titan.run FAIL return=-1` is an intentional gate that stops
before later Titan stages.

This is a stateful queue-creation result, not packet consumption. No
selector-25 packet, GFX MMIO read, physical write, protected-memory
change, code injection, or SPTM/TXM bypass was observed. The next
blocker is the pre-parser backend/resource effect on selector 25;
the read-only path to prove buffer consumption remains unestablished.
See `docs/A15_IOS26_AGX_OWN_QUEUE_2026_10_19.md`.

### 2026-10-19: selector-25 parser-only route closed by CFG audit

The exact-image audit at `tools/a15_ios26/audit_agx_submit_boundary.py`
models local normal-return control flow in the selector-25 batch and
processor routines. On the exact 23A355 image, the queue-state write
dominates the processor call; the backend virtual call and its success
gate dominate the parser dispatch, and backend failure skips it. The
machine-readable result is
`outputs/agx-submit-boundary-cfg-2026-10-19.json`. A selector-25 request
cannot be both an evidenced parser-consumption test and free of the
identified pre-parser effects on this active path. No new phone test was
run. The consolidated capability and route decisions are in
`docs/A15_IOS26_BLOCKERS_AFTER_QUEUE_2026_10_19.md`.

The conditional G14P device factory and `AGXBlockFence` preparation
vtable resolve statically; the latter contains at least four pool-bitmap
write sites under lock. The returned object's live identity and which
write sites execute remain unobserved. This narrows the candidate
backend without making selector 25 a passive or bounded probe.
The expanded audit also proves a local object-state write and an
indirect call dominate the candidate preparation method's return;
the call's target and effects were unresolved at that step.

The next offline check decoded that call's AGX GOT pointer into an
IOGPUFamily const table and its `+0xa0` slot into the exact-image
initializer at `0xfffffff009f21f00`. Its base-initializer call dominates
normal return; successful paths include state stores, authenticated
callbacks, and allocation. The first static target is now resolved,
but live object identity and downstream callback effects are not.
The helper's first virtual call also resolves through a kernel table
to `0xfffffff0085fad18`, which returns `1`. The helper's success path
still modifies object state and calls other setup routines. This
third-hop resolution is pinned by the exact-image audit, not by a
live execution trace. The selector-25 phone-test gate remains closed.
The audit has 191
passing offline tests; no further device launch was made.

The next offline pass joined the v2 queue observation to selector 25's
static lookup path. That entry resolves a queue ID through the client's
`+0x120` table, passes the queue to the batch routine, and reads its
`+0x538` G14P device before the `+0x5c0` factory call. The journal's
queue/device vtables and backreference match this static route; its
exact SHA-256 and run ID are pinned in the audit report. No selector-25
call or backend object identity was observed. This is a conditional
prediction, not an additional live capability.

Static class registration narrows the conditional factory route further:
the G14P factory uses a metaclass global whose initializer names
`AGXBlockFence` and installs its allocation vtable; that allocator
installs the instance vtable containing the audited preparation slot.
The intended class identity is now pinned, but no returned backend
object or its effects were measured in the v2 run. Selector 25 remains
disabled for a phone experiment.
The combined exact-image and journal audit passes; 195 offline tests and
the research integration check pass. No new IPA or device run was made.

An additional local CFG check found a possible `AGXBlockFence::prepare`
path that reserves pool bitmap slots, records both object slots, and
returns without visiting the function's rollback stores. This is a
static possible path, not a measured runtime reservation; other paths
restore state. It confirms that a selector-25 parser test cannot be
described as pre-parser read-only. No new device run was made.

The observed queue's `+0x118` packet slot was resolved to a G14P
override, then through its GOT-loaded base slot to IOGPUFamily's known
packet processor. The override calls queue `+0x160`, another virtual
method, and writes queue state before its base tailcall. Both older
selector-0 entries converge on the same batch routine as selector 25;
they do not offer a parser-only shortcut on the checked static path.
Runtime availability of the older dispatch and the intermediate virtual
target remain unobserved. The exact-image audit and 200 offline tests
pass. No new IPA or phone run was made.

Further exact-image tracing narrowed the queue `+0x670` helper to an
`AGXCommandBuffer` allocation and its `+0x98` callback. The callback
updates command entries and associated-table state before another
virtual call. Device `+0x4a0`, used for that call, is populated by a
factory associated with `AGXArmFirmwareASC`; the statically installed
base vtable's `+0x210` slot resolves to `__cxa_pure_virtual`. The live
field object's final vtable is unknown, so this is a type/effects
ambiguity, not a predicted phone panic. The expanded audit and 206
offline tests pass. No new IPA or device launch was made.

The next G14P initializer call after the `device+0x4a0` store was
resolved through device vtable `+0x858`. Its receiver is the device,
not the newly stored firmware object, so this local call does not
explain away the base-vtable `__cxa_pure_virtual` slot. Later object
replacement, an unobserved runtime subtype, or an inactive packet
branch remain possible. The audit pins this distinction; 207 tests
pass. No phone action was taken.

The firmware class hierarchy was checked in the same image.
`AGXArmFirmwareASC` registers `AGXArmFirmware` as its parent; the
parent metaclass's allocator returns null, while the device factory
selects the ASC allocator. No concrete parent `+0x210` implementation
appears on this factory route. The callback remains unobserved at
runtime and the effective field/vtable remains unknown. The exact
audit and 207 tests pass; no IPA was produced.

The offline review was closed with an explicit no-go for a packet-
submission IPA. The ASC allocator installs the same statically checked
vtable; the other direct references found in this fileset are destructor
paths, not proof of a concrete runtime callback. The observed queue does
not establish parser consumption, a physical write, or SPTM/TXM access.
The required runtime identity and pre-parser effect bounds remain open;
no further device launch was requested.

### 2026-10-19: minimal 3D descriptor route reaches legitimate SPTM registration

Offline exact-image analysis identified a direct descriptor path that is
independent of the older MDSID/RTKit continuation. The minimal command is
`0x550` bytes: prefix `0x10000`, command size `0x550`, nested size `0x488`,
kind 2, and a `0xffffffff` resource-free sentinel at packet `+0x450`; all
other bytes are zero. Its deterministic SHA-256 is
`97a4ed9626a831b7f7bfdc7b505631ef47d17670f78ae1860ce9694fa58bf434`.

The exact parser, kind-2 object parser, deep setup, ring insertion, worker,
descriptor slot `+0x90`, and dynamic context allocator are linked. Ring
insertion is the lifecycle trigger; no second submit is needed for the
context callback. The slot encoding `0x8011bed3017d45f0` resolves to
`0xfffffff0087d85f0` and matches the caller's `0xbed3` discriminator.

The context allocator selects an ID from its internal free list and calls
the live GART route. In mode one this reaches `0xfffffff008760e44`, issues
kernel method `0xBEE0` with one four-byte input, enters protected table 7
entry 10 and reaches `sptm_uat_set_ctx_id` at `0xfffffff0270a009c`.
SPTM enforces ID `< 0x40`, an unregistered descriptor, empty destination
slots, and UAT-eligible pre-existing roots. The packet controls neither the
ID nor those roots, so this is legitimate SPTM registration, not a bypass.

`tools/a15_ios26/audit_agx_3d_context_route.py` pins the kernelcache and
SPTM hashes, reconstructs the packet and validates the full static route.
Its eight focused tests pass, and the report is
`outputs/iphone-system/agx-3d-context-route-2026-10-19.json`. No IPA was
built and no device probe was run. The next offline blocker is the exact
`0xBEE1`/release/reuse lifecycle and whether AGX and SPTM can disagree about
an ID or root after teardown.

### 2026-10-19: context reuse closed and iOS 26 command ABI adapted offline

The `0xBEE1` removal path is now pinned from AGX release through the kernel
protected stub to `sptm_uat_remove_ctx_id`. AGX holds `device+0xeed8` while
the protected removal runs and only then pushes the ID to the free stack at
`device+0xef10` and updates the count at `device+0xef18`. SPTM obtains the ID
from the protected descriptor, clears both context slots, invalidates the
ASID, and resets the descriptor ID to `0xffff`. The simple early-ID-reuse
hypothesis is therefore closed. The focused route audit now has 11 tests.

The historical Titan IOGPU wrappers were compared with the exact 23A355
external-method tables. All five methods are shifted by one: queue 6, shared
memory 12, notification 14, notification binding 24, and submission 25. The
queue input is `0x410`, and the submission record and scalar `arg_size` are
both `0x30`. Runtime-selecting helpers now encode those contracts for iOS 26
while preserving the legacy ABI on earlier versions. The iOS 26 full-chain
gate remains in place; this is source adaptation, not a device success.

The static nonempty packet route still reaches the MDSID handler, so the next
useful bridge is no longer the command ABI. It is either a controlled firmware
write followed by a post-GFX primitive that does not rely on forged saved
state, or a caller-controlled IOUAT/SPTM mapping transition. Titan's original
RTKit continuation remains closed by PACGA verification and helper-derived
`TTBR1_EL1` restoration. No IPA, CI run, or phone probe was used.

### 2026-10-20: RTBuddy power route to GXF command 3 closed statically

Exact-image analysis found the missing host producer in
`com.apple.driver.RTBuddy`. Function `0xfffffff00a51fe54` accepts AP power
states 0, 1 and 3, maps them to payloads `0x201`, `0x20` and `0`, adds RTKit
class `0xb`, and sends one 64-bit message on endpoint 0. The callback chain is
registered through `0xfffffff00a51f730`, with the nested power callback at
`0xfffffff00a51fcd4`. Generic RTBuddy fanout reaches it from the pinned
callsites `0xfffffff00a50c4c0`, `0xfffffff00a50c574` and
`0xfffffff00a50ecf8`.

In the exact iOS 26 GFX image, bits 55:52 select a 16-entry jump table. Entry
`0xb` lands at `0xffffff800003e404`, maps the payload to firmware power state,
and schedules the state worker. Payload `0x201` maps to state 8 and `0x20`
maps to `0x21`. The non-`0x10` transition calls `0xffffff8000040e5c`, whose
command-3 constructor callsite is `0xffffff8000040ee8`. The existing exact
audit then proves command 3 reaches UAT wake and reloads `TTBR0_EL1` from the
registered current-context root.

`tools/a15_ios26/audit_rtb_power_command3_route.py` pins both image hashes,
the host callback/producer instructions, the complete GFX class table, the
payload mapper, state worker and command-3-to-TTBR0 route. Its focused negative
tests reject a changed class constant, jump target, state mapping or command-3
call. The combined focused suite has 24 passing tests. The report is
`../../outputs/iphone-system/rtb-power-command3-route-2026-10-20.json`.

This closes the internal producer route but not the runtime trigger contract.
The next blocker is a bounded app-visible action that forces the required AP
power transition while preserving the controlled AGX context, followed by
owned-root acceptance and a verified rollback. No production Titan code, IPA,
device probe, packet submission, MMIO or protected-memory write was used.

### 2026-10-20: G14P RTBuddy-to-firmware lifecycle pinned

The concrete G14P power lifecycle is now tied to the firmware object and vtable
already observed by the bounded phone probe. The RTBuddy transition wrapper at
`0xfffffff0087d455c` reads the firmware object from `RTBuddy+0x160`, calls slot
`+0xa08` before the gated transition, and calls `+0xa10` for completion. The
gated state handler at `0xfffffff0087d4848` uses `+0x9c8` for active-state
changes and `+0x9e0` for external-state publication.

Using the kernel static base rather than a fileset-local Mach-O base, the live
firmware vtable `0xfffffff007b19ab8` resolves `+0xa08` to
`0xfffffff00882e520`, `+0xa10` to `0xfffffff00882e474`, `+0x9c8` to
`0xfffffff00882ea00`, and `+0x9e0` to `0xfffffff00882e8a4`. The start routine
records transition state 1 or 2; completion clears it and signals the matching
event; the external-state routine stores the state and increments its
generation. The direct callback path does not dereference the AGX user-client
queue registry. That narrows, but does not prove, queue/context survival across
a normal transition.

`tools/a15_ios26/audit_agx_firmware_power_lifecycle.py` pins the exact image
hash, RTBuddy control flow, all relevant authenticated vtable slots and the
concrete firmware implementations. Its four focused tests pass. The report is
`../../outputs/iphone-system/agx-firmware-power-lifecycle-2026-10-20.json`.
No device probe, packet submission, MMIO, physical write or protected-memory
write was performed. The next device evidence is the separately verified ABI
v3 selector-25 `0x40` record with cleanup observation; a power-cycle probe is
not combined with it.

### 2026-10-20: ABI v2 stopped safely and exposed the G14P 0x40 override

The private ABI v2 IPA ran once on iPhone14,2/23A355 without a restart. All
identity and preflight gates passed through stable firmware-pool and queue
snapshots. Two kernel reads then returned `device+0x268=0x40/0x40`; the v2
`0x30` guard blocked before `IOConnectCallMethod`, so selector 25 was not
invoked and no post-call side effects existed to clean up.

An exact-image rescan found the missing subclass write. IOGPU initializes the
base field to `0x30`, but the G14P initializer at
`0xfffffff0087e7344..0xfffffff0087e7350` overwrites `+0x268` with `0x40` and
immediately writes `0x410` to `+0x278`. The latter matches the independently
observed queue-input contract on the same live object. The selector-25 wrapper
reads the queue device back-reference and compares scalar input 3 against this
live field, so `0x40` is now supported by both runtime and static evidence.

ABI v3 changes only the bounded record size to `0x40`, updates the revision
markers and retains the one-call, no-retry, no-MMIO, no-physical-write and
no-protected-write gates. V2 is retired and must not be run again.

### 2026-10-20: ABI v3 private artifact built and verified

Private GitHub Actions run `39384824664` built commit
`0ec47e4e2a1dd27ad57f4ee1e226124a3c27206f` successfully. The downloaded IPA
has SHA-256
`F4F98891E9BC2998BBB94207BC53F5528EF012FA92D898554F520DC3E891C8AB` and
embeds revision
`self-page-write-v1+agx-zero-packet-abi-v3+rtkit-mmio-disabled-v1`, safety mode
`no-gfx-mmio` and marker `titan.zero-packet.record-contract`.

The compiled `_titan_probe_zero_packet_once` function reads offset `0x268`,
compares the live value against `0x40`, builds an exact `0x40`-byte structure,
selects external method `0x19` and contains exactly one branch to the
`_IOConnectCallMethod` stub. The artifact is promoted only to one bounded
target run; the result of that run is recorded in the next entry.

### 2026-10-20: ABI v3 reached the notification prerequisite

ABI v3 ran once on iPhone14,2/23A355 without a restart. The live record-size
check passed at `0x40/0x40`, and selector 25 was called exactly once. It
returned `0xe00002bc`; pre/post firmware-pool digests were identical and the
queue backend, status, flags, count, dispatch, command index and all tracked
object identities remained unchanged. Cleanup and connection close passed.

The exact batch routine explains the result without another device guess. It
loads `queue+0x428` before backend allocation or parsing and returns its default
`0xe00002bc` when that pointer is null. ABI v3 never created or bound the normal
IOGPU notification queue, so the backend and parser were not reached.

Static wrappers and the setter now pin the missing prerequisite: selector 14
creates 256 entries of 32 bytes, returns a `0x10` output and registers the
`IOGPUNotificationQueue` under `client-table+0x90`; selector 24 stores the
derived object at `queue+0x428` and the notification object through
`queue+0x430`. The exact notification vtable is `0xfffffff007e42f28`.

### 2026-10-20: notification-bound v4 source prepared offline

Revision
`self-page-write-v1+agx-notification-bound-zero-packet-v1+rtkit-mmio-disabled-v1`
adds one selector-14 creation and one selector-24 bind before the existing
single selector-25 boundary. It validates the empty pre-state, registry array,
notification object and memory map, post-bind `queue+0x428/+0x430` relations,
and binding stability after selector 25. Connection close remains the cleanup
owner; retries, nonempty records, MMIO, physical writes and protected writes
remain disabled.

The offline exact-image audit passes and now reports both the observed unbound
status `0xe00002bc` and the statically predicted linked path. The complete
Python suite has 297 passing tests, including dedicated v4 triage tests and
integration checks that enforce exactly one selector 14, one selector 24 and
at most one selector 25. Private CI, compiled IPA inspection and the single
bounded phone run remain pending.

