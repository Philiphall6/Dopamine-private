# A15 / iOS 26.0.1 offline functional-path ledger

Target: iPhone14,2, build 23A355. Updated 2026-10-20.

A stage is `RUNTIME PASS` only when its effect was observed on the phone.
`STATIC PASS` means that exact instructions and image hashes close the route,
but the effect has not yet been exercised safely on the device.

## Current candidate

```text
[RUNTIME PASS] ClearSword kernel read/write
  -> [RUNTIME PASS] reversible kernel-alias write to an app-owned page
  -> [RUNTIME PASS] owned AGX client, shared buffer and same-client queue
  -> [RUNTIME PASS] selector-25 G14P wrapper ABI
       selector 25, four scalars, live record size 0x40
  -> [RUNTIME PASS]
       selector 14 notification create -> selector 24 bind -> queue+0x428/+0x430
  -> [RUNTIME PASS] bound selector-25 empty record accepted and cleaned up
       one 0x40 record returned 0; dispatch and command index advanced once
  -> [STATIC PASS] MDSID packet 0x0e reaches the firmware handler
  -> [STATIC PASS] low target VA resolves through active GXF TTBR0
  -> [STATIC PASS] BEE7 exposes the active root fields read-only
       IOUAT+0x20 -> descriptor PA -> PAPT alias -> roots +0x8/+0x10
  -> [STATIC PASS] 25-bit low VA root geometry
       one 16 KiB root, 2048 leaves, 14-bit page offset
  -> [STATIC PASS] RTBuddy AP-power producer sends RTKit class 0xb
  -> [STATIC PASS] RTBuddy G14P power lifecycle reaches live firmware slots
       start +0xa08, state +0x9c8/+0x9e0, completion +0xa10
  -> [STATIC PASS] GXF class 0xb -> power state worker -> command 3
  -> [STATIC PASS] command 3 reloads TTBR0 from current-context root
  -> [RUNTIME BLOCKER] deterministic app-side power assertion and timing
  -> [RUNTIME BLOCKER] owned queue/context survives one normal transition
  -> [RUNTIME BLOCKER] owned 16 KiB cloned root accepted by firmware
  -> [RUNTIME BLOCKER] nonempty selector-25/MDSID write accepted
  -> [RUNTIME BLOCKER] registry and live-TTBR0 rollback proven
  -> [BLOCKED] stable physical write independently observed
  -> [BLOCKED] protected-state/SPTM policy bypass
  -> [BLOCKED] jailbreak policy, trust cache, bootstrap and Sileo
```

## What changed on 2026-10-20

The previous ledger treated the host wake trigger as an unknown firmware
producer. Exact-image analysis now identifies it in
`com.apple.driver.RTBuddy`:

- `0xfffffff00a51fe54` accepts AP states 0, 1 and 3.
- Those states become payloads `0x201`, `0x20` and `0`.
- The producer ORs `0xb0000000000000` into the message and sends one word on
  endpoint 0.
- GXF extracts bits 55:52. Jump-table entry `0xb` lands at
  `0xffffff800003e404`.
- Payload `0x201` maps to firmware state 8; `0x20` maps to state `0x21`.
- The non-`0x10` worker path reaches the command-3 constructor at
  `0xffffff8000040ee8`.
- The previously pinned command-3 route reloads `TTBR0_EL1` from the
  registered current-context root.

This closes the internal host-to-firmware route. It does not yet identify a
bounded application action that forces the desired transition while preserving
the controlled AGX context.

The host-side G14P lifecycle is now closed one level further. The RTBuddy
transition wrapper at `0xfffffff0087d455c` reads its live firmware object from
`RTBuddy+0x160`, invokes `powerTransitionStart` through vtable slot `+0xa08`,
and completes through `+0xa10`. `powerStateChangeGated` at
`0xfffffff0087d4848` uses `+0x9c8` for active-state transitions and `+0x9e0`
for the external-state update. Every slot resolves through the runtime-observed
firmware vtable `0xfffffff007b19ab8` to the exact G14P implementation. The
direct path does not dereference the user-client queue registry, but queue and
context survival still require one bounded runtime observation.

## Evidence ledger

| Stage | State | Missing fact |
|---|---|---|
| Kernel foothold | RUNTIME PASS | None for this stage |
| AGX object identity and owned queue | RUNTIME PASS | Packet consumption remains separate |
| Selector-25 ABI | RUNTIME PASS | Wrapper accepted the `0x40` contract; batch reached its missing-notification gate |
| Notification create/bind | RUNTIME PASS | One selector-14/24 run established stable `queue+0x428/+0x430` relations |
| Bound empty selector-25 call | RUNTIME PASS | One accepted record and immediate cleanup observation |
| MDSID-to-GXF-TTBR0 binding | STATIC PASS | Runtime packet transport, effective callback identity, complete effects and final release |
| Active-root discovery through BEE7 | STATIC PASS / RUNTIME PENDING | Confirm both returned roots on-device without mutation |
| RTBuddy class-`0xb` producer | STATIC PASS | Deterministic app-visible transition and lifecycle |
| RTBuddy-to-firmware lifecycle | STATIC PASS | App-visible power assertion and queue/context survival |
| GXF command 3 to TTBR0 reload | STATIC PASS | Observe the transition without losing the queue/context |
| Cloned root acceptance | BLOCKED | Firmware acceptance of owned DRAM as the root frame |
| Rollback | BLOCKED | Restore registry entry and force restoration of live TTBR0 |
| Physical write | BLOCKED | Stable repeated read/write plus restoration |
| SPTM bypass | BLOCKED | Independently measured protected-state change |
| Bootstrap/Sileo | NOT STARTED | Every preceding security boundary |

## Closed branches

- Forged full-register RTKit saved state is closed by PACGA verification.
- The old hibernation continuation writes a helper-derived `TTBR1_EL1`.
- Simple early context-ID reuse is serialized by the allocator lock and BEE1.
- BEE6 only mutates an existing tracked mapping; it is not arbitrary mapping.
- GFX MMIO remains disabled after unresolved SError provenance.
- Hypervisor.framework and the required entitlement/device-tree support are
  absent on this target.

## Work order

1. DONE: read-only active-root discovery through BEE7 and the PAPT alias.
2. DONE: bind controlled low MDSID targets to GXF `TTBR0_EL1`.
3. DONE: pin RTBuddy AP-power message class `0xb` through GXF command 3 and
   the registered-root TTBR0 reload.
4. DONE: pin the G14P RTBuddy transition wrapper, gated state change and exact
   live firmware-vtable slots without invoking them.
5. DONE: run ABI v3 once; it returned `0xe00002bc` with unchanged state because
   the command queue had no notification binding at `+0x428`.
6. DONE: the notification-bound empty selector-25 probe ran once; selectors
   14/24/25 completed with one accepted empty record and cleanup.
7. NEXT: retain the offline MDSID no-go until effective callback identity,
   complete effects and final release have independent evidence.
8. DEFERRED: define one normal app-side power-assertion observation with exact
   queue, buffer, context and registered-root stability checks.
9. DEFERRED: define cloned-root construction from the live root without inventing
   attribute bits, plus registry and live-TTBR0 rollback.

No IPA for a nonempty MDSID record is currently justified. The completed probe
did not install a root, force a power transition, perform MMIO, submit a
nonempty command, or attempt a protected-memory write.

Machine-readable evidence:

- `../../outputs/iphone-system/agx-submit-boundary-2026-10-20.json`
- `../../outputs/iphone-system/rtb-power-command3-route-2026-10-20.json`
- `../../outputs/iphone-system/agx-firmware-power-lifecycle-2026-10-20.json`
- `../../outputs/iphone-system/gxf-ttbr0-wake-route-2026-10-19.json`
- `../../outputs/iphone-system/mdsid-ttbr0-binding-2026-10-19.json`
- `../../outputs/iphone-system/iouat-method-surface-2026-10-19.json`

## Honest progress assessment

The route no longer stops at an unidentified post-GFX bridge, and the first
selector-25 runtime rejection is now explained by an exact pre-backend gate.
Active-root
discovery, low-VA MDSID binding, the host class-`0xb` producer, firmware power
state dispatch, command 3 and TTBR0 reload are all statically linked on the
exact 23A355 images. The remaining gap is still significant: no owned root has
been installed, no corrected MDSID packet has been accepted on-device, no
physical write has been observed, and no SPTM policy bypass or jailbreak
bootstrap exists yet.
