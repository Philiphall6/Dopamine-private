# A15 / iOS 26.0.1 jailbreak-chain blockers

Exact target: iPhone14,2, build 23A355. Updated 2026-10-20.

```text
[RUNTIME PASS] ClearSword KRW and reversible self-page alias write
   |
[RUNTIME PASS] Owned AGX mapping, kernel alias and same-client queue
   |
[RUNTIME PASS] Correct G14P selector-25 wrapper ABI
   |    selector 25 accepted four scalars and the 0x40-byte record contract
   |
[STATIC PASS / SOURCE READY] IOGPU notification prerequisite
   |    selector 14 creates 256 x 32 bytes; selector 24 binds queue+0x428/+0x430
   |
[STATIC PASS] MDSID packet route and low-VA GXF-TTBR0 binding
   |
[STATIC PASS] BEE7 active-root discovery
   |    IOUAT+0x20 -> descriptor PA -> PAPT alias -> root0/root1
   |
[STATIC PASS] Clone format known
   |    one 16 KiB table, 2048 leaves, preserve live attribute bits
   |
[STATIC PASS] RTBuddy AP-power message producer
   |    states 0/1/3 -> payloads 0x201/0x20/0, RTKit class 0xb
   |
[STATIC PASS] RTBuddy G14P lifecycle -> live firmware vtable
   |    start +0xa08, state +0x9c8/+0x9e0, completion +0xa10
   |
[STATIC PASS] GXF class 0xb -> state worker -> command 3
   |
[STATIC PASS] Command 3 -> current-context registered root -> TTBR0_EL1
   |
[BLOCKER 1] Bound empty selector-25 call and cleanup
   |    ABI v3 returned 0xe00002bc before backend because queue+0x428 was null
   |
[BLOCKER 2] Deterministic app-side power transition
   |    Must request normal power and keep queue/context alive
   |
[BLOCKER 3] Owned cloned-root acceptance
   |    Firmware must accept owned DRAM as the registered root frame
   |
[BLOCKER 4] Nonempty selector-25/MDSID runtime transport
   |    Allowed only after the bound empty-record call and cleanup pass
   |
[BLOCKER 5] Safe rollback
   |    Restore registry entry, trigger command 3 again, verify live TTBR0
   |
[BLOCKED] Stable physical write independently observed and restored
   |
[BLOCKED] SPTM/PAPT policy bypass with protected-state proof
   |
[BLOCKED] Trust cache, jailbreak policy, bootstrap and Sileo
```

## Important separation

The RTBuddy power transition does not require selector 25. It is the mechanism
that causes firmware command 3 and the TTBR0 reload. Selector 25 is still
required for the controlled MDSID writes that would patch the registered root
entry and later exercise a low virtual address through the cloned root.

## Closed alternatives

| Route | Current state |
|---|---|
| Hypervisor | Framework, entitlement and device-tree virtualization support absent |
| GFX/RTKit MMIO | Disabled after unresolved SError provenance |
| Legacy Titan IPC copy | Old Darwin/PAC/SMR assumptions invalid |
| Forged RTKit saved state | Closed by PACGA signature verification |
| Hibernation fake TTBR | Closed by helper-derived `TTBR1_EL1` |
| Simple context-ID reuse | Closed by lock-serialized BEE1 removal and free-list publication |
| BEE6 arbitrary remap | Closed: only an existing tracked mapping can be prepared for unmap |

## Current decision

This is a coherent static physical-write candidate, not a working jailbreak.
ABI v3 closed the record-size question and exposed the ordinary notification
prerequisite before any backend or parser work. The next useful IPA creates and
binds exactly one notification queue, validates the resulting kernel relations,
then performs one empty selector-25 call. A power-transition observation comes
only after that call is accepted; nonempty packets, root replacement and
protected writes remain disabled.
