# A15 / iOS 26.0.1 jailbreak-chain blockers

Exact target: iPhone14,2, build 23A355. Updated 2026-10-20.

```text
[RUNTIME PASS] ClearSword KRW and reversible self-page alias write
   |
[RUNTIME PASS] Owned AGX mapping, kernel alias and same-client queue
   |
[STATIC PASS / SOURCE READY] Correct G14P selector-25 ABI
   |    selector 25, four scalars, 0x40-byte record
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
[BLOCKER 1] Deterministic app-side power transition
   |    Must request normal power and keep queue/context alive
   |
[BLOCKER 2] Owned cloned-root acceptance
   |    Firmware must accept owned DRAM as the registered root frame
   |
[BLOCKER 3] Corrected selector-25/MDSID runtime transport
   |    0x38 was rejected; v2 stopped before call on live 0x40 contract
   |
[BLOCKER 4] Safe rollback
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

This is now a coherent static physical-write candidate, not a working
jailbreak. The direct G14P RTBuddy-to-firmware lifecycle is pinned and does not
touch the user-client queue registry in its direct path, but runtime survival
is not yet observed. The next useful IPA is exactly one corrected selector-25
G14P `0x40` contract probe. A power-transition observation comes only after that
call is accepted; root replacement and protected writes remain disabled.
