# A15 / iOS 26 backend contract

This is the integration boundary for a future iOS 26 physical backend. It is
not an implementation of a physical or protected-memory primitive.

## Current decision

The exact iPhone14,2 / iOS 26.0.1 path does not enter the historical Titan
chain. The UI routes that target to the read-only AGX diagnostics path. Titan
remains available through the ordinary compatibility path for versions that
still select it; the A15 research path cannot publish a jailbreak result.

The V9 `physrw_pte_handoff()` fix is present in `physrw_pte.c`: handoff errors
are returned, partial PTE writes are checked, the ASID output is validated,
and callbacks are not installed on those failure paths. This preserves the
existing compatibility implementation; it is not evidence that a new A15
physical backend exists.

## Required attestation before publication

`libjailbreak_backend_publish_verified()` is the only publication boundary for
a future backend. It validates the caller's attestation before changing
`gPrimitives` or the capability ledger. A failed call leaves callbacks from an
earlier backend untouched.

| Capability | Minimum independent evidence |
| --- | --- |
| Kernel read/write | callback plus bounded runtime read/write verification |
| Physical read | successful handoff, valid handoff output, read window verification, callback, verified resource lifetime and cleanup |
| Physical write | successful handoff, valid handoff output, write window verification, callback, verified resource lifetime and cleanup |
| Protected-memory write | all physical-write requirements plus a separate protected-memory observation |

A successful initializer or a non-null function pointer is only a declared
capability. It cannot promote a capability to `RUNTIME_VERIFIED`.

## Evidence available today

| Component | A15 / iOS 26 status | Meaning |
| --- | --- | --- |
| ClearSword | `VALIDATED` in the bounded kernel-read/write scope | Does not establish physical or protected-memory access |
| Titan historical chain | `BLOCKED` for the exact A15/iOS 26 research path | No incompatible ROP/firmware path is entered |
| Existing PTE route | `STATIC_ONLY` for a future A15 backend | V9 error handling is present; no new target-specific physical proof is added here |
| Physical read/write | `NOT_TESTED` | No callbacks are published by the new A15 path |
| Protected-memory write | `NOT_TESTED` | No SPTM/PAPT or bootstrap operation is added |

No public or in-tree alternative examined by this change supplies the missing
target-specific physical and protected-memory evidence. A future backend must
provide those observations and pass the contract; this change deliberately
does not manufacture them.

## Public references checked

- The upstream Titan description is explicitly scoped to iOS 16.1–17.4 beta 3.
  It documents the historical `kalloc`/`kmap` prerequisites and records later
  changes to AGX thread-state PAC, TTBR restoration, and the iOS 26 IPC-port
  PAC boundary. It is therefore a historical reference, not an A15/iOS 26
  backend.
- `panicIDK` describes a device-receipted AppleAVE2 kernel-write research path
  for iOS 27.0 RC. It is a different component and target; the repository does
  not supply evidence for this A15/iOS 26 physical or protected-memory
  contract.
- The public iOS 27 SPTM research identifies later UAT/TLBI changes and
  explicitly reports no working exploit. Those observations do not establish
  reachability or a primitive on 23A355.

These references support reassessing historical assumptions; none is imported
or treated as proof of a new backend.
