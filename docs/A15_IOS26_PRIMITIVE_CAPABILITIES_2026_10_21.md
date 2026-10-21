# A15 / iOS 26 primitive capability map

Target: `iPhone14,2`, A15, iOS 26.0.1, build `23A355`.

This document records the safe integration boundary between the private A15
research components and the official Dopamine 3.x path. It does not enable a
new exploit operation, submit a new AGX record, build physrw, modify SPTM/PAPT,
change credentials, install a trust cache or install a bootstrap.

## Findings

The official path is callback-driven. `libjailbreak` stores read/write
callbacks in `gPrimitives`, and its wrappers derive virtual or physical access
only when the required callback pair is present. `DOJailbreaker` then performs
the following privileged sequence after exploit execution:

1. initialize translation and IOSurface helpers;
2. build a physical read/write primitive;
3. clean up exploit objects;
4. elevate credentials and remove sandbox restrictions;
5. prepare the rootless environment and bootstrap;
6. load trust caches and continue daemon setup.

The private A15 probe is deliberately stopped before steps 2 through 6.
Therefore a successful ClearSword self-page observation must not be treated as
proof that the official post-exploitation path is safe to enter.

## Capability ledger

`BaseBin/libjailbreak/src/primitives.h` now defines a small ledger with five
explicit capabilities:

| Capability | Meaning | Current A15 evidence |
| --- | --- | --- |
| `KERNEL_READ` | Read kernel virtual addresses | `RUNTIME_VERIFIED` for the bounded ClearSword diagnostic only |
| `KERNEL_WRITE` | Write kernel virtual addresses | `RUNTIME_VERIFIED` for the reversible app-owned-page diagnostic only |
| `PHYSICAL_READ` | Generic physical-memory read callback | `NOT_TESTED` as a libjailbreak primitive |
| `PHYSICAL_WRITE` | Generic physical-memory write callback | `BLOCKED`/`NOT_TESTED`; no stable target primitive |
| `PROTECTED_MEMORY_WRITE` | Write SPTM/PAPT or other protected state | `BLOCKED`; no evidence |

The code does not automatically promote any state to `RUNTIME_VERIFIED`.
`libjailbreak_capabilities_refresh_declared()` only records that a callback is
present as `DECLARED`. In particular, it never infers protected-memory access
from `physwritebuf`, `kcall`, translation callbacks or metadata.

## Component mapping

| Component | Reusable surface | Boundary |
| --- | --- | --- |
| ClearSword | Kernel read/write callback shape and reversible diagnostic | Does not prove generic physrw, protected writes or post-exploitation safety |
| Titan | Target selection, AGX lifecycle journal and cleanup contract | Current A15 run stops before a validated physical-write publication |
| `libjailbreak` | `gPrimitives`, wrapper functions and offset/translation helpers | Existing wrappers assume their callbacks are already trustworthy |
| `DOExploitManager` | Metadata discovery, support ranges and exploit selection | Selection is not runtime execution or validation |
| `DOJailbreaker` | Ordering and cleanup structure for the official path | Privileged stages remain gated; the ledger is observational and does not authorize them |

## A12/A13 versus A15

The official A12/A13 entries use their own kernel/PPL exploit metadata and
physrw construction paths. Their support ranges and device filters are not a
proof that the A15 Titan route supplies an equivalent capability. The A15
branch additionally has an SPTM/TXM boundary and a G14P AGX lifecycle that
remain `NOT_TESTED` or `BLOCKED` at the relevant transition.

Consequently:

- metadata selection can be shared;
- callback naming and cleanup contracts can be shared;
- the A12/A13 physrw and bootstrap assumptions cannot be copied to A15;
- protected-memory capability remains a separate explicit state;
- `DOExploit` refreshes declared callback state after a successful `exploit_init`;
  no privileged stage consumes that state as authorization.

## Validation

The new interface is covered by an offline source-contract test:
`tools/a15_ios26/test_primitive_capabilities.py`.

The intended status vocabulary is `NOT_TESTED`, `DECLARED`,
`RUNTIME_VERIFIED`, `BLOCKED` and `UNAVAILABLE`. A function pointer alone can
only produce `DECLARED`; a runtime result needs an explicit bounded evidence
record. Device execution, Objective-C compilation and post-exploitation
behavior remain separate validation questions.
