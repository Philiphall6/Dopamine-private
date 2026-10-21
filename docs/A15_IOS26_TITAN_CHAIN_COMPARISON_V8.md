# A15 / iOS 26 Titan chain comparison V8

Target: `iPhone14,2`, A15, iOS 26.0.1, build `23A355`.

References:

| Chain | Reference | Meaning |
| --- | --- | --- |
| Official | `opa334/Dopamine`, local `origin/3.x` at `448ff1a8` | Supported Dopamine 3.x selection, exploitation, physrw and bootstrap path |
| Historical private | `a91336d4` | Bounded empty `0x40` selector-25 observation, with cleanup-time alias restoration |
| Current private | V7 at `ae75f26` | Explicit buffer baseline, early restoration and selector 25 disabled |

This is a source and offline-contract comparison. It does not enable a new
privileged operation, install a bootstrap, submit a new AGX record, modify
SPTM/PAPT state or claim that the A15 device is jailbroken.

## Executive result

The three chains share the exploit metadata and object-lifecycle framework,
but they do not share the same demonstrated primitive contract.

* `DOExploitManager` and `DOExploit` are reusable for discovery, support
  filtering, priority selection, load/run/cleanup and symbol lookup.
* ClearSword currently demonstrates kernel virtual read/write behavior only
  within the bounded diagnostics. The reversible app-owned-page write is not
  generic physical write and is not protected-memory write.
* Titan V7 validates the AGX shared-buffer invariant and the selector 6/14/24
  resource relationships, then stops before selector 25. Queue readiness,
  callback identities and a Mach return code are not proof of MDSID parser or
  GPU firmware execution.
* The first official post-exploitation component that cannot be justified by
  the current A15 evidence is `buildPhysRWPrimitive`, followed by credential
  elevation, rootless bootstrap and trust-cache work.

The V8 code change is limited to one offline-safe `libjailbreak` interface
fix: `proc_vwritebuf()` now dispatches to `vwritebuf()` instead of recursively
calling itself. No Titan or exploit mechanism was changed.

## Chain map

### Official Dopamine 3.x

`DOExploitManager` scans bundled framework metadata, creates `DOExploit`
instances for each flavor, filters them through `isSupported` and selects the
highest-priority candidate per exploit type. The selected kernel, PAC and PPL
objects are then consumed by `DOJailbreaker`.

The normal `DOJailbreaker` sequence is:

1. require a kernel exploit and any required PAC/PPL bypass;
2. load and run the selected exploit objects;
3. initialize kernel translation and IOSurface helpers;
4. build physrw with `libjailbreak_physrw_pte_init()` or
   `libjailbreak_physrw_init()`;
5. clean up exploit objects;
6. elevate credentials and remove the sandbox;
7. create and prepare the rootless bootstrap, upload trust caches and start
   the launchd hook.

The official code comments explicitly presume that a successful PPL bypass has
provided unrestricted physical write. That presumption is valid only for a
supported official exploit path; it is not supplied by the A15 diagnostic
ledger.

### Historical private chain: `a91336d4`

The historical Titan route created the AGX shared buffer, observed the
temporary `0x20` alias mutation, created a queue, created and bound the
notification object, and issued one bounded selector-25 call with a `0x40`
empty record. A `0x0` Mach result was recorded as an accepted call and the
post-call queue/firmware cleanup observations were used to close that bounded
test.

The old alias restoration lived in the cleanup block. It restored and checked
the `0x20` window before continuing to the queue probe, but it did not have
the V7 full-buffer snapshot contract: no `BUFFER_INITIALIZED` baseline digest,
no explicit `restore-before-preflight` checkpoint, and no requirement that the
whole 16 KiB buffer match the initial state before the queue path.

That historical return value therefore means only that the bounded request
returned normally under the observed conditions. It does not prove that the
MDSID parser consumed meaningful data, that the firmware callback executed, or
that any physical/protected write occurred.

### Current private chain: V7

V7 keeps the same bounded AGX object path but makes the buffer invariant
explicit:

1. selector 12 creates a 16 KiB shared buffer;
2. the user mapping is explicitly zeroed and verified;
3. `BUFFER_INITIALIZED` stores the baseline snapshot;
4. the alias test changes exactly 32 bytes at `0x100` and confirms both
   aliases observe the change;
5. `titan_restore_shared_alias_mutation()` checks its prerequisites, restores
   only those 32 bytes, reads them back through the alias and user mapping,
   and compares the complete buffer with the baseline;
6. `ALIAS_AFTER_RESTORE` and `PREFLIGHT_FINAL` must report
   `nonzero-count=0` and the initial digest;
7. selectors 6, 14 and 24 may establish the bounded queue and notification
   relationship;
8. the compile-time V7 guard stops before selector 25 and records it as
   `NOT_TESTED`;
9. cleanup repeats the narrow restoration as a fallback, verifies it, unlocks
   the page and closes/releases owned objects once.

The supplied device trace matches this contract: the 32-byte mutation is
visible at `ALIAS_AFTER_WRITE`, the early restoration returns the buffer to
the zero baseline, the later snapshots remain zero, and selector 25 is not
called. This validates the restoration ordering only; it is not a jailbreak
validation.

## Primitive and interface compatibility

`libjailbreak` represents ordinary primitive callbacks in `gPrimitives`:

| Capability | Interface surface | A15 status |
| --- | --- | --- |
| `KERNEL_READ` | `kreadbuf`, or physical read plus translation | Bounded ClearSword read observed; not a general authorization token |
| `KERNEL_WRITE` | `kwritebuf`, or physical write plus translation | Bounded reversible app-owned-page write observed only |
| `PHYSICAL_READ` | `physreadbuf`, or kernel read plus `phystokv` | Not tested as a published A15 libjailbreak primitive |
| `PHYSICAL_WRITE` | `physwritebuf`, or kernel write plus `phystokv` | Not tested and not published by the active probe |
| `PROTECTED_MEMORY_WRITE` | No ordinary `gPrimitives` callback proves this | Blocked/not demonstrated |

The capability ledger added at `139b8b4` is deliberately observational. Its
`DECLARED` state means callback presence or a derivable wrapper path. Only an
explicit bounded evidence record may set `RUNTIME_VERIFIED`; the refresh helper
never does so automatically and never infers `PROTECTED_MEMORY_WRITE`.

The following surfaces are compatible and reusable without changing their
contracts:

* `DOExploitManager` metadata discovery and selection;
* `DOExploit` load/run/cleanup and `resolveSymbol:`;
* `kreadbuf`, `kwritebuf`, `vreadbuf`, `vwritebuf`, `proc_vreadbuf` and the
  corrected `proc_vwritebuf` dispatch;
* translation and IOSurface initialization after a kernel primitive has been
  independently validated;
* Titan's read-only object identity, snapshot, restoration and cleanup
  contracts while selector 25 remains disabled.

The following surfaces are not interchangeable with the current A15 evidence:

* `physrw_handoff()` requires `pmap_map_in()` to establish a user mapping of
  the kernel physical range;
* `libjailbreak_physrw_init()` and `libjailbreak_physrw_pte_init()` publish
  physical read/write callbacks only after their handoff paths succeed;
* `DOJailbreaker`'s `elevatePrivileges`, bootstrap, trust-cache and launchd
  stages require the post-PPL primitive contract, not merely kernel callbacks;
* Titan's selector-25 backend/parser path is not validated by pointer/vtable
  identity, queue readiness, a callback address or a normal Mach return.

## A12/A13 versus A15

The official A12/A13 path is selected from exploit metadata whose support
ranges, PPL assumptions and physrw handoff are coupled to the supported
kernel/PPL exploit. `DOEnvironmentManager` also keeps the exact A15 research
target out of the normal `isSupported` path.

The A15 branch differs in four relevant ways:

1. the target has the SPTM/TXM protected-memory boundary;
2. ClearSword supplies the currently demonstrated kernel callback shape, but
   no published generic physrw primitive;
3. Titan's G14P route has a separate AGX buffer/queue/notification contract;
4. the research path intentionally stops before the privileged official
   stages and does not consume the capability ledger as authorization.

Thus the official selection and lifecycle scaffolding can be shared, while the
PPL-to-physrw handoff, protected-memory transition and bootstrap cannot be
copied to A15 without new, independently validated primitives.

## Changes in V8

Implemented:

* fixed the `proc_vwritebuf()` interface dispatch in
  `BaseBin/libjailbreak/src/primitives.c`;
* added `tools/a15_ios26/test_titan_chain_comparison_v8.py` covering the
  dispatch fix, V7 restore ordering/selector guard, active-probe stop boundary
  and official physrw mapping contract;
* added this comparison and updated the README/worklog.

Not implemented:

* no Titan source change;
* no selector-25 reactivation;
* no MDSID or GPU packet, MMIO access, physical write, protected write,
  SPTM/PAPT change or bootstrap installation;
* no compatibility guard was weakened and no metadata was broadened.

## Validation and remaining blocker

The local validation command set is:

```text
python3 -m unittest discover -s tools/a15_ios26 -p 'test_*.py'
python3 -m compileall -q tools/a15_ios26
python3 tools/a15_ios26/check_research_integration.py
git diff --check
```

The exact results are recorded in the V8 worklog entry and commit message
after execution. Objective-C compilation remains a separate GitHub Actions
check; a successful compile is not device validation.

The first functional blocker remains the missing demonstrated A15
`PHYSICAL_WRITE` / `PROTECTED_MEMORY_WRITE` boundary required by the official
`buildPhysRWPrimitive` and later bootstrap path. The immediate next concrete
change should be an offline-only capability-gated contract check in the normal
path, if the project elects to expose the ledger there: it must refuse the
physrw/bootstrap stages unless the required states are explicitly
`RUNTIME_VERIFIED`. It must not promote those states or execute a new
privileged operation.
