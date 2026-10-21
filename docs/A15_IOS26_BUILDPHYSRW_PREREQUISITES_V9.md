# A15 / iOS 26 `buildPhysRWPrimitive` prerequisites V9

Target: `iPhone14,2`, Apple A15, iOS 26.0.1, build `23A355`.

This is a read-only source and evidence review. It does not run
`buildPhysRWPrimitive`, submit a Titan packet, access MMIO, perform a physical
or protected-memory write, change SPTM/PAPT state, elevate privileges or install
a bootstrap.

## Executive result

`buildPhysRWPrimitive` is only a dispatcher. On A15,
`device_supports_physrw_pte()` selects `libjailbreak_physrw_pte_init(false, 0)`
(`Application/Dopamine/Jailbreak/DOJailbreaker.m:774-787`). The meaningful
precondition is therefore the PTE handoff, not the presence of the builder
method or the existence of a `physwritebuf` field.

The first unverified transition is:

```text
ClearSword KRW
  -> current task/map/pmap/ttep discovery
  -> pmap_expand_range()
  -> physical PTE writes in physrw_pte_handoff()
  -> magic page-table window and ASID mapping
  -> publish physical callbacks
```

The A15 evidence validates only the first line, and only within a bounded
diagnostic. Titan V7 validates the shared-buffer restoration and selectors
6/14/24, then deliberately stops before selector 25 and before any physical
callback publication. It does not satisfy the PTE handoff contract.

## Exact official path

The normal `DOJailbreaker` sequence is:

1. `doExploitation()` runs the selected kernel exploit, initializes translation
   and IOSurface helpers, and would run PAC/PPL bypasses when required
   (`DOJailbreaker.m:602-656`). The source comments presume that a PPL bypass
   supplies unrestricted physical write; the A15 research evidence does not
   establish that presumption.
2. `buildPhysRWPrimitive()` selects the PTE path on every supported family
   except A8/Typhoon (`physrw_pte.c:216-229`).
3. `physrw_pte_handoff()` finds the current process pmap, expands a virtual
   range, translates the new page-table location, and writes PTEs for the
   magic table and ASID page (`physrw_pte.c:150-195`).
4. The PTE initializer publishes `physreadbuf`, `physwritebuf` and
   `physaccess_mapped`, then clears the direct kernel callbacks
   (`physrw_pte.c:197-213`).
5. The normal path cleans up exploits and immediately enters credential
   elevation (`DOJailbreaker.m:1142-1157`).

The conventional `physrw_init()` path is not the A15 selection. If used, it
requires `pmap_map_in()` to map the complete physical range and checks the
handoff return before publishing callbacks (`physrw.c:69-116`).

## Requirement matrix

| Requirement | Source-level presence | A15 evidence | Classification |
| --- | --- | --- | --- |
| Kernel virtual read | `gPrimitives.kreadbuf`, ClearSword callback, wrappers | Mach-O kernel magic read passed in the bounded probe | `RUNTIME_VERIFIED`, bounded only |
| Kernel virtual write | `gPrimitives.kwritebuf`, ClearSword callback, wrappers | Reversible 0x20 app-owned-page kernel-alias write passed | `RUNTIME_VERIFIED`, bounded only |
| Translation setup | `libjailbreak_translation_init()` installs `phystokv` and `vtophys` | Called after ClearSword in the active probe; no generic physical target was tested | `DECLARED` / `NOT_TESTED` |
| Generic physical read | Direct PTE and conventional callbacks plus a KRW-to-`phystokv` fallback | No A15 physical read callback or arbitrary physical target was observed | `NOT_TESTED` |
| Generic physical write | PTE/conventional callbacks, KRW-to-`phystokv` fallback, and Titan publication function | Titan V7 stops with `titan.run FAIL`; the active probe never reaches `titan.physwrite.publish` | `BLOCKED` / `NOT_TESTED` |
| Current pmap discovery | `proc_find`, `proc_task`, `task.map`, `vm_map.pmap`, `pmap.ttep` reads | The offsets and kernel context are read during diagnostics, but no PTE handoff was run | `PRESENT`, not runtime-validated for physrw |
| Page-table expansion | `pmap_expand_range()` has kcall and no-kcall branches | Neither branch has been exercised in the A15 evidence | `PRESENT`, unvalidated |
| Physical PTE write | `physwrite64()` calls in `physrw_pte_handoff()` and `pmap_expand_range()`; V9 now checks handoff write errors | No physical write was attempted or published | `BLOCKED` |
| PAC/kcall path | `is_kcall_available()` consults `usesPACBypass` on arm64e | PAC is `NOT_REQUIRED` in the diagnostic; stable kcall is not proven | `NOT_TESTED` |
| Protected-memory write | No ordinary `gPrimitives` callback represents this capability | No SPTM/PAPT request or protected write was issued | `BLOCKED` |
| Post-physrw privilege/bootstrap contract | `elevatePrivileges`, rootless setup, trust-cache and bootstrap stages exist | Active probe stops before all of them | `NOT_REACHED` |

The capability ledger deliberately keeps these states separate. Callback
presence can be `DECLARED`; only explicit bounded evidence may produce
`RUNTIME_VERIFIED`. `libjailbreak_capabilities_refresh_declared()` never
promotes physical or protected capabilities automatically
(`primitives.c:99-120`).

## What ClearSword + Titan actually provide

### ClearSword

`ClearSword/exploit_init()` installs only `kreadbuf` and `kwritebuf`, plus the
minimum safe read size (`Application/Dopamine/Exploits/ClearSword/ClearSword.m:14-25`).
The A15 trace validates a kernel read and a reversible write through a kernel
alias of an app-owned page. That is sufficient for bounded kernel-object
inspection and the current diagnostic, but it is not a generic physical
memory writer and does not cross the SPTM/PAPT protected boundary.

### Titan

`Titan/exploit_init()` publishes `titan_physwritebuf` only after
`titan_run()` returns success (`Application/Dopamine/Exploits/Titan/Titan.m:14-27`).
The current V7 run returns failure by design after the zero-buffer preflight
because selector 25 is disabled. Consequently, the function and assignment
are present in source, but the current A15 trace does not validate a published
physical-write callback.

Titan's `gfx_phystokv`/`gfx_vtophys`-style helpers describe its AGX/GPU domain;
they are not evidence that `libjailbreak` can read or write arbitrary physical
memory. The active trace validates AGX metadata, GART/IOUAT object identity,
buffer restoration and queue/notification relationships only.

## Why the PTE handoff remains blocked

`physrw_pte_handoff()` needs all of the following at runtime:

* valid current-process `proc`, `task`, `vm_map`, `pmap` and `ttep` reads;
* valid 16 KiB page-table geometry and kernel offsets;
* a working `pmap_expand_range()` path;
* page-table allocation/refcount handling, including the SPTM frame-table path
  when a new entry is installed;
* `vtophys_lvl()` to resolve the magic page-table entry;
* a verified physical write for the magic-table PTE and ASID-page PTE;
* a TLB flush and a postcondition proving that the user window reads and writes
  the intended physical pages;
* only if the kcall branch is selected, a stable arm64e kcall/PAC contract.

The current logs establish none of the physical-PTE-write, magic-window,
ASID-window or postcondition items. The absence of a PPL/SPTM bypass is also
explicit in the diagnostic: `ppl_bypass` is `NOT_TESTED`, and the active probe
does not issue a protected-component request.

V9 now captures and propagates the `physrw_pte_handoff()` result, destroys the
temporary mutex on that failure path, commits `gAsid` only after a successful
handoff, and leaves the pre-existing callbacks untouched until publication is
allowed. The handoff also checks its `ttep`, ASID physical address and both PTE
write return values. The underlying `pmap_expand_range()` and
`pmap_map_in_with_flags()` paths now propagate their existing physical-write
errors as well. A zero handoff token is rejected before publication, and the
remote initializer path propagates the local initializer result too.

This is error handling, not a validity proof. `pmap_expand_range()` may have
performed partial page-table allocation before returning an error, and a zero
handoff result still does not prove the memory window can access the intended
physical pages. No rollback or new physical write was added for those cases;
they remain a separate postcondition and runtime-validation problem.

## Reusable versus blocked official stages

### Directly reusable

* `DOExploitManager`/`DOExploit` discovery, support filtering, selection and
  lifecycle plumbing.
* `gPrimitives` callback names and ordinary kernel read/write wrappers.
* Kernel translation initialization after a separately verified KRW primitive.
* Titan's target gate, read-only identity checks, V7 snapshot/restore contract
  and cleanup path while selector 25 stays disabled.

### Adaptation required

* Make the normal path consume an explicit capability precondition before
  entering physrw, privilege or bootstrap stages.
* Add a separately authorized postcondition for the physical mapping window;
  the V9 error path prevents false callback publication but does not perform
  that runtime validation.
* Add a separately authorized, offline-designed evidence contract for the
  physical mapping window; do not infer it from a callback address.

These are reviewable interface changes only. They do not create the missing
primitive.

### Blocked by absent or unverified primitives

* A15 `physrw_pte_handoff()` and the physical PTE writes it requires.
* Generic `PHYSICAL_READ`/`PHYSICAL_WRITE` as runtime capabilities.
* Any `PROTECTED_MEMORY_WRITE` or SPTM/PAPT transition.
* Credential elevation, unsandboxing, trust-cache changes and rootless
  bootstrap, because they consume the post-physrw contract.
* Titan selector 25 and any GPU/backend conclusion, which are outside this
  validation and remain disabled.

## Bottom line

The chain is not blocked by the absence of a `buildPhysRWPrimitive` symbol or
by the AGX buffer-restore ordering. It is blocked at the unverified physical
PTE handoff required by the A15-selected PTE route. ClearSword supplies a
bounded KRW primitive; Titan supplies a bounded AGX diagnostic and a source
level physical-write publication point that has not been reached or validated.
No justified adaptation can claim more than that until a separate, explicitly
authorized physical-write and postcondition contract exists. This report does
not validate a jailbreak.

