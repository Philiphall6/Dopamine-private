# A15 / iOS 26 MDSID -> GXF transition V12

Target: `iPhone14,2`, Apple A15, iOS 26.0.1, build `23A355`.

Branch: `codex/a15-ios26-private-research`.

This revision is an offline and read-only analysis. It does not change Titan,
does not enable selector 25, does not construct or submit a nonempty MDSID
record, and does not perform MMIO, RTKit, TTBR0, physical or protected-memory
writes.

## Executive conclusion

The current evidence closes the distinction between two formats, but not the
runtime transition between them:

```text
IOGPU submission record (0x40 bytes on G14P)
  -> queue/backend validation
  -> empty-record finalizer OR nonempty parser
  -> internal GXF ring message (0x30 bytes)
  -> GXF MDSID handler
  -> low-VA store through the active GXF TTBR0
```

The first and last parts of this diagram are supported by exact-image static
analysis. The empty record has one historical runtime acceptance and cleanup
observation. The nonempty branch, the effective callback execution, the GXF
store effect, and final resource release timing remain `NOT_TESTED`.

Selector 25 returning zero is therefore not evidence of firmware execution,
physical write, protected-memory write, or a jailbreak primitive.

## 1. Existing evidence reused

### Runtime evidence

The earlier bounded observations establish:

| Stage | State | Evidence and limit |
| --- | --- | --- |
| ClearSword KRW | `RUNTIME PASS` | Bounded kernel read/write and reversible app-owned-page test |
| AGX client | `RUNTIME PASS` | G14P service, owned client and shared buffer |
| Command queue | `RUNTIME PASS` | Selector 6 and queue identity checks |
| Notification | `RUNTIME PASS` | Selectors 14 and 24, one bound queue |
| Empty selector-25 record | `PASS HISTORICAL` | One all-zero `0x40` record returned `0x0` and cleaned up |
| Nonempty MDSID record | `NOT_TESTED` | No device submission |
| Firmware GXF execution | `NOT_TESTED` | Callback identity is not callback execution |
| Physical write | `BLOCKED` | No independently validated physical window |
| Protected-memory write | `BLOCKED` | No SPTM/PAPT state change observed |

The relevant source-level gates are already captured by
`audit_agx_submit_boundary.py` and `triage_agx_mdsid_readiness.py`. The
triage result remains a device no-go even when the static route and historical
empty-record evidence are both present.

### Static evidence

`audit_mdsid_ttbr0_binding.py` establishes on the exact 23A355 images that:

- the kernel-side route identifies the MDSID command transport;
- the firmware sender copies a `0x30`-byte internal entry;
- GXF packet type `0x0e` dispatches to the identified handler;
- the handler consumes the target, value and DSID fields at fixed offsets;
- a low target VA is translated through the active GXF `TTBR0_EL1` window.

This is an address and control-flow result. It does not establish that an
application can supply a valid nonempty record or that the firmware executes
the resulting store.

## 2. The two formats are distinct

### IOGPU submission record

The G14P wrapper overrides the generic `0x30` submission record size with
`0x40`, stored through the device record-size field. The associated queue input
size is `0x410`.

The static contract identifies these semantic fields:

| Offset | Meaning | Status |
| --- | --- | --- |
| `+0x00` | Primary buffer ID | Static contract only |
| `+0x04` | Control buffer ID | Static contract only |
| `+0x08` | Optional buffer ID, zero in the audited route | Static contract only |
| `+0x0c` | Control-buffer command header | Static contract only |
| `+0x18` | Backend context | Static contract only |
| `+0x20` | Batch sideband | Static contract only |

The wrapper and queue path validate the selected record size before the batch
processor. The historical missing-notification result `0xe00002bc` is a
pre-backend gate failure; it is not a nonempty-record parser result.

### Internal GXF message

The firmware ring uses fixed `0x30`-byte entries. The audited MDSID route
identifies packet type `0x0e` and the following field bindings:

| Offset | Meaning | Status |
| --- | --- | --- |
| `+0x04` | Target VA consumed by GXF | Static binding only |
| `+0x0c` | Value written by GXF | Static binding only |
| `+0x14` | DSID/context selector | Static binding only |

The audited handler ends in a store equivalent to `str w23, [x22]`. The target
address is not proven to be caller-controlled at runtime, and the store has
not been observed on the device.

## 3. Transition and cleanup boundaries

The exact-image audit separates the following stages:

1. **Record validation**: G14P accepts the `0x40` wrapper contract. A wrong
   record size stops before backend preparation.
2. **Notification prerequisite**: the batch requires the derived notification
   field at `queue+0x428`; the absent field returns before backend allocation
   and parsing.
3. **Backend preparation**: an `AGXBlockFence`-related object is prepared and
   the success gate is checked before the parser call.
4. **Empty path**: a zero command header selects the empty-record path. The
   command parser is skipped, the zero-item finalizer is selected, and the
   backend is released on the normal source-level return path.
5. **Nonempty path**: the static control flow checks command/range metadata and
   can reach the parser. This branch has no runtime observation in the target
   journal.
6. **GXF transport**: a `0x30`-byte internal message is statically copied to
   the firmware ring. No runtime confirmation links this copy to a completed
   firmware operation.
7. **Cleanup**: source-level release and clear edges are identified, but
   failure timing, object lifetime and final release before selector return
   are not independently observed for the nonempty path.

The new offline model represents each boundary as a state transition and
deliberately reports firmware execution, physical write and protected write as
false for every scenario.

## 4. V12 offline bench

Added:

- `tools/a15_ios26/mdsid_gxf_transition_model.py`
- `tools/a15_ios26/test_mdsid_gxf_transition_model.py`

No separate V11 bench artifact was present in this checkout; the V12 model
therefore reuses the existing static contracts and introduces only the
offline state-transition coverage required for this review.

The model accepts semantic scenario metadata only. It has no byte serializer,
IOKit entry point, selector wrapper, packet builder, or device transport.

Covered scenarios:

| Scenario | Expected observation |
| --- | --- |
| Empty record | Accepted model path, parser skipped, no execution proof |
| Wrong IOGPU record length | Rejected before backend |
| Wrong GXF message length | Rejected before parser |
| Nonempty metadata-only path | Parser stage reached in the model, no execution proof |
| Backend preparation error | Parser not reached, release remains required |
| Parser rejection | Error recorded, cleanup can still complete |
| Incomplete release or clear | `CLEANUP_INCOMPLETE`, never converted to success |
| Successful cleanup | All modeled resources reach the terminal cleanup state |

These tests demonstrate control-flow accounting only. They cannot prove the
behavior of the kernel, AGX firmware, GXF ring, TTBR0, or SPTM.

### Local validation

The following checks were run against this checkout:

| Check | Result |
| --- | --- |
| `python -m unittest discover -s tools/a15_ios26 -p "test_*.py"` | `359 tests`, `OK` |
| `python -m compileall -q tools/a15_ios26` | Pass |
| `python tools/a15_ios26/check_research_integration.py` | Pass; exact target remains enabled only for the bounded probe and privileged/bootstrap stages remain blocked |
| `git diff --check` | Pass |

These are offline/source checks. No Xcode build, device submission, firmware
execution, TTBR0 modification, physical write or protected-memory operation
was performed for V12.

## 5. Evidence matrix

| Step | State | Proof |
| --- | --- | --- |
| AGX client | `PASS` | Device logs |
| Command queue | `PASS` | Device logs |
| Notification | `PASS` | Device logs |
| Empty record | `PASS HISTORICAL` | One accepted all-zero `0x40` record and cleanup |
| Nonempty MDSID processing | `NOT_TESTED` | No runtime evidence |
| GXF firmware execution | `NOT_TESTED` | Static route only |
| Low-VA translation | `STATIC PASS` | Exact-image TTBR0 audit |
| Physical write | `BLOCKED` | No runtime proof |
| Protected-memory write | `BLOCKED` | No SPTM/PAPT mutation proof |

## 6. Comparison with official Titan and Dopamine 3.x

The public Titan reference describes an iOS 16 to 17.3.1 A14-A17 chain with
AGX code execution, secondary `kalloc` and `kmap` prerequisites, and a later
page-table-based PPL/SPTM bypass. Its documented assumptions and patch
boundaries are not a proof for G14P on iOS 26.0.1:
<https://github.com/alfiecg24/Titan>.

The official Dopamine 3.x path reuses exploit metadata, selection, lifecycle,
`libjailbreak` callbacks, privilege elevation and rootless bootstrap contracts.
Those interfaces are reusable as contracts, but the post-PPL stages require a
validated physical-write capability. The private A15 path currently supplies
neither that capability nor a protected-memory proof:
<https://github.com/opa334/Dopamine/tree/3.x>.

| Area | Official Titan / Dopamine reference | A15 private branch |
| --- | --- | --- |
| Target range | Supported historical devices and versions | iPhone14,2 / 23A355 |
| AGX route | Exploit path intended to reach later PPL/SPTM stages | Bounded identity, buffer and queue observations |
| Submission | Functional exploit contract in supported range | Empty record only, historically accepted |
| GXF MDSID | Not the same as proof of the iOS 26 route | Static packet-to-TTBR0 binding only |
| Physrw | Published only after its supported prerequisite path | Not published or runtime-verified |
| Bootstrap | Runs after required primitives are valid | Must remain gated |

## 7. Correctable issues without privileged operations

The following are safe and justified:

- keep `device_submission_authorized` false in the existing readiness gate;
- keep Titan's controlled `return -1` and selector-25 guard unchanged;
- represent parser reachability, backend preparation and cleanup as separate
  statuses instead of treating a zero return as execution proof;
- preserve explicit error states for backend release and state-clear failures;
- keep `PHYSICAL_WRITE` and `PROTECTED_MEMORY_WRITE` outside the verified
  capability set;
- require independent runtime evidence before changing any capability state.

No production Titan modification is required by this review.

## 8. Limits and final status

The V12 result is:

```text
IOGPU 0x40 contract: STATIC PASS; empty record: HISTORICAL RUNTIME PASS
GXF 0x30 route: STATIC PASS
nonempty MDSID parser: NOT_TESTED
firmware execution: NOT_TESTED
physical write: BLOCKED
protected-memory write: BLOCKED
bootstrap: NOT STARTED
```

This report does not authorize a nonempty device submission and does not
constitute jailbreak validation.
