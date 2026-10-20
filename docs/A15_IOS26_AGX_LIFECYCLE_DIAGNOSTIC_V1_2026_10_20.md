# A15 / iOS 26 AGX lifecycle diagnostic v1

Date: 2026-10-20  
Branch: `codex/a15-ios26-private-research`  
Target: iPhone14,2, iOS 26.0.1, build `23A355`

## Scope

This revision is an offline diagnostic and cleanup hardening pass. It does
not add a nonempty MDSID record, a new selector, a power transition, GPU MMIO,
physical/protected writes, root replacement, trust-cache changes, bootstrap,
or Sileo installation. No new device run is authorized by this document.

## Sources inspected

- `Application/Dopamine/Exploits/Titan/exploit/titan.m`
- `Application/Dopamine/Exploits/Titan/exploit/Titan.h`
- `Application/Dopamine/Exploits/Titan/Titan.m`
- `Application/Dopamine/Jailbreak/DOExploitManager.m`
- `Application/Dopamine/Jailbreak/DOExploit.m`
- `README.md`
- `docs/A15_IOS26_WORKLOG.md`
- `docs/A15_IOS26_MDSID_READINESS_NO_GO_2026_10_20.md`
- `docs/A15_IOS26_EMPTY_RECORD_ACCEPTED_V3_2026_10_20.md`
- `docs/A15_IOS26_NOTIFICATION_MAP_V3_2026_10_20.md`
- `docs/A15_IOS26_PRIVATE_BUILD_V4_2026_10_20.md`
- `docs/A15_IOS26_CHAIN_BLOCKERS_SCHEMA_2026_10_19.md`

## Observed and unobserved states

| Stage | State | Evidence boundary |
| --- | --- | --- |
| ClearSword KRW and reversible app-owned alias write | `RUNTIME PASS` | Recorded on the target; the test restores its bytes. |
| AGX service, shared buffer, queue and notification link | `RUNTIME PASS` | The bounded run observed selectors 12, 6, 14 and 24 with stable object relations. |
| Empty selector-25 record | `RUNTIME PASS` | One `0x40` all-zero record returned `kr=0x0`; dispatch/index advanced and tracked state settled. |
| Normal power assertion and context retention | `NOT TESTED` | `ready=1` is only a field observation; no explicit power/context hold exists in this probe. |
| Nonempty MDSID parser and callback effects | `NOT TESTED` | Deliberately excluded from this revision. |
| Owned cloned root, physical write, SPTM/PAPT policy, rootless bootstrap | `BLOCKED` | No validated reversible path exists in the current branch. |

## Code findings

1. The original post-call observation used two fixed 1 ms sleeps. That could
   label a transient state as stable or miss a delayed transition.
2. The queue's `ready` byte was logged as evidence, but the code did not make
   clear that power and context survival were not exercised.
3. The shared-alias cleanup path had an early return when the ClearSword
   redirect check failed. That bypassed `munlock` and `IOServiceClose`, leaving
   owned resources to process teardown.
4. Kernel return values were logged as hexadecimal values only, making failure
   triage needlessly dependent on a second lookup.

## Changes made

- Added a structured `TitanAGXLifecycle` journal for service, connection,
  buffer, queue, notification, binding, page-lock and cleanup state.
- Added explicit `mach_error_string()` text to the AGX open, create, bind,
  submit and close checkpoints.
- Replaced the fixed post-call delay with one read-only settling window capped
  at 250 ms. It polls snapshots and succeeds only after two matching pool and
  queue snapshots. It never retries selector 25.
- Added an idempotent cleanup helper that restores user bytes, checks the
  ClearSword redirect, unlocks the page, closes the connection and releases
  the service even when an earlier check fails. A second cleanup attempt is
  logged and suppressed.
- Added an explicit `NOT_TESTED` checkpoint for normal power assertion and
  context retention; a ready queue is not treated as proof of either.

## Verification status

- `STATIC PASS`: source-level audit confirms one existing selector-25 call,
  no new selector and no new nonempty packet path.
- `STATIC PASS`: `git diff --check` is clean.
- `NOT TESTED`: iOS/Xcode compilation. This Windows workspace has no Apple SDK
  or Xcode toolchain.
- `NOT TESTED`: device execution. No IPA was built, installed or run from
  this revision.
- `NOT TESTED`: any root, sandbox, trust-cache, SPTM/PAPT or bootstrap effect.

The next safe development step is an offline source/test audit of these new
checkpoint contracts, followed by a human-reviewed build only if the branch
owner explicitly requests it. A device run must remain a separate decision
and must not be inferred from this static pass.
