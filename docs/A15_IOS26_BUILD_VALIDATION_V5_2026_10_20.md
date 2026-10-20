# A15 / iOS 26 build validation V5

Date: 2026-10-20
Branch: `codex/a15-ios26-private-research`
Target: `iPhone14,2`, A15, iOS 26.0.1, build `23A355`
Reference commit: `ebbb78881629f77ac6afd684f4bd0f4520cff0c0`

## 1. Executive result

The private GitHub Actions run [`39437143268`](https://github.com/Philiphall6/Dopamine-private/actions/runs/39437143268) completed with `success` at the reference commit. It is a real compile-only result for the Titan framework, not an IPA build and not a device or jailbreak validation.

The run provides sufficient evidence for:

```text
BUILD PASS (Titan.framework compile-only, Xcode 26.6.0, iPhoneOS26.5 SDK)
```

It does not yet provide `BUILD PASS` for the corrected iPhoneOS 16.5 SDK path introduced by this V5 update. That requires a new manual Actions run.

## 2. Evidence from run 39437143268

| Check | Observed evidence | Status |
| --- | --- | --- |
| Xcode job | `compile-check` succeeded on `macos-26-arm64`; Xcode `26.6.0 (17F113)` | `BUILD PASS` |
| Titan target | `xcodebuild -project Application/Dopamine.xcodeproj -target Titan -configuration Debug -sdk iphoneos` | `BUILD PASS` |
| Modified source | `titan.m` appears in `ScanDependencies` and the Objective-C compile command | `BUILD PASS` |
| Architecture and deployment | `-target arm64-apple-ios16.1` | `BUILD PASS` |
| Framework product | `Titan.framework` was linked, received `Titan.tbd`, and was touched after copy phases | `BUILD PASS` |
| Compiler result | `** BUILD SUCCEEDED **` | `BUILD PASS` |
| Signing | `CODE_SIGNING_REQUIRED=NO`, `CODE_SIGNING_ALLOWED=NO`, empty identity | `PASS` |
| Dependencies | BaseBin generated headers, ChOma and libjailbreak built; `libjailbreak.dylib` copied into Titan.framework | `PASS` |
| Python suite | `Ran 315 tests ... OK` | `PASS` |
| Static checks | `compileall`, integration check and `git diff --check` all returned success | `PASS` |

The exact log also shows that the old run resolved its sysroot to
`.../SDKs/iPhoneOS26.5.sdk`. Therefore the old success proves compilation
against that SDK with an iOS 16.1 deployment target; it does not prove use of
an iOS 16 SDK.

## 3. SDK correction

The compile-check workflow now has an explicit `Install iOS 16 SDK for the
compile check` step. It downloads the existing `iPhoneOS16.5.sdk` archive,
from pinned SDK release `master-146e41f`, checks `SDKSettings.plist`, exports
`IOS16_SDK_PATH`, and passes that path to `xcodebuild -sdk`. The command also
sets `IPHONEOS_DEPLOYMENT_TARGET=16.1` explicitly.

This is deliberately separate from the Xcode version. The selected Xcode
toolchain remains responsible for `xcodebuild` and Clang, while the sysroot is
the iPhoneOS 16.5 SDK. The correction is pending a fresh Actions run and is
therefore `NOT_TESTED` in this document.

The project file already sets Titan Debug and Release to
`IPHONEOS_DEPLOYMENT_TARGET = 16.1`; no exploit or runtime code was changed.

## 4. Warnings and corrective changes

### Node.js 20 and action versions

The old job reported that `actions/cache@v3`, `actions/checkout@v4`,
`actions/setup-python@v5` and `actions/upload-artifact@v4` targeted Node.js 20
while the runner was forcing Node.js 24. The workflow now uses:

| Action | Previous | V5 |
| --- | --- | --- |
| checkout | `v4` | `v5` |
| setup-python | `v5` | `v6` |
| upload-artifact | `v4` | `v6` |

The Xcode setup action remains unchanged because the compile result already
proves that its selected toolchain works.

### `actions/cache@v3` and `/opt/procursus/bin/gtar`

The warning did not come from the project source. `dhinakg/procursus-action`
enabled its internal cache by default. Its restore/save path invokes
`actions/cache@v3`; during post-job save, Procursus `gtar` tried to archive
apt/dpkg lock files under `/opt/procursus` and reported permission denied.
That warning did not invalidate the successful compile, but it made the cache
step noisy and non-deterministic.

The workflow now passes `cache: false` to that action. `ldid` remains
installed, and no Procursus package set or project build command was changed.
The old warning is retained as historical evidence; it can only be marked
resolved after the corrected workflow runs.

### Xcode warnings

The old Xcode log contained two informational warnings:

1. `DEFINES_MODULE` is enabled but Titan has no umbrella header for module-map
   generation.
2. An existing `Run Script` build phase has no declared outputs and therefore
   runs on every build.

Neither warning identifies a compile failure in `titan.m`. They are not
changed in V5 because resolving them would be unrelated project-structure
work and is not required for this compile-only check.

## 5. AGX diagnostic audit

The existing `titan.m` V1-V3 diagnostic contract remains intact:

- lifecycle events carry session IDs and monotonic timestamps;
- operation records include Mach return codes, durations, resource state and
  close reasons;
- cleanup continues after partial failure and neutralizes handles after a
  successful release;
- duplicate cleanup is suppressed and logged;
- the observation window is capped at 250 ms;
- `ready=1`, a command index, or an accepted empty record is not treated as
  proof of firmware-context persistence;
- power assertion confirmation and context retention remain `NOT_TESTED`.

The supplied iPhone log adds one concrete precondition result. The first
blocked checkpoint was `titan.zero-packet.buffer-preflight`, which observed a
non-zero byte at offset `0x100` in the returned 16 KiB user mapping. The
selector-25 call was therefore not reached in that run. This does not prove a
parser or MDSID failure; it proves that the prior probe had not established a
deterministic buffer baseline before observing it.

The follow-up change in `titan.m` now zeroes the returned shared user mapping
with `memset`, verifies the complete 0x4000-byte range, and records
`buffer-initialize` before the existing temporary 0x20-byte alias mutation.
The mutation remains restored by the existing cleanup path. This is a
userland initialization and observation change only; it does not add a GPU
submission, a nonempty MDSID record, an MMIO access, or a physical/protected
memory write.

Client closure and child-resource destruction are now separate lifecycle
observations. `client-closed` records the `IOServiceClose` result, while
`child-resources-teardown` remains explicitly `NOT_TESTED` because the code
does not independently observe destruction of the buffer, queue, or
notification objects. A successful client close must not be read as proof of
that child teardown.

The compile result is independent from the runtime AGX result. A successful
Objective-C compile proves that the source can be compiled and linked; it does
not prove GPU parser behavior, firmware persistence, MDSID effects, SPTM/PAPT
access or privilege changes.

## 6. Offline verification

The previous local verification for this branch reported:

```text
python -m unittest discover -s tools/a15_ios26 -p "test_*.py"  -> 318 tests, OK
python -m compileall -q tools/a15_ios26                       -> PASS
python tools/a15_ios26/check_research_integration.py          -> PASS
git diff --check                                               -> PASS
```

The V5 workflow keeps the same suite and runs it after the compile step with
`always()`, so a compile failure still leaves offline diagnostics available.
The corrected SDK path and the action-cache changes require a fresh Actions
execution; no local Windows environment can reproduce an Xcode compile.

The three new local source-contract tests cover the explicit shared-buffer
baseline, restoration of temporary bytes and the distinction between client
closure and independently unverified child teardown. Their result is
static/offline evidence, not an on-device lifetime proof.

## 7. Remaining blockers

The following remain `BLOCKED` or `NOT_TESTED`:

- exact iPhoneOS 16.5 SDK compilation after the V5 workflow change: `NOT_TESTED`;
- power assertion request and confirmation: `NOT_TESTED`;
- firmware context retention and recovery: `NOT_TESTED`;
- nonempty MDSID parser effects and complete backend release: `NOT_TESTED`;
- independent destruction of the shared buffer, queue and notification child
  objects after client close: `NOT_TESTED`;
- physical or protected memory writes and SPTM/PAPT policy changes: `BLOCKED`;
- root replacement, trust-cache changes, bootstrap and Sileo: `BLOCKED`;
- IPA generation and installation: `NOT_TESTED` in this compile-only workflow.

No new GPU submission, nonempty MDSID record, physical write, protected write,
SPTM/PAPT modification, bootstrap operation or device run was added by this
follow-up.

## 8. Next step

Run `a15-ios26-compile-check.yml` manually at the V5 commit and inspect the
archived `titan-xcodebuild.log` for both
`-isysroot .../iPhoneOS16.5.sdk` and `** BUILD SUCCEEDED **`. Then record the
new run ID here. Do not infer an IPA or jailbreak result from that compilation.
