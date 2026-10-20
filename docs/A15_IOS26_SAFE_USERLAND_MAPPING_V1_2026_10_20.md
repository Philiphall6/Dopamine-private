# A15 iOS 26 safe userland mapping diagnostic

Revision: `safe-userland-mapping-v1`.

This build is a diagnostic guard, not a jailbreak probe. `SAFE_DIAGNOSTIC=1`
defines `SAFE_DIAGNOSTIC_ONLY=1` and selects `Info-SafeDiagnostic.plist`.
The active-probe entry point returns before XPF, ClearSword, Titan, IOSurface,
kernel primitives, IOKit user-client opens, SPTM/TXM access and any physical
address operation.

The diagnostic allocates one application-owned anonymous `MAP_SHARED` page and
64 additional application-owned anonymous mappings, writes a small marker,
checks it through the same user mapping and immediately unmaps each mapping.
It records only allocation, userland readback and release results in the
existing JSONL journal. It does not select or target a physical page and does
not infer kernel state from the test.

Build on a macOS host with the repository's existing toolchain:

```sh
make -C Application safe-diagnostic
```

The resulting IPA is a separate diagnostic build only when the build log shows
`SAFE_DIAGNOSTIC_ONLY=1` and the embedded revision is
`safe-userland-mapping-v1`. A Windows checkout cannot run `xcodebuild`; the
source and build guard are prepared here but no IPA is claimed until a macOS
build completes and its artifact hash is recorded.
