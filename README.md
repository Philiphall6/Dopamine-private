<img src="https://github.com/opa334/Dopamine/assets/52459150/ed04dd3e-d879-456d-9aa3-d4ed44819c7e" width="64" />

# Dopamine

A rootless semi-untethered jailbreak for iOS 15.0 - 17.3.1 (arm64e), iOS 15.0 - 18.7.1, 26.0 - 26.0.1 (A12/A13) and iOS 15.0 - 18.7.1 (arm64). More details will follow here soon.

Please note that all issues related to version support will be deleted without response.

Official website / download: https://ellekit.space/dopamine/

## Private A15 / iOS 26 research status

Last updated: 2026-10-20. Exact target: iPhone14,2, iOS 26.0.1,
build 23A355. Private research branch:
`codex/a15-ios26-private-research`.

This branch is research in progress, not a working jailbreak release. A stage
is marked `RUNTIME PASS` only after its effect is observed on the target phone.
`STATIC PASS` means that the route is closed on the exact firmware images but
has not yet been exercised safely on-device.

```mermaid
flowchart TD
    A[ClearSword kernel read/write<br/>RUNTIME PASS]
    B[Reversible app-owned page alias write<br/>RUNTIME PASS]
    C[Owned AGX client, shared buffer and queue<br/>RUNTIME PASS]
    D[Selector 25 exact 0x30 record ABI<br/>STATIC PASS / DEVICE PENDING]
    E[MDSID packet and low-VA GXF TTBR0 route<br/>STATIC PASS]
    F[BEE7 active-root discovery<br/>STATIC PASS]
    G[16 KiB cloned-root format<br/>STATIC PASS]
    H[RTBuddy and G14P firmware power lifecycle<br/>STATIC PASS]
    I[GXF command 3 reloads current-context TTBR0<br/>STATIC PASS]
    J[Corrected selector-25 packet accepted<br/>RUNTIME BLOCKER]
    K[Normal power assertion keeps queue/context alive<br/>RUNTIME BLOCKER]
    L[Owned cloned root accepted and restored<br/>BLOCKED]
    M[Stable physical write with rollback<br/>BLOCKED]
    N[SPTM/PAPT policy bypass<br/>BLOCKED]
    O[Trust cache, bootstrap and Sileo<br/>BLOCKED]

    A --> B --> C --> D --> J
    C --> H --> I --> K
    D --> E --> F --> G
    J --> K --> L --> M --> N --> O
    G --> L

    classDef runtime fill:#1f6f43,color:#fff,stroke:#164f31
    classDef static fill:#2166a5,color:#fff,stroke:#174a78
    classDef pending fill:#a86200,color:#fff,stroke:#744400
    classDef blocked fill:#8a3030,color:#fff,stroke:#5e2020
    class A,B,C runtime
    class D,E,F,G,H,I static
    class J,K pending
    class L,M,N,O blocked
```

### Current deployment gate

The only justified device build is the bounded
`self-page-write-v1+agx-zero-packet-abi-v2+rtkit-mmio-disabled-v1` probe. It
submits one exact selector-25 record of `0x30` bytes, records pre/post state,
and stops. It does not install a replacement root, force a power transition,
perform GPU MMIO, write physical memory, or modify protected memory.

Deployment order:

1. Build one IPA from the exact private commit and verify its embedded revision.
2. Install and run it once on the exact target; do not retry automatically.
3. Accept promotion only if the call contract and cleanup observations pass.
4. Then build a separate power-lifecycle observation that checks queue, buffer,
   context and registered-root stability.
5. Root replacement, physical writes and SPTM work stay disabled until their
   restoration contracts are independently complete.

### Evidence and maintenance

- Functional ledger: [`docs/A15_IOS26_OFFLINE_FUNCTIONAL_PATH_2026_10_19.md`](docs/A15_IOS26_OFFLINE_FUNCTIONAL_PATH_2026_10_19.md)
- Blocker schema: [`docs/A15_IOS26_CHAIN_BLOCKERS_SCHEMA_2026_10_19.md`](docs/A15_IOS26_CHAIN_BLOCKERS_SCHEMA_2026_10_19.md)
- Detailed worklog: [`docs/A15_IOS26_WORKLOG.md`](docs/A15_IOS26_WORKLOG.md)
- Power lifecycle audit: [`tools/a15_ios26/audit_agx_firmware_power_lifecycle.py`](tools/a15_ios26/audit_agx_firmware_power_lifecycle.py)

Keep this section synchronized whenever a stage changes state or a new IPA is
promoted. Extracted Apple firmware, phone journals, signing material and local
IPA artifacts are intentionally excluded from Git.
