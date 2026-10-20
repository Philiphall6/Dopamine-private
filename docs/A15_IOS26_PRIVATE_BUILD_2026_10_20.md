# A15 iOS 26 private probe build - 2026-10-20

## Artifact identity

- Target: iPhone14,2, iOS 26.0.1, build 23A355.
- Source commit: `20e28f2d5dea8ac6c3737074575b4d55d92bed70`.
- GitHub Actions run: [39383221146](https://github.com/Philiphall6/Dopamine-private/actions/runs/39383221146), completed successfully.
- IPA SHA-256: `8566FC2D517D7B144964005E9EB06DC18977D6B0ADAD3DDD863A2B2799F70806`.
- Embedded revision: `self-page-write-v1+agx-zero-packet-abi-v2+rtkit-mmio-disabled-v1`.
- Embedded safety mode: `no-gfx-mmio`.
- Titan marker: `titan.zero-packet.record-contract`.

## Compiled contract evidence

The checks below were made against
`Payload/Dopamine.app/Frameworks/Titan.framework/Titan` inside the downloaded
IPA, not inferred only from source code.

Function `_titan_probe_zero_packet_once` occupies virtual range
`0x16e78..0x17ce8` in this build.

| Address | Compiled operation | Meaning |
| --- | --- | --- |
| `0x1734c` | `mov x1, #0x268` | Read the runtime record-size field. |
| `0x173c8` | `subs w8, w8, #0x30` | Require the corrected `0x30` contract. |
| `0x174cc` | `mov x2, #0x30` | Initialize an exact `0x30`-byte record. |
| `0x175a4` | `mov w1, #0x19` | Select external method 25. |
| `0x175ac` | `bl #0x1abcc` | Perform the sole call through the method stub. |

Mach-O indirect symbol entry 0 maps stub `0x1abcc` to
`_IOConnectCallMethod`. There is exactly one branch to that stub inside the
probe function.

## Promotion decision

The IPA is promoted only to **ready for one bounded device observation**. It
is not a working jailbreak. The next runtime gate is acceptance of the exact
selector-25 record with stable cleanup state. Power-lifecycle survival,
reversible root replacement, physical writes, SPTM/PAPT policy work,
bootstrap and Sileo all remain disabled or blocked.
