# A15 iOS 26 private ABI v3 probe build - 2026-10-20

## Artifact identity

- Target: iPhone14,2, iOS 26.0.1, build 23A355.
- Source commit: `0ec47e4e2a1dd27ad57f4ee1e226124a3c27206f`.
- GitHub Actions run: [39384824664](https://github.com/Philiphall6/Dopamine-private/actions/runs/39384824664), completed successfully.
- IPA SHA-256: `F4F98891E9BC2998BBB94207BC53F5528EF012FA92D898554F520DC3E891C8AB`.
- Embedded revision: `self-page-write-v1+agx-zero-packet-abi-v3+rtkit-mmio-disabled-v1`.
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
| `0x173c8` | `subs w8, w8, #0x40` | Require the concrete G14P `0x40` contract. |
| `0x174cc` | `mov x2, #0x40` | Initialize an exact `0x40`-byte record. |
| `0x175a4` | `mov w1, #0x19` | Select external method 25. |
| `0x175ac` | `bl #0x1abcc` | Perform the sole call through the method stub. |

Mach-O indirect symbol entry 0 maps stub `0x1abcc` to
`_IOConnectCallMethod`. There is exactly one branch to that stub inside the
probe function.

## Promotion decision

The IPA is promoted only to **one bounded device observation**. It validates
the live `device+0x268` field twice, permits exactly one selector-25 call, then
records cleanup state and stops. It is not a working jailbreak. Power-lifecycle
survival, reversible root replacement, physical writes, SPTM/PAPT policy work,
bootstrap and Sileo remain disabled or blocked.
