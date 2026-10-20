# A15 iOS 26 private notification-bound v4 build - 2026-10-20

## Artifact identity

- Target: iPhone14,2, iOS 26.0.1, build 23A355.
- Source commit: `ecb789d505fef44aed3088c5f0af34ffcf1ac6f9`.
- GitHub Actions run:
  [39387291888](https://github.com/Philiphall6/Dopamine-private/actions/runs/39387291888),
  completed successfully.
- IPA SHA-256:
  `541A21AC39E652DBF4B6C7825925E1670BA8C4B86BAADA4EBCF54542E1CC9EEC`.
- Embedded revision:
  `self-page-write-v1+agx-notification-bound-zero-packet-v1+rtkit-mmio-disabled-v1`.
- Embedded safety mode: `no-gfx-mmio`.
- Probe markers: `titan.notification-binding.create`,
  `titan.notification-binding.bind`, `titan.notification-binding.link`,
  `titan.zero-packet.notification-binding` and
  `titan.zero-packet.record-contract`.

## Compiled contract evidence

The checks below were made against
`Payload/Dopamine.app/Frameworks/Titan.framework/Titan` inside the downloaded
IPA. The Titan Mach-O has SHA-256
`05B3EE63EBDE1A6E9C4D0DF0A89BD81C2D63342B0700AB306B3187B4159042B1`.

`_titan_probe_notification_binding` occupies virtual range
`0x16ebc..0x17e00`.

| Address | Compiled operation | Meaning |
| --- | --- | --- |
| `0x1701c` | `mov x1, #0x430` | Read the notification-object slot. |
| `0x17050` | `mov x1, #0x428` | Require an empty derived binding before setup. |
| `0x17208` | `mov w1, #0xe` | Select external method 14. |
| `0x17220` | `bl #0x1bbe8` | Sole notification-creation call. |
| `0x178e4` | `mov w1, #0x18` | Select scalar external method 24. |
| `0x178f4` | `bl #0x1bbf4` | Sole notification-binding call. |
| `0x179ac` | `mov x1, #0x428` | Read the linked derived object. |
| `0x179e8` | `mov x1, #0x430` | Re-read the linked notification slot. |

`_titan_probe_zero_packet_once` occupies virtual range
`0x17e00..0x18d04`.

| Address | Compiled operation | Meaning |
| --- | --- | --- |
| `0x18310` | `mov x1, #0x268` | Read the runtime record-size field. |
| `0x1838c` | `subs w8, w8, #0x40` | Require the concrete G14P contract. |
| `0x18490` | `mov x2, #0x40` | Initialize an exact zero record. |
| `0x18568` | `mov w1, #0x19` | Select external method 25. |
| `0x18570` | `bl #0x1bbe8` | Sole bounded submission call. |

Mach-O indirect symbols map stub `0x1bbe8` to `_IOConnectCallMethod` and stub
`0x1bbf4` to `_IOConnectCallScalarMethod`.

## Promotion state

The artifact is ready for one bounded device observation. It is not a working
jailbreak. It does not contain a nonempty MDSID record and does not enable GPU
MMIO, physical writes, protected-memory writes, root replacement, bootstrap or
Sileo. A later MDSID probe depends on this run proving that notification
binding lets the empty record reach and release the backend cleanly.
