# A15 / iOS 26.0.1 AGX 3D to SPTM route

Target: iPhone14,2, build 23A355.

This note records an exact-image, offline-only route. It proves that a minimal
3D descriptor can reach the legitimate SPTM UAT context-registration handler.
It does not prove that the packet controls protected translation state, and it
does not establish a jailbreak primitive.

## Minimal command contract

The candidate command is `0x550` bytes and is zero-filled except for five
32-bit fields:

| Packet offset | Value | Meaning |
|---|---:|---|
| `+0x000` | `0x00010000` | AGX descriptor-command prefix |
| `+0x004` | `0x00000550` | Complete chunk size |
| `+0x0a4` | `0x00000488` | Nested payload length |
| `+0x0a8` | `0x00000002` | 3D descriptor kind |
| `+0x450` | `0xffffffff` | Resource-free sentinel at nested `+0x388` |

The packet SHA-256 is
`97a4ed9626a831b7f7bfdc7b505631ef47d17670f78ae1860ce9694fa58bf434`.

The generic parser consumes the eight-byte prefix, copies a `0xc0`-byte
header, then starts the nested payload at packet `+0xc8`. The kind-2 parser
requires exactly `0x488` bytes. Its field at nested `+0x388` becomes parsed
object `+0x98`; `0xfffffff008867ed8` accepts `0xffffffff` there without a
resource lookup. Empty optional resource lists and the remaining zero fields
reach the deep setup success return.

## Descriptor lifecycle

```text
IOGPU chunk parser 0xfffffff009f4bd6c
  -> AGX descriptor dispatcher 0xfffffff008805500
  -> kind-2 parser 0xfffffff0088177e0
  -> 3D descriptor factory 0xfffffff0088064e0
  -> deep setup 0xfffffff00880b228
  -> ring insertion 0xfffffff009f3025c
  -> ring worker 0xfffffff009f335e8
  -> descriptor dispatch 0xfffffff009f2faac
  -> vtable slot +0x90 0xfffffff0087d85f0
  -> dynamic context allocator 0xfffffff0087f04a4
```

The slot is pinned at `0xfffffff007b22880`, encoded as
`0x8011bed3017d45f0`; its decoded target is
`0xfffffff0087d85f0`. The matching `0xbed3` PAC discriminator is used by the
only lifecycle call at `0xfffffff009f2fb8c`.

Insertion is the trigger. There is no missing second submit between creation
of the descriptor and its context-allocation callback.

## Protected registration

The dynamic allocator chooses the context ID from an internal free list. It
passes that ID and a driver-selected context class to GART slot `+0x128`.
For the live mode-one configuration already observed on the device, the route
is:

```text
AGXGart registerContextID 0xfffffff00887b8c4
  -> IOUAT setClientContextID 0xfffffff008760e44
  -> kernel method 0xBEE0 with one 4-byte input
  -> kernel handler 0xfffffff0081350e0
  -> protected stub 0xfffffff0087b3504 (table 7, entry 10)
  -> sptm_uat_set_ctx_id 0xfffffff0270a009c
```

The kernel masks the supplied ID to 16 bits. SPTM then enforces all of the
following before updating its two global context slots:

1. The context ID is below `0x40`.
2. The protected descriptor currently contains context ID `0xffff`.
3. Both destination context slots are empty.
4. The descriptor has a UAT-eligible type and pre-existing typed roots.

The packet therefore controls neither the context ID nor either translation
root. The demonstrated effect is legitimate registration of a driver-selected
ID against protected roots selected before the protected call.

## Removal and reuse result

The simple early-ID-reuse hypothesis is closed. Removal follows this exact
order:

```text
AGX context release 0xfffffff008867218
  -> lock device+0xeed8
  -> GART removal 0xfffffff00887b8c4
  -> IOUAT method 0xBEE1 at 0xfffffff008761004
  -> kernel handler 0xfffffff008134eb4
  -> protected table 7 entry 11 at 0xfffffff0087b351c
  -> sptm_uat_remove_ctx_id 0xfffffff02709faac
  -> return ID to device+0xef10 and update device+0xef18
  -> unlock device+0xeed8
```

SPTM derives the ID from the protected descriptor rather than from caller
input, clears both registered context slots, invalidates the ASID, and resets
the descriptor field to `0xffff`. The allocator uses the same lock and free
stack as release. Another context therefore cannot obtain the ID before the
protected removal has returned.

## Current blocker

The route reaches a real SPTM operation but does not make any protected value
attacker-controlled. Registration and removal are serialized and internally
select their ID and roots. Work should move to a different boundary: either an
IOUAT mapping operation whose address or length remains caller-controlled, or
the MDSID GFX-write transport followed by a replacement for Titan's closed
PACGA-protected RTKit continuation.

Machine-readable evidence:
`../../outputs/iphone-system/agx-3d-context-route-2026-10-19.json`.

Reproduction:

```powershell
python tools/a15_ios26/audit_agx_3d_context_route.py `
  ..\..\outputs\iphone-system\unpacked\kernelcache.bin `
  --sptm ..\..\outputs\iphone-system\unpacked\sptm.bin `
  --output ..\..\outputs\iphone-system\agx-3d-context-route-2026-10-19.json
```

No IPA was built and no device probe was run for this result.
