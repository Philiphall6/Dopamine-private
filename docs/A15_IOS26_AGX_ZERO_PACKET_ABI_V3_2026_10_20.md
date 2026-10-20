# A15 / 23A355: selector-25 G14P record ABI v3

Revision: `self-page-write-v1+agx-zero-packet-abi-v3+rtkit-mmio-disabled-v1`.

Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

## Why v2 stopped

The bounded v2 device run read `device+0x268` twice and observed the stable
value `0x40`. Its expected value was `0x30`, so it stopped before
`IOConnectCallMethod`. There was no selector-25 call, retry, GPU MMIO, physical
write, protected write or restart.

The retained kernelcache explains the difference. The IOGPU base initializer
stores `0x30`, but the concrete G14P initializer overrides the live field:

```text
0xfffffff0087e7344  mov w8, #0x40
0xfffffff0087e7348  str w8, [x19, #0x268]
0xfffffff0087e734c  mov w8, #0x410
0xfffffff0087e7350  str w8, [x19, #0x278]
```

The selector-25 wrapper reads the queue's device back-reference at `+0x538`,
loads this exact `device+0x268` field and rejects a different scalar record
size before entering the batch routine. The adjacent G14P `0x410` store
matches the live queue-input contract already observed at `device+0x278`.

## Bounded v3 contract

1. Require the same owned queue, buffer, command-buffer and firmware identities.
2. Require a stable zeroed 16 KiB owned mapping and stable pre-call snapshots.
3. Read `device+0x268` twice and require `0x40/0x40`.
4. Supply one `0x40`-byte zero-initialized record whose first two 32-bit fields
   contain the same owned buffer ID.
5. Invoke selector 25 at most once and capture all post-call cleanup state.
6. Stop and close the connection; do not retry or continue into MMIO, physical
   writes, root replacement, protected writes, bootstrap or Sileo.

This is still an empty-record transport observation, not a jailbreak or a
physical-write primitive.

## Verified build

Commit `0ec47e4e2a1dd27ad57f4ee1e226124a3c27206f` was built by private GitHub
Actions run [39384824664](https://github.com/Philiphall6/Dopamine-private/actions/runs/39384824664).
The downloaded IPA has SHA-256
`F4F98891E9BC2998BBB94207BC53F5528EF012FA92D898554F520DC3E891C8AB`.
Its compiled Titan function reads `device+0x268`, compares against `0x40`,
sets the structure size to `0x40`, selects method 25 and contains exactly one
branch to the `_IOConnectCallMethod` stub. It is ready for one bounded target
run only.

## Device result

The one permitted run completed without a restart. The live `0x40` contract
passed and selector 25 returned `0xe00002bc`; all tracked pool, queue and object
state remained unchanged. Exact-image control flow identifies this as the
pre-backend `queue+0x428 == 0` notification-binding gate. ABI v3 is retired and
must not be rerun. The bounded successor is documented in
`A15_IOS26_AGX_NOTIFICATION_BINDING_V1_2026_10_20.md`.
