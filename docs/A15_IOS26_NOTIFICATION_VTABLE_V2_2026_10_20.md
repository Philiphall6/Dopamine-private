# A15 / iOS 26: notification queue vtable correction

Target: iPhone14,2, iOS 26.0.1, build 23A355.

## Device observation

The private v4 probe created one notification queue through selector 14. The
returned registry object was stable but its unslid vtable was
`0xfffffff007e479a8`, rather than the v4 candidate
`0xfffffff007e42f28`. The probe therefore stopped before selector 24 and
selector 25. No MDSID record, MMIO operation, physical write or protected-memory
write occurred; connection close passed.

## Exact-image confirmation

The retained 23A355 kernelcache SHA-256 is
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
`tools/a15_ios26/audit_agx_submit_boundary.py` now verifies:

1. The `IOGPUNotificationQueue` class string.
2. Selector 14 reaches the factory at `0xfffffff009f555f0`.
3. The class metaclass allocator slot `0xfffffff007e47ab0` decodes to
   `0xfffffff009f554c4`.
4. That allocator installs `0xfffffff007e479a8` as the instance vtable.

The source now uses that value under revision
`self-page-write-v1+agx-notification-vtable-v2+rtkit-mmio-disabled-v1`.

## Scope

The next artifact keeps the v4 call budget unchanged: one selector 14 create,
one selector 24 bind, and at most one selector 25 all-zero record. It does not
submit a nonempty MDSID record or advance to power, root, physical-memory, SPTM,
bootstrap or Sileo work.
