# A15 / 23A355: selector-25 record ABI v2

Revision: `self-page-write-v1+agx-zero-packet-abi-v2+rtkit-mmio-disabled-v1`.

Target: iPhone14,2, iOS 26.0.1, build 23A355 only.

The v1 device run returned `0xe00002c2` with stable before/after snapshots and
no backend allocation. The exact retained kernelcache explains that result:

```text
0xfffffff009f43aa4  mov w8, #0x30
0xfffffff009f43aa8  str w8, [x0, #0x268]
...
0xfffffff009f1ae4c  ldr x8, [x0, #0x538]
0xfffffff009f1ae50  ldr w8, [x8, #0x268]
0xfffffff009f1ae54  cmp x24, x8
0xfffffff009f1ae58  b.ne 0xfffffff009f1af44
```

Scalar input 3 is the per-record size. V1 supplied the historical value 0x38,
while this build requires 0x30. The mismatch returns the selector's initialized
`kIOReturnBadArgument` value before the batch call at `0xfffffff009f1ae74`.

V2 performs one bounded correction:

1. Read `device+0x268` twice through the existing kernel-read primitive.
2. Require both values to be exactly 0x30.
3. Submit one 0x30-byte zero-initialized record with the two owned buffer IDs.
4. Preserve the single selector-25 call limit and all existing snapshots.
5. Stop after cleanup observation; do not retry or continue to MMIO, physical
   writes, protected writes, SPTM/TXM policy changes, bootstrap, or Sileo.

The exact-image parser also fixes the meaning of the leading record fields:

```text
+0x00  required owned buffer ID
+0x04  required owned buffer ID
+0x08  optional object ID; also the zero-count field in the empty finalizer
+0x0c  command header in the owned buffer
```

The probe already writes the same valid owned buffer ID at `+0x00` and `+0x04`.
It leaves the 16 KiB owned buffer itself zeroed. Static control-flow therefore
predicts the zero command-header path, then the zero-count finalizer cleanup,
without assigning queue status 9 (missing required object) or 10 (nonempty
format error). Assuming the live identities remain those measured by the prior
probe, the expected bounded result is `kr=0`, scalar status `0`, a released
temporary backend, and an unchanged zeroed buffer.

This revision tests only whether the corrected record reaches and exits the
empty-record batch path cleanly. Success does not establish a physical-write
primitive or SPTM authority.
