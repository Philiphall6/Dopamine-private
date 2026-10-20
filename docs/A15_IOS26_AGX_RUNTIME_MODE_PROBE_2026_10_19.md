# A15 / 23A355: runtime AGX UAT dispatch bit

The exact retained kernelcache has SHA-256
`8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1`.
`tools/a15_ios26/audit_agx_uat_dispatch.py` verifies the instructions and
encoded vtable entry described below. This is an offline result until a new
device run supplies the byte values.

- The live `AGXAcceleratorG14P` instance vtable observed in the prior run
  unslides to `0xfffffff007b1e0d0`. Its authenticated entry at `+0x618`
  (`0xfffffff007b1e6e8`, encoding `0x80112d1401853ee4`) resolves to
  `0xfffffff008857ee4` in the same exact image.
- That method starts with `x0` as the instance, sets `x24=x0+0xdab8`, reads
  `[x24+0x28]` (instance `+0xdb08`), masks bit 0, and stores the result at
  `0xfffffff00ab61150`. It then writes `1` to the initialization byte at
  `0xfffffff00ab61160`. This is not the ProbeConfig `mode=2` byte recorded
  in the previous device run.
- The AGX map method loads the same global at `0xfffffff00887acbc`. Value 1
  selects the kernel IOUAT mapper; value 0 selects the AGXUAT mapper. These are
  static branch targets, not proof that any map operation has occurred.
- Within the exact AGX image, reference scanning finds 18 mode-global
  references with one store (the initializer), and two initialization-byte
  references with one store. This does not exclude writes by another image.

The bounded probe reads the instance byte, global mode, and initialization
byte twice through
ClearSword's exact kernel-virtual reader, after the existing service, wrapper,
instance-vtable, and exact build gates. It reports a route only if all reads
are stable, the initialization byte is stably 1, the global is 0 or 1, and it
equals the source byte's low bit.
Disagreement is a blocker, not a guessed mode. No UAT object or map pointer is
followed, and no GPU selector, command, MMIO access, IPC transfer, or write is
performed in this stage. The separate self-page write remains limited to an
app-owned page; it does not prove a physical or protected-memory write.

The falsifiable next observation is `titan.agx-uat-mode PASS` in the persistent
JSONL for `iPhone14,2` / `23A355`. `route=AGXUAT` would eliminate the default
IOUAT route for this initialization. `route=IOUAT` would justify examining the
validated state and callback provenance next, but would not establish an SPTM
call or a bypass. An unstable or mismatched pair stops at that checkpoint.
GFX MMIO remains disabled pending attribution of the earlier SError panic.

## Device result: provenance mismatch

The user ran the signed `0e0d52d` build once on the exact target without a
reboot. `outputs/device/a15-uat-mode-v1-after-20261019.jsonl` has SHA-256
`DCFF653A1600935B327BBA7A8F4221EA8665A6E2927B2F518200E39B8EC7A599`.
It preserves the 986-line pre-run prefix exactly and appends 89 checkpoints
under run ID `E451E4DF-FF17-45F7-B33C-E2286A328CB5`.

Both reads returned source `0` at the validated AGX service instance
`+0xdb08`, global `1` at the audited mode address, and initialized `1`.
The guard therefore stopped at `titan.agx-uat-mode.stability:BLOCKED`; no map
method, GPU selector, MMIO, IPC copy, or protected operation followed. The
app-owned self-page kernel-alias write separately passed and restored.

This falsifies the proposed **current-value equality** between this service
instance's byte and the global. It does not falsify the exact-image
instruction path: the audited map method reads the global, so a call through
that method while it remains `1` would take its IOUAT branch. No such call was
observed. The initializer may have used a different instance or the service
byte may have changed after initialization; the log cannot distinguish them.
The mode-global write-site scan covers AGX text only and cannot exclude an
indirect or other-image writer. ProbeConfig `mode=2` is still unrelated.

The next bounded test should first identify a stable, validated state object
for the IOUAT branch from the exact image, then read its expected factory
field without invoking a map. A null or mismatched state field would reject
the route before any active mapping experiment. The source/global mismatch
must remain separately reported, not silently converted into provenance.
In the audited setup routine at `0xfffffff00887c5a0`, `x19=x0` and the
state pointer is stored at `[x19+0x2e8]`; `x21=x1` is a distinct argument.
The current registry-service read does not establish that this `x0` is the
service object, so reading service `+0x2e8` as a shortcut is unjustified.

## Exact-image GART linkage and next bounded test

Further audit of the retained 23A355 kernelcache identifies the missing
intermediate object. The live service vtable's authenticated `+0x6f8` entry
resolves to `0xfffffff0087dbe18`. That method calls the same vtable's `+0x850`
entry, resolving to `0xfffffff008850840`, to obtain a GART candidate. During
service start, the returned pointer is stored at `service+0xee80` (the code
uses `service+0xeb20+0x360`). Separately, the `AGXGartG14` class tag and
constructor identify vtable `0xfffffff007b1c4d8`. Its authenticated `+0xb0`
entry resolves to `0xfffffff00887c57c`, which passes that GART object as `x0`
to the setup routine at `0xfffffff00887c5a0`. The setup routine stores a
state pointer at `GART+0x2e8`. The offline audit pins these instructions,
encoded entries, and class tag. It does not establish that the live field is
non-null or still refers to that class.

Revision `self-page-write-v1+agx-gart-state-v1+rtkit-mmio-disabled-v1` reads
the service field twice after the existing target, service, wrapper, and
instance-vtable gates. It then double-reads the candidate vtable and requires
the exact GART vtable before following `+0x2e8`. A final double-read checks
that the state pointer and its vtable are stable; the state type is **not**
claimed. Every step writes a persistent checkpoint. No state `+0x10` factory
field, map method, GPU command, GFX MMIO, IPC copy, or new write is used.
The previously verified 0x20-byte app-owned-page write remains separate.

Success means only that the static service-to-GART-to-state chain has a
matching live instance. Null, unstable, or type-mismatched values falsify the
corresponding link and stop the probe. Even success would not prove an IOUAT
request, SPTM call, physical write, or protected-memory modification. The
source/global mode mismatch above remains unresolved.

The `449016e` app commit built successfully in GitHub Actions run
`39216523358`. The verified, not-yet-device-run IPA is
`outputs/agx-gart-state-v1-ci-449016e/Dopamine.ipa` (SHA-256
`C30A01FFB51F97AC41CF76863BAD47008BF3531FCA49D7EE5AFF148485394594`).
Its embedded revision and `no-gfx-mmio` marker match this probe, and the
GART checkpoint strings are present in `Titan.framework`.

## Device result: GART and state observed

The user installed and ran `449016e` once. The exact target and installed
revision were verified over USB before the run. The persistent post-run file
is `outputs/device/a15-gart-state-v1-20261019/after.jsonl`, SHA-256
`1553B2C094D18D37D2DD93D2E16394AD092E119366DE8EF43C1E749AADED4ADB`.
Its pre-run prefix matches the separately saved `before.jsonl`; 97 new
checkpoints belong to run ID `91500365-97B0-42B6-9F3D-6C46F72DFC31`.
The duplicate post-run pull had the same SHA-256. The user reported no reboot.

The validated G14P service at `0xffffffe1c17bc000` gave the same GART
pointer `0xffffffeb1e0fc000` twice at `+0xee80`. Its unslid vtable was
`0xfffffff007b1c4d8` twice, exactly the pinned `AGXGartG14` value. The
GART `+0x2e8` field gave `0xffffffe78605fdc0` twice, with stable unslid
vtable `0xfffffff007b22ae0`. The vtable was not classified by the device
probe itself; the exact-image audit now links it to the `site.AGXUATMux`
class tag and constructor. The live result establishes an object identity
candidate, not a map operation.

The same offline image shows a mode-gated factory call at
`0xfffffff00887c95c`, followed by the result store to the mux `+0x10` at
`0xfffffff00887c960`. The called kernel factory installs vtable
`0xfffffff007aed3a0` on a successful result. The field's live contents,
factory success, and whether any map operation accepts this object remain
unobserved. The earlier source-bit/global-bit mismatch also remains.

Revision `self-page-write-v1+agx-iouat-object-v1+rtkit-mmio-disabled-v1`
therefore validates the exact mux vtable, double-reads the mode and its
initialization marker, and follows `+0x10` only when both stably read `1`.
It then double-reads the field and the resulting object's vtable. Mode 0,
null, unstable, or mismatched values stop the probe. This test is still
read-only after the separate app-owned-page write;
it does not call a mapper, submit GPU commands, read GFX MMIO, transfer IPC
rights, write physical memory, modify protected memory, or invoke SPTM/TXM.

The final app commit is `eed8d43` on the authorized public research branch.
GitHub Actions run `39221012920` succeeded. The verified IPA is
`outputs/agx-iouat-object-v1-ci-eed8d43/Dopamine.ipa`, SHA-256
`F3F92ABFCFBDDDF7696542F342CDCA81C972CA3D51A4FA41B28C1218395DCB34`.
Its ZIP CRC, embedded revision, safety marker, and new checkpoint strings
were checked locally.

## Device result: IOUAT factory-result object

The user ran this build once on the exact target without a reboot. The
post-run persistent file is
`outputs/device/a15-iouat-object-v1-20261019/after.jsonl`, SHA-256
`2FAA7538CEA433F28BB2D999B165CA2E4032D1A0D276673429A369EE15B527F9`.
Its saved 279,909-byte baseline is an exact prefix; 113 checkpoints were
appended under run ID `9FF6E3D7-BF8C-44C2-8A63-3390AFE71F0F`.
A second USB pull produced the same hash. The offline triage verdict is
`iouat_factory_object_observed` with no missing, reordered, or forbidden
stages.

The service, GART, and mux pointers and exact unslid vtables remained stable.
The mode global and initialized byte each read `1` twice. The mux
`0xffffffe78605fdc0` field `+0x10` read `0xffffffeb1e204c00` twice;
that object's PAC-stripped unslid vtable matched the audited factory value
`0xfffffff007aed3a0` twice. This confirms that the factory-result field is
non-null and has the expected type signature at runtime. It does not show
that an IOUAT map callback was invoked or that the object accepted a
descriptor. The earlier service-source/global mismatch remains unexplained;
the positive factory observation does not retroactively prove their
provenance equality.

The existing app-owned-page 0x20-byte kernel-virtual alias write and
restoration also passed. That is not a physical write or modification of
SPTM-protected memory. The probe then stopped deliberately: no mapping,
GPU command, GFX MMIO, IPC copy, or SPTM/TXM call was made. The next
falsifiable boundary is a live registered-buffer identity and a bounded
user/kernel alias comparison before any packet or protected request.
