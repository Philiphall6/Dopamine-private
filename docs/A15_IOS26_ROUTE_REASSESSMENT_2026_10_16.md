# A15 / iOS 26.0.1 route reassessment (2026-10-16)

Target scope: iPhone14,2, A15, iOS 26.0.1, build 23A355. This note separates
offline firmware contracts from observations on the device. It does not claim
an injection, a protected-memory change, or a new device-side write.

## Evidence boundary

The last retained post-reboot JSONL contains 795 records and 14 `probe.entry`
events. Its final run starts at 14:33:56 CEST and ends at
`titan.command-buffers FAIL`; `task_copy_ipc_entry` is not reached. The 15:06:38
CEST `GFX SERROR` panic has an error address whose low bits match the physical
IORVBAR descriptor, but there is no corresponding persisted probe entry or
RTKit-metadata checkpoint. The installed binary revision was not independently
confirmed. This supports an address correlation, not attribution of the panic
to the proposed MMIO read. Live MMIO remains disabled.

The post-panic guard build from Actions run `38906834273` succeeded. Its
downloaded `Dopamine.ipa` has SHA-256
`510CF5B3B4D5263BC735F92411F9FCEF3C0FE1282CB98EB2B545DCF4FD0CB354`.
Archive inspection confirms `A15ProbeSafetyMode=no-gfx-mmio`, the
`rtkit-mmio-disabled-v1` revision, and the RTKit stop marker in the packaged
Titan framework. This IPA was neither installed nor run as part of this work;
the package check does not establish the revision currently on the device.

| Capability | Evidence on this target | Status |
|---|---|---|
| Kernel read | ClearSword kernel-base/Mach-O check and bounded object reads in repeated device logs | Observed |
| Kernel write | Primitive source and KRW setup logs, but no independently verified controlled write/readback in this investigation | Not demonstrated here |
| Physical write | Titan stops before IPC transfer and command-buffer submission | Not demonstrated |
| Protected-memory modification | No accepted SPTM/TXM operation or protected readback | Not demonstrated |

## Route decisions

| Route | Earliest identified entry | Candidate controlled data | Blocking check / decision |
|---|---|---|---|
| Titan IPC handoff | Existing AGX user-client objects in `backboardd`'s stable IPC census | Local port names and candidate objects can be observed, not transferred | XNU 12377 changed `ipc_object` state and port unions; `ip_nsrequest` is field-PAC-signed and table entries have SMR lifetime rules. The legacy write would address `ip_pdrequest`. Keep the unconditional stop; no offset-only repair. |
| AGX to SPTM UAT | `acquire_uat_segments_page` is a confirmed internal protected request producer | Segment descriptors, count and `map_options` are function inputs; their external provenance is not established | Descriptor page must be `XNU_DEFAULT`; leaf frames face per-domain/per-class policy. The direct GXF constructor found in firmware is a bootstrap/internal route, not a demonstrated caller-controlled ingress. Retain as an offline provenance question. |
| GFX / RTKit | IORVBAR descriptor walk and GFX firmware strings are observable | No externally controlled firmware command or safe register read has been established | GFX panic provenance unresolved. Do not retry live MMIO, map a direct firmware command, or infer a write from the descriptor. |
| UPPL | Offline dispatcher and state images | No reachable weak handler/relocation/fixup producer identified | Zero weak handler count/table on the exact image; abandon a direct UPPL-writer claim. |
| Stage-2 / Hypervisor | Typed guest-service code exists in SPTM | No accessible app-side `hv_*` ABI or entitlement on this device | Framework/symbols absent; device-tree virtualization property absent; typed Stage-2 frames are not eligible UAT leaves. Separate research surface, not a Titan substitute. |
| Kernel-only / pmap PoC | ClearSword kernel access and public `pmap-tte-remove` claim | No measured protected write from either | Kernel access does not imply SPTM authority; the PoC's printed refcount and sentinel are not independent measurements. Do not promote this route without a distinct proof. |

## New offline result: UAT option selector

The analyzer now requires the exact 23A355 instruction sequence from the
`map_options` read through its lookup and class calculation, and reads the
16-byte lookup table from `sptm.bin` instead of assuming an option meaning.
The table and rejection mask agree at all 16 indices. Selectors
`0,1,4,5` request class 1; `2,3,8,10,12,13,15` request class 2; and
`6,7,9,11,14` are rejected at this selector gate. The selector combines only
option bits 0, 1, 8 and 9. Other option bits and earlier/later checks can
still reject a request. These are requested mapping classes on the ordinary
leaf-registration path, not a list of accepted external commands or writable
physical addresses.

Falsifiable hypothesis: on the exact SPTM image, every selector not rejected
by this gate has a lookup value consistent with the class computation, while
any instruction-shape or table/mask mismatch must downgrade the result to
`PARTIAL`. The minimal test is offline: run the analyzer against the retained
23A355 SPTM image, then run unit tests that perturb the instruction sequence
and table. Success requires `UAT_MAP_OPTIONS_MATRIX_CONFIRMED`, 16 decoded
entries, the class/reject sets above, and `PARTIAL` or an exception for a
mutated contract. It is not a test of kernel, physical, or protected writing.

Input SPTM SHA-256:
`ED7781D2D82FE4818B85DD18C6B07DC172440EEECC2F7B33FC1E048313583F7C`.
Regenerated reports (kept separate from prior output):
`outputs/iphone-system/uat-options-v1/agx-uppl-producer.json` SHA-256
`CD3F1F299C940E4DEAB0B70C086B0B5E66F9C19455544B67153C84EEAA5949B7`,
and `.md` SHA-256
`241FDEFA4565E94CDE726A83DE356457B858768F1E24C8D62D1BDC4572980539`.

Next concrete blocker: the `segments_page` and `map_options` inputs to the
protected producer still have no demonstrated caller-controlled, reachable
origin on this target. Even such an origin would face the authenticated frame
policy and would not by itself prove a physical or protected-memory write.
