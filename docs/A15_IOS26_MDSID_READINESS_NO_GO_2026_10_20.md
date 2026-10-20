# A15 / iOS 26 MDSID readiness correlation gate

Target: iPhone14,2, iOS 26.0.1, build 23A355. Updated 2026-10-20.

`triage_agx_mdsid_readiness.py` correlates three independently bounded facts:

1. The exact-image static audit proves the MDSID packet to GXF TTBR0 binding.
2. The phone journal identifies the live command-buffer and firmware callback
   objects and their static callback targets by read-only checks.
3. The same journal records one notification-bound, all-zero `0x40` selector-25
   record accepted with immediate cleanup.

It consumes an exported phone JSONL and the exact static-audit JSON:

```powershell
py tools/a15_ios26/triage_agx_mdsid_readiness.py <probe.jsonl> `
  --static-audit outputs/mdsid-ttbr0-static-audit-2026-10-20.json --compact
```

With all three facts present, the only successful state is
`STATIC_AND_EMPTY_ROUTE_EVIDENCED_NO_GO`. The report always emits
`device_submission_authorized: false`.

## Why this is still a no-go

- The accepted device record was empty; no MDSID record was sent.
- Callback addresses and objects were identified, but no nonempty callback
  execution or effect boundary was observed.
- Backend effects and release timing for a nonempty record are not fully
  bounded.
- The host wake trigger, root-frame acceptance/restoration and power-lifecycle
  recovery are not observed.

The tool is evidence accounting, not a probe. It cannot generate an IPA,
contact the phone, invoke IOKit, or authorize a next device experiment.
