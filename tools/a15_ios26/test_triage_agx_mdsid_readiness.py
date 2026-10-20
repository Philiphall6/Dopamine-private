import unittest

from test_triage_agx_notification_bound_probe import complete_run
from triage_agx_mdsid_readiness import (
    BUILD,
    GFX_SHA256,
    KERNELCACHE_SHA256,
    STATIC_ROUTE_STATUS,
    assess,
    render_compact,
    triage,
)


def static_audit(status=STATIC_ROUTE_STATUS):
    return {
        "status": status,
        "build": BUILD,
        "kernelcache_sha256": KERNELCACHE_SHA256,
        "gfx_sha256": GFX_SHA256,
        "limits": "Exact-image static analysis only.",
    }


class MDSIDReadinessTriageTests(unittest.TestCase):
    def test_complete_safe_evidence_remains_a_device_no_go(self):
        report = triage(complete_run(), "run-a", static_audit())
        self.assertEqual(report["state"], "STATIC_AND_EMPTY_ROUTE_EVIDENCED_NO_GO")
        self.assertTrue(report["evidence"]["static_mdsid_ttbr0_binding"])
        self.assertTrue(report["evidence"]["runtime_packet_route_identity"])
        self.assertTrue(
            report["evidence"]["runtime_notification_bound_empty_record_cleanup"]
        )
        self.assertFalse(report["device_submission_authorized"])
        self.assertIn("nonempty MDSID record submission has not been observed",
                      report["remaining_blockers"])
        self.assertIn("device_submission_authorized: False", render_compact(report))

    def test_absent_static_binding_stays_incomplete_and_denied(self):
        report = triage(complete_run(), "run-a", static_audit("UNKNOWN"))
        self.assertEqual(report["state"], "INCOMPLETE_EVIDENCE_NO_GO")
        self.assertFalse(report["device_submission_authorized"])
        self.assertIn("exact 23A355 MDSID-to-GXF TTBR0 static binding is absent",
                      report["missing_evidence"])

    def test_wrong_exact_image_is_not_static_evidence(self):
        audit = static_audit()
        audit["gfx_sha256"] = "0" * 64
        report = triage(complete_run(), "run-a", audit)
        self.assertEqual(report["state"], "INCOMPLETE_EVIDENCE_NO_GO")
        self.assertFalse(report["evidence"]["static_mdsid_ttbr0_binding"])

    def test_assessment_cannot_grant_device_submission(self):
        report = assess(
            {
                "packet_route_identity_ok": True,
                "verdict": "agx_notification_bound_zero_packet_cleanup_observed",
            },
            static_audit(),
        )
        self.assertFalse(report["device_submission_authorized"])
        self.assertEqual(report["state"], "STATIC_AND_EMPTY_ROUTE_EVIDENCED_NO_GO")


if __name__ == "__main__":
    unittest.main()
