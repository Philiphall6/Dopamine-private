import unittest

from mdsid_gxf_transition_model import (
    GXF_MESSAGE_SIZE,
    IOGPU_SUBMISSION_RECORD_SIZE,
    SyntheticScenario,
    default_scenarios,
    simulate_transition,
)


class MDSIDGXFTransitionModelTests(unittest.TestCase):
    def assert_offline_only(self, result):
        self.assertFalse(result.device_submission_performed)
        self.assertFalse(result.payload_serialized)
        self.assertFalse(result.firmware_execution_confirmed)
        self.assertFalse(result.physical_write)
        self.assertFalse(result.protected_memory_write)

    def test_default_scenarios_cover_requested_boundaries(self):
        results = {scenario.name: simulate_transition(scenario)
                   for scenario in default_scenarios()}
        self.assertEqual(
            results["empty-record-accepted"].outcome,
            "ACCEPTED_NO_EXECUTION_PROOF",
        )
        self.assertEqual(
            results["gxf-parser-reached"].outcome,
            "PARSE_PATH_REACHED_NO_EXECUTION_PROOF",
        )
        self.assertEqual(results["backend-preparation-error"].outcome,
                         "BACKEND_ERROR")
        self.assertEqual(results["parser-rejection"].outcome, "PARSER_ERROR")
        self.assertEqual(results["incomplete-release"].cleanup, "RELEASE_FAILED")
        self.assertEqual(results["cleanup-success"].cleanup, "SUCCESS")
        for result in results.values():
            self.assert_offline_only(result)

    def test_format_lengths_are_explicit_and_distinct(self):
        result = simulate_transition(SyntheticScenario("format-baseline"))
        self.assertIn("IOGPU_RECORD_VALIDATED", result.phases)
        self.assertIn("BACKEND_PREPARED", result.phases)
        self.assertEqual(IOGPU_SUBMISSION_RECORD_SIZE, 0x40)
        self.assertEqual(GXF_MESSAGE_SIZE, 0x30)
        self.assertNotEqual(IOGPU_SUBMISSION_RECORD_SIZE, GXF_MESSAGE_SIZE)

    def test_submission_length_rejection_happens_before_backend(self):
        result = simulate_transition(
            SyntheticScenario("bad-submission", submission_record_size=0x30)
        )
        self.assertEqual(result.outcome, "REJECTED_BEFORE_BACKEND")
        self.assertIn("IOGPU_RECORD_REJECTED", result.phases)
        self.assertNotIn("BACKEND_PREPARED", result.phases)
        self.assert_offline_only(result)

    def test_gxf_length_rejection_happens_before_parser(self):
        result = simulate_transition(
            SyntheticScenario("bad-gxf", gxf_message_size=0x40,
                              empty_command_header=False)
        )
        self.assertEqual(result.outcome, "REJECTED_BEFORE_PARSER")
        self.assertIn("GXF_MESSAGE_LAYOUT_REJECTED", result.phases)
        self.assertNotIn("GXF_PARSER_SIMULATED", result.phases)
        self.assert_offline_only(result)

    def test_backend_failure_stops_before_parser_and_requires_release(self):
        result = simulate_transition(
            SyntheticScenario("backend-error", empty_command_header=False,
                              backend_prepare_succeeds=False)
        )
        self.assertEqual(result.outcome, "BACKEND_ERROR")
        self.assertEqual(result.cleanup, "BACKEND_OBJECT_RELEASE_REQUIRED")
        self.assertNotIn("GXF_PARSER_SIMULATED", result.phases)
        self.assert_offline_only(result)

    def test_parser_error_still_completes_model_cleanup(self):
        result = simulate_transition(
            SyntheticScenario("parser-error", empty_command_header=False,
                              parser_accepts=False)
        )
        self.assertEqual(result.outcome, "PARSER_ERROR")
        self.assertEqual(result.cleanup, "SUCCESS")
        self.assertIn("GXF_PARSER_REJECTED", result.phases)
        self.assertIn("CLEANUP_COMPLETE", result.phases)
        self.assert_offline_only(result)

    def test_missing_notification_never_reaches_backend(self):
        result = simulate_transition(
            SyntheticScenario("notification-missing", notification_bound=False)
        )
        self.assertEqual(result.outcome, "REJECTED_BEFORE_BACKEND")
        self.assertEqual(result.rejection, "notification binding absent")
        self.assertNotIn("BACKEND_PREPARATION_STARTED", result.phases)
        self.assert_offline_only(result)

    def test_cleanup_failures_are_visible_and_not_converted_to_success(self):
        release = simulate_transition(
            SyntheticScenario("release-failure", cleanup_release_succeeds=False)
        )
        clear = simulate_transition(
            SyntheticScenario("clear-failure", cleanup_clear_succeeds=False)
        )
        self.assertEqual(release.outcome, "CLEANUP_INCOMPLETE")
        self.assertEqual(clear.outcome, "CLEANUP_INCOMPLETE")
        self.assertNotEqual(release.cleanup, "SUCCESS")
        self.assertNotEqual(clear.cleanup, "SUCCESS")
        self.assert_offline_only(release)
        self.assert_offline_only(clear)


if __name__ == "__main__":
    unittest.main()
