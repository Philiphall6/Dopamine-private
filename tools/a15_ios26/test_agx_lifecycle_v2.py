import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "Application" / "Dopamine" / "Exploits" / "Titan" / "exploit" / "titan.m"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


@dataclass
class CleanupModel:
    """Small offline contract model for the shared-alias cleanup helper."""

    service_held: bool = False
    connection_open: bool = False
    page_locked: bool = False
    cleanup_done: bool = False
    unlock_calls: int = 0
    close_calls: int = 0
    release_calls: int = 0

    def cleanup(self, *, unlock_ok=True, close_ok=True, release_ok=True):
        if self.cleanup_done:
            return True
        self.cleanup_done = True
        failed = False

        if self.page_locked:
            self.unlock_calls += 1
            if unlock_ok:
                self.page_locked = False
            else:
                failed = True

        if self.connection_open:
            self.close_calls += 1
            if close_ok:
                self.connection_open = False
            else:
                failed = True

        if self.service_held:
            self.release_calls += 1
            if release_ok:
                self.service_held = False
            else:
                failed = True

        return not failed


class TestAGXLifecycleV2Source(unittest.TestCase):
    def test_structured_event_contract_is_present(self):
        for marker in (
            "session_id",
            "timestamp_monotonic_ns",
            "operation",
            "return_code",
            "duration_ns",
            "resource_state",
            "close_reason",
            "titan_checkpoint_operation",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, SOURCE)

    def test_lifecycle_has_explicit_unverified_states(self):
        self.assertIn("TitanObservationNotTested", SOURCE)
        self.assertIn('power-assertion-requested", @"NOT_TESTED"', SOURCE)
        self.assertIn('power-assertion-confirmed", @"NOT_TESTED"', SOURCE)
        self.assertIn('firmware-context", @"NOT_TESTED"', SOURCE)
        self.assertNotRegex(
            SOURCE,
            r"powerAssertion(?:Requested|Confirmed)\s*=\s*TitanObservationYes",
        )
        self.assertIn("ready=1 is not proof of persistence", SOURCE)

    def test_only_empty_record_boundary_is_present(self):
        self.assertEqual(SOURCE.count("IOConnectCallMethod(connection, 25"), 1)
        self.assertIn('selector-25.empty-record', SOURCE)
        self.assertIn('kIOS2601AGXSubmitRecordSize', SOURCE)
        self.assertIn('titan_wait_for_zero_packet_settle', SOURCE)

    def test_cleanup_is_centralized_and_guarded(self):
        self.assertEqual(
            SOURCE.count("titan_cleanup_shared_alias_resources(&resources, result, &lifecycle);"),
            1,
        )
        self.assertIn("if (resources->cleanupDone)", SOURCE)
        self.assertIn("duplicate cleanup suppressed", SOURCE)
        self.assertIn("@\"IOServiceClose\"", SOURCE)
        self.assertIn("@\"IOObjectRelease\"", SOURCE)


class TestAGXLifecycleV2CleanupModel(unittest.TestCase):
    def test_normal_cleanup_releases_each_owned_resource_once(self):
        state = CleanupModel(service_held=True, connection_open=True, page_locked=True)

        self.assertTrue(state.cleanup())
        self.assertEqual((state.unlock_calls, state.close_calls, state.release_calls), (1, 1, 1))
        self.assertFalse(state.page_locked or state.connection_open or state.service_held)
        self.assertTrue(state.cleanup())
        self.assertEqual((state.unlock_calls, state.close_calls, state.release_calls), (1, 1, 1))

    def test_partial_failures_continue_and_remain_visible(self):
        state = CleanupModel(service_held=True, connection_open=True, page_locked=True)

        self.assertFalse(state.cleanup(unlock_ok=False, close_ok=False, release_ok=False))
        self.assertEqual((state.unlock_calls, state.close_calls, state.release_calls), (1, 1, 1))
        self.assertTrue(state.page_locked and state.connection_open and state.service_held)

        # The helper is idempotent: a second exit path cannot double-release.
        self.assertTrue(state.cleanup())
        self.assertEqual((state.unlock_calls, state.close_calls, state.release_calls), (1, 1, 1))

    def test_mixed_failure_releases_successful_steps(self):
        state = CleanupModel(service_held=True, connection_open=True, page_locked=True)

        self.assertFalse(state.cleanup(unlock_ok=True, close_ok=False, release_ok=True))
        self.assertEqual((state.unlock_calls, state.close_calls, state.release_calls), (1, 1, 1))
        self.assertFalse(state.page_locked)
        self.assertTrue(state.connection_open)
        self.assertFalse(state.service_held)


if __name__ == "__main__":
    unittest.main()
