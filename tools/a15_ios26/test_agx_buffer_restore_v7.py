import hashlib
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Application" / "Dopamine" / "Exploits" / "Titan" / "exploit" / "titan.m").read_text(encoding="utf-8")
BUFFER_SIZE = 0x4000
WINDOW_OFFSET = 0x100
WINDOW_SIZE = 0x20


@dataclass
class RestoreModel:
    value: bytearray
    baseline: bytes | None
    original: bytes | None
    cleanup_done: bool = False

    def restore_window(self):
        if len(self.value) != BUFFER_SIZE or self.baseline is None or self.original is None:
            return False
        if len(self.original) != WINDOW_SIZE:
            return False
        self.value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE] = self.original
        return bytes(self.value) == self.baseline

    def cleanup(self):
        if self.cleanup_done:
            return False
        self.cleanup_done = True
        return self.restore_window()


class TestAGXBufferRestoreV7(unittest.TestCase):
    def test_mutation_restores_exact_baseline_digest(self):
        baseline = bytes(BUFFER_SIZE)
        value = bytearray(baseline)
        original = bytes(value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE])
        value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE] = bytes([0xA5] * WINDOW_SIZE)
        model = RestoreModel(value, baseline, original)

        self.assertEqual(sum(byte != 0 for byte in value), WINDOW_SIZE)
        self.assertTrue(model.restore_window())
        self.assertEqual(hashlib.sha256(value).digest(), hashlib.sha256(baseline).digest())
        self.assertEqual(sum(byte != 0 for byte in value), 0)

    def test_following_observation_sees_no_additional_change(self):
        baseline = bytes(BUFFER_SIZE)
        value = bytearray(baseline)
        original = bytes(value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE])
        value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE] = bytes([0xA5] * WINDOW_SIZE)
        model = RestoreModel(value, baseline, original)

        self.assertTrue(model.restore_window())
        after_restore = bytes(value)
        self.assertEqual(after_restore, baseline)
        self.assertEqual(bytes(value), after_restore)

    def test_failure_does_not_overwrite_outside_window(self):
        baseline = bytes(BUFFER_SIZE)
        value = bytearray(baseline)
        original = bytes(value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE])
        value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE] = bytes([0xA5] * WINDOW_SIZE)
        value[0x200] = 1
        model = RestoreModel(value, baseline, original)

        self.assertFalse(model.restore_window())
        self.assertEqual(value[0x200], 1)
        self.assertEqual(value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE], original)

    def test_invalid_restore_inputs_are_rejected(self):
        baseline = bytes(BUFFER_SIZE)
        self.assertFalse(RestoreModel(bytearray(BUFFER_SIZE - 1), baseline, bytes(WINDOW_SIZE)).restore_window())
        self.assertFalse(RestoreModel(bytearray(BUFFER_SIZE), None, bytes(WINDOW_SIZE)).restore_window())
        self.assertFalse(RestoreModel(bytearray(BUFFER_SIZE), baseline, bytes(WINDOW_SIZE - 1)).restore_window())

    def test_cleanup_is_idempotent(self):
        baseline = bytes(BUFFER_SIZE)
        value = bytearray(baseline)
        original = bytes(value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE])
        value[WINDOW_OFFSET:WINDOW_OFFSET + WINDOW_SIZE] = bytes([0xA5] * WINDOW_SIZE)
        model = RestoreModel(value, baseline, original)

        self.assertTrue(model.cleanup())
        self.assertFalse(model.cleanup())
        self.assertEqual(bytes(value), baseline)


class TestAGXBufferRestoreV7Source(unittest.TestCase):
    def test_restore_order_and_selector_guard_are_explicit(self):
        restore = SOURCE.index('titan.shared-alias.restore-before-preflight')
        queue = SOURCE.index('titan_probe_owned_agx_queue', restore)
        guard = SOURCE.index('#define TITAN_DISABLE_SELECTOR_25_FOR_BUFFER_RESTORE_VALIDATION 1')
        else_guard = SOURCE.index('#else', guard)
        selector_call = SOURCE.index('titan_probe_zero_packet_once(connection', else_guard)
        self.assertLess(restore, queue)
        self.assertLess(guard, else_guard)
        self.assertLess(else_guard, selector_call)
        self.assertLess(restore, SOURCE.index('@"ALIAS_AFTER_RESTORE"', restore))
        self.assertIn('TITAN_DISABLE_SELECTOR_25_FOR_BUFFER_RESTORE_VALIDATION', SOURCE)

    def test_restore_contract_checks_baseline_and_cleanup(self):
        for marker in (
            'bufferTracker->hasInitial',
            'baseline-match=',
            'all-zero=',
            '@"ALIAS_AFTER_RESTORE"',
            'restore preconditions unavailable',
            'duplicate cleanup suppressed',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, SOURCE)


if __name__ == "__main__":
    unittest.main()
