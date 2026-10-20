import hashlib
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "Application" / "Dopamine" / "Exploits" / "Titan" / "exploit" / "titan.m"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")
BUFFER_SIZE = 0x4000


@dataclass
class SnapshotTracker:
    previous: bytes | None = None

    def capture(self, value, address=0x100000000):
        if not isinstance(value, (bytes, bytearray)) or len(value) != BUFFER_SIZE:
            return {"result": "NOT_TESTED", "reason": "invalid-or-unavailable-buffer"}
        if not address or address >= 0x0000800000000000:
            return {"result": "NOT_TESTED", "reason": "invalid-or-unavailable-buffer"}

        current = bytes(value)
        digest = hashlib.sha256(current).hexdigest()
        nonzero = [index for index, byte in enumerate(current) if byte]
        changed = []
        if self.previous is not None:
            changed = [
                index
                for index, (before, after) in enumerate(zip(self.previous, current))
                if before != after
            ]
        result = {
            "result": "PASS",
            "sha256": digest,
            "nonzero_count": len(nonzero),
            "first_nonzero": nonzero[0] if nonzero else None,
            "changed_bytes": len(changed),
            "first_changed": changed[0] if changed else None,
            "address_token": hashlib.sha256(address.to_bytes(8, "little")).hexdigest()[:16],
        }
        self.previous = current
        return result


class TestAGXBufferTrackingV6(unittest.TestCase):
    def test_zero_buffer(self):
        snapshot = SnapshotTracker().capture(bytes(BUFFER_SIZE))
        self.assertEqual(snapshot["result"], "PASS")
        self.assertEqual(snapshot["sha256"], hashlib.sha256(bytes(BUFFER_SIZE)).hexdigest())
        self.assertEqual(snapshot["nonzero_count"], 0)
        self.assertIsNone(snapshot["first_nonzero"])
        self.assertEqual(snapshot["changed_bytes"], 0)
        self.assertIsNone(snapshot["first_changed"])

    def test_byte_at_0x100_is_visible(self):
        value = bytearray(BUFFER_SIZE)
        value[0x100] = 0xA5
        tracker = SnapshotTracker()
        first = tracker.capture(value)
        second = tracker.capture(value)
        self.assertEqual(first["first_nonzero"], 0x100)
        self.assertEqual(first["nonzero_count"], 1)
        self.assertEqual(second["changed_bytes"], 0)
        self.assertEqual(second["first_changed"], None)

    def test_multiple_regions_report_exact_offsets(self):
        value = bytearray(BUFFER_SIZE)
        for offset in (0x100, 0x2000, 0x3FFF):
            value[offset] = 1
        snapshot = SnapshotTracker().capture(value)
        self.assertEqual(snapshot["nonzero_count"], 3)
        self.assertEqual(snapshot["first_nonzero"], 0x100)

    def test_temporary_write_and_restore(self):
        value = bytearray(BUFFER_SIZE)
        tracker = SnapshotTracker()
        baseline = tracker.capture(value)
        original = bytes(value)
        value[0x100:0x120] = bytes([0xA5] * 0x20)
        changed = tracker.capture(value)
        value[0x100:0x120] = original[0x100:0x120]
        restored = tracker.capture(value)
        self.assertEqual(changed["changed_bytes"], 0x20)
        self.assertEqual(changed["first_changed"], 0x100)
        self.assertEqual(restored["sha256"], baseline["sha256"])
        self.assertEqual(restored["changed_bytes"], 0x20)

    def test_identical_snapshots_have_no_changes(self):
        value = bytes(BUFFER_SIZE)
        tracker = SnapshotTracker()
        tracker.capture(value)
        identical = tracker.capture(value)
        self.assertEqual(identical["changed_bytes"], 0)
        self.assertIsNone(identical["first_changed"])

    def test_invalid_or_inaccessible_buffer_is_not_tested(self):
        tracker = SnapshotTracker()
        for value in (None, bytes(BUFFER_SIZE - 1), object()):
            with self.subTest(value_type=type(value).__name__):
                result = tracker.capture(value)
                self.assertEqual(result["result"], "NOT_TESTED")
                self.assertEqual(result["reason"], "invalid-or-unavailable-buffer")
        self.assertIsNone(tracker.previous)

    def test_capture_does_not_mutate_buffer(self):
        value = bytearray(BUFFER_SIZE)
        value[0x100] = 0xA5
        before = bytes(value)
        SnapshotTracker().capture(value)
        self.assertEqual(bytes(value), before)

    def test_address_is_tokenized(self):
        snapshot = SnapshotTracker().capture(bytes(BUFFER_SIZE), address=0x12345000)
        self.assertEqual(len(snapshot["address_token"]), 16)
        self.assertNotIn("12345000", snapshot["address_token"])


class TestAGXBufferTrackingV6Source(unittest.TestCase):
    def test_snapshot_contract_and_checkpoints_are_present(self):
        for marker in (
            "CommonCrypto/CommonDigest.h",
            "struct TitanBufferSnapshotTracker",
            "titan_buffer_address_token",
            "address-token=",
            "sha256=",
            "nonzero-count=",
            "first-nonzero=",
            "changed-bytes=",
            "first-changed=",
            "read-only=yes",
            '@"BUFFER_CREATED"',
            '@"BUFFER_INITIALIZED"',
            '@"ALIAS_BEFORE"',
            '@"ALIAS_AFTER_WRITE"',
            '@"ALIAS_AFTER_RESTORE"',
            '@"QUEUE_BEFORE"',
            '@"QUEUE_AFTER"',
            '@"NOTIFICATION_BEFORE"',
            '@"NOTIFICATION_AFTER"',
            '@"BIND_BEFORE"',
            '@"BIND_AFTER"',
            '@"PREFLIGHT_FINAL"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, SOURCE)

    def test_snapshot_helper_is_passive(self):
        declaration = SOURCE.index("static bool titan_capture_buffer_snapshot")
        start = SOURCE.index("static bool titan_capture_buffer_snapshot", declaration + 1)
        end = SOURCE.index("static bool titan_capture_zero_packet_queue_state", start)
        helper = SOURCE[start:end]
        for forbidden in ("IOConnectCall", "IOServiceOpen", "selector=25", "address=0x%llx"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, helper)
        self.assertEqual(SOURCE.count("IOConnectCallMethod(connection, 25"), 1)


if __name__ == "__main__":
    unittest.main()
