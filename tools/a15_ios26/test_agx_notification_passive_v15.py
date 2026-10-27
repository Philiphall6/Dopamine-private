import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TITAN = (
    ROOT
    / "Application"
    / "Dopamine"
    / "Exploits"
    / "Titan"
    / "exploit"
    / "titan.m"
).read_text()


def body_between(source: str, start: str, end: str) -> str:
    start_index = source.rfind(start)
    end_index = source.find(end, start_index + len(start))
    if start_index < 0 or end_index < 0:
        raise AssertionError(f"missing source boundary: {start!r} -> {end!r}")
    return source[start_index:end_index]


class TestAGXNotificationPassiveV15(unittest.TestCase):
    def test_snapshot_is_bounded_and_revalidates_mapping(self):
        body = body_between(
            TITAN,
            "static bool titan_capture_notification_snapshot(",
            "static int titan_probe_metal_positive_control(",
        )
        for marker in (
            "vm_region_64",
            "size == kIOS2601AGXNotificationMapBytes",
            "regionStart + regionSize >= address + size",
            "(regionInfo.protection & VM_PROT_READ) != 0",
            "memcpy(current, (const void *)(uintptr_t)address, size)",
            "read-only=yes",
            "changed-ranges=%@",
        ):
            self.assertIn(marker, body)

    def test_notification_observation_points_are_ordered(self):
        binding = body_between(
            TITAN,
            "static int titan_probe_notification_binding(",
            "struct TitanZeroPacketQueueState",
        )
        points = (
            '@"AFTER_CREATE"',
            'IOConnectCallScalarMethod(connection, 24,',
            '@"AFTER_BIND"',
            "usleep(kIOS2601AGXPostCallObservationPollUs)",
            '@"AFTER_DELAY"',
        )
        positions = [binding.find(point) for point in points]
        self.assertTrue(all(position >= 0 for position in positions))
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("IOConnectCallMethod(connection, 25", binding)

    def test_cleanup_captures_before_release(self):
        cleanup = body_between(
            TITAN,
            "static int titan_cleanup_shared_alias_resources(",
            "static int titan_probe_shared_alias(void)",
        )
        capture = cleanup.find('@"BEFORE_RELEASE"')
        unlock = cleanup.find("munlock(")
        close = cleanup.find("IOServiceClose(resources->connection)")
        self.assertGreaterEqual(capture, 0)
        self.assertLess(capture, unlock)
        self.assertLess(capture, close)

    def test_metal_control_is_independent_and_positive_only(self):
        body = body_between(
            TITAN,
            "static int titan_probe_metal_positive_control(",
            "static bool titan_capture_zero_packet_queue_state(",
        )
        for marker in (
            "MTLCreateSystemDefaultDevice",
            "newCommandQueue",
            "newBufferWithBytes",
            "newBufferWithLength",
            "blitCommandEncoder",
            "[commandBuffer commit]",
            "[commandBuffer waitUntilCompleted]",
            "MTLCommandBufferStatusCompleted",
            "contents-match",
            "not MDSID/GXF evidence",
        ):
            self.assertIn(marker, body)
        self.assertNotIn("IOConnectCall", body)
        self.assertNotIn("IOServiceOpen", body)

    def test_selector_25_remains_guarded(self):
        self.assertIn(
            "#define TITAN_DISABLE_SELECTOR_25_FOR_BUFFER_RESTORE_VALIDATION 1",
            TITAN,
        )
        shared = body_between(
            TITAN,
            "static int titan_probe_shared_alias(void)",
            "static int titan_resolve_ios26_iorvbar_mapping(void)",
        )
        self.assertNotIn("IOConnectCallMethod(connection, 25", shared)


if __name__ == "__main__":
    unittest.main()
