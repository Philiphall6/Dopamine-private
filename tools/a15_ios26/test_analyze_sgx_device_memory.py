import struct
import unittest

from analyze_sgx_device_memory import intersection, io_ranges, resolve_reg, u64_pairs


class SgxDeviceMemoryTests(unittest.TestCase):
    def test_resolve_two_windows(self):
        ranges = [(0, 0x200000000, 0x100000000)]
        self.assertEqual(
            resolve_reg([(0x4000000, 0x4000000), (0x4D00000, 0x20000)], ranges),
            [(0x204000000, 0x4000000), (0x204D00000, 0x20000)],
        )

    def test_reject_reg_crossing_parent_window(self):
        with self.assertRaises(ValueError):
            resolve_reg([(0xFFF, 2)], [(0, 0x200000000, 0x1000)])

    def test_reject_ambiguous_parent_windows(self):
        with self.assertRaises(ValueError):
            resolve_reg([(0x10, 1)], [(0, 0x1000, 0x100), (0, 0x2000, 0x100)])

    def test_decode_fourcc_and_intersection(self):
        record = struct.pack("<QQII", 0x206000000, 0x50000, 0x4007, 0x44454E59)
        self.assertEqual(io_ranges(record), [(0x206000000, 0x50000, 0x4007, "DENY")])
        self.assertEqual(intersection((0x204000000, 0x4000000), (0x206000000, 0x50000)), (0x206000000, 0x50000))
        self.assertIsNone(intersection((0x204D00000, 0x20000), (0x206000000, 0x50000)))

    def test_reject_incomplete_data(self):
        with self.assertRaises(ValueError):
            u64_pairs(b"\0" * 15, "reg")
        with self.assertRaises(ValueError):
            io_ranges(b"\0" * 23)


if __name__ == "__main__":
    unittest.main()
