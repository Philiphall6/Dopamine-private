import struct
import unittest

from audit_rtb_power_command3_route import (
    GFX_CLASS_OFFSETS,
    GFX_CLASS_TABLE,
    GFX_EXPECTED,
    HOST_EXPECTED,
    verify_gfx_power_ingress,
    verify_host_producer,
)


class FakeHostImage:
    def __init__(self, instructions):
        self.instructions = instructions

    def instruction_at(self, address):
        value = self.instructions.get(address)
        if value is None:
            return None
        return type("Instruction", (), {"mnemonic": value[0], "op_str": value[1]})()


class FakeGfxImage:
    def __init__(self, offsets=GFX_CLASS_OFFSETS):
        self.offsets = offsets

    def read(self, address, size):
        if address != GFX_CLASS_TABLE or size != 64:
            raise ValueError("unexpected read")
        return struct.pack("<16i", *self.offsets)


def gfx_instructions(expected):
    return [
        {
            "address": address,
            "size": 4,
            "mnemonic": mnemonic,
            "op_str": operands,
        }
        for address, (mnemonic, operands) in sorted(expected.items())
    ]


class RTBPowerCommand3RouteTests(unittest.TestCase):
    def test_exact_host_producer(self):
        result = verify_host_producer(FakeHostImage(dict(HOST_EXPECTED)))
        self.assertEqual(result["rtkit_class"], "0xb")
        self.assertEqual(result["payloads"]["0"], "0x201")
        self.assertEqual(result["message_count"], 1)

    def test_changed_host_class_constant_is_rejected(self):
        changed = dict(HOST_EXPECTED)
        changed[0xfffffff00a51fea4] = ("mov", "x9, #0xa0000000000000")
        with self.assertRaises(ValueError):
            verify_host_producer(FakeHostImage(changed))

    def test_exact_gfx_ingress(self):
        result = verify_gfx_power_ingress(
            FakeGfxImage(), gfx_instructions(GFX_EXPECTED)
        )
        self.assertEqual(result["class_b_target"], "0xffffff800003e404")
        self.assertEqual(result["payload_state_map"]["0x201"], 8)

    def test_changed_class_b_jump_is_rejected(self):
        changed = list(GFX_CLASS_OFFSETS)
        changed[0xB] = 0x74
        with self.assertRaises(ValueError):
            verify_gfx_power_ingress(
                FakeGfxImage(tuple(changed)), gfx_instructions(GFX_EXPECTED)
            )

    def test_changed_state_mapping_is_rejected(self):
        changed = dict(GFX_EXPECTED)
        changed[0xffffff800003e768] = ("mov", "w8, #7")
        with self.assertRaises(ValueError):
            verify_gfx_power_ingress(FakeGfxImage(), gfx_instructions(changed))

    def test_changed_command3_call_is_rejected(self):
        changed = dict(GFX_EXPECTED)
        changed[0xffffff8000040ee8] = ("bl", "#0xffffff800004456c")
        with self.assertRaises(ValueError):
            verify_gfx_power_ingress(FakeGfxImage(), gfx_instructions(changed))


if __name__ == "__main__":
    unittest.main()
