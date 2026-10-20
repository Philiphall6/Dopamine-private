import struct
import unittest
from types import SimpleNamespace

from audit_mdsid_ttbr0_binding import (
    FIRMWARE_ADDRESS_ENCODING,
    FIRMWARE_ADDRESS_SLOT,
    FIRMWARE_SEND_ENCODING,
    FIRMWARE_SEND_SLOT,
    GFX_EXPECTED,
    GXF_DISPATCH_ANCHOR,
    GXF_DISPATCH_TABLE,
    GXF_MDSID_HANDLER,
    GXF_MDSID_PACKET_TYPE,
    KERNEL_EXPECTED,
    verify_binding,
)


class FakeKernel:
    def __init__(self, expected=None, slots=None):
        expected = KERNEL_EXPECTED if expected is None else expected
        self.instructions = {
            address: SimpleNamespace(mnemonic=mnemonic, op_str=operands)
            for address, (mnemonic, operands) in expected.items()
        }
        self.slots = {
            FIRMWARE_ADDRESS_SLOT: FIRMWARE_ADDRESS_ENCODING,
            FIRMWARE_SEND_SLOT: FIRMWARE_SEND_ENCODING,
        }
        if slots:
            self.slots.update(slots)

    def instruction_at(self, address):
        return self.instructions.get(address)

    def read_u64(self, address):
        return self.slots.get(address)


class FakeGfx:
    def __init__(self, target=GXF_MDSID_HANDLER):
        index = GXF_MDSID_PACKET_TYPE - 4
        self.address = GXF_DISPATCH_TABLE + index * 4
        self.value = struct.pack("<i", target - GXF_DISPATCH_ANCHOR)

    def read(self, address, size):
        if (address, size) != (self.address, 4):
            raise ValueError("unexpected read")
        return self.value


def gfx_instructions(expected=None):
    expected = GFX_EXPECTED if expected is None else expected
    return [
        {
            "address": address,
            "size": 4,
            "mnemonic": mnemonic,
            "op_str": operands,
        }
        for address, (mnemonic, operands) in sorted(expected.items())
    ]


class MdsidTTBR0BindingTests(unittest.TestCase):
    def test_exact_route_closes_binding_blocker(self):
        result = verify_binding(FakeKernel(), FakeGfx(), gfx_instructions())
        self.assertEqual(result["closed_blocker"], "MDSID_TTBR0_BINDING")
        self.assertEqual(
            result["address_space_binding"]["ttbr0_window"], "0x0..0x1ffffff"
        )
        self.assertEqual(result["gfx_route"]["terminal_effect"], "str w23, [x22]")

    def test_changed_dispatch_target_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_binding(
                FakeKernel(),
                FakeGfx(GXF_MDSID_HANDLER + 4),
                gfx_instructions(),
            )

    def test_changed_terminal_store_is_rejected(self):
        changed = dict(GFX_EXPECTED)
        changed[0xFFFFFF80000046D4] = ("str", "w23, [x22, #4]")
        with self.assertRaises(ValueError):
            verify_binding(FakeKernel(), FakeGfx(), gfx_instructions(changed))

    def test_changed_identity_callback_is_rejected(self):
        changed = dict(KERNEL_EXPECTED)
        changed[0xFFFFFFF008841D70] = ("add", "x0, x1, #4")
        with self.assertRaises(ValueError):
            verify_binding(FakeKernel(changed), FakeGfx(), gfx_instructions())

    def test_changed_firmware_send_slot_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_binding(
                FakeKernel(slots={FIRMWARE_SEND_SLOT: FIRMWARE_SEND_ENCODING ^ 1}),
                FakeGfx(),
                gfx_instructions(),
            )


if __name__ == "__main__":
    unittest.main()
