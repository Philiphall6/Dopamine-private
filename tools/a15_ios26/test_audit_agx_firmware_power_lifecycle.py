import unittest
from types import SimpleNamespace

from audit_agx_firmware_power_lifecycle import (
    AGX_EXPECTED,
    FIRMWARE_SLOTS,
    FIRMWARE_VTABLE,
    RTBUDDY_EXPECTED,
    verify_power_lifecycle,
)


class FakeImage:
    def __init__(self, instructions, slots=None):
        self.instructions = instructions
        self.slots = slots or {}

    def instruction_at(self, address):
        value = self.instructions.get(address)
        if value is None:
            return None
        return SimpleNamespace(mnemonic=value[0], op_str=value[1])

    def read_u64(self, address):
        return self.slots.get(address)


def slot_map():
    return {
        FIRMWARE_VTABLE + offset: encoding
        for offset, (encoding, _target) in FIRMWARE_SLOTS.items()
    }


class AGXFirmwarePowerLifecycleTests(unittest.TestCase):
    def test_exact_lifecycle(self):
        result = verify_power_lifecycle(
            FakeImage(dict(RTBUDDY_EXPECTED)),
            FakeImage(dict(AGX_EXPECTED), slot_map()),
        )
        self.assertEqual(result["firmware_object_offset"], "RTBuddy+0x160")
        self.assertFalse(result["direct_user_client_queue_registry_access"])
        self.assertEqual(
            result["firmware_slots"]["+0xa08"], "0xfffffff00882e520"
        )

    def test_changed_transition_slot_is_rejected(self):
        changed = dict(RTBUDDY_EXPECTED)
        changed[0xfffffff0087d45c4] = ("mov", "x17, #0xa10")
        with self.assertRaises(ValueError):
            verify_power_lifecycle(
                FakeImage(changed), FakeImage(dict(AGX_EXPECTED), slot_map())
            )

    def test_changed_runtime_vtable_slot_is_rejected(self):
        slots = slot_map()
        slots[FIRMWARE_VTABLE + 0xa08] = FIRMWARE_SLOTS[0xa10][0]
        with self.assertRaises(ValueError):
            verify_power_lifecycle(
                FakeImage(dict(RTBUDDY_EXPECTED)),
                FakeImage(dict(AGX_EXPECTED), slots),
            )

    def test_changed_external_state_store_is_rejected(self):
        changed = dict(AGX_EXPECTED)
        changed[0xfffffff00882e8b8] = ("strb", "w1, [x19, #0x599]")
        with self.assertRaises(ValueError):
            verify_power_lifecycle(
                FakeImage(dict(RTBUDDY_EXPECTED)), FakeImage(changed, slot_map())
            )


if __name__ == "__main__":
    unittest.main()
