import unittest
from types import SimpleNamespace

from audit_iouat_method_surface import (
    BEE7_DISPATCH_EXPECTED,
    BEE7_PAPT_HELPER_EXPECTED,
    BEE7_VTABLE_ENCODING,
    BEE7_VTABLE_SLOT,
    BEE6_DISPATCH_EXPECTED,
    CALLER_EXPECTED,
    METHOD_STRINGS,
    PROTECTED_STUB_EXPECTED,
    SPTM_BEE6_EXPECTED,
    verify_kernel_surface,
    verify_sptm_prepare_fw_unmap,
)


class FakeImage:
    def __init__(self, instructions, strings=None, slots=None):
        self.instructions = dict(instructions)
        self.strings = dict(METHOD_STRINGS if strings is None else strings)
        self.slots = {BEE7_VTABLE_SLOT: BEE7_VTABLE_ENCODING}
        if slots:
            self.slots.update(slots)

    def instruction_at(self, address):
        mnemonic, operands = self.instructions[address]
        return SimpleNamespace(mnemonic=mnemonic, op_str=operands)

    def find_string(self, value):
        address = self.strings.get(value)
        return [] if address is None else [address]

    def read_u64(self, address):
        return self.slots.get(address)


class IOUATMethodSurfaceTests(unittest.TestCase):
    def test_exact_kernel_surface(self):
        instructions = {
            **CALLER_EXPECTED,
            **BEE6_DISPATCH_EXPECTED,
            **BEE7_DISPATCH_EXPECTED,
            **BEE7_PAPT_HELPER_EXPECTED,
            **PROTECTED_STUB_EXPECTED,
        }
        result = verify_kernel_surface(FakeImage(instructions))
        self.assertEqual([entry["method"] for entry in result["methods"]], [
            "0xbee2", "0xbee3", "0xbee4", "0xbee5", "0xbee6", "0xbee7",
        ])
        self.assertEqual(result["bee6_dispatch"]["length_to_pages"], "length >> 14")
        self.assertEqual(
            result["bee7_root_mirror"]["classification"],
            "ACTIVE_ROOT_DISCOVERY_STATICALLY_CLOSED_RUNTIME_PENDING",
        )
        self.assertTrue(result["bee7_root_mirror"]["root0_uses_receiver_unconditionally"])

    def test_changed_bee6_selector_is_rejected(self):
        instructions = {
            **CALLER_EXPECTED,
            **BEE6_DISPATCH_EXPECTED,
            **BEE7_DISPATCH_EXPECTED,
            **BEE7_PAPT_HELPER_EXPECTED,
            **PROTECTED_STUB_EXPECTED,
        }
        instructions[0xfffffff008761ac0] = ("mov", "w1, #0xbee5")
        with self.assertRaises(ValueError):
            verify_kernel_surface(FakeImage(instructions))

    def test_missing_method_string_is_rejected(self):
        instructions = {
            **CALLER_EXPECTED,
            **BEE6_DISPATCH_EXPECTED,
            **BEE7_DISPATCH_EXPECTED,
            **BEE7_PAPT_HELPER_EXPECTED,
            **PROTECTED_STUB_EXPECTED,
        }
        strings = dict(METHOD_STRINGS)
        del strings["prepareFWUnmap"]
        with self.assertRaises(ValueError):
            verify_kernel_surface(FakeImage(instructions, strings))

    def test_exact_sptm_constraints_close_arbitrary_range(self):
        result = verify_sptm_prepare_fw_unmap(FakeImage(SPTM_BEE6_EXPECTED, {}))
        self.assertEqual(
            result["classification"],
            "CONSTRAINED_EXISTING_MAPPING_OPERATION_NOT_ARBITRARY_PRIMITIVE",
        )
        self.assertTrue(result["capabilities"]["mutates_existing_tracked_mapping"])
        self.assertFalse(result["capabilities"]["accepts_arbitrary_untracked_range"])
        self.assertFalse(result["capabilities"]["controls_physical_target"])

    def test_changed_containment_check_is_rejected(self):
        instructions = dict(SPTM_BEE6_EXPECTED)
        instructions[0xfffffff0270aed3c] = ("b.lo", "#0xfffffff0270aedb4")
        with self.assertRaises(ValueError):
            verify_sptm_prepare_fw_unmap(FakeImage(instructions, {}))

    def test_changed_saved_mapping_source_is_rejected(self):
        instructions = dict(SPTM_BEE6_EXPECTED)
        instructions[0xfffffff0270a1160] = ("ldr", "x19, [x0, #0x28]")
        with self.assertRaises(ValueError):
            verify_sptm_prepare_fw_unmap(FakeImage(instructions, {}))

    def test_changed_bee7_root_offset_is_rejected(self):
        instructions = {
            **CALLER_EXPECTED,
            **BEE6_DISPATCH_EXPECTED,
            **BEE7_DISPATCH_EXPECTED,
            **BEE7_PAPT_HELPER_EXPECTED,
            **PROTECTED_STUB_EXPECTED,
        }
        instructions[0xfffffff0087b2e4c] = ("add", "x9, x9, #0x10")
        with self.assertRaises(ValueError):
            verify_kernel_surface(FakeImage(instructions))

    def test_changed_bee7_vtable_slot_is_rejected(self):
        instructions = {
            **CALLER_EXPECTED,
            **BEE6_DISPATCH_EXPECTED,
            **BEE7_DISPATCH_EXPECTED,
            **BEE7_PAPT_HELPER_EXPECTED,
            **PROTECTED_STUB_EXPECTED,
        }
        with self.assertRaises(ValueError):
            verify_kernel_surface(
                FakeImage(instructions, slots={BEE7_VTABLE_SLOT: 0})
            )


if __name__ == "__main__":
    unittest.main()
