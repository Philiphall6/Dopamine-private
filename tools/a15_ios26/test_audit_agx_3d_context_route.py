import struct
import unittest
from types import SimpleNamespace

from audit_agx_3d_context_route import (
    AGX_EXPECTED,
    AGX_REMOVAL_EXPECTED,
    COMMAND_SIZE_OFFSET,
    CONTEXT_SLOT_ENCODING,
    CONTEXT_SLOT_OFFSET,
    CONTEXT_SLOT_TARGET,
    DESCRIPTOR_VTABLE,
    IOGPU_EXPECTED,
    KERNEL_EXPECTED,
    KERNEL_REMOVAL_EXPECTED,
    PACKET_SENTINEL_OFFSET,
    PACKET_SIZE,
    PROTECTED_AGX_EXPECTED,
    RESOURCE_FREE_SENTINEL,
    SPTM_EXPECTED,
    SPTM_REMOVAL_EXPECTED,
    build_minimal_packet,
    validate_minimal_packet,
    verify_protected_registration,
    verify_protected_removal,
    verify_route,
)


class FakeImage:
    def __init__(self, instructions, encoding=CONTEXT_SLOT_ENCODING):
        self.instructions = dict(instructions)
        self.encoding = encoding

    def instruction_at(self, address):
        mnemonic, operands = self.instructions[address]
        return SimpleNamespace(mnemonic=mnemonic, op_str=operands)

    def read_u64(self, address):
        if address == DESCRIPTOR_VTABLE + CONTEXT_SLOT_OFFSET:
            return self.encoding
        return None


class MinimalPacketTests(unittest.TestCase):
    def test_exact_minimal_packet(self):
        packet = build_minimal_packet()
        report = validate_minimal_packet(packet)
        self.assertEqual(len(packet), PACKET_SIZE)
        self.assertEqual(
            struct.unpack_from("<I", packet, PACKET_SENTINEL_OFFSET)[0],
            RESOURCE_FREE_SENTINEL,
        )
        self.assertEqual(report["resource_free_sentinel_offset"], "0x450")

    def test_wrong_size_field_is_rejected(self):
        packet = bytearray(build_minimal_packet())
        struct.pack_into("<I", packet, COMMAND_SIZE_OFFSET, PACKET_SIZE + 4)
        with self.assertRaises(ValueError):
            validate_minimal_packet(bytes(packet))

    def test_unexpected_nonzero_byte_is_rejected(self):
        packet = bytearray(build_minimal_packet())
        packet[0x200] = 1
        with self.assertRaises(ValueError):
            validate_minimal_packet(bytes(packet))


class StaticRouteTests(unittest.TestCase):
    def test_exact_route(self):
        result = verify_route(FakeImage(AGX_EXPECTED), FakeImage(IOGPU_EXPECTED))
        self.assertEqual(
            result["lifecycle"]["context_slot_target"],
            f"{CONTEXT_SLOT_TARGET:#x}",
        )

    def test_changed_sentinel_gate_is_rejected(self):
        changed = dict(AGX_EXPECTED)
        changed[0xfffffff008867ef8] = ("cmp", "w8, #-1")
        with self.assertRaises(ValueError):
            verify_route(FakeImage(changed), FakeImage(IOGPU_EXPECTED))

    def test_changed_context_slot_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_route(
                FakeImage(AGX_EXPECTED, CONTEXT_SLOT_ENCODING ^ 1),
                FakeImage(IOGPU_EXPECTED),
            )

    def test_exact_protected_registration(self):
        result = verify_protected_registration(
            FakeImage(PROTECTED_AGX_EXPECTED),
            FakeImage(KERNEL_EXPECTED),
            FakeImage(SPTM_EXPECTED),
        )
        self.assertEqual(result["protected_stub"], "table=7 entry=10")
        self.assertFalse(result["packet_controls_context_id"])
        self.assertFalse(result["packet_controls_translation_roots"])

    def test_changed_sptm_limit_is_rejected(self):
        changed = dict(SPTM_EXPECTED)
        changed[0xfffffff0270a00c4] = ("cmp", "w8, #0x80")
        with self.assertRaises(ValueError):
            verify_protected_registration(
                FakeImage(PROTECTED_AGX_EXPECTED),
                FakeImage(KERNEL_EXPECTED),
                FakeImage(changed),
            )

    def test_exact_protected_removal(self):
        result = verify_protected_removal(
            FakeImage(AGX_REMOVAL_EXPECTED),
            FakeImage(KERNEL_REMOVAL_EXPECTED),
            FakeImage(SPTM_REMOVAL_EXPECTED),
        )
        self.assertTrue(result["allocation_and_release_share_lock"])
        self.assertTrue(result["remove_precedes_free_id_push"])
        self.assertFalse(result["early_reuse_mismatch"])

    def test_changed_release_order_anchor_is_rejected(self):
        changed = dict(AGX_REMOVAL_EXPECTED)
        changed[0xfffffff0088672f4] = ("nop", "")
        with self.assertRaises(ValueError):
            verify_protected_removal(
                FakeImage(changed),
                FakeImage(KERNEL_REMOVAL_EXPECTED),
                FakeImage(SPTM_REMOVAL_EXPECTED),
            )

    def test_changed_sptm_remove_id_source_is_rejected(self):
        changed = dict(SPTM_REMOVAL_EXPECTED)
        changed[0xfffffff02709fad0] = ("ldrh", "w20, [x1, #0x18]")
        with self.assertRaises(ValueError):
            verify_protected_removal(
                FakeImage(AGX_REMOVAL_EXPECTED),
                FakeImage(KERNEL_REMOVAL_EXPECTED),
                FakeImage(changed),
            )


if __name__ == "__main__":
    unittest.main()
