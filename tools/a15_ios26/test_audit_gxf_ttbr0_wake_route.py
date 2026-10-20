import unittest
from types import SimpleNamespace

from audit_gxf_ttbr0_wake_route import (
    IOS26_EXPECTED,
    IOS26_SYMBOLS,
    IOS27_EXPECTED,
    IOS27_SYMBOLS,
    LOCAL_COMMANDS,
    verify_ios26_route,
    verify_ios27_delta,
)


def instructions(expected):
    return [
        {
            "address": address,
            "size": 4,
            "mnemonic": mnemonic,
            "op_str": operands,
        }
        for address, (mnemonic, operands) in sorted(expected.items())
    ]


def producers(forwarder, callsite):
    return {
        "local_constant_commands": list(LOCAL_COMMANDS),
        "command_0x20_local_producer_observed": False,
        "command_3_local_producer_observed": True,
        "submit_wrapper_exact_pointer_references": [],
        "forwarding_wrappers": [
            {
                "address": forwarder,
                "exact_pointer_references": [],
                "callsites": [{"command": 3, "callsite": callsite}],
            }
        ],
    }


class GxfTTBR0WakeRouteTests(unittest.TestCase):
    def test_exact_ios26_route(self):
        result = verify_ios26_route(
            SimpleNamespace(symbols=dict(IOS26_SYMBOLS)),
            instructions(IOS26_EXPECTED),
            producers(0xFFFFFF8000044560, 0xFFFFFF8000040EE8),
        )
        self.assertEqual(result["authorized_wake"]["translation_register"], "TTBR0_EL1")
        self.assertEqual(result["low_root_geometry"]["table_size"], "0x4000")
        self.assertEqual(result["low_root_geometry"]["levels_for_25_bit_low_va"], 1)

    def test_changed_ios26_root_mask_is_rejected(self):
        changed = dict(IOS26_EXPECTED)
        changed[0xFFFFFF800004874C] = ("and", "x1, x8, #0xffffffff000")
        with self.assertRaises(ValueError):
            verify_ios26_route(
                SimpleNamespace(symbols=dict(IOS26_SYMBOLS)),
                instructions(changed),
                producers(0xFFFFFF8000044560, 0xFFFFFF8000040EE8),
            )

    def test_local_command_0x20_producer_is_rejected(self):
        report = producers(0xFFFFFF8000044560, 0xFFFFFF8000040EE8)
        report["local_constant_commands"] = sorted(LOCAL_COMMANDS + [0x20])
        report["command_0x20_local_producer_observed"] = True
        with self.assertRaises(ValueError):
            verify_ios26_route(
                SimpleNamespace(symbols=dict(IOS26_SYMBOLS)),
                instructions(IOS26_EXPECTED),
                report,
            )

    def test_exact_ios27_removal(self):
        result = verify_ios27_delta(
            SimpleNamespace(symbols=dict(IOS27_SYMBOLS)),
            instructions(IOS27_EXPECTED),
            producers(0xFFFFFF800004797C, 0xFFFFFF800004407C),
        )
        self.assertFalse(result["command_0x20_handler_present"])
        self.assertFalse(result["wake_calls_low_level_ttbr_switch"])
        self.assertTrue(result["generic_low_level_ttbr_switch_still_present"])

    def test_ios27_by_context_symbol_is_rejected(self):
        symbols = dict(IOS27_SYMBOLS)
        symbols["__rtk_mmu_switch_region_base_by_contextID"] = 0x1234
        with self.assertRaises(ValueError):
            verify_ios27_delta(
                SimpleNamespace(symbols=symbols),
                instructions(IOS27_EXPECTED),
                producers(0xFFFFFF800004797C, 0xFFFFFF800004407C),
            )


if __name__ == "__main__":
    unittest.main()
