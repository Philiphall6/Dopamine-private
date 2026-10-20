import unittest

from analyze_titan import (
    MappedImage,
    Segment,
    analyze_gxf_context_switch_contract,
    classify_linear_range_guard,
    classify_pacga_chain,
    conditional_branch_target,
    direct_branch_target,
    instruction_window,
    parse_immediate_operand,
    parse_shifted_immediate_operands,
    reconstruct_w_immediate_return,
)


def instruction(address: int, mnemonic: str, op_str: str = "") -> dict:
    return {
        "address": address,
        "size": 4,
        "mnemonic": mnemonic,
        "op_str": op_str,
    }


class GfxSecurityControlTests(unittest.TestCase):
    def test_classifies_comparison_guard(self) -> None:
        following = [
            instruction(0x1000, "ldr", "x2, [sp, #0x340]"),
            instruction(0x1004, "cmp", "x1, x2"),
            instruction(0x1008, "b.ne", "#0x1008"),
        ]
        self.assertEqual(
            classify_pacga_chain(following),
            "comparison_guard_candidate",
        )

    def test_classifies_signature_storage(self) -> None:
        following = [instruction(0x1000, "str", "x1, [x0, #0x340]")]
        self.assertEqual(
            classify_pacga_chain(following),
            "signature_storage_candidate",
        )

    def test_does_not_overclassify_unrelated_control_flow(self) -> None:
        following = [instruction(0x1000, "ret")]
        self.assertEqual(classify_pacga_chain(following), "unclassified")

    def test_instruction_window_is_bounded(self) -> None:
        instructions = [instruction(0x1000 + index * 4, "nop") for index in range(5)]
        self.assertEqual(
            instruction_window(instructions, 0x1008, before=1, after=1),
            ["0x1004: nop", "0x1008: nop", "0x100c: nop"],
        )

    def test_parses_capstone_immediate(self) -> None:
        self.assertEqual(parse_immediate_operand("#0x21"), 0x21)
        self.assertEqual(parse_immediate_operand("-1"), -1)
        self.assertIsNone(parse_immediate_operand("x8"))
        self.assertEqual(
            parse_shifted_immediate_operands(["#8", "lsl #12"]),
            0x8000,
        )

    def test_resolves_only_direct_branch_targets(self) -> None:
        self.assertEqual(
            direct_branch_target(instruction(0x1000, "bl", "#0x2000")),
            0x2000,
        )
        self.assertIsNone(direct_branch_target(instruction(0x1004, "braaz", "x4")))
        self.assertEqual(
            conditional_branch_target(
                instruction(0x1008, "cbz", "x4, #0x1040")
            ),
            0x1040,
        )

    def test_reconstructs_split_w0_error_status(self) -> None:
        body = [
            instruction(0x1000, "mov", "w0, #0xb"),
            instruction(0x1004, "movk", "w0, #0x8000, lsl #16"),
            instruction(0x1008, "ret"),
        ]
        self.assertEqual(
            reconstruct_w_immediate_return(body, 0x1000),
            0x8000000B,
        )

    def test_classifies_bounded_range_guard(self) -> None:
        body = [
            instruction(0x1000, "adds", "x21, x0, x1"),
            instruction(0x1004, "b.hs", "#0x1040"),
            instruction(0x1008, "cmp", "x11, x21"),
            instruction(0x100C, "ccmp", "x10, x20, #0, lo"),
            instruction(0x1010, "lsr", "x8, x8, #0x1c"),
            instruction(0x1014, "movk", "w0, #0x8003, lsl #16"),
        ]
        result = classify_linear_range_guard(body)
        self.assertEqual(result["status"], "RANGE_GUARD_CANDIDATE")
        self.assertTrue(result["high_address_limit"])

    def test_does_not_classify_plain_add_as_range_guard(self) -> None:
        result = classify_linear_range_guard(
            [instruction(0x1000, "adds", "x0, x0, x1")]
        )
        self.assertEqual(result["status"], "NOT_CLASSIFIED")


class GxfContextSwitchContractTests(unittest.TestCase):
    @staticmethod
    def _fixture() -> tuple[MappedImage, list[dict]]:
        image = MappedImage(
            "fixture",
            [
                Segment("__TEXT", 0x1000, 0x1000, b"\0" * 0x1000),
                Segment("__DATA", 0x8000, 0x400, b"\0" * 0x400),
            ],
            {
                "__rtk_mmu_gxf_dispatcher": 0x1000,
                "__rtk_mmu_switch_region_base_by_contextID": 0x1100,
                "__rtk_mmu_switch_region_base": 0x1200,
                "__rtk_mmu_uat_wake": 0x1300,
                "__rtk_arm_start_bootstrap_area": 0x1400,
            },
        )
        instructions = [
            instruction(0x1000, "ldr", "w21, [x0]"),
            instruction(0x1004, "ldr", "x8, [x8, #8]"),
            instruction(0x1008, "ldp", "w0, w1, [x8]"),
            instruction(0x100C, "cmp", "w21, #0x20"),
            instruction(0x1010, "mov", "w2, #0"),
            instruction(0x1014, "b", "#0x1100"),
            instruction(0x1100, "adrp", "x8, #0x8000"),
            instruction(0x1104, "add", "x8, x8, #0x1e0"),
            instruction(0x1108, "ldr", "x23, [x8]"),
            instruction(0x110C, "ldr", "x8, [x8, #8]"),
            instruction(0x1110, "cmp", "x8, #0x40"),
            instruction(0x1114, "lsl", "x8, x24, #4"),
            instruction(0x1118, "ldr", "x8, [x23, x8]"),
            instruction(0x111C, "and", "x1, x8, #0x3ffffffc000"),
            instruction(0x1120, "tbz", "w8, #0, #0x1180"),
            instruction(0x1124, "ldrb", "w8, [x21, #0x638]"),
            instruction(0x1128, "tbnz", "w22, #0, #0x1130"),
            instruction(0x112C, "mov", "w2, #0x27"),
            instruction(0x1130, "bl", "#0x1200"),
            instruction(0x1200, "msr", "ttbr1_el1, x20"),
            instruction(0x1204, "msr", "ttbr0_el1, x20"),
            instruction(0x1208, "msr", "tcr_el1, x8"),
            instruction(0x1300, "ldr", "w1, [x8, #0x1f8]"),
            instruction(0x1304, "mov", "w2, #1"),
            instruction(0x1308, "bl", "#0x1100"),
            instruction(0x1400, "adrp", "x27, #0x8000"),
            instruction(0x1404, "adrp", "x26, #0x8000"),
            instruction(0x1408, "lsl", "x8, x25, #0xe"),
            instruction(0x140C, "str", "x8, [x27, #0x1e0]"),
            instruction(0x1410, "lsr", "x9, x19, #4"),
            instruction(0x1414, "str", "x9, [x26, #0x1e8]"),
        ]
        return image, instructions

    def test_reconstructs_registered_context_ttbr_switch(self) -> None:
        image, instructions = self._fixture()

        result = analyze_gxf_context_switch_contract(image, instructions)

        self.assertEqual(result["status"], "STATIC_CANDIDATE_PRODUCER_UNRESOLVED")
        self.assertTrue(result["direct_command_0x20"]["complete"])
        self.assertEqual(result["context_registry"]["state"], 0x81E0)
        self.assertEqual(result["context_registry"]["entry_stride"], 0x10)
        self.assertEqual(result["context_registry"]["root_mask"], 0x3FFFFFFC000)
        self.assertEqual(result["context_registry"]["bootstrap_table_store"], 0x140C)
        self.assertEqual(result["context_registry"]["bootstrap_count_store"], 0x1414)
        self.assertEqual(result["authorized_wake_route"]["authorization_argument"], 1)
        self.assertEqual(result["low_level_switch"]["ttbr1_write"], 0x1200)

    def test_registry_page_survives_long_callee_saved_live_range(self) -> None:
        image, instructions = self._fixture()
        shift = 140 * 4
        expanded = []
        for item in instructions:
            copied = dict(item)
            if copied["address"] >= 0x1408:
                copied["address"] += shift
            expanded.append(copied)
        expanded.extend(
            instruction(0x1408 + index * 4, "nop") for index in range(140)
        )
        expanded.sort(key=lambda item: item["address"])

        result = analyze_gxf_context_switch_contract(image, expanded)

        self.assertIsNotNone(result["context_registry"]["bootstrap_count_store"])

    def test_missing_authorization_guard_keeps_contract_incomplete(self) -> None:
        image, instructions = self._fixture()
        instructions = [
            item
            for item in instructions
            if not (
                item["mnemonic"] == "tbnz"
                and item["op_str"].startswith("w22, #0,")
            )
        ]

        result = analyze_gxf_context_switch_contract(image, instructions)

        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["context_registry"]["complete"])


if __name__ == "__main__":
    unittest.main()
