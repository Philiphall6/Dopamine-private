import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "BaseBin" / "libjailbreak" / "src" / "primitives.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "BaseBin" / "libjailbreak" / "src" / "primitives.c").read_text(encoding="utf-8")
EXPLOIT_SOURCE = (ROOT / "Application" / "Dopamine" / "Jailbreak" / "DOExploit.m").read_text(encoding="utf-8")


class TestPrimitiveCapabilityContract(unittest.TestCase):
    def test_required_capabilities_are_named(self):
        for name in (
            "LJB_CAPABILITY_KERNEL_READ",
            "LJB_CAPABILITY_KERNEL_WRITE",
            "LJB_CAPABILITY_PHYSICAL_READ",
            "LJB_CAPABILITY_PHYSICAL_WRITE",
            "LJB_CAPABILITY_PROTECTED_MEMORY_WRITE",
        ):
            with self.subTest(name=name):
                self.assertIn(name, HEADER)

    def test_runtime_state_is_not_inferred_from_pointer_presence(self):
        refresh_start = SOURCE.index("void libjailbreak_capabilities_refresh_declared")
        refresh = SOURCE[refresh_start:]
        self.assertIn("libjailbreak_capability_declare_if_unset", refresh)
        self.assertIn("LJB_CAPABILITY_DECLARED", SOURCE)
        self.assertNotIn("LJB_CAPABILITY_RUNTIME_VERIFIED", refresh)
        self.assertNotIn("LJB_CAPABILITY_PROTECTED_MEMORY_WRITE", refresh)

    def test_snapshot_api_is_public(self):
        for declaration in (
            "libjailbreak_capabilities_reset",
            "libjailbreak_capabilities_refresh_declared",
            "libjailbreak_capability_set",
            "libjailbreak_capability_get",
            "libjailbreak_capabilities_snapshot",
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, HEADER)
                self.assertIn(declaration, SOURCE)

    def test_exploit_manager_refreshes_after_successful_init(self):
        self.assertIn("if (r == 0)", EXPLOIT_SOURCE)
        self.assertIn("libjailbreak_capabilities_refresh_declared();", EXPLOIT_SOURCE)
        self.assertLess(
            EXPLOIT_SOURCE.index("libjailbreak_capabilities_refresh_declared();"),
            EXPLOIT_SOURCE.index("[DOExploitManager sharedManager].activeExploits addObject:self"),
        )


if __name__ == "__main__":
    unittest.main()
