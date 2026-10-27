import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "BaseBin/libjailbreak/src/backend_contract.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "BaseBin/libjailbreak/src/backend_contract.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "BaseBin/libjailbreak/Makefile").read_text(encoding="utf-8")
JAILBREAKER = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
MAIN_VIEW = (ROOT / "Application/Dopamine/UI/DOMainViewController.m").read_text(encoding="utf-8")


class TestA15BackendContract(unittest.TestCase):
    def test_attestation_requires_independent_window_and_cleanup_evidence(self):
        for marker in (
            "handoff_succeeded",
            "handoff_output_valid",
            "window_read_verified",
            "window_write_verified",
            "resource_lifetime_verified",
            "cleanup_verified",
            "physical_read_verified",
            "physical_write_verified",
            "protected_memory_write_verified",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, HEADER)
        self.assertIn("LJB_BACKEND_CONTRACT_HANDOFF_UNVERIFIED", HEADER)
        self.assertIn("LJB_BACKEND_CONTRACT_WINDOW_UNVERIFIED", HEADER)
        self.assertIn("LJB_BACKEND_CONTRACT_CLEANUP_UNVERIFIED", HEADER)

    def test_physical_capabilities_are_gated_before_mutation(self):
        validation = SOURCE.index("int libjailbreak_backend_validate_attestation")
        publication = SOURCE.index("int libjailbreak_backend_publish_verified")
        validation_body = SOURCE[validation:publication]
        publication_body = SOURCE[publication:]
        self.assertIn("handoff_succeeded", validation_body)
        self.assertIn("handoff_output_valid", validation_body)
        self.assertIn("window_read_verified", validation_body)
        self.assertIn("window_write_verified", validation_body)
        self.assertIn("cleanup_verified", validation_body)
        self.assertLess(
            publication_body.index("libjailbreak_backend_validate_attestation"),
            publication_body.index("gPrimitives.physreadbuf = callbacks->physreadbuf"),
        )

    def test_protected_memory_requires_physical_write_proof(self):
        self.assertIn("LJB_BACKEND_CONTRACT_PROTECTED_MEMORY_UNVERIFIED", SOURCE)
        self.assertIn("!attestation->physical_write_verified", SOURCE)
        self.assertIn("attestation->protected_memory_write_verified", SOURCE)

    def test_failed_publication_does_not_clear_previous_callbacks(self):
        publication = SOURCE[SOURCE.index("int libjailbreak_backend_publish_verified"):]
        self.assertNotIn("gPrimitives.physreadbuf = NULL", publication)
        self.assertNotIn("gPrimitives.physwritebuf = NULL", publication)
        self.assertIn("if (validation != LJB_BACKEND_CONTRACT_OK) return validation;", publication)

    def test_backend_contract_is_in_the_libjailbreak_build_inputs(self):
        self.assertIn("$(wildcard src/*.c", MAKEFILE)
        self.assertEqual(SOURCE.count("int libjailbreak_backend_validate_attestation("), 1)
        self.assertEqual(SOURCE.count("int libjailbreak_backend_publish_verified("), 1)

    def test_each_unvalidated_physical_precondition_returns_before_publication(self):
        for marker in (
            "LJB_BACKEND_CONTRACT_HANDOFF_UNVERIFIED",
            "LJB_BACKEND_CONTRACT_WINDOW_UNVERIFIED",
            "LJB_BACKEND_CONTRACT_LIFETIME_UNVERIFIED",
            "LJB_BACKEND_CONTRACT_CLEANUP_UNVERIFIED",
            "LJB_BACKEND_CONTRACT_CALLBACK_MISSING",
            "LJB_BACKEND_CONTRACT_PROTECTED_MEMORY_UNVERIFIED",
        ):
            self.assertIn(marker, SOURCE)
        publication = SOURCE[SOURCE.index("int libjailbreak_backend_publish_verified"):]
        self.assertLess(
            publication.index("if (validation != LJB_BACKEND_CONTRACT_OK) return validation;"),
            publication.index("gPrimitives.physwritebuf = callbacks->physwritebuf"),
        )

    def test_a15_ui_uses_read_only_diagnostics(self):
        self.assertIn("[self startA15AGXDiagnostics]", MAIN_VIEW)
        self.assertIn("runA15IOS2601AGXDiagnosticsWithError", MAIN_VIEW)
        self.assertNotIn("[self startA15ActiveTitanProbe]", MAIN_VIEW)
        start = MAIN_VIEW.index("- (void)startA15AGXDiagnostics")
        end = MAIN_VIEW.index("- (NSString *)jailbreakButtonTitle", start)
        diagnostics = MAIN_VIEW[start:end]
        self.assertNotIn("completeJailbreak", diagnostics)

    def test_legacy_a15_titan_entrypoint_is_explicitly_blocked(self):
        start = JAILBREAKER.index("- (void)runA15IOS2601ActiveTitanProbeWithError")
        end = JAILBREAKER.index("- (void)runA15IOS2601AGXDiagnosticsWithError", start)
        body = JAILBREAKER[start:end]
        self.assertIn('A15ActiveProbeCheckpoint(@"titan.legacy", @"BLOCKED"', body)
        self.assertIn("historical Titan disabled on iOS 26", body)
        self.assertLess(body.index("return;"), body.index('A15ActiveProbeCheckpoint(@"xpf.gather"'))


if __name__ == "__main__":
    unittest.main()
