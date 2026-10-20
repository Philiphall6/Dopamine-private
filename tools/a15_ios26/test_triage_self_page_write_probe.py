import unittest

from triage_self_page_write_probe import REVISION, REQUIRED, triage


def event(stage, status, detail="", run_id="run-a"):
    return {"run_id": run_id, "stage": stage, "status": status, "detail": detail}


def complete_run():
    run = [event("probe.entry", "START",
                 f"target=iPhone14,2 build=23A355 revision={REVISION}")]
    run += [event(stage, status) for stage, status in REQUIRED]
    return run


def through(stage, status):
    run = complete_run()
    return run[:next(i for i, item in enumerate(run)
                     if item["stage"] == stage and item["status"] == status) + 1]


class SelfPageWriteTriageTests(unittest.TestCase):
    def test_complete_dual_readback_and_restore(self):
        run = complete_run() + [event("titan.run", "FAIL", "bounded stop")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "verified_app_page_kernel_alias_write")
        self.assertIn("no physical write", result["limits"])

    def test_combined_uat_revision_retains_self_page_evidence(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace(
            REVISION, "self-page-write-v1+agx-uat-mode-v1+rtkit-mmio-disabled-v1")
        run += [event("titan.agx-uat-mode.stability", "BLOCKED", "source mismatch")]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "verified_app_page_kernel_alias_write")

    def test_combined_gart_revision_retains_self_page_evidence(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace(
            REVISION, "self-page-write-v1+agx-gart-state-v1+rtkit-mmio-disabled-v1")
        run += [event("titan.agx-gart-state.identity", "BLOCKED", "vtable mismatch")]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "verified_app_page_kernel_alias_write")

    def test_syscall_success_without_readback_is_not_proof(self):
        run = through("kernel-write.self-page.attempt", "START")
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "interrupted_after_attempt_checkpoint")

    def test_readback_failure_is_blocker(self):
        run = through("kernel-write.self-page.observe", "START")
        run.append(event("kernel-write.self-page.observe", "FAIL", "mismatch"))
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "blocked_or_failed")
        self.assertEqual(result["first_blocker"]["stage"],
                         "kernel-write.self-page.observe")

    def test_observation_without_restoration_is_not_complete(self):
        run = through("kernel-write.self-page.observe", "PASS")
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "change_observed_but_cleanup_unconfirmed")

    def test_cleanup_failure_invalidates_complete_sequence(self):
        run = complete_run()
        run.insert(-1, event("kernel-write.self-page.cleanup", "FAIL"))
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "change_observed_but_cleanup_unconfirmed")

    def test_wrong_revision_cannot_borrow_other_run_evidence(self):
        run = through("kernel-write.self-page.prepare", "START")
        run += [dict(item, run_id="run-b") for item in complete_run()]
        self.assertEqual(triage(run, "run-a")["verdict"], "no_write_attempt_observed")
        run[0]["detail"] = run[0]["detail"].replace(REVISION, "old-revision")
        self.assertEqual(triage(run, "run-a")["verdict"], "wrong_target_or_revision")


if __name__ == "__main__":
    unittest.main()
