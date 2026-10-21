import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JAILBREAKER = (ROOT / "Application" / "Dopamine" / "Jailbreak" / "DOJailbreaker.m").read_text(encoding="utf-8")
CLEARSWORD = (ROOT / "Application" / "Dopamine" / "Exploits" / "ClearSword" / "ClearSword.m").read_text(encoding="utf-8")
TITAN = (ROOT / "Application" / "Dopamine" / "Exploits" / "Titan" / "Titan.m").read_text(encoding="utf-8")
PHYSRW = (ROOT / "BaseBin" / "libjailbreak" / "src" / "physrw.c").read_text(encoding="utf-8")
PHYSRW_PTE = (ROOT / "BaseBin" / "libjailbreak" / "src" / "physrw_pte.c").read_text(encoding="utf-8")
PRIMITIVES = (ROOT / "BaseBin" / "libjailbreak" / "src" / "primitives.c").read_text(encoding="utf-8")
UTIL = (ROOT / "BaseBin" / "libjailbreak" / "src" / "util.c").read_text(encoding="utf-8")
MAIN = (ROOT / "BaseBin" / "libjailbreak" / "src" / "main.c").read_text(encoding="utf-8")


class TestBuildPhysRWPrerequisites(unittest.TestCase):
    def test_a15_builder_selects_pte_route_and_a8_is_the_only_source_exclusion(self):
        start = JAILBREAKER.index("- (NSError *)buildPhysRWPrimitive")
        end = JAILBREAKER.index("- (NSError *)cleanUpExploits", start)
        body = JAILBREAKER[start:end]
        self.assertIn("device_supports_physrw_pte()", body)
        self.assertIn("libjailbreak_physrw_pte_init(false, 0)", body)
        self.assertIn("libjailbreak_physrw_init(false)", body)
        start = PHYSRW_PTE.index("bool device_supports_physrw_pte")
        self.assertIn("return false", PHYSRW_PTE[start:])
        self.assertIn("return true", PHYSRW_PTE[start:])

    def test_pte_handoff_requires_mapping_and_physical_pte_writes(self):
        start = PHYSRW_PTE.index("int physrw_pte_handoff")
        end = PHYSRW_PTE.index("int libjailbreak_physrw_pte_init", start)
        body = PHYSRW_PTE[start:end]
        for required in (
            "proc_find(pid)",
            "proc_task(proc)",
            "koffsetof(task, map)",
            "koffsetof(vm_map, pmap)",
            "koffsetof(pmap, ttep)",
            "pmap_expand_range(pmap, MAGIC_PT_ADDRESS, L2_BLOCK_SIZE)",
            "vtophys_lvl(ttep, MAGIC_PT_ADDRESS",
            "physwrite64(magicPT,",
            "kvtophys(asid_page)",
            "physwrite64(magicPT+8,",
        ):
            self.assertIn(required, body)

    def test_pte_initializer_propagates_handoff_failure_before_publishing(self):
        start = PHYSRW_PTE.index("int libjailbreak_physrw_pte_init")
        end = PHYSRW_PTE.index("bool device_supports_physrw_pte", start)
        body = PHYSRW_PTE[start:end]
        self.assertIn("int handoffRet = physrw_pte_handoff(getpid(), &handoffAsid);", body)
        self.assertIn("if (handoffRet != 0)", body)
        self.assertIn("pthread_mutex_destroy(&gLock)", body)
        self.assertIn("return handoffRet", body)
        failure_end = body.index("gAsid = (void *)handoffAsid")
        failure_path = body[:failure_end]
        self.assertNotIn("gPrimitives.physreadbuf", failure_path)
        self.assertNotIn("gPrimitives.physwritebuf", failure_path)
        self.assertIn("uint64_t handoffAsid = 0", body)
        self.assertIn("if (!handoffAsid)", body)
        self.assertIn("if (!asidPtr)", body)
        self.assertIn("gPrimitives.physwritebuf = physrw_pte_physwritebuf", body)

    def test_pte_handoff_checks_partial_pte_writes_before_reporting_success(self):
        start = PHYSRW_PTE.index("int physrw_pte_handoff")
        end = PHYSRW_PTE.index("int libjailbreak_physrw_pte_init", start)
        body = PHYSRW_PTE[start:end]
        self.assertIn("if (physwrite64(magicPT, magicPTE) != 0)", body)
        self.assertIn("if (physwrite64(magicPT+8, asidPTE) != 0)", body)
        self.assertIn("if (!asid_page_pa)", body)
        self.assertIn("*asidPtr =", body)

    def test_remote_initializer_propagates_local_initializer_failure(self):
        self.assertIn("initResult = libjailbreak_physrw_pte_init(true, asidPtr);", MAIN)
        self.assertIn("if (initResult != 0) return initResult;", MAIN)

    def test_clear_sword_only_installs_kernel_callbacks(self):
        self.assertIn("gPrimitives.kreadbuf = clearsword_kreadbuf", CLEARSWORD)
        self.assertIn("gPrimitives.kwritebuf = clearsword_kwritebuf", CLEARSWORD)
        for callback in ("physreadbuf", "physwritebuf", "kcall", "kexec", "kmap"):
            self.assertNotIn(f"gPrimitives.{callback}", CLEARSWORD)

    def test_titan_physical_write_publication_is_after_successful_run(self):
        self.assertLess(TITAN.index("if (titan_run() != 0)"), TITAN.index("gPrimitives.physwritebuf = titan_physwritebuf"))
        probe_start = JAILBREAKER.index("- (void)runA15IOS2601ActiveTitanProbeWithError")
        probe_end = JAILBREAKER.index("- (NSError *)buildPhysRWPrimitive", probe_start)
        probe = JAILBREAKER[probe_start:probe_end]
        self.assertIn("titan.physwrite.publish", probe)
        for forbidden in ("buildPhysRWPrimitive", "elevatePrivileges", "prepareBootstrap"):
            self.assertNotIn(forbidden, probe)

    def test_pmap_mapping_requires_physical_write_and_capability_ledger_stays_observational(self):
        self.assertIn("pmap_expand_range(pmap, uaStart, size)", UTIL)
        self.assertIn("physwritebuf(level2Table, tableToWrite", UTIL)
        self.assertIn("if (physwrite64(pte, newTable | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE) != 0)", UTIL)
        self.assertIn("if (physwritebuf(level2Table, tableToWrite, vm_real_kernel_page_size) != 0)", UTIL)
        self.assertIn("pmap_map_in(pmap,", PHYSRW)
        self.assertIn("if (r != 0) return r;", PHYSRW)
        self.assertIn("gPrimitives.physwritebuf = physrw_physwritebuf", PHYSRW)
        self.assertIn("gPrimitives.physwritebuf || (gPrimitives.kwritebuf && gPrimitives.phystokv)", PRIMITIVES)
        self.assertIn("never promotes a", PRIMITIVES)
        self.assertIn("capability to RUNTIME_VERIFIED", PRIMITIVES)


if __name__ == "__main__":
    unittest.main()
