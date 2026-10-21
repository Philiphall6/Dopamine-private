import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TITAN = (ROOT / "Application" / "Dopamine" / "Exploits" / "Titan" / "exploit" / "titan.m").read_text(encoding="utf-8")
JAILBREAKER = (ROOT / "Application" / "Dopamine" / "Jailbreak" / "DOJailbreaker.m").read_text(encoding="utf-8")
PRIMITIVES = (ROOT / "BaseBin" / "libjailbreak" / "src" / "primitives.c").read_text(encoding="utf-8")
PHYSRW = (ROOT / "BaseBin" / "libjailbreak" / "src" / "physrw.c").read_text(encoding="utf-8")


class TestTitanChainComparisonV8(unittest.TestCase):
    def test_proc_virtual_write_dispatches_to_virtual_writer(self):
        start = PRIMITIVES.index("int proc_vwritebuf")
        end = PRIMITIVES.index("// Convenience Wrappers", start)
        body = PRIMITIVES[start:end]
        self.assertIn("return vwritebuf(ttep, addr, indata, datalen);", body)
        self.assertNotIn("return proc_vwritebuf(ttep, addr, indata, datalen);", body)

    def test_current_titan_keeps_restore_before_preflight_and_selector_guard(self):
        restore = TITAN.index("titan.shared-alias.restore-before-preflight")
        queue = TITAN.index("titan_probe_owned_agx_queue", restore)
        guard = TITAN.index("#define TITAN_DISABLE_SELECTOR_25_FOR_BUFFER_RESTORE_VALIDATION 1")
        disabled_branch = TITAN.index('titan_checkpoint(@"titan.zero-packet", @"NOT_TESTED"', guard)
        selector_call = TITAN.index("titan_probe_zero_packet_once(connection", disabled_branch)
        self.assertLess(restore, queue)
        self.assertLess(guard, disabled_branch)
        self.assertLess(disabled_branch, selector_call)
        self.assertIn("baseline-match=", TITAN)
        self.assertIn('ALIAS_AFTER_RESTORE', TITAN)

    def test_active_a15_probe_stops_before_official_physrw_and_bootstrap(self):
        start = JAILBREAKER.index("- (void)runA15IOS2601ActiveTitanProbeWithError")
        end = JAILBREAKER.index("- (NSError *)buildPhysRWPrimitive", start)
        body = JAILBREAKER[start:end]
        self.assertIn("titan.physwrite.publish", body)
        for forbidden in (
            "buildPhysRWPrimitive",
            "elevatePrivileges",
            "prepareBootstrap",
            "loadBasebinTrustcache",
        ):
            self.assertNotIn(forbidden, body)

    def test_official_physrw_requires_pmap_mapping_and_publishes_physical_write(self):
        self.assertIn("pmap_map_in", PHYSRW)
        self.assertIn("gPrimitives.physwritebuf = physrw_physwritebuf", PHYSRW)
        self.assertIn("gPrimitives.physreadbuf = physrw_physreadbuf", PHYSRW)


if __name__ == "__main__":
    unittest.main()
