import unittest

from test_triage_agx_iouat_object_probe import event
from test_triage_agx_zero_packet_probe import complete_run as zero_run
from triage_agx_notification_bound_probe import REQUIRED, REVISION, render_compact, triage
from triage_agx_zero_packet_probe import REVISION as ZERO_REVISION


def complete_run():
    run = zero_run()
    run[0]["detail"] = run[0]["detail"].replace(ZERO_REVISION, REVISION)
    details = {
        ("titan.notification-binding.empty", "PASS"):
            "derived=0x0 slot=0xffffffe000100000 object=0x0",
        ("titan.notification-binding.create", "START"):
            "selector=14 entries=256 entry-size=32 output=0x10 attempt=1/1",
        ("titan.notification-binding.create", "PASS"):
            "kr=0x0 output-size=0x10 address=0x105000000 id=1 count=1024 attempt=1/1",
        ("titan.notification-binding.registry", "PASS"):
            "id=1 object=0xffffffe000200000 map=0xffffffe000300000 address=0x105000000/0x105000000 length=0x2000 expected=0x2000",
        ("titan.notification-binding.bind", "START"):
            "selector=24 queue-id=1 notification-id=1 attempt=1/1",
        ("titan.notification-binding.bind", "PASS"):
            "kr=0x0 queue-id=1 notification-id=1 attempt=1/1",
        ("titan.notification-binding.link", "PASS"):
            "queue=0xffffffe000400000 derived=0xffffffe000500000 slot=0xffffffe000100000 notification=0xffffffe000200000 expected=0xffffffe000200000 vtable-unslid=0xfffffff007e42f28",
        ("titan.notification-binding", "PASS"):
            "queue-id=1 notification-id=1 derived=0xffffffe000500000 notification=same selectors=14/24 attempts=1/1",
        ("titan.notification-binding", "STOP"):
            "notification prerequisite linked; selector 25 remains a separate single bounded call",
    }
    binding = [event(stage, status, details.get((stage, status), "value=0x1"))
               for stage, status in REQUIRED]
    anchor = next(index for index, item in enumerate(run) if
                  (item["stage"], item["status"]) == ("titan.zero-packet", "START"))
    run[anchor:anchor] = binding
    return run


class NotificationBoundTriageTests(unittest.TestCase):
    def test_complete_bound_probe(self):
        report = triage(complete_run(), "run-a")
        self.assertEqual(
            report["verdict"],
            "agx_notification_bound_zero_packet_cleanup_observed",
        )
        self.assertTrue(report["notification_binding_ok"])
        self.assertEqual(report["selector14_attempts"], 1)
        self.assertEqual(report["selector24_attempts"], 1)
        self.assertEqual(report["notification_id"], 1)
        compact = render_compact(report)
        self.assertIn("notification_binding: ok", compact)
        self.assertIn("selector14: attempts=1 id=1", compact)

    def test_duplicate_create_is_incomplete(self):
        run = complete_run()
        create = next(item for item in run if
                      (item["stage"], item["status"]) ==
                      ("titan.notification-binding.create", "START"))
        run.insert(run.index(create), dict(create))
        report = triage(run, "run-a")
        self.assertFalse(report["notification_binding_ok"])
        self.assertEqual(report["verdict"], "incomplete_or_blocked")

    def test_wrong_map_length_is_incomplete(self):
        run = complete_run()
        registry = next(item for item in run if item["stage"] ==
                        "titan.notification-binding.registry")
        registry["detail"] = registry["detail"].replace("length=0x2000", "length=0x4000")
        self.assertFalse(triage(run, "run-a")["notification_binding_ok"])

    def test_bind_block_is_incomplete(self):
        run = complete_run()
        bind = next(item for item in run if
                    (item["stage"], item["status"]) ==
                    ("titan.notification-binding.bind", "PASS"))
        bind["status"] = "BLOCKED"
        bind["detail"] = bind["detail"].replace("kr=0x0", "kr=0xe00002bc")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")


if __name__ == "__main__":
    unittest.main()
