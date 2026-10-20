import unittest

try:
    from audit_agx_lifecycle_log import audit_events
except ModuleNotFoundError:
    from tools.a15_ios26.audit_agx_lifecycle_log import audit_events


def event(**overrides):
    value = {
        "schema": "dopamine.a15-ios26.active-probe.v1",
        "run_id": "run-1",
        "session_id": "session-1",
        "timestamp": 1.0,
        "timestamp_monotonic_ns": 100,
        "stage": "titan.example",
        "operation": "titan.example",
        "status": "PASS",
        "return_code": None,
        "duration_ns": 0,
        "resource_state": None,
        "close_reason": None,
        "detail": "offline fixture",
    }
    value.update(overrides)
    return value


class TestAGXLifecycleLog(unittest.TestCase):
    def test_valid_structured_run_passes(self):
        report = audit_events(
            [
                event(stage="titan.start", timestamp_monotonic_ns=100),
                event(
                    stage="titan.shared-alias.open",
                    operation="IOServiceOpen",
                    timestamp_monotonic_ns=200,
                    return_code=0,
                    duration_ns=5000,
                    resource_state={"connection_open": True},
                ),
                event(
                    stage="titan.own-queue.connection-close",
                    operation="IOServiceClose",
                    timestamp_monotonic_ns=300,
                    return_code=0,
                    duration_ns=4000,
                    resource_state={"connection_open": False},
                    close_reason="offline fixture cleanup",
                ),
            ]
        )
        self.assertEqual(report["state"], "PASS")
        self.assertEqual(report["events_checked"], 3)
        self.assertEqual(report["operations_checked"], 2)

    def test_missing_resource_state_is_rejected_for_operation(self):
        report = audit_events(
            [event(operation="selector-25.empty-record", return_code=0, duration_ns=10)]
        )
        self.assertEqual(report["state"], "FAIL")
        self.assertTrue(any("resource_state" in error for error in report["errors"]))

    def test_monotonic_regression_and_missing_close_reason_are_rejected(self):
        report = audit_events(
            [
                event(timestamp_monotonic_ns=200),
                event(
                    stage="titan.shared-alias.munlock",
                    operation="munlock",
                    timestamp_monotonic_ns=100,
                    return_code=0,
                    duration_ns=10,
                    resource_state={"page_locked": False},
                ),
            ]
        )
        self.assertEqual(report["state"], "FAIL")
        self.assertTrue(any("regressed" in error for error in report["errors"]))
        self.assertTrue(any("close_reason" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
