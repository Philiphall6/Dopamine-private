import unittest

from audit_agx_map_reads import audit_capture


class AgxMapReadAuditTests(unittest.TestCase):
    def capture(self, root="IOGPUDevice", obj="0x1234", vtable="0xfffffff007b21c50"):
        return {
            "machine": "iPhone14,2",
            "productVersion": "26.0.1",
            "connections": [{
                "IOGPUDevice": "0x1234",
                "IOGPUDeviceUnslidVtable": vtable,
                "kernelReadPlans": [{
                    "name": "AGXMappedAddresses",
                    "root": root,
                    "object": obj,
                    "reads": [{"offset": "0x310", "value": "0x0"}],
                }],
            }],
        }

    def test_device_read_is_not_agx_map_evidence(self):
        self.assertIn("WRONG-RECEIVER", audit_capture(self.capture())[0])

    def test_unverified_object_is_not_upgraded(self):
        self.assertIn("UNVERIFIED-RECEIVER", audit_capture(self.capture(obj="0x5678"))[0])
        self.assertIn("UNVERIFIED-RECEIVER", audit_capture(self.capture(vtable="0x0"))[0])

    def test_missing_read_and_wrong_target(self):
        capture = self.capture()
        capture["connections"][0]["kernelReadPlans"][0]["reads"] = []
        self.assertIn("no +0x310 read", audit_capture(capture)[0])
        capture["machine"] = "iPhone15,2"
        with self.assertRaises(ValueError):
            audit_capture(capture)

    def test_base_service_agrees_with_static_path_but_not_live_map(self):
        capture = self.capture()
        capture["serviceClass"] = "AGXAcceleratorG14P"
        self.assertTrue(any("BASE-SERVICE" in item and "agrees" in item
                            and "does not establish a live map" in item
                            for item in audit_capture(capture)))


if __name__ == "__main__":
    unittest.main()
