import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
EXPLOIT = ROOT / "Application/Dopamine/Exploits/Titan/exploit"


def function_body(source: str, name: str) -> str:
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"unterminated function {name}")


class TitanIOS26CommandABITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (EXPLOIT / "IOGPUDevice.h").read_text()
        cls.device = (EXPLOIT / "IOGPUDevice.c").read_text()
        cls.gfx = (EXPLOIT / "gfx.m").read_text()

    def test_ios26_exact_sizes_are_pinned(self) -> None:
        self.assertRegex(
            self.header,
            r"IOGPU_IOS26_CREATE_COMMAND_QUEUE_INPUT_SIZE\s+\(0x410\)",
        )
        self.assertRegex(
            self.header,
            r"IOGPU_IOS26_SUBMIT_RECORD_SIZE\s+\(0x30\)",
        )

    def test_only_known_ios26_selectors_shift(self) -> None:
        body = function_body(self.device, "uint32_t IOGPU_runtime_selector")
        self.assertIn("gTitanContext.os_major_version == 26", self.device)
        for selector in (
            "IOGPU_SELECTOR_CREATE_COMMAND_QUEUE",
            "IOGPU_SELECTOR_CREATE_NOTIFICATION_QUEUE",
            "IOGPU_SELECTOR_CREATE_SHARED_MEMORY",
            "IOGPU_SELECTOR_SET_NOTIFICATION_QUEUE",
            "IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS",
        ):
            self.assertIn(f"case {selector}:", body)
        self.assertIn("return legacy_selector - 1;", body)
        self.assertIn("default:", body)
        self.assertIn("return legacy_selector;", body)

    def test_all_iogpu_wrappers_use_runtime_selectors(self) -> None:
        for function, selector in (
            ("int IOGPU_create_command_queue", "IOGPU_SELECTOR_CREATE_COMMAND_QUEUE"),
            ("int IOGPU_create_notification_queue", "IOGPU_SELECTOR_CREATE_NOTIFICATION_QUEUE"),
            ("int IOGPU_create_shared_memory", "IOGPU_SELECTOR_CREATE_SHARED_MEMORY"),
            ("int IOGPU_set_notification_queue", "IOGPU_SELECTOR_SET_NOTIFICATION_QUEUE"),
            ("int IOGPU_submit_command_buffers", "IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS"),
        ):
            body = function_body(self.device, function)
            self.assertIn(f"IOGPU_runtime_selector({selector})", body)

    def test_queue_creation_uses_runtime_input_size(self) -> None:
        body = function_body(self.device, "int IOGPU_create_command_queue")
        self.assertIn(
            "uint8_t input[IOGPU_IOS26_CREATE_COMMAND_QUEUE_INPUT_SIZE]",
            body,
        )
        self.assertIn("IOGPU_create_command_queue_input_size()", body)

    def test_submit_record_size_reaches_scalar_and_structure(self) -> None:
        for source, function in (
            (self.device, "int IOGPU_submit_command_buffers"),
            (self.gfx, "int gfx_write32"),
        ):
            body = function_body(source, function)
            self.assertIn("size_t argument_size = IOGPU_submit_record_size();", body)
            self.assertIn(".arg_size = argument_size", body)
            self.assertRegex(
                body,
                re.compile(r"argument,\s*argument_size", re.MULTILINE),
            )

    def test_gfx_write_uses_runtime_submit_selector(self) -> None:
        body = function_body(self.gfx, "int gfx_write32")
        self.assertIn(
            "IOGPU_runtime_selector(IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS)",
            body,
        )


if __name__ == "__main__":
    unittest.main()
