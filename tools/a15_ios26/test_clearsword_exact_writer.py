"""Compile the actual strict ClearSword writer against a mocked socket."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Application/Dopamine/Exploits/ClearSword/exploit/krw.c"
SIGNATURE = "int clearsword_kwritebuf_exact("


def exact_writer_source():
    source = SOURCE.read_text()
    start = source.index("__attribute__((visibility(\"default\")))", source.index("int clearsword_kwritebuf("))
    opening = source.index("{", source.index(SIGNATURE, start))
    depth = 0
    for position in range(opening, len(source)):
        depth += (source[position] == "{") - (source[position] == "}")
        if depth == 0:
            return source[start:position + 1]
    raise AssertionError("strict writer has no closing brace")


HARNESS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#define EARLY_KRW_LENGTH 0x20
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 1
static struct { int rw_socket; } g_ctx = { 7 };
static bool allow_target = true;
static bool fail_socket = false;
static int socket_calls = 0;
static uint64_t target_address = 0;
static uint8_t received[EARLY_KRW_LENGTH];
static bool set_target_kaddr(uint64_t address) {
    target_address = address;
    return allow_target;
}
static int mock_setsockopt(int socket, int level, int option, const void *data, unsigned int size) {
    assert(socket == 7 && level == IPPROTO_ICMPV6 && option == ICMP6_FILTER);
    assert(size == EARLY_KRW_LENGTH);
    socket_calls++;
    memcpy(received, data, size);
    if (fail_socket) { errno = EACCES; return -1; }
    return 0;
}
#define setsockopt mock_setsockopt
__FUNCTION__
int main(void) {
    uint8_t input[EARLY_KRW_LENGTH];
    memset(input, 0x5a, sizeof(input));
    assert(clearsword_kwritebuf_exact(0xfffffff000001000ULL, NULL, sizeof(input)) == EINVAL);
    assert(clearsword_kwritebuf_exact(0xfffffff000001000ULL, input, 8) == EINVAL);
    assert(clearsword_kwritebuf_exact(0xfffffff000001001ULL, input, sizeof(input)) == EINVAL);
    assert(socket_calls == 0);
    allow_target = false;
    assert(clearsword_kwritebuf_exact(0xfffffff000001000ULL, input, sizeof(input)) == EFAULT);
    assert(socket_calls == 0);
    allow_target = true;
    fail_socket = true;
    assert(clearsword_kwritebuf_exact(0xfffffff000001000ULL, input, sizeof(input)) == EACCES);
    assert(socket_calls == 1);
    fail_socket = false;
    assert(clearsword_kwritebuf_exact(0xfffffff000001000ULL, input, sizeof(input)) == 0);
    assert(socket_calls == 2 && target_address == 0xfffffff000001000ULL);
    assert(memcmp(input, received, sizeof(input)) == 0);
    return 0;
}
"""


class ClearSwordExactWriterTests(unittest.TestCase):
    def test_actual_function_contract(self):
        compiler = shutil.which("gcc") or shutil.which("clang")
        wsl = shutil.which("wsl") if not compiler else None
        if not compiler and not wsl:
            self.skipTest("C compiler unavailable")

        source = HARNESS.replace("__FUNCTION__", exact_writer_source())
        if wsl:
            output = f"/tmp/a15_exact_writer_{uuid.uuid4().hex}"
            compile_cmd = [wsl, "-e", "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-x", "c", "-", "-o", output]
            run_cmd = [wsl, "-e", output]
            cleanup_cmd = [wsl, "-e", "rm", "-f", "--", output]
            try:
                compiled = subprocess.run(compile_cmd, input=source, text=True,
                                          capture_output=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                ran = subprocess.run(run_cmd, capture_output=True, text=True, timeout=30)
                self.assertEqual(ran.returncode, 0, ran.stderr)
            finally:
                subprocess.run(cleanup_cmd, capture_output=True, timeout=30)
            return

        with tempfile.TemporaryDirectory() as directory:
            output = str(pathlib.Path(directory) / "a15_exact_writer")
            compiled = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra",
                                       "-Werror", "-x", "c", "-", "-o", output],
                                      input=source, text=True, capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([output], capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == "__main__":
    unittest.main()
