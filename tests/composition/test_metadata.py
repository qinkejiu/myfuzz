from __future__ import annotations

import unittest

from myfuzz.composition.metadata import sanitize_metadata, semantic_source_hash


class MetadataSanitizerTests(unittest.TestCase):
    def test_rejects_host_specific_mapping_keys_before_stringification(self) -> None:
        unsafe_keys = (
            "pid=4242",
            "built=2026-07-23T10:11:12Z",
            "object at 0x7ffd1234",
            "/private/build/top.sv",
        )

        for unsafe_key in unsafe_keys:
            with self.subTest(unsafe_key=unsafe_key), self.assertRaisesRegex(ValueError, r"^test.metadata:host-specific"):
                sanitize_metadata({unsafe_key: "portable"}, context="test.metadata")

    def test_rejects_mapping_keys_with_the_same_canonical_string(self) -> None:
        with self.assertRaisesRegex(ValueError, r"^test.metadata:duplicate-key"):
            sanitize_metadata({1: "numeric", "1": "string"}, context="test.metadata")

    def test_rejects_embedded_windows_absolute_paths(self) -> None:
        unsafe_values = (
            "debug=C:\\build\\top.sv",
            r"source=\\server\share\x",
        )

        for unsafe_value in unsafe_values:
            with self.subTest(unsafe_value=unsafe_value), self.assertRaisesRegex(ValueError, r"^test.metadata:host-specific"):
                sanitize_metadata({"debug": unsafe_value}, context="test.metadata")

    def test_rejects_root_posix_paths_and_common_pid_forms(self) -> None:
        unsafe_values = (
            "/tmp",
            "/tmp/",
            "PID 123",
            "process id=456",
        )

        for unsafe_value in unsafe_values:
            with self.subTest(unsafe_value=unsafe_value), self.assertRaisesRegex(ValueError, r"^test.metadata:host-specific"):
                sanitize_metadata({"debug": unsafe_value}, context="test.metadata")

    def test_source_hash_accepts_division_but_rejects_paths_in_comments_and_strings(self) -> None:
        for source in (
            "assign y = a/b;",
            "assign y = a /b;",
            "assign y = a/b+c/d;",
            "assign y = a/b/c;",
            "assign y = a/u.foo/v;",
            "/* portable comment */\nmodule top; endmodule",
        ):
            with self.subTest(source=source):
                semantic_source_hash(source, context="test.source")

        for source in (
            "// generated from /tmp/top.sv\nmodule top; endmodule",
            'string metadata = "generated from /tmp/top.sv";',
            "// generated under /@cache\nmodule top; endmodule",
            'string metadata = "generated under /~";',
        ):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, r"^test.source:host-specific"):
                semantic_source_hash(source, context="test.source")

    def test_source_hash_rejects_absolute_path_after_code_operand(self) -> None:
        for source in (
            "assign y = a /tmp/build/top.sv;",
            "assign y = a /tmp/build/top;",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, r"^test.source:host-specific"):
                semantic_source_hash(source, context="test.source")


if __name__ == "__main__":
    unittest.main()
