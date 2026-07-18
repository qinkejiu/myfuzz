from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import yaml

from myfuzz.scripts.write_compose_v5_fusesoc_wrapper import (
    WrapperCoreError,
    write_wrapper_core,
)


class ComposeV5FuseSoCWrapperTest(unittest.TestCase):
    def test_writes_metadata_only_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "wrapper.core"
            write_wrapper_core(
                output,
                name="myfuzz:compose_v5:ram_wrapper:1",
                dependency="lowrisc:prim_generic:ram_1p",
                top_module="prim_ram_1p",
            )
            header, body = output.read_text(encoding="ascii").split("\n", 1)
            self.assertEqual(header, "CAPI=2:")
            value = yaml.safe_load(body)
            self.assertEqual(
                value["filesets"]["dependency"]["depend"],
                ["lowrisc:prim_generic:ram_1p"],
            )
            self.assertEqual(value["targets"]["default"]["toplevel"], "prim_ram_1p")
            self.assertNotIn("files", value["filesets"]["dependency"])

    def test_rejects_invalid_or_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "wrapper.core"
            with self.assertRaises(WrapperCoreError):
                write_wrapper_core(
                    output, name="bad", dependency="vendor:lib:core", top_module="top",
                )
            with self.assertRaises(WrapperCoreError):
                write_wrapper_core(
                    output,
                    name="vendor:lib:wrapper",
                    dependency="vendor:lib:core",
                    top_module="bad-name",
                )
            output.write_text("occupied\n", encoding="ascii")
            with self.assertRaises(WrapperCoreError):
                write_wrapper_core(
                    output,
                    name="vendor:lib:wrapper",
                    dependency="vendor:lib:core",
                    top_module="top",
                )


if __name__ == "__main__":
    unittest.main()
