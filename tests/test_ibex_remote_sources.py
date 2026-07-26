import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "configs/designs/ibex_multicomponent_ip/scripts/prepare_remote_sources.py"
SPEC = importlib.util.spec_from_file_location("prepare_remote_sources", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class IbexRemoteSourcesTest(unittest.TestCase):
    def test_flattened_paths_are_repo_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rtl = root / "third_party/ibex/rtl"
            rtl.mkdir(parents=True)
            (rtl / "top.sv").write_text("module top; endmodule\n")
            flist = root / "third_party/ibex/sources.f"
            flist.write_text("+incdir+rtl\nrtl/top.sv\n")
            self.assertEqual(
                MODULE.flatten_flist(flist, root),
                ["+incdir+third_party/ibex/rtl", "third_party/ibex/rtl/top.sv"],
            )

    def test_flattened_paths_reject_sources_outside_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            root = workspace / "repo"
            root.mkdir()
            external = workspace / "external.sv"
            external.write_text("module external; endmodule\n")
            flist = root / "sources.f"
            flist.write_text(f"{external}\n")

            with self.assertRaisesRegex(ValueError, "outside repository root"):
                MODULE.flatten_flist(flist, root)


if __name__ == "__main__":
    unittest.main()
