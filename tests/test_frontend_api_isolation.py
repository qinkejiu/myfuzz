from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from myfuzz.scripts.frontend_api import isolated_frontend_manifest


class FrontendApiIsolationTest(unittest.TestCase):
    def test_worker_receives_only_fixed_and_explicit_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "frontend.so"
            library.write_bytes(b"fixture")
            observed: dict[str, object] = {}

            def run(argv, **kwargs):
                observed.update({"argv": argv, **kwargs})
                return subprocess.CompletedProcess(argv, 0, json.dumps({"schema": "fixture"}), "")

            with mock.patch.dict(os.environ, {"HOST_SECRET": "must-not-pass"}, clear=False):
                with mock.patch("myfuzz.scripts.frontend_api.subprocess.run", side_effect=run):
                    result = isolated_frontend_manifest(
                        library, ["--lint-only"], root,
                        environment={"MYFUZZ_FRONTEND_VERILATOR_ROOT": "/tool/verilator"},
                        timeout=17,
                    )
            self.assertEqual(result, {"schema": "fixture"})
            environment = observed["env"]
            self.assertNotIn("HOST_SECRET", environment)
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertEqual(environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"], "/tool/verilator")
            self.assertEqual(observed["timeout"], 17)

    def test_unknown_environment_key_and_invalid_timeout_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "frontend.so"
            library.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "unsupported frontend environment"):
                isolated_frontend_manifest(library, [], root, environment={"LD_PRELOAD": "x"})
            with self.assertRaisesRegex(ValueError, "positive integer"):
                isolated_frontend_manifest(library, [], root, timeout=0)

    def test_timeout_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "frontend.so"
            library.write_bytes(b"fixture")
            with mock.patch(
                "myfuzz.scripts.frontend_api.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["worker"], 3),
            ):
                with self.assertRaisesRegex(RuntimeError, "exceeded 3 seconds"):
                    isolated_frontend_manifest(library, [], root, timeout=3)


if __name__ == "__main__":
    unittest.main()
