from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock
from pathlib import Path

import myfuzz.integration.reference_adapter as reference_adapter
from myfuzz.integration.reference_adapter import (
    GeneratorCommand,
    GeneratorFlag,
    GeneratorPathArgument,
    GeneratorPathSyntax,
    ReferenceAdapter,
    assert_reference_not_in_generator_argv,
)


class ReferenceIsolationTests(unittest.TestCase):
    def _generator(
        self,
        *arguments: GeneratorFlag | GeneratorPathArgument,
    ) -> GeneratorCommand:
        return GeneratorCommand("generate", tuple(arguments))

    def _paths(
        self,
        *paths: Path,
        syntax: GeneratorPathSyntax = GeneratorPathSyntax.POSITIONAL,
    ) -> GeneratorPathArgument:
        return GeneratorPathArgument(tuple(paths), syntax)

    def _evaluator(self, root: Path, name: str = "evaluate.py") -> Path:
        path = root / name
        path.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path

                output = Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"])
                output.write_text(
                    json.dumps({"status": "passed", "covered_points": [1, 3]}),
                    encoding="utf-8",
                )
                """
            ),
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_allowlisted_evaluator_returns_descriptive_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            output = root / "output"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)

            summary = ReferenceAdapter((str(evaluator),), allowed).run(output)

            self.assertEqual("reference-descriptive", summary["comparison_scope"])
            self.assertEqual("passed", summary["status"])
            self.assertEqual([1, 3], summary["covered_points"])
            persisted = json.loads((output / "reference_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary, persisted)

    def test_evaluator_outside_allowlist_is_rejected_without_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            outside = root / "outside"
            output = root / "output"
            allowed.mkdir()
            outside.mkdir()
            evaluator = self._evaluator(outside)

            with self.assertRaises(PermissionError):
                ReferenceAdapter((str(evaluator),), allowed).run(output)

            self.assertFalse(output.exists())

    def test_symlinked_evaluator_cannot_escape_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            target = self._evaluator(outside)
            link = allowed / "evaluate.py"
            link.symlink_to(target)

            with self.assertRaises(PermissionError):
                ReferenceAdapter((str(link),), allowed).run(root / "output")

    def test_evaluator_replacement_after_validation_cannot_change_executed_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            replacement = allowed / "replacement.py"
            replacement.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    from pathlib import Path

                    Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"]).write_text(
                        json.dumps({"status": "replacement"}), encoding="utf-8"
                    )
                    """
                ),
                encoding="utf-8",
            )
            replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)

            original_supervisor_command = reference_adapter._supervisor_command

            def replace_after_validation(
                command: tuple[str, ...],
                status_descriptor: int,
            ) -> tuple[str, ...]:
                os.replace(replacement, evaluator)
                return original_supervisor_command(command, status_descriptor)

            with mock.patch(
                "myfuzz.integration.reference_adapter._supervisor_command",
                side_effect=replace_after_validation,
            ):
                summary = ReferenceAdapter((str(evaluator),), allowed).run(root / "output")

            self.assertEqual("passed", summary["status"])

    def test_nested_directory_replacement_cannot_escape_allowlisted_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            nested = allowed / "nested"
            outside = root / "outside"
            allowed.mkdir()
            nested.mkdir()
            outside.mkdir()
            evaluator = self._evaluator(nested)
            escaped = outside / "evaluate.py"
            escaped.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                f"Path({str(root / 'escaped')!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            escaped.chmod(escaped.stat().st_mode | stat.S_IXUSR)
            descriptor_count = len(tuple(Path("/proc/self/fd").iterdir()))
            original_open = reference_adapter.os.open
            replaced = False

            def replace_nested(
                path: str | bytes | os.PathLike[str],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if Path(path).name == "evaluate.py" and not replaced:
                    replaced = True
                    os.rename(nested, allowed / "nested-original")
                    nested.symlink_to(outside, target_is_directory=True)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch(
                "myfuzz.integration.reference_adapter.os.open",
                side_effect=replace_nested,
            ):
                summary = ReferenceAdapter(("nested/evaluate.py",), allowed).run(root / "output")

            self.assertTrue(replaced)
            self.assertFalse((root / "escaped").exists())
            self.assertEqual("passed", summary["status"])
            self.assertEqual(descriptor_count, len(tuple(Path("/proc/self/fd").iterdir())))

    def test_evaluator_path_with_parent_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)

            with self.assertRaises(PermissionError):
                ReferenceAdapter(("../allowed/evaluate.py",), allowed).run(root / "output")

            self.assertTrue(evaluator.exists())
            self.assertFalse((root / "output").exists())

    def test_allowed_root_replacement_cannot_change_relative_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            self._evaluator(allowed)
            escaped = self._evaluator(outside)
            escaped.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "Path(os.environ['MYFUZZ_REFERENCE_OUTPUT']).write_text(\n"
                "    json.dumps({'status': 'outside'}), encoding='utf-8'\n"
                ")\n",
                encoding="utf-8",
            )
            descriptor_count = len(tuple(Path("/proc/self/fd").iterdir()))
            original_open = reference_adapter.os.open
            replaced = False

            def replace_root(
                path: str | bytes | os.PathLike[str],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if Path(path).name == "evaluate.py" and not replaced:
                    replaced = True
                    os.rename(allowed, root / "allowed-original")
                    allowed.symlink_to(outside, target_is_directory=True)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch(
                "myfuzz.integration.reference_adapter.os.open",
                side_effect=replace_root,
            ):
                summary = ReferenceAdapter(("evaluate.py",), allowed).run(root / "output")

            self.assertTrue(replaced)
            self.assertEqual("passed", summary["status"])
            self.assertEqual(descriptor_count, len(tuple(Path("/proc/self/fd").iterdir())))

    def test_evaluator_argument_cannot_escape_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            outside = root / "original_top.sv"
            outside.write_text("module original; endmodule\n", encoding="utf-8")

            with self.assertRaises(PermissionError):
                ReferenceAdapter(
                    (str(evaluator), "--source", str(outside)),
                    allowed,
                ).run(root / "output")

            self.assertFalse((root / "output").exists())

    def test_encoded_path_arguments_are_rejected_as_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            outside = root / "outside.json"
            outside.write_text("{}\n", encoding="utf-8")

            for argument in (f"@{outside}", f"--define=SOURCE={outside}"):
                with self.subTest(argument=argument):
                    with self.assertRaises(PermissionError):
                        ReferenceAdapter((str(evaluator), argument), allowed).run(
                            root / "output"
                        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
    def test_forked_descendant_is_terminated_before_summary_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            output = root / "output"
            allowed.mkdir()
            evaluator = allowed / "forking.py"
            evaluator.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import time
                    from pathlib import Path

                    output = Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"])
                    child = os.fork()
                    if child == 0:
                        time.sleep(0.25)
                        output.write_text(json.dumps({"status": "child"}), encoding="utf-8")
                        os._exit(0)
                    output.write_text(json.dumps({"status": "parent"}), encoding="utf-8")
                    """
                ),
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            summary = ReferenceAdapter((str(evaluator),), allowed).run(output)
            time.sleep(0.4)

            self.assertEqual("parent", summary["status"])
            self.assertEqual(
                "parent",
                json.loads((output / "reference_summary.json").read_text())["status"],
            )
            self.assertEqual(
                ["reference_summary.json"],
                sorted(path.name for path in output.iterdir()),
            )

    @unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "setsid"), "requires Linux process discovery")
    def test_setsid_descendant_is_terminated_before_summary_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            output = root / "output"
            allowed.mkdir()
            evaluator = allowed / "daemonizing.py"
            evaluator.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import time
                    from pathlib import Path

                    output = Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"])
                    child = os.fork()
                    if child == 0:
                        os.setsid()
                        time.sleep(0.25)
                        output.write_text(json.dumps({"status": "escaped"}), encoding="utf-8")
                        os._exit(0)
                    output.write_text(json.dumps({"status": "parent"}), encoding="utf-8")
                    """
                ),
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            summary = ReferenceAdapter((str(evaluator),), allowed).run(output)
            time.sleep(0.4)

            self.assertEqual("parent", summary["status"])
            self.assertEqual(
                ["reference_summary.json"],
                sorted(path.name for path in output.iterdir()),
            )

    @unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "setsid"), "requires Linux subreapers")
    def test_clean_environment_exec_descendant_cannot_escape_supervisor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            output = root / "output"
            allowed.mkdir()
            evaluator = allowed / "clean_exec.py"
            evaluator.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import sys
                    import time
                    from pathlib import Path

                    output = Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"])
                    child = os.fork()
                    if child == 0:
                        os.setsid()
                        code = (
                            "import json,time; from pathlib import Path; "
                            "time.sleep(0.25); "
                            f"Path({str(output)!r}).write_text(json.dumps({{'status':'escaped'}}))"
                        )
                        os.execve(sys.executable, [sys.executable, "-c", code], {"PATH": os.defpath})
                    output.write_text(json.dumps({"status": "parent"}), encoding="utf-8")
                    """
                ),
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            summary = ReferenceAdapter((str(evaluator),), allowed).run(output)
            time.sleep(0.4)

            self.assertEqual("parent", summary["status"])
            self.assertEqual(
                ["reference_summary.json"],
                sorted(path.name for path in output.iterdir()),
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fifo_summary_is_rejected_without_blocking_past_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            output = root / "output"
            allowed.mkdir()
            evaluator = allowed / "fifo.py"
            evaluator.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n"
                "output = Path(os.environ['MYFUZZ_REFERENCE_OUTPUT'])\n"
                "output.unlink()\n"
                "os.mkfifo(output)\n",
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)
            script = textwrap.dedent(
                """\
                import sys
                from pathlib import Path
                from myfuzz.integration.reference_adapter import ReferenceAdapter

                try:
                    ReferenceAdapter((sys.argv[1],), Path(sys.argv[2]), timeout_seconds=0.1).run(Path(sys.argv[3]))
                except ValueError:
                    raise SystemExit(0)
                raise SystemExit(2)
                """
            )

            completed = subprocess.run(
                [sys.executable, "-c", script, str(evaluator), str(allowed), str(output)],
                cwd=Path(__file__).resolve().parents[2],
                env={**os.environ, "PYTHONPATH": "src"},
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_timeout_terminates_evaluator_and_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = allowed / "sleep.py"
            evaluator.write_text(
                "#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n",
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            with self.assertRaises(TimeoutError):
                ReferenceAdapter((str(evaluator),), allowed, timeout_seconds=0.05).run(
                    root / "output"
                )

            self.assertEqual([], list((root / "output").iterdir()))

    def test_timeout_reports_supervisor_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            process = mock.Mock()
            process.stderr = io.BytesIO()
            process.wait.side_effect = subprocess.TimeoutExpired((str(evaluator),), 0.01)

            with mock.patch(
                "myfuzz.integration.reference_adapter.subprocess.Popen",
                return_value=process,
            ), mock.patch(
                "myfuzz.integration.reference_adapter._terminate_supervisor",
                return_value=125,
            ):
                with self.assertRaisesRegex(RuntimeError, "process tree"):
                    ReferenceAdapter(
                        (str(evaluator),),
                        allowed,
                        timeout_seconds=0.01,
                    ).run(root / "output")

    def test_malformed_and_oversized_summaries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            for name, payload in (
                ("malformed.py", "b'['"),
                ("oversized.py", "b'x' * (2 * 1024 * 1024 + 1)"),
            ):
                with self.subTest(name=name):
                    evaluator = allowed / name
                    evaluator.write_text(
                        "#!/usr/bin/env python3\n"
                        "import os\n"
                        "from pathlib import Path\n"
                        f"Path(os.environ['MYFUZZ_REFERENCE_OUTPUT']).write_bytes({payload})\n",
                        encoding="utf-8",
                    )
                    evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)
                    with self.assertRaises(ValueError):
                        ReferenceAdapter((str(evaluator),), allowed).run(root / name)
                    self.assertFalse((root / name / "reference_summary.json").exists())

    def test_evaluator_exit_125_is_not_a_supervisor_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = allowed / "exit_125.py"
            evaluator.write_text(
                "#!/usr/bin/env python3\nraise SystemExit(125)\n",
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            with self.assertRaisesRegex(RuntimeError, "exited with status 125") as raised:
                ReferenceAdapter((str(evaluator),), allowed).run(root / "output")

            self.assertNotIn("process tree", str(raised.exception))

    def test_large_output_is_drained_with_bounded_error_retention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = allowed / "noisy.py"
            evaluator.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stdout.write('o' * (3 * 1024 * 1024))\n"
                "sys.stderr.write('e' * (3 * 1024 * 1024))\n"
                "raise SystemExit(17)\n",
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            with mock.patch(
                "myfuzz.integration.reference_adapter.tempfile.TemporaryFile",
            ) as temporary_file:
                with self.assertRaisesRegex(RuntimeError, "status 17") as raised:
                    ReferenceAdapter((str(evaluator),), allowed, timeout_seconds=2).run(
                        root / "output"
                    )

            temporary_file.assert_not_called()

            self.assertLessEqual(
                len(str(raised.exception).encode("utf-8")),
                len("reference evaluator exited with status 17: ")
                + reference_adapter._MAX_ERROR_BYTES
                + len(" [stderr truncated]"),
            )
            self.assertEqual([], list((root / "output").iterdir()))

    def test_large_output_does_not_prevent_successful_summary_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = allowed / "noisy-success.py"
            evaluator.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "from pathlib import Path\n"
                "sys.stdout.write('o' * (3 * 1024 * 1024))\n"
                "sys.stderr.write('e' * (3 * 1024 * 1024))\n"
                "Path(os.environ['MYFUZZ_REFERENCE_OUTPUT']).write_text(\n"
                "    json.dumps({'status': 'passed'}), encoding='utf-8'\n"
                ")\n",
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)

            with mock.patch(
                "myfuzz.integration.reference_adapter.tempfile.TemporaryFile",
            ) as temporary_file:
                summary = ReferenceAdapter(
                    (str(evaluator),), allowed, timeout_seconds=2
                ).run(root / "output")

            temporary_file.assert_not_called()
            self.assertEqual("passed", summary["status"])
            self.assertEqual(
                summary,
                json.loads((root / "output" / "reference_summary.json").read_text()),
            )

    def test_wait_base_exceptions_terminate_reap_and_close_status_reader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            for exception in (RuntimeError("wait failed"), KeyboardInterrupt()):
                with self.subTest(exception=type(exception).__name__):
                    process = mock.Mock()
                    process.stderr = io.BytesIO()
                    process.poll.return_value = None
                    process.wait.side_effect = (exception, 0)
                    descriptor_count = len(tuple(Path("/proc/self/fd").iterdir()))

                    with mock.patch(
                        "myfuzz.integration.reference_adapter.subprocess.Popen",
                        return_value=process,
                    ):
                        with self.assertRaises(type(exception)):
                            ReferenceAdapter((str(evaluator),), allowed).run(root / "output")

                    process.terminate.assert_called_once_with()
                    self.assertGreaterEqual(process.wait.call_count, 2)
                    self.assertEqual(descriptor_count, len(tuple(Path("/proc/self/fd").iterdir())))

    def test_wait_exception_retains_cleanup_failure_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = self._evaluator(allowed)
            process = mock.Mock()
            process.stderr = io.BytesIO()
            process.wait.side_effect = RuntimeError("wait failed")

            with mock.patch(
                "myfuzz.integration.reference_adapter.subprocess.Popen",
                return_value=process,
            ), mock.patch(
                "myfuzz.integration.reference_adapter._terminate_supervisor",
                side_effect=RuntimeError("unreaped"),
            ):
                with self.assertRaisesRegex(RuntimeError, "wait failed") as raised:
                    ReferenceAdapter((str(evaluator),), allowed).run(root / "output")

            self.assertIn(
                "reference evaluator supervisor cleanup failed: RuntimeError: unreaped",
                "\n".join(getattr(raised.exception, "__notes__", ())),
            )

    def test_generator_argv_rejects_reference_path_and_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference"
            reference.mkdir()
            candidate = reference / "original_top.sv"
            candidate.write_text("module x; endmodule\n", encoding="utf-8")

            with self.assertRaises(PermissionError):
                assert_reference_not_in_generator_argv(
                    self._generator(self._paths(candidate, syntax=GeneratorPathSyntax.SOURCE)),
                    reference,
                )

            assert_reference_not_in_generator_argv(
                self._generator(
                    self._paths(
                        Path("declared_input.sv"),
                        syntax=GeneratorPathSyntax.SOURCE,
                    ),
                ),
                reference,
            )

    def test_generator_command_rejects_path_text_without_structured_provenance(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            GeneratorCommand(
                "generate",
                ("--source=reference/secret.sv",),  # type: ignore[arg-type]
            )

    def test_generator_command_rejects_bare_and_decoration_hidden_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            reference.mkdir()

            for arguments in (("reference",), ("-I", "reference")):
                with self.subTest(arguments=arguments):
                    with self.assertRaises(TypeError):
                        GeneratorCommand("generate", arguments)  # type: ignore[arg-type]

            with self.assertRaises(TypeError):
                GeneratorPathArgument(
                    (Path("declared"),),
                    "--dirs=reference;",  # type: ignore[arg-type]
                )

            for hidden in (Path("declared;reference"), Path("@reference")):
                with self.subTest(hidden=hidden):
                    with self.assertRaises(ValueError):
                        GeneratorPathArgument(
                            (hidden,),
                            GeneratorPathSyntax.DIRECTORIES,
                        )

            class SpoofPath(type(Path())):
                def __fspath__(self) -> str:
                    return "--source=reference/secret.sv"

            with self.assertRaises(TypeError):
                GeneratorPathArgument(
                    (SpoofPath("safe.sv"),),
                    GeneratorPathSyntax.SOURCE,
                )

            class SpoofArgument(GeneratorPathArgument):
                def render(self) -> str:
                    return "--source=reference/secret.sv"

            with self.assertRaises(TypeError):
                GeneratorCommand(
                    "generate",
                    (
                        SpoofArgument(
                            (Path("safe.sv"),),
                            GeneratorPathSyntax.SOURCE,
                        ),
                    ),
                )

    def test_generator_argv_resolves_relative_paths_without_prefix_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            sibling = root / "reference-other"
            reference.mkdir()
            sibling.mkdir()

            with self.assertRaises(PermissionError):
                assert_reference_not_in_generator_argv(
                    self._generator(
                        self._paths(
                            Path("reference/original_top.sv"),
                            syntax=GeneratorPathSyntax.SOURCE,
                        ),
                    ),
                    reference,
                    base_root=root,
                )

            assert_reference_not_in_generator_argv(
                self._generator(
                    self._paths(
                        sibling / "input.sv",
                        syntax=GeneratorPathSyntax.SOURCE,
                    ),
                ),
                reference,
                base_root=root,
            )

            same_name_elsewhere = root / "x" / "reference" / "input.sv"
            assert_reference_not_in_generator_argv(
                self._generator(
                    self._paths(
                        same_name_elsewhere,
                        syntax=GeneratorPathSyntax.SOURCE,
                    ),
                ),
                reference,
                base_root=root,
            )

    def test_generator_argv_rejects_compact_path_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            sibling = root / "reference-other"
            reference.mkdir()
            sibling.mkdir()

            cases = (
                self._paths(reference, syntax=GeneratorPathSyntax.INCLUDE),
                self._paths(Path("reference"), syntax=GeneratorPathSyntax.INCLUDE),
                self._paths(reference, syntax=GeneratorPathSyntax.INCDIR),
                self._paths(Path("reference"), syntax=GeneratorPathSyntax.INCDIR),
                self._paths(reference, syntax=GeneratorPathSyntax.SYSTEM_INCLUDE),
                self._paths(Path("reference"), syntax=GeneratorPathSyntax.SYSTEM_INCLUDE),
                self._paths(reference, syntax=GeneratorPathSyntax.SOURCE_COLON),
                self._paths(
                    Path("declared.sv"),
                    Path("reference/hidden.sv"),
                    syntax=GeneratorPathSyntax.SOURCES,
                ),
                self._paths(
                    reference / "arguments.rsp",
                    syntax=GeneratorPathSyntax.RESPONSE,
                ),
                self._paths(
                    Path("reference"),
                    Path("declared"),
                    syntax=GeneratorPathSyntax.DIRECTORIES,
                ),
                self._paths(
                    Path("reference"),
                    syntax=GeneratorPathSyntax.DIRECTORY_PAREN,
                ),
            )
            for argument in cases:
                with self.subTest(argument=argument.render()):
                    with self.assertRaises(PermissionError):
                        assert_reference_not_in_generator_argv(
                            self._generator(argument),
                            reference,
                            base_root=root,
                        )

            assert_reference_not_in_generator_argv(
                self._generator(
                    self._paths(sibling, syntax=GeneratorPathSyntax.INCLUDE),
                ),
                reference,
                base_root=root,
            )
            assert_reference_not_in_generator_argv(
                self._generator(
                    self._paths(sibling, syntax=GeneratorPathSyntax.INCDIR),
                ),
                reference,
                base_root=root,
            )
            assert_reference_not_in_generator_argv(
                self._generator(
                    GeneratorFlag.DEREFERENCE,
                    GeneratorFlag.PREFERENCE,
                ),
                reference,
                base_root=root,
            )

            with self.assertRaisesRegex(TypeError, "GeneratorCommand"):
                assert_reference_not_in_generator_argv(
                    ("generate", "--dirs=reference;declared"),  # type: ignore[arg-type]
                    reference,
                    base_root=root,
                )

    def test_parent_environment_is_not_exposed_to_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "reference"
            allowed.mkdir()
            evaluator = allowed / "environment.py"
            evaluator.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    from pathlib import Path

                    Path(os.environ["MYFUZZ_REFERENCE_OUTPUT"]).write_text(
                        json.dumps({"secret_visible": "MYFUZZ_TEST_SECRET" in os.environ}),
                        encoding="utf-8",
                    )
                    """
                ),
                encoding="utf-8",
            )
            evaluator.chmod(evaluator.stat().st_mode | stat.S_IXUSR)
            previous = os.environ.get("MYFUZZ_TEST_SECRET")
            os.environ["MYFUZZ_TEST_SECRET"] = "must-not-leak"
            try:
                summary = ReferenceAdapter((str(evaluator),), allowed).run(root / "output")
            finally:
                if previous is None:
                    os.environ.pop("MYFUZZ_TEST_SECRET", None)
                else:
                    os.environ["MYFUZZ_TEST_SECRET"] = previous

            self.assertFalse(summary["secret_visible"])


if __name__ == "__main__":
    unittest.main()
