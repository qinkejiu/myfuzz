from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from myfuzz.composition import source_elaboration
from myfuzz.composition.source_elaboration import ElaborationError, run_verilator_elaboration
from tests.composition.test_source_elaboration import SOURCE, fixture


class SourceElaborationRunnerTests(unittest.TestCase):
    def test_zero_exit_rejects_malformed_incomplete_and_error_summaries(self) -> None:
        cases = ("malformed", "incomplete", "error")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "top.sv").write_text("ok", encoding="utf-8")
                output = root / "evidence"
                def supervise(_options):
                    (output / "frontend.log").write_bytes(b"")
                    (output / "tool-version.log").write_text("fake\n", encoding="utf-8")
                    summary = {"sha256": hashlib.sha256(b"").hexdigest(), "byte_count": 0,
                               "warning_classes": {}, "warning_count": 0, "error_count": 0,
                               "parse_complete": True}
                    if case == "malformed":
                        (output / "frontend.log.summary.json").write_text("{", encoding="utf-8")
                    else:
                        if case == "incomplete": summary["parse_complete"] = False
                        if case == "error": summary["error_count"] = 1
                        (output / "frontend.log.summary.json").write_text(json.dumps(summary), encoding="utf-8")
                    return {"status": "completed", "returncode": 0, "peak_rss_bytes": 1, "rss_sample_count": 1}
                with mock.patch.object(source_elaboration.shutil, "which", return_value=sys.executable), \
                     mock.patch.object(source_elaboration, "_tool_source_allowlist", return_value={}), \
                     mock.patch("myfuzz.integration.campaign.run_supervised_command", side_effect=supervise):
                    with self.assertRaises(ElaborationError):
                        run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), output_dir=output)
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertNotEqual("completed", manifest["status"])

    def test_frontend_wrapper_keeps_fast_child_alive_through_first_rss_poll(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "instant-tool"
            tool.write_text(
                "#!/usr/bin/python3\nimport sys\n"
                "print('instant 1.0') if sys.argv[1:] == ['--version'] else None\n"
                "raise SystemExit(0 if sys.argv[1:] == ['--version'] else 7)\n",
                encoding="utf-8",
            )
            tool.chmod(0o755)
            started = time.monotonic()
            completed = subprocess.run(
                (
                    sys.executable, "-c", source_elaboration._FRONTEND_WRAPPER,
                    str(root / "diagnostic.log"), str(root / "version.log"),
                    "1024", "1024", str(tool), str(tool), "compile",
                ),
                check=False,
                timeout=5,
            )
            elapsed = time.monotonic() - started

        self.assertEqual(7, completed.returncode)
        self.assertGreaterEqual(elapsed, 0.15)

    def _fake_frontend(self, root: Path) -> Path:
        tree, metadata = fixture()
        script = root / "fake-verilator"
        script.write_text(
            "#!/usr/bin/python3\n" + textwrap.dedent(f"""
                import json, os, subprocess, sys, time
                if sys.argv[1:] == ['--version']:
                    print('Verilator fake 1.0')
                    raise SystemExit(0)
                args = sys.argv[1:]
                source = args[-1]
                mode = open(source, encoding='utf-8').read().strip()
                if mode == 'fail':
                    sys.stderr.write('broken.sv:7: syntax error\\n' + 'x' * (80 * 1024))
                    sys.stderr.flush()
                    raise SystemExit(1)
                if mode == 'hang':
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
                    open(source + '.pid', 'w').write(str(child.pid))
                    sys.stderr.write('hung.sv:9: stalled\\n'); sys.stderr.flush()
                    time.sleep(60)
                if mode == 'mutate':
                    open(source, 'w').write('changed')
                if mode == 'warning':
                    sys.stderr.write('%Warning-WIDTH: top.sv:1: warning detail\\n')
                    sys.stderr.flush()
                if mode == 'warning-large':
                    sys.stderr.write('%Warning-WIDTH: top.sv:1: warning detail\\n' * 2000)
                    sys.stderr.flush()
                if mode == 'warning-long-line':
                    sys.stderr.write('%Warning-WIDTH: ' + 'x' * (70 * 1024) + '\\n')
                    sys.stderr.flush()
                if mode == 'warning-bad-class':
                    sys.stderr.write('%Warning-lower: invalid category\\n')
                    sys.stderr.flush()
                if mode == 'warning-many-classes':
                    sys.stderr.write(''.join(f'%Warning-W{{index:04d}}: category\\n' for index in range(1025)))
                    sys.stderr.flush()
                tree_path = args[args.index('--json-only-output') + 1]
                meta_path = args[args.index('--json-only-meta-output') + 1]
                if mode == 'huge':
                    open(tree_path, 'w').write(' ' * 2048)
                    open(meta_path, 'w').write('{{}}')
                    raise SystemExit(0)
                if mode == 'special':
                    os.symlink(source, tree_path)
                    open(meta_path, 'w').write('{{}}')
                    raise SystemExit(0)
                if mode == 'fifo':
                    os.mkfifo(tree_path)
                    open(meta_path, 'w').write('{{}}')
                    raise SystemExit(0)
                if mode == 'malformed':
                    open(tree_path, 'w').write('{{')
                    open(meta_path, 'w').write('{{}}')
                    raise SystemExit(0)
                tree = json.loads({json.dumps(tree)!r})
                metadata = json.loads({json.dumps(metadata)!r})
                metadata['files']['s']['realpath'] = os.path.realpath(source)
                metadata['files']['s']['filename'] = source
                if mode == 'bad-evidence':
                    tree['modulesp'][0]['stmtsp'][0]['dtypep'] = '(missing)'
                if mode == 'external-meta':
                    metadata['files']['x'] = {{'realpath': '/outside/external.svh', 'filename': '/outside/external.svh'}}
                if mode == 'relative-meta':
                    metadata['files']['x'] = {{'realpath': 'relative.svh', 'filename': 'relative.svh'}}
                if mode == 'missing-meta':
                    metadata['files']['x'] = {{'filename': 'missing.svh'}}
                if mode == 'header':
                    include = next(value[2:] for value in args if value.startswith('-I'))
                    header = os.path.join(include, 'width.svh')
                    width = int(open(header).read().strip())
                    metadata['files']['h'] = {{'realpath': os.path.realpath(header), 'filename': header}}
                    tree['miscsp'][0]['typesp'][1]['range'] = f'{{width - 1}}:0'
                    tree['miscsp'][0]['typesp'][1]['loc'] = 'h,1:1,1:2'
                open(tree_path, 'w').write(json.dumps(tree))
                open(meta_path, 'w').write(json.dumps(metadata))
            """),
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _run(self, root: Path, output: Path, source: str = "ok", warning_policy: str = "fatal"):
        source_path = root / "top.sv"
        source_path.write_text(source, encoding="utf-8")
        frontend = self._fake_frontend(root)
        with mock.patch.object(source_elaboration.shutil, "which", return_value=str(frontend)):
            return run_verilator_elaboration(
                source_root=root,
                top_module="renamed_top",
                source_files=("top.sv",),
                warning_policy=warning_policy,
                output_dir=output,
            )

    def test_recorded_nonfatal_warning_is_hashed_counted_and_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "evidence"
            self._run(root, output, "warning", "recorded-nonfatal")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual("recorded-nonfatal", manifest["warning_policy"])
        self.assertEqual({"WIDTH": 1}, manifest["warning_summary"]["warning_classes"])
        self.assertEqual(1, manifest["warning_summary"]["warning_count"])
        self.assertEqual(0, manifest["warning_summary"]["error_count"])
        self.assertTrue(manifest["warning_summary"]["parse_complete"])
        self.assertIn("-Wno-fatal", manifest["command"])

    def test_truncated_diagnostics_retain_complete_stream_hash_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "evidence"
            self._run(root, output, "warning-large", "recorded-nonfatal")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        payload = ("%Warning-WIDTH: top.sv:1: warning detail\n" * 2000).encode()
        self.assertTrue(manifest["diagnostics_truncated"])
        self.assertEqual((len(payload), hashlib.sha256(payload).hexdigest(), 2000),
                         (manifest["warning_summary"]["byte_count"], manifest["warning_summary"]["sha256"], manifest["warning_summary"]["warning_count"]))

    def test_zero_exit_rejects_overlong_complete_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "evidence"
            with self.assertRaisesRegex(ElaborationError, "summary rejected"):
                self._run(root, output, "warning-long-line", "recorded-nonfatal")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["warning_summary"]["parse_complete"])
        self.assertEqual(0, manifest["warning_summary"]["warning_count"])

    def test_producer_rejects_invalid_or_excess_warning_classes(self) -> None:
        for mode in ("warning-bad-class", "warning-many-classes"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / "evidence"
                with self.assertRaises(ElaborationError):
                    self._run(root, output, mode, "recorded-nonfatal")
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertFalse(manifest["warning_summary"]["parse_complete"])
                self.assertLessEqual(len(manifest["warning_summary"]["warning_classes"]), 1024)

    def test_runs_bounded_frontend_and_publishes_manifest_and_physical_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "evidence"

            result = self._run(root, output)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(22, result["ports"][1]["width"])
            self.assertEqual("completed", manifest["status"])
            self.assertEqual("Verilator fake 1.0", manifest["tool_version"])
            self.assertEqual(64, len(manifest["sources"][0]["sha256"]))
            self.assertEqual("top.sv", manifest["sources"][0]["file"])
            self.assertEqual("nice", manifest["command"][0])
            self.assertEqual("-n15", manifest["command"][1])
            self.assertGreater(manifest["peak_rss_bytes"], 0)
            self.assertTrue((output / "ports.tree.json").is_file())
            self.assertTrue((output / "ports.meta.json").is_file())

    def test_rejects_unsafe_paths_tokens_and_existing_output_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text("ok", encoding="utf-8")
            outside = root.parent / "outside.sv"
            cases = [
                ({"source_files": ("missing.sv",)}, "missing"),
                ({"source_files": ("top.sv", "top.sv")}, "duplicate"),
                ({"source_files": ("../outside.sv",)}, "escape"),
                ({"include_roots": ("../outside",)}, "escape"),
                ({"defines": (("BAD-NAME", "1"),)}, "define"),
                ({"defines": (("GOOD", "a b"),)}, "define"),
                ({"parameters": (("BAD-NAME", "1"),)}, "parameter"),
                ({"parameters": (("WIDTH", "1"), ("WIDTH", "2"))}, "duplicate"),
                ({"parameters": (("WIDTH", "1+2"),)}, "decimal"),
            ]
            for index, (overrides, message) in enumerate(cases):
                with self.subTest(message=message), self.assertRaisesRegex(ElaborationError, message):
                    arguments = {
                        "source_root": root,
                        "top_module": "top",
                        "source_files": ("top.sv",),
                        "output_dir": root / f"out-{index}",
                        **overrides,
                    }
                    run_verilator_elaboration(**arguments)
            symlink = root / "link.sv"
            symlink.symlink_to(root / "top.sv")
            with self.assertRaisesRegex(ElaborationError, "symlink"):
                run_verilator_elaboration(source_root=root, top_module="top", source_files=("link.sv",), output_dir=root / "symlink-out")
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ElaborationError, "output"):
                run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), output_dir=existing)

    def test_missing_tool_and_failed_frontend_preserve_bounded_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text("ok", encoding="utf-8")
            with mock.patch.object(source_elaboration.shutil, "which", return_value=None):
                with self.assertRaisesRegex(ElaborationError, "not found"):
                    run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), output_dir=root / "missing-tool")
            output = root / "failed"
            with self.assertRaisesRegex(ElaborationError, "broken.sv:7"):
                self._run(root, output, "fail")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("frontend-error", manifest["status"])
            self.assertEqual("crashed", manifest["frontend_status"])
            self.assertTrue(manifest["diagnostics_truncated"])
            self.assertLessEqual(len(manifest["diagnostics"].encode("utf-8")), 65 * 1024)

    def test_timeout_reaps_descendant_and_keeps_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "timed-out"
            with mock.patch.object(source_elaboration, "_ELABORATION_TIMEOUT_SECONDS", 1):
                with self.assertRaisesRegex(ElaborationError, "hung.sv:9"):
                    self._run(root, output, "hang")
            pid = int((root / "top.sv.pid").read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("frontend-error", manifest["status"])
            self.assertEqual("timed-out", manifest["frontend_status"])

    def test_zero_exit_with_malformed_json_preserves_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "malformed"
            with self.assertRaisesRegex(ElaborationError, "JSON"):
                self._run(root, output, "malformed")
            self.assertTrue((output / "manifest.json").is_file())

    def test_rejects_oversized_and_non_regular_frontend_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "huge-output"
            with mock.patch.object(source_elaboration, "_MAX_JSON_BYTES", 1024):
                with self.assertRaisesRegex(ElaborationError, "size|large"):
                    self._run(root, output, "huge")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("malformed-output", manifest["status"])
            with self.assertRaisesRegex(ElaborationError, "regular|symlink"):
                self._run(root, root / "special-output", "special")
            with self.assertRaisesRegex(ElaborationError, "regular"):
                self._run(root, root / "fifo-output", "fifo")

    def test_rejects_all_non_pseudo_metadata_files_outside_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode in ("external-meta", "relative-meta", "missing-meta"):
                with self.subTest(mode=mode):
                    output = root / mode
                    with self.assertRaisesRegex(ElaborationError, "metadata.*closure|metadata.*file"):
                        self._run(root, output, mode)
                    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                    self.assertEqual("evidence-error", manifest["status"])

    def test_rejects_forged_verilator_pseudo_metadata_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree, metadata = fixture()
            metadata["files"]["forged"] = {
                "filename": "<verilated_std>",
                "realpath": "/outside/actual.svh",
            }
            path = root / "metadata.json"
            path.write_text(json.dumps(metadata), encoding="utf-8")
            closure = {Path(SOURCE): ("0" * 64, 1)}
            forged_root = root / "forged" / "include"
            forged_root.mkdir(parents=True)
            forged = forged_root / "verilated_std.sv"
            forged.write_text("fake", encoding="utf-8")
            metadata["files"]["forged"]["realpath"] = str(forged)
            with self.assertRaisesRegex(ElaborationError, "pseudo|verilated_std|tool"):
                source_elaboration._validate_metadata_closure(metadata, closure, {})

    def test_rejects_tool_source_changed_during_frontend_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text("ok", encoding="utf-8")
            standard = root / "verilated_std.sv"
            waiver = root / "verilated_std_waiver.vlt"
            standard.write_text("original", encoding="utf-8")
            waiver.write_text("waiver", encoding="utf-8")
            output = root / "evidence"
            allowlist = {
                "<verilated_std>": standard,
                "<verilated_std_waiver>": waiver,
            }

            def mutate(_options):
                standard.write_text("changed", encoding="utf-8")
                (output / "frontend.log").write_bytes(b"")
                (output / "tool-version.log").write_text("Python fake\n", encoding="utf-8")
                (output / "frontend.log.summary.json").write_text(json.dumps({
                    "sha256": hashlib.sha256(b"").hexdigest(), "byte_count": 0,
                    "warning_classes": {}, "warning_count": 0, "error_count": 0,
                    "parse_complete": True,
                }), encoding="utf-8")
                return {"status": "completed", "returncode": 0, "peak_rss_bytes": 1, "rss_sample_count": 1}

            with mock.patch.object(source_elaboration.shutil, "which", return_value=sys.executable), mock.patch.object(source_elaboration, "_tool_source_allowlist", return_value=allowlist), mock.patch("myfuzz.integration.campaign.run_supervised_command", side_effect=mutate):
                with self.assertRaisesRegex(ElaborationError, "tool.*changed|stale.*tool"):
                    run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), output_dir=output)

            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("stale-tool-source", manifest["status"])
            self.assertEqual(8, manifest["tool_sources"][0]["size"])

    def test_json_structure_budget_ignores_delimiters_inside_strings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid.json"
            expected = {"text": '{[,:]} and "quoted" and \\ escaped'}
            valid.write_text(json.dumps(expected), encoding="utf-8")
            with mock.patch.object(source_elaboration, "_MAX_JSON_STRUCTURE_TOKENS", 3):
                self.assertEqual(expected, source_elaboration._json_file(valid))
            for index, payload in enumerate(("[0,0,0]", "[{},{},{}]")):
                path = root / f"too-many-{index}.json"
                path.write_text(payload, encoding="utf-8")
                with mock.patch.object(source_elaboration, "_MAX_JSON_STRUCTURE_TOKENS", 2):
                    with self.assertRaisesRegex(ElaborationError, "structure"):
                        source_elaboration._json_file(path)

    def test_closure_budgets_explicit_files_and_directory_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = []
            for name in ("one.sv", "two.sv", "three.sv"):
                path = root / name
                path.write_text("x", encoding="utf-8")
                files.append((path, name))
            with mock.patch.object(source_elaboration, "_MAX_CLOSURE_FILES", 1):
                with self.assertRaisesRegex(ElaborationError, "file limit"):
                    source_elaboration._closure(root, files[:2], ())
            include = root / "include"
            include.mkdir()
            for index in range(3):
                (include / f"h{index}.svh").write_text("x", encoding="utf-8")
            with mock.patch.object(source_elaboration, "_MAX_CLOSURE_ENTRIES", 2):
                with self.assertRaisesRegex(ElaborationError, "entry limit"):
                    source_elaboration._closure(root, (), (include,))

    def test_include_closure_rejects_symlink_and_non_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text("ok", encoding="utf-8")
            include = root / "include"
            include.mkdir()
            (include / "link.svh").symlink_to(root / "top.sv")
            with self.assertRaisesRegex(ElaborationError, "symlink"):
                run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), include_roots=("include",), output_dir=root / "symlink-closure")
            (include / "link.svh").unlink()
            os.mkfifo(include / "named-pipe")
            with self.assertRaisesRegex(ElaborationError, "non-regular"):
                run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), include_roots=("include",), output_dir=root / "fifo-closure")

    def test_include_closure_is_hashed_mapped_and_checked_for_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            include = root / "include"
            include.mkdir()
            (include / "width.svh").write_text("13", encoding="utf-8")
            source = root / "top.sv"
            source.write_text("header", encoding="utf-8")
            frontend = self._fake_frontend(root)
            with mock.patch.object(source_elaboration.shutil, "which", return_value=str(frontend)):
                result = run_verilator_elaboration(source_root=root, top_module="renamed_top", source_files=("top.sv",), include_roots=("include",), output_dir=Path("header-output"))
            manifest = json.loads((root / "header-output" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(13, result["ports"][1]["members"][1]["width"])
            self.assertEqual(["include/width.svh", "top.sv"], sorted(item["file"] for item in manifest["sources"]))

            source.write_text("mutate", encoding="utf-8")
            with mock.patch.object(source_elaboration.shutil, "which", return_value=str(frontend)):
                with self.assertRaisesRegex(ElaborationError, "stale|changed"):
                    run_verilator_elaboration(source_root=root, top_module="renamed_top", source_files=("top.sv",), output_dir=root / "stale-output")

    def test_extract_failure_updates_manifest_evidence_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bad-evidence"
            with self.assertRaises(ElaborationError):
                self._run(root, output, "bad-evidence")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("completed", manifest["frontend_status"])
            self.assertEqual("evidence-error", manifest["status"])

    def test_manifest_exists_before_supervision_and_records_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text("ok", encoding="utf-8")
            output = root / "interrupted"

            def interrupt(_options):
                self.assertTrue((output / "manifest.json").is_file())
                raise KeyboardInterrupt

            with mock.patch.object(source_elaboration.shutil, "which", return_value=sys.executable), mock.patch("myfuzz.integration.campaign.run_supervised_command", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run_verilator_elaboration(source_root=root, top_module="top", source_files=("top.sv",), output_dir=output)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("interrupted", manifest["status"])

    @unittest.skipUnless(shutil.which("verilator"), "verilator is required")
    def test_real_verilator_elaborates_nested_package(self) -> None:
        source_text = """package p; typedef struct packed {logic valid; logic [12:0] addr;} req_t; typedef struct packed {req_t req; logic [1:0][3:0] lanes;} bundle_t; endpackage
module real_top(input p::bundle_t request_i, output logic [12:0] value_o); assign value_o=request_i.req.addr; endmodule
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "top.sv").write_text(source_text, encoding="utf-8")
            result = run_verilator_elaboration(source_root=root, top_module="real_top", source_files=("top.sv",), output_dir=root / "evidence")
        self.assertEqual(22, result["ports"][0]["width"])


if __name__ == "__main__":
    unittest.main()
