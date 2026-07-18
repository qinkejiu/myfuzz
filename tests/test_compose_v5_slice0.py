import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.compose_v5 import (  # noqa: E402
    ComposeV5Failure,
    audit_compose_v5_targets,
    compose_v5_manifest_from_dict,
    load_compose_v5_manifest,
    qualify_compose_v5_manifest,
    write_compose_v5_json,
)
from myfuzz.builder.contracts import validate_contract  # noqa: E402
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.scripts.compose_v5 import main as compose_v5_main  # noqa: E402
from myfuzz.scripts.fetch_compose_v5_upstreams import (  # noqa: E402
    SourceLockError,
    _fetch as fetch_locked_source,
    _load as load_upstream_lock,
    _run as run_locked_source_command,
)


def _manifest() -> dict[str, object]:
    return {
        "schema": "myfuzz.compose-v5-manifest/v1",
        "name": "fixture",
        "sources": [
            {"id": name, "rtl_files": [f"rtl/{name}.sv"], "filelists": []}
            for name in ("cpu", "ram", "ip0", "ip1")
        ],
        "components": [
            {"id": "cpu0", "role": "cpu", "module": "cpu", "source_set": "cpu", "parameters": {}},
            {"id": "ram0", "role": "ram", "module": "ram", "source_set": "ram", "parameters": {"WORDS": 64}},
            {"id": "ip0", "role": "ip", "module": "ip0", "source_set": "ip0", "parameters": {}},
            {"id": "ip1", "role": "ip", "module": "ip1", "source_set": "ip1", "parameters": {}},
        ],
        "digest": "",
    }


def _write_fixture(root: Path, *, unsafe_module: str = "", unsafe_text: str = "") -> Path:
    rtl = root / "rtl"
    rtl.mkdir()
    for name in ("cpu", "ram", "ip0", "ip1"):
        body = unsafe_text if name == unsafe_module else ""
        parameter = " #(parameter int WORDS = 32)" if name == "ram" else ""
        (rtl / f"{name}.sv").write_text(
            f"module {name}{parameter}(input logic clk_i);\n{body}\nendmodule\n", encoding="ascii"
        )
    path = root / "compose-v5.json"
    path.write_text(json.dumps(_manifest()), encoding="ascii")
    return path


class ComposeV5Slice0Test(unittest.TestCase):
    def test_checked_in_upstream_lock_and_real_rvx_manifest_are_frozen_inputs(self):
        lock = load_upstream_lock(ROOT / "materials" / "compose_v5" / "upstreams.json")
        self.assertEqual([item["id"] for item in lock], ["cva6", "ibex", "rvx"])
        self.assertEqual(
            [item["revision"] for item in lock],
            [
                "3f39c6830d333ecc40b28790f8f9a1de6463124d",
                "13a8919bceac625dbd1b6ad804e62f9bdeadee86",
                "38bdee0ef8da0b606b7024f85934898e99963756",
            ],
        )
        manifest = load_compose_v5_manifest(
            ROOT / "materials" / "compose_v5" / "targets" / "rvx.compose-v5.json"
        )
        self.assertEqual(
            manifest.digest,
            "8e2e463e202ab9acb654886fd4cf797660b0dee6efbf97e3f5ccea1f032d58ce",
        )

    def test_upstream_lock_parser_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            value = json.loads(
                (ROOT / "materials" / "compose_v5" / "upstreams.json").read_text(encoding="ascii")
            )
            value["targets"][0]["port_hint"] = "forbidden"
            path.write_text(json.dumps(value), encoding="ascii")
            with self.assertRaisesRegex(SourceLockError, "field mismatch"):
                load_upstream_lock(path)

    def test_source_acquisition_commands_disable_host_git_rewrites_and_time_out(self):
        with mock.patch(
            "myfuzz.scripts.fetch_compose_v5_upstreams.subprocess.run"
        ) as run:
            run.return_value = mock.Mock(returncode=0, stdout="ok\n", stderr="")
            self.assertEqual(
                run_locked_source_command(["git", "status"], timeout_seconds=7),
                "ok",
            )
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs["timeout"], 7)
            self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(kwargs["env"]["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(kwargs["env"]["GIT_ASKPASS"], "/bin/false")
            self.assertEqual(kwargs["env"]["SSH_ASKPASS"], "/bin/false")

        with mock.patch(
            "myfuzz.scripts.fetch_compose_v5_upstreams.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["git", "fetch"], timeout=1),
        ):
            with self.assertRaisesRegex(SourceLockError, "timed out after 1s"):
                run_locked_source_command(["git", "fetch"], timeout_seconds=1)

    def test_source_acquisition_updates_nested_submodules_from_parent_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "cva6"
            (destination / ".git").mkdir(parents=True)
            target = {
                "id": "cva6",
                "url": "https://example.invalid/cva6.git",
                "revision": "0" * 40,
                "sparse_paths": [],
                "license_path": "LICENSE",
                "license_sha256": "0" * 64,
                "submodules": [
                    {"path": "core/cvfpu/src/fpu_div_sqrt_mvp", "revision": "2" * 40},
                    {"path": "core/cvfpu", "revision": "1" * 40},
                ],
            }
            calls: list[list[str]] = []

            def fake_run(argv: list[str], **_: object) -> str:
                calls.append(argv)
                if argv[-3:] == ["remote.origin.url"] or argv[-1] == "remote.origin.url":
                    return "https://example.invalid/cva6.git"
                return ""

            with mock.patch(
                "myfuzz.scripts.fetch_compose_v5_upstreams._run",
                side_effect=fake_run,
            ), mock.patch("myfuzz.scripts.fetch_compose_v5_upstreams._verify"):
                fetch_locked_source(target, root, timeout_seconds=11)

            self.assertIn(
                [
                    "git", "-C", str(destination),
                    "submodule", "update", "--init", "--depth", "1", "core/cvfpu",
                ],
                calls,
            )
            self.assertIn(
                [
                    "git", "-C", str(destination / "core/cvfpu"),
                    "submodule", "update", "--init", "--depth", "1", "src/fpu_div_sqrt_mvp",
                ],
                calls,
            )

    def test_strict_manifest_seals_and_qualifies_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(root)
            first = load_compose_v5_manifest(path)
            second = compose_v5_manifest_from_dict(_manifest())
            self.assertEqual(first.digest, second.digest)
            report = qualify_compose_v5_manifest(first, project_root=root)
            self.assertTrue(report.eligible)
            self.assertEqual(report.failure_codes, ())
            self.assertTrue(all(item.source_count == 1 for item in report.components))
            validate_contract(first.to_dict(), "compose_v5_manifest_v1")
            validate_contract(report.to_dict(), "compose_v5_qualification_v1")
            output = write_compose_v5_json(report, root / "out" / "qualification.json")
            self.assertEqual(
                json.loads(output.read_text()),
                json.loads(json.dumps(report.to_dict())),
            )

    def test_manifest_rejects_port_protocol_and_address_annotations(self):
        for field in ("ports", "protocol", "address"):
            value = _manifest()
            value["components"][0][field] = {}  # type: ignore[index]
            with self.subTest(field=field), self.assertRaisesRegex(
                InputValidationError, "unknown=.*" + field
            ):
                compose_v5_manifest_from_dict(value)

    def test_manifest_requires_one_cpu_one_ram_and_multiple_ips(self):
        cases = []
        no_cpu = _manifest(); no_cpu["components"][0]["role"] = "ip"  # type: ignore[index]
        cases.append(no_cpu)
        no_ram = _manifest(); no_ram["components"][1]["role"] = "ip"  # type: ignore[index]
        cases.append(no_ram)
        one_ip = _manifest(); one_ip["components"] = one_ip["components"][:-1]  # type: ignore[index]
        cases.append(one_ip)
        for value in cases:
            with self.assertRaises(InputValidationError):
                compose_v5_manifest_from_dict(value)

    def test_missing_source_is_target_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(root)
            (root / "rtl" / "ip1.sv").unlink()
            report = qualify_compose_v5_manifest(load_compose_v5_manifest(path), project_root=root)
            failed = next(item for item in report.components if item.component_id == "ip1")
            self.assertFalse(report.eligible)
            self.assertEqual(failed.failure_code, ComposeV5Failure.TARGET_UNAVAILABLE.value)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_escape_is_target_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            path = _write_fixture(root)
            source = root / "rtl" / "ip1.sv"
            source.unlink()
            external = Path(outside) / "ip1.sv"
            external.write_text("module ip1; endmodule\n", encoding="ascii")
            source.symlink_to(external)
            report = qualify_compose_v5_manifest(load_compose_v5_manifest(path), project_root=root)
            failed = next(item for item in report.components if item.component_id == "ip1")
            self.assertEqual(failed.failure_code, ComposeV5Failure.TARGET_UNAVAILABLE.value)
            self.assertIn("escapes allowlist", failed.reason)

    def test_host_effect_tasks_and_dpi_imports_are_rejected_but_exports_are_allowed(self):
        rejected = ("initial $system(\"date\");", 'import "DPI-C" function int host_call();')
        for unsafe in rejected:
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = _write_fixture(root, unsafe_module="ip0", unsafe_text=unsafe)
                report = qualify_compose_v5_manifest(load_compose_v5_manifest(path), project_root=root)
                failed = next(item for item in report.components if item.component_id == "ip0")
                self.assertEqual(failed.failure_code, ComposeV5Failure.SOURCE_UNTRUSTED.value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(
                root, unsafe_module="ip0",
                unsafe_text='// $system("ignored")\ninitial $display("$fopen ignored");',
            )
            self.assertTrue(
                qualify_compose_v5_manifest(load_compose_v5_manifest(path), project_root=root).eligible
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(
                root, unsafe_module="ip0",
                unsafe_text='export "DPI-C" function rtl_observe; function int rtl_observe; return 1; endfunction',
            )
            self.assertTrue(
                qualify_compose_v5_manifest(load_compose_v5_manifest(path), project_root=root).eligible
            )

    def test_source_content_drift_changes_qualification_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(root)
            manifest = load_compose_v5_manifest(path)
            first = qualify_compose_v5_manifest(manifest, project_root=root)
            source = root / "rtl" / "ip1.sv"
            source.write_text("module ip1(input logic clk_i); logic changed; endmodule\n", encoding="ascii")
            second = qualify_compose_v5_manifest(manifest, project_root=root)
            self.assertNotEqual(first.digest, second.digest)
            self.assertNotEqual(
                next(item.elaboration_digest for item in first.components if item.component_id == "ip1"),
                next(item.elaboration_digest for item in second.components if item.component_id == "ip1"),
            )

    def test_target_audit_reports_real_targets_unavailable_without_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = {name: Path("targets") / name / "compose-v5.json" for name in ("ibex", "rvx", "cva6")}
            first = audit_compose_v5_targets(targets, project_root=root)
            second = audit_compose_v5_targets(dict(reversed(tuple(targets.items()))), project_root=root)
            self.assertEqual(first.digest, second.digest)
            self.assertFalse(first.all_eligible)
            self.assertEqual([item.target_id for item in first.targets], ["cva6", "ibex", "rvx"])
            self.assertTrue(all(item.status == "unavailable" for item in first.targets))
            self.assertTrue(all(item.failure_code == "target_unavailable" for item in first.targets))
            validate_contract(first.to_dict(), "compose_v5_target_audit_v1")

    def test_cli_writes_audit_and_returns_ineligible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "audit.json"
            code = compose_v5_main([
                "audit", "--project-root", str(root), "--output", str(output),
                "--target", "ibex=missing.json",
            ])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.read_text())["targets"][0]["target_id"], "ibex")

    def test_frontend_verifies_declared_top_when_library_is_available(self):
        library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("frontend library is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = _write_fixture(root)
            report = qualify_compose_v5_manifest(
                load_compose_v5_manifest(path), project_root=root,
                verify_elaboration=True, frontend_library=library,
            )
            self.assertTrue(report.eligible)
            self.assertTrue(all(item.frontend_schema != "not-run" for item in report.components))


if __name__ == "__main__":
    unittest.main()
