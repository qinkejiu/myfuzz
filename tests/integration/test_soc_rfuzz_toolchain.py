"""Contracts for the fail-closed profile SoC RFuzz toolchain boundary."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.rfuzz_toolchain import (
    RfuzzToolchainError,
    normalize_rfuzz_config,
    resolve_rfuzz_toolchain,
    resolve_rfuzz_verilator_toolchain,
)
from myfuzz.integration.soc_campaign import preflight_soc_campaign


class RfuzzToolchainTests(unittest.TestCase):
    def _executable(self, root: Path, name: str, version: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        path = root / name
        path.write_text("#!/bin/sh\nprintf '%s\\n' '" + version + "'\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_explicit_client_has_auditable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            client = self._executable(root, "kfuzz", "kfuzz 1.2.3")
            verilator = self._executable(root, "verilator", "Verilator 5.020 test")
            toolchain = resolve_rfuzz_toolchain(
                root, {"client_binary": str(client), "verilator": str(verilator)}, environment={})
        self.assertEqual(str(client), toolchain["client"]["path"])
        self.assertEqual("kfuzz 1.2.3", toolchain["client"]["version"])
        self.assertRegex(toolchain["client"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual("controlled", toolchain["verilator"]["source"])
        self.assertEqual("Verilator 5.020 test", toolchain["verilator"]["version"])
        self.assertEqual({}, toolchain["verilator_environment"])

    def test_client_prefers_explicit_then_environment_then_repo_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            explicit = self._executable(root, "explicit-kfuzz", "explicit")
            env_client = self._executable(root, "env-kfuzz", "env")
            default = self._executable(root / "runs/rfuzz_client_native_build/target/debug", "kfuzz", "default")
            verilator = self._executable(root, "verilator", "Verilator 5.020 test")
            environment = {"MYFUZZ_RFuzz_CLIENT": str(env_client)}
            self.assertEqual(str(explicit), resolve_rfuzz_toolchain(root, {"client_binary": str(explicit), "verilator": str(verilator)}, environment=environment)["client"]["path"])
            self.assertEqual(str(env_client), resolve_rfuzz_toolchain(root, {"verilator": str(verilator)}, environment=environment)["client"]["path"])
            self.assertEqual(str(default), resolve_rfuzz_toolchain(root, {"verilator": str(verilator)}, environment={})["client"]["path"])

    def test_unavailable_and_version_mismatch_are_concrete_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            verilator = self._executable(root, "verilator", "Verilator 5.051")
            with self.assertRaisesRegex(RfuzzToolchainError, "rfuzz-client-unavailable"):
                resolve_rfuzz_toolchain(root, {"verilator": str(verilator)}, environment={})
            client = self._executable(root, "kfuzz", "client")
            with self.assertRaisesRegex(RfuzzToolchainError, "rfuzz-verilator-version-mismatch"):
                resolve_rfuzz_toolchain(root, {"client_binary": str(client), "verilator": str(verilator)}, environment={})

    def test_normalization_merges_equivalent_legacy_fields_and_rejects_conflicts(self):
        config = {"client_binary": "kfuzz", "duration_seconds": 5, "seed_cycles": 3,
                  "rfuzz": {"client_binary": "kfuzz", "duration_seconds": 5, "seed_cycles": 3,
                            "verilator": "bundled", "run_dir": "runs/live",
                            "build_cache_dir": "runs/cache", "arm": "direct_input"}}
        normal = normalize_rfuzz_config(config)
        self.assertEqual("kfuzz", normal["client_binary"])
        self.assertEqual("bundled", normal["verilator"])
        self.assertEqual("direct_input", normal["arm"])
        with self.assertRaisesRegex(ValueError, "rfuzz:conflict:duration_seconds"):
            normalize_rfuzz_config({"duration_seconds": 5, "rfuzz": {"duration_seconds": 6}})

    def test_legacy_client_alias_is_resolved_and_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            client = self._executable(root, "legacy-kfuzz", "kfuzz")
            verilator = self._executable(root, "verilator", "Verilator 5.020")
            result = resolve_rfuzz_toolchain(
                root, {"client": str(client), "verilator": str(verilator)}, environment={})
            self.assertEqual(str(client), result["client"]["path"])
        with self.assertRaisesRegex(ValueError, "rfuzz:conflict:client_binary"):
            normalize_rfuzz_config({
                "client": "legacy-kfuzz",
                "rfuzz": {"client_binary": "nested-kfuzz"},
            })

    def test_rejects_non_regular_or_non_executable_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            client = root / "kfuzz"
            client.write_text("not executable", encoding="utf-8")
            verilator = self._executable(root, "verilator", "Verilator 5.020")
            with self.assertRaisesRegex(RfuzzToolchainError, "rfuzz-client-unavailable"):
                resolve_rfuzz_toolchain(root, {"client_binary": str(client), "verilator": str(verilator)}, environment={})

    def test_bundled_environment_override_is_not_labelled_bundled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundled = self._executable(
                root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin",
                "verilator", "Verilator 5.020 bundled")
            override = self._executable(root, "override-verilator", "Verilator 5.020 override")
            client = self._executable(root, "kfuzz", "kfuzz")
            result = resolve_rfuzz_toolchain(
                root, {"client_binary": str(client), "verilator": "bundled"},
                environment={"MYFUZZ_SERVER_VERILATOR_BIN": str(override)})
        self.assertEqual(str(override), result["verilator"]["path"])
        self.assertEqual("environment-override", result["verilator"]["source"])
        self.assertNotEqual(str(bundled), result["verilator"]["path"])

    def test_injected_environment_controls_verilator_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundled = self._executable(
                root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin",
                "verilator", "Verilator 5.020 bundled")
            injected = self._executable(root, "injected-verilator", "Verilator 5.020 injected")
            ambient = self._executable(root, "ambient-verilator", "Verilator 5.020 ambient")
            client = self._executable(root, "kfuzz", "kfuzz")
            with patch.dict(os.environ, {"MYFUZZ_SERVER_VERILATOR_BIN": str(ambient)}, clear=False):
                result = resolve_rfuzz_toolchain(
                    root, {"client_binary": str(client), "verilator": "bundled"},
                    environment={"MYFUZZ_SERVER_VERILATOR_BIN": str(injected)})
        self.assertEqual(str(injected), result["verilator"]["path"])
        self.assertNotEqual(str(ambient), result["verilator"]["path"])

    def test_run_directory_and_effective_environment_identity_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            client = self._executable(root, "kfuzz", "kfuzz")
            verilator = self._executable(root, "verilator", "Verilator 5.020")
            result = resolve_rfuzz_toolchain(
                root,
                {"client_binary": str(client), "verilator": str(verilator),
                 "run_dir": "runs/campaign"},
                environment={"KEEP_ME": "yes"})
        self.assertEqual(str(root / "runs/campaign"), result["run_dir"])
        self.assertEqual(result["run_dir"], result["client"]["working_dir"])
        self.assertRegex(result["verilator_environment_sha256"], r"^[0-9a-f]{64}$")

    def test_empty_explicit_client_is_rejected(self):
        with self.assertRaisesRegex(RfuzzToolchainError, "rfuzz-client-unavailable"):
            resolve_rfuzz_toolchain(
                Path("/tmp").resolve(),
                {"client_binary": "", "verilator": "bundled"}, environment={})

    def test_preflight_reports_a_concrete_toolchain_category(self):
        config = {"config_id": "toolchain", "cpu": "cpu", "duration_seconds": 1,
                  "client_binary": "missing-kfuzz", "rfuzz": {"verilator": "bundled"}}
        with tempfile.TemporaryDirectory() as directory, patch(
            "myfuzz.integration.soc_campaign.probe_soc_dependencies",
            return_value={"ready": True, "status": "ready"},
        ):
            report = preflight_soc_campaign(config, root=Path(directory), environment={})
        self.assertEqual("rfuzz-client-unavailable", report["toolchain"]["category"])
        self.assertFalse(report["ready"])

    def test_preflight_client_report_matches_environment_selected_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            client = self._executable(root, "env-kfuzz", "kfuzz")
            verilator = self._executable(root, "verilator", "Verilator 5.020")
            config = {"config_id": "toolchain", "cpu": "cpu", "duration_seconds": 1,
                      "verilator": str(verilator)}
            with patch(
                "myfuzz.integration.soc_campaign.probe_soc_dependencies",
                return_value={"ready": True, "status": "ready"},
            ):
                report = preflight_soc_campaign(
                    config, root=root,
                    environment={"MYFUZZ_RFuzz_CLIENT": str(client)})
        self.assertTrue(report["toolchain"]["ready"])
        self.assertTrue(report["client"]["requested"])
        self.assertEqual(str(client), report["client"]["path"])

    def test_profile_verilator_helper_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = self._executable(root, "real-verilator", "Verilator 5.020")
            link = root / "verilator-link"
            link.symlink_to(target)
            with self.assertRaisesRegex(RfuzzToolchainError, "rfuzz-verilator-unavailable"):
                resolve_rfuzz_verilator_toolchain(
                    root, {"verilator": str(link)}, environment={})

    def test_profile_verilator_helper_marks_environment_override_and_hashes_full_env(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            override = self._executable(root, "override-verilator", "Verilator 5.020 override")
            first = resolve_rfuzz_verilator_toolchain(
                root, {"verilator": "bundled"},
                environment={"MYFUZZ_SERVER_VERILATOR_BIN": str(override), "CXX": "cc1"})
            second = resolve_rfuzz_verilator_toolchain(
                root, {"verilator": "bundled"},
                environment={"MYFUZZ_SERVER_VERILATOR_BIN": str(override), "CXX": "cc2"})
        self.assertEqual("environment-override", first["verilator"]["source"])
        self.assertNotEqual(first["environment_sha256"], second["environment_sha256"])

    def test_profile_verilator_helper_normalizes_nested_cache_and_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tool = self._executable(root, "verilator", "Verilator 5.020")
            result = resolve_rfuzz_verilator_toolchain(
                root,
                {"rfuzz": {"verilator": str(tool), "build_cache_dir": "cache"}},
                environment={})
        self.assertEqual(str(root / "cache"), result["build_cache_dir"])
        with self.assertRaisesRegex(ValueError, "rfuzz:conflict:verilator"):
            resolve_rfuzz_verilator_toolchain(
                root, {"verilator": "a", "rfuzz": {"verilator": "b"}}, environment={})
