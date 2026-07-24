from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from myfuzz.experiments import (
    ExperimentConfigurationError,
    load_experiment_config,
    preflight_experiment_sources,
)
from myfuzz.integration.pipeline import run_candidate_pipeline
import myfuzz.integration.pipeline as pipeline_module


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/experiments/ibex_opentitan/experiment.json"


class IbexOpenTitanConfigTests(unittest.TestCase):
    def test_declaration_is_reference_free_and_has_generic_constraints(self) -> None:
        config = load_experiment_config(CONFIG)

        self.assertGreaterEqual(len(config.components), 5)
        self.assertTrue(all(isinstance(item.component_id, int) for item in config.components))
        self.assertTrue(all(item.role for item in config.components))
        self.assertTrue(all(item.role or item.uninterpreted_external for item in config.ports))
        self.assertTrue(all(item.protocol_id and item.field_bindings for item in config.protocol_endpoints))
        self.assertEqual(
            config.source_roots,
            (
                "external_designs/opentitan",
                "third_party/rfuzz/upstream/ibex",
            ),
        )
        self.assertEqual(config.clock_reset.clock_role, "clock")
        self.assertEqual(config.clock_reset.reset_role, "reset")
        self.assertEqual(config.clock_reset.reset_active_level, 0)
        self.assertTrue(config.clock_reset.reset_synchronous)
        self.assertEqual(config.address_constraints.width, 32)
        self.assertEqual(config.address_constraints.alignment_bytes, 4)
        self.assertIsNone(config.reference)
        self.assertNotIn("reference", config.document)
        self.assertNotIn("reference_top", config.document)

    def test_missing_external_sources_are_dependency_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = preflight_experiment_sources(
                load_experiment_config(CONFIG),
                Path(temporary),
            )

        self.assertEqual(result.status, "dependency_unavailable")
        self.assertEqual(result.sources, ())
        self.assertEqual(
            result.missing_paths,
            (
                "external_designs/opentitan/hw/ip/gpio/rtl/gpio.sv",
                "external_designs/opentitan/hw/ip/rv_timer/rtl/rv_timer.sv",
                "external_designs/opentitan/hw/ip/uart/rtl/uart.sv",
                "third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv",
            ),
        )

    def test_source_outside_declared_roots_is_rejected(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["source_lists"][0]["files"][0] = "external_designs/unapproved/core.sv"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "experiment.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ExperimentConfigurationError, "declared source_roots"):
                load_experiment_config(path)

    def test_source_symlink_cannot_escape_declared_root(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["source_roots"] = ["allowed"]
        document["source_lists"][0]["files"] = ["allowed/escape.sv"]
        document["source_lists"][1]["files"] = ["allowed/peripheral.sv"]
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            allowed = repo_root / "allowed"
            outside = repo_root / "outside"
            allowed.mkdir()
            outside.mkdir()
            (outside / "private.sv").write_text("module private; endmodule\n", encoding="ascii")
            (allowed / "escape.sv").symlink_to(outside / "private.sv")
            (allowed / "peripheral.sv").write_text("module p; endmodule\n", encoding="ascii")
            path = repo_root / "experiment.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(ExperimentConfigurationError, "escapes declared source_root"):
                preflight_experiment_sources(load_experiment_config(path), repo_root)

    def test_source_symlink_loop_is_reported_as_a_configuration_error(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["source_roots"] = ["allowed"]
        document["source_lists"][0]["files"] = ["allowed/loop.sv"]
        document["source_lists"][1]["files"] = ["allowed/peripheral.sv"]
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            allowed = repo_root / "allowed"
            allowed.mkdir()
            (allowed / "loop.sv").symlink_to("loop.sv")
            (allowed / "peripheral.sv").write_text("module p; endmodule\n", encoding="ascii")
            path = repo_root / "experiment.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(ExperimentConfigurationError, "cannot resolve source path"):
                preflight_experiment_sources(load_experiment_config(path), repo_root)

    def test_available_sources_expose_typed_constraints_to_composition(self) -> None:
        class RequestObserved(Exception):
            pass

        config = load_experiment_config(CONFIG)
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            for source_list in config.source_lists:
                for declared_file in source_list.files:
                    source = repo_root / declared_file
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("module declared_source; endmodule\n", encoding="ascii")
            output = repo_root / "out"

            def observe_request(request: object) -> list[dict[str, object]]:
                self.assertEqual(request.clock_reset, config.clock_reset)
                self.assertEqual(request.address_constraints, config.address_constraints)
                self.assertFalse(hasattr(request, "document"))
                self.assertFalse(hasattr(request, "reference"))
                self.assertFalse(hasattr(request, "path"))
                raise RequestObserved

            with self.assertRaises(RequestObserved):
                run_candidate_pipeline(
                    CONFIG,
                    output_dir=output,
                    top_k=3,
                    dry_run=True,
                    composition_producer=observe_request,
                    runtime_preparer=lambda _candidate, _request: {},
                    memory_state_path=repo_root / "memory-tokens.json",
                    repo_root=repo_root,
                )

    def test_verified_source_capabilities_survive_cwd_and_path_replacement(self) -> None:
        class RequestObserved(Exception):
            pass

        config = load_experiment_config(CONFIG)
        declared = "third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv"
        observed_capabilities: list[object] = []
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as other:
            repo_root = Path(temporary)
            source = repo_root / declared
            source.parent.mkdir(parents=True)
            source.write_bytes(b"original source\n")
            for source_list in config.source_lists:
                for declared_file in source_list.files:
                    path = repo_root / declared_file
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if not path.exists():
                        path.write_bytes(b"module declared_source; endmodule\n")
            output = repo_root / "out"
            original_cwd = Path.cwd()
            try:
                os.chdir(other)

                def observe(request: object) -> list[dict[str, object]]:
                    self.assertEqual(request.source_roots[0], repo_root / "external_designs/opentitan")
                    capability = next(
                        item for item in request.sources if item.declared_path == declared
                    )
                    observed_capabilities.append(capability)
                    before = capability.read_bytes()
                    with capability.open() as first, capability.open() as second:
                        self.assertEqual(first.read(), before)
                        self.assertEqual(second.read(), before)
                    source.unlink()
                    source.write_bytes(b"replacement source\n")
                    self.assertEqual(capability.read_bytes(), before)
                    self.assertTrue(all(item.resolved_path.is_absolute() for item in request.sources))
                    raise RequestObserved

                with self.assertRaises(RequestObserved):
                    run_candidate_pipeline(
                        CONFIG,
                        output_dir=output,
                        top_k=3,
                        dry_run=True,
                        composition_producer=observe,
                        runtime_preparer=lambda _candidate, _request: {},
                        memory_state_path=repo_root / "memory-tokens.json",
                        repo_root=repo_root,
                    )
                with self.assertRaisesRegex(ValueError, "closed"):
                    observed_capabilities[0].read_bytes()
            finally:
                os.chdir(original_cwd)

    def test_source_capabilities_close_when_request_construction_fails(self) -> None:
        config = load_experiment_config(CONFIG)
        observed: list[object] = []
        with tempfile.TemporaryDirectory() as temporary:
            repo_root = Path(temporary)
            for source_list in config.source_lists:
                for declared_file in source_list.files:
                    source = repo_root / declared_file
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("module declared_source; endmodule\n", encoding="ascii")

            def capture_preflight(*args: object, **kwargs: object) -> object:
                dependency = preflight_experiment_sources(*args, **kwargs)
                observed.append(dependency)
                return dependency

            with mock.patch.object(
                pipeline_module,
                "preflight_experiment_sources",
                side_effect=capture_preflight,
            ), mock.patch.object(
                pipeline_module,
                "GenerationRequest",
                side_effect=RuntimeError("request construction failed"),
            ):
                with self.assertRaisesRegex(RuntimeError, "request construction failed"):
                    run_candidate_pipeline(
                        CONFIG,
                        output_dir=repo_root / "out",
                        top_k=3,
                        dry_run=True,
                        composition_producer=lambda _request: [],
                        runtime_preparer=lambda _candidate, _request: {},
                        memory_state_path=repo_root / "memory-tokens.json",
                        repo_root=repo_root,
                    )

            try:
                self.assertTrue(observed)
                self.assertTrue(
                    all(
                        capability.descriptor < 0
                        for capability in observed[0].capabilities
                    )
                )
            finally:
                for dependency in observed:
                    dependency.close()

    def test_generated_components_have_no_input_files_and_topology_is_balanced(self) -> None:
        config = load_experiment_config(CONFIG)
        self.assertEqual(
            {path for source_list in config.source_lists for path in source_list.files},
            {
                "external_designs/opentitan/hw/ip/gpio/rtl/gpio.sv",
                "external_designs/opentitan/hw/ip/rv_timer/rtl/rv_timer.sv",
                "external_designs/opentitan/hw/ip/uart/rtl/uart.sv",
                "third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv",
            },
        )
        generated = {component.component_id for component in config.components if component.generated}
        self.assertEqual(generated, {1205, 1206, 1207})
        self.assertTrue(all(not component.source_list_ids for component in config.components if component.generated))
        by_protocol: dict[tuple[str, str], dict[str, int]] = {}
        for endpoint in config.protocol_endpoints:
            counts = by_protocol.setdefault((endpoint.protocol_id, endpoint.version), {"initiator": 0, "target": 0})
            counts[endpoint.side] += 1
        self.assertEqual(by_protocol[("obi", "1")], {"initiator": 1, "target": 1})
        self.assertEqual(by_protocol[("tl-ul", "1")], {"initiator": 5, "target": 5})
        declarations = config.clock_reset.declarations
        declared_ports = {(item.component_id, item.port_id, item.kind, item.domain_id) for item in declarations}
        self.assertEqual(
            len(declared_ports),
            sum(port.role in {"clock", "reset"} for port in config.ports),
        )

    def test_pipeline_skips_producers_when_dependencies_are_unavailable(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out"
            result = run_candidate_pipeline(
                CONFIG,
                output_dir=output,
                top_k=3,
                dry_run=True,
                composition_producer=lambda _request: calls.append("composition") or [],
                runtime_preparer=lambda _candidate, _request: calls.append("runtime") or {},
                repo_root=Path(temporary),
            )

            self.assertEqual(result["status"], "dependency_unavailable")
            self.assertEqual(result["candidate_count"], 0)
            self.assertEqual(result["manifests"], [])
            self.assertEqual(calls, [])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
