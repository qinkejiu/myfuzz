from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition.auto import _generic_dependencies
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.integration.low_resource_smoke import run_generic_composition_smoke
from myfuzz.experiments.resource_policy import (
    CONSERVATIVE_PROFILE,
    apply_resource_profile,
)
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import (
    ChannelRelationSpec,
    FieldSpec,
    ProjectionActionSpec,
    ProtocolPlugin,
)


_COMPONENTS = ("ram", "uart", "gpio", "clint", "plic")
_PROTOCOLS = tuple((f"bounded-mmio-{component}", "1") for component in _COMPONENTS)
_PROTOCOL = _PROTOCOLS[0]


def _bounded_protocol() -> ProtocolCatalog:
    plugins = []
    for protocol_id, version in _PROTOCOLS:
        plugins.append(
            _bounded_plugin(protocol_id, version)
        )
    return ProtocolCatalog(tuple(plugins))


def _bounded_plugin(protocol_id: str, version: str) -> ProtocolPlugin:
    return ProtocolCatalog(
        (
            ProtocolPlugin(
                protocol_id,
                version,
                (
                    FieldSpec("addr", "host_to_device", "address_width", True, 0),
                    FieldSpec("valid", "host_to_device", "1", True, 0),
                    FieldSpec("ready", "device_to_host", "1", True, 0),
                    FieldSpec("wdata", "host_to_device", "data_width", True, 0),
                    FieldSpec("rdata", "device_to_host", "data_width", True, 0),
                    FieldSpec("error", "device_to_host", "1", True, 0),
                    FieldSpec("irq", "device_to_host", "1", False, 0),
                ),
                (),
                (ProjectionActionSpec(1, ("valid",), "gate", "protocol_legality", 16),),
                (),
                (ChannelRelationSpec(1, "request_response_handshake", ("valid", "ready", "rdata")),),
                (
                    ("max_outstanding", 1),
                    ("bursts", False),
                    ("ids", False),
                    ("single_beat_only", True),
                    ("ordering", "in_order_single_id"),
                    ("completion", "ack_or_err"),
                    ("max_wait_cycles", 16),
                ),
            ),
        )
    ).plugins[0]


def _cpu_source() -> str:
    ports = []
    for component in _COMPONENTS:
        ports.extend(
            (
                f"input logic clk_{component}",
                f"input logic rst_{component}",
                f"output logic [15:0] {component}_addr",
                f"output logic {component}_valid",
                f"input logic {component}_ready",
                f"output logic [31:0] {component}_wdata",
                f"input logic [31:0] {component}_rdata",
                f"input logic {component}_error",
                f"input logic {component}_irq",
            )
        )
    declarations = ",\n  ".join(ports)
    assignments = []
    for index, component in enumerate(_COMPONENTS):
        assignments.append(
            f"  always_ff @(posedge clk_{component} or negedge rst_{component}) begin\n"
            f"    if (!rst_{component}) begin\n"
            f"      {component}_valid <= 1'b0;\n"
            "    end else begin\n"
            f"      {component}_valid <= 1'b1;\n"
            f"      {component}_addr <= 16'h{index * 16:04x};\n"
            f"      {component}_wdata <= 32'h{index + 1:08x};\n"
            "    end\n"
            "  end"
        )
    return (
        "module synthetic_cpu(\n  "
        + declarations
        + "\n);\n"
        + "\n".join(assignments)
        + "\nendmodule\n"
    )


def _component_source(module: str) -> str:
    return f"""module {module}(
  input logic clock,
  input logic reset,
  input logic [15:0] addr,
  input logic valid,
  output logic ready,
  input logic [31:0] wdata,
  output logic [31:0] rdata,
  output logic error,
  output logic irq
);
  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
      ready <= 1'b0;
      rdata <= '0;
      irq <= 1'b0;
    end else begin
      ready <= valid;
      rdata <= wdata ^ addr;
      irq <= 1'b0;
    end
  end
  assign error = 1'b0;
endmodule
"""


def _fixture(root: Path, endpoint_names: tuple[str, ...] = _COMPONENTS):
    source_root = root / "source"
    cpu = source_root / "rtl" / "synthetic_cpu.sv"
    cpu.parent.mkdir(parents=True)
    cpu.write_text(_cpu_source(), encoding="utf-8")
    for component in _COMPONENTS:
        path = root / f"{component}.sv"
        path.write_text(_component_source(component), encoding="utf-8")

    endpoints = []
    for component in endpoint_names:
        endpoints.append(
            {
                "endpoint_id": f"cpu.{component}",
                "function": "memory_master",
                "module": "synthetic_cpu",
                "protocol": list(next(protocol for protocol in _PROTOCOLS if protocol[0].endswith(component))),
                "fields": [
                    {"role": "clock", "aliases": [f"clk_{component}"]},
                    {"role": "reset", "aliases": [f"rst_{component}"]},
                    {"role": "addr", "aliases": [f"{component}_addr"]},
                    {"role": "valid", "aliases": [f"{component}_valid"]},
                    {"role": "ready", "aliases": [f"{component}_ready"]},
                    {"role": "wdata", "aliases": [f"{component}_wdata"]},
                    {"role": "rdata", "aliases": [f"{component}_rdata"]},
                    {"role": "error", "aliases": [f"{component}_error"]},
                    {"role": "irq", "aliases": [f"{component}_irq"]},
                ],
            }
        )
    description = load_interface_description(
        {
            "schema_version": "interface_description.v1",
            "source": {
                "root": "source",
                "revision": source_tree_hash(source_root, (cpu,)),
                "top_module": "synthetic_cpu",
                "files": ["rtl/synthetic_cpu.sv"],
            },
            "endpoints": endpoints,
        }
    )
    profiles = tuple(
        PeripheralProfile(
            component,
            component,
            (next(protocol for protocol in _PROTOCOLS if protocol[0].endswith(component)),),
            0x1000,
            0x1000,
            True,
            (),
            "implemented",
            (f"{component}.sv",),
            True,
            {},
        )
        for component in _COMPONENTS
    )
    return description, ComponentCatalog(profiles), _bounded_protocol()


class GenericLowResourceSmokeTests(unittest.TestCase):
    def _request(self, description, components=_COMPONENTS):
        return GenericCompositionRequest(
            description,
            components,
            _PROTOCOLS,
            seed=19,
        )

    def _assert_rejected(self, root: Path, request, catalog, protocols) -> dict[str, object]:
        output = root / "published"
        result = run_generic_composition_smoke(
            root,
            request,
            output_dir=output,
            component_catalog=catalog,
            protocol_catalog=protocols,
            timeout_seconds=17,
        )
        self.assertNotEqual(result["status"], "passed")
        self.assertFalse(result["published"])
        self.assertEqual([], result["artifact_paths"])
        self.assertFalse(output.exists())
        self.assertTrue(result["functional_diagnostics"])
        self.assertEqual([], result["resource_diagnostics"])
        return result

    def test_synthetic_cpu_and_ram_uart_gpio_clint_plic_publish_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root)
            result = run_generic_composition_smoke(
                root,
                self._request(description),
                output_dir=root / "published",
                component_catalog=catalog,
                protocol_catalog=protocols,
                timeout_seconds=17,
            )

            self.assertEqual("passed", result["status"])
            self.assertTrue(result["published"])
            self.assertEqual(
                {"composition_ir.json", "input_layout.json", "generic_composition_top.sv", "sources.f"},
                {Path(path).name for path in result["artifact_paths"]},
            )
            self.assertEqual(5, len(result["capabilities"]))
            self.assertEqual(5, len(result["ir"]["components"]))
            self.assertEqual(5, len(result["ir"]["address_regions"]))
            self.assertEqual(5, len(result["ir"]["irq_routes"]))
            self.assertEqual(1, result["runtime_policy"]["build_concurrency"])
            self.assertEqual(1, result["runtime_policy"]["frontend_concurrency"])
            self.assertFalse(result["runtime_policy"]["waveforms"])
            self.assertEqual(17, result["runtime_policy"]["timeout_seconds"])
            self.assertEqual("metadata-only", result["runtime_policy"]["enforcement"])
            self.assertEqual(
                "not-applied-by-generic-smoke",
                result["runtime_policy"]["rss_enforcement"],
            )
            self.assertIn("synthetic_cpu", result["annotations"]["source"]["modules"])
            self.assertTrue(result["ir"]["source_file_ids"])

    def test_missing_cpu_source_fails_closed_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root)
            (root / "source" / "rtl" / "synthetic_cpu.sv").unlink()
            result = self._assert_rejected(root, self._request(description), catalog, protocols)
            self.assertIn("source", " ".join(str(item) for item in result["functional_diagnostics"]))

    def test_existing_output_is_preserved_and_not_reported_as_a_new_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root, ("ram",))
            output = root / "published"
            output.mkdir()
            sentinel = output / "caller-owned.txt"
            sentinel.write_text("keep", encoding="utf-8")
            result = run_generic_composition_smoke(
                root,
                self._request(description, ("ram",)),
                output_dir=output,
                component_catalog=catalog,
                protocol_catalog=protocols,
            )
            self.assertNotEqual("passed", result["status"])
            self.assertEqual([], result["artifact_paths"])
            self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_ambiguous_endpoint_fails_closed_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root, ("ram", "uart"))
            ambiguous = replace(
                description,
                endpoints=(
                    description.endpoints[0],
                    replace(description.endpoints[1], protocol=_PROTOCOL),
                ),
            )
            result = self._assert_rejected(root, self._request(ambiguous, ("ram",)), catalog, protocols)
            self.assertIn("ambiguous", " ".join(str(item) for item in result["functional_diagnostics"]))

    def test_invalid_protocol_feature_fails_closed_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root, ("ram",))
            plugin = protocols.plugins[0]
            invalid = ProtocolCatalog((replace(plugin, capability_limits=(("max_outstanding", 1),)),))
            result = self._assert_rejected(root, self._request(description, ("ram",)), catalog, invalid)
            self.assertIn("single-channel", " ".join(str(item) for item in result["functional_diagnostics"]))

    def test_overlapping_address_regions_fail_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description, catalog, protocols = _fixture(root, ("ram",))
            plan = plan_generic_composition(
                self._request(description, ("ram",)),
                base_dir=root,
                component_catalog=catalog,
                protocol_catalog=protocols,
            )
            region = dict(plan.ir["address_regions"][0])
            duplicate = dict(region)
            duplicate["component_id"] = "forged0"
            forged = dict(plan.ir)
            forged["address_regions"] = [region, duplicate]
            object.__setattr__(plan, "ir", forged)
            with self.assertRaisesRegex(ValueError, "address-overlap"):
                write_generic_composition(plan, root / "published", base_dir=root)
            self.assertFalse((root / "published").exists())

    def test_dependency_cycle_fails_closed_without_a_publication_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _description, catalog, _protocols = _fixture(root, ("ram", "uart"))
            left = replace(catalog.require("ram"), component_type="left", requires=("right",))
            right = replace(catalog.require("uart"), component_type="right", requires=("left",))
            with self.assertRaisesRegex(ValueError, "generic:dependency-cycle"):
                _generic_dependencies({"left": left, "right": right})
            self.assertFalse((root / "published").exists())

    def test_resource_profile_forces_one_frontend_worker_and_bounded_runtime(self) -> None:
        config = {
            "candidate_selection": {"k": 8},
            "candidate_pair": {"seeds": [1, 2, 3]},
            "budgets": [{"name": "smoke", "kind": "seconds", "value": 60}],
            "soft_memory_bytes": 2 * 1024 * 1024 * 1024,
            "hard_memory_bytes": 3 * 1024 * 1024 * 1024,
            "token_bytes": 128 * 1024 * 1024,
            "build_concurrency": 4,
            "frontend_concurrency": 4,
            "waveforms": True,
            "replay_queue_capacity": 1000,
            "event_ring_capacity": 1000,
            "field_groups_per_batch": 100,
        }
        effective = apply_resource_profile(config, CONSERVATIVE_PROFILE)
        self.assertEqual(1, effective["build_concurrency"])
        self.assertEqual(1, effective["frontend_concurrency"])
        self.assertFalse(effective["waveforms"])
        self.assertLessEqual(effective["replay_queue_capacity"], 32)
        self.assertLessEqual(effective["event_ring_capacity"], 512)
        self.assertLessEqual(effective["field_groups_per_batch"], 16)
        self.assertLessEqual(effective["soft_memory_bytes"], CONSERVATIVE_PROFILE.soft_memory_bytes)
        self.assertLessEqual(effective["hard_memory_bytes"], CONSERVATIVE_PROFILE.hard_memory_bytes)


if __name__ == "__main__":
    unittest.main()
