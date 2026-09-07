from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.components import load_builtin_component_catalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.composition.protocol_manifest import (
    load_protocol_composition,
    validate_protocol_composition,
)
from myfuzz.composition.registry import default_component_registry
from myfuzz.isa import CpuCatalog, CpuProfile, load_builtin_cpu_catalog
from myfuzz.protocols.catalog import load_protocol_catalog

from myfuzz.composition.auto import (
    AutoCompositionError,
    AutoCompositionRequest,
    plan_auto_composition,
    write_auto_composition_manifest,
)


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "src" / "myfuzz" / "protocols" / "plugins"
LOCAL_CPU_SOURCE = (
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_multicomponent_ip_top.sv"
)


def _executable_cpu_catalog(
    *,
    integration_protocols: tuple[tuple[str, str], ...] = (
        ("tl-ul", "1"),
        ("apb", "4"),
        ("axi4-lite", "1"),
    ),
) -> CpuCatalog:
    return CpuCatalog(
        (
            CpuProfile(
                cpu_id="fixture.rv32i",
                vendor="test",
                xlen=(32,),
                extensions=("I",),
                core_native_protocols=(("ready-valid-mmio", "1"),),
                integration_protocols=integration_protocols,
                source_status="implemented",
                source_paths=(LOCAL_CPU_SOURCE,),
                implemented=True,
            ),
        )
    )


def _request(
    *,
    component_types: tuple[str, ...] = ("timer", "gpio", "uart", "spi"),
    protocol_preferences: tuple[tuple[str, str], ...] = (
        ("apb", "4"),
        ("axi4-lite", "1"),
        ("tl-ul", "1"),
    ),
    **overrides: object,
) -> AutoCompositionRequest:
    values: dict[str, object] = {
        "cpu_id": "fixture.rv32i",
        "component_types": component_types,
        "protocol_preferences": protocol_preferences,
    }
    values.update(overrides)
    return AutoCompositionRequest(**values)  # type: ignore[arg-type]


class AutoCompositionTests(unittest.TestCase):
    def plan(self, request: AutoCompositionRequest) -> object:
        return plan_auto_composition(
            request,
            cpu_catalog=_executable_cpu_catalog(),
            component_catalog=load_builtin_component_catalog(),
            root=ROOT,
        )

    def test_executable_fixture_selects_protocols_and_deterministic_resources(self) -> None:
        plan = self.plan(_request())

        self.assertTrue(plan.complete, plan.diagnostics)  # type: ignore[attr-defined]
        components = plan.components  # type: ignore[attr-defined]
        self.assertEqual(
            [component["component_id"] for component in components],
            ["gpio0", "spi0", "timer0", "uart0"],
        )
        self.assertEqual(
            [
                (component["protocol"]["id"], component["protocol"]["version"])
                for component in components
            ],
            [
                ("apb", "4"),
                ("axi4-lite", "1"),
                ("apb", "4"),
                ("axi4-lite", "1"),
            ],
        )
        self.assertEqual(
            [component["base"] for component in components],
            [0x80010000, 0x80011000, 0x80012000, 0x80013000],
        )
        self.assertEqual([component["size"] for component in components], [0x1000] * 4)
        self.assertEqual([component["irq"] for component in components], [1, 2, 3, 4])
        self.assertEqual(plan.dependencies, ())  # type: ignore[attr-defined]
        self.assertTrue(plan.content_hash.startswith("sha256:"))  # type: ignore[attr-defined]

    def test_declared_component_dependencies_are_normalized_and_recorded(self) -> None:
        source = "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_timer.sv"
        component_catalog = ComponentCatalog(
            (
                PeripheralProfile(
                    component_type="memory",
                    module_name="fixture_memory",
                    protocols=(("tl-ul", "1"),),
                    address_alignment=4096,
                    default_size=4096,
                    irq_capable=False,
                    requires=(),
                    source_status="implemented",
                    source_paths=(source,),
                    implemented=True,
                    parameter_limits={},
                ),
                PeripheralProfile(
                    component_type="child",
                    module_name="fixture_child",
                    protocols=(("apb", "4"),),
                    address_alignment=4096,
                    default_size=4096,
                    irq_capable=True,
                    requires=("memory",),
                    source_status="implemented",
                    source_paths=(source,),
                    implemented=True,
                    parameter_limits={},
                ),
            )
        )
        request = _request(
            component_types=("child", "memory"),
            protocol_preferences=(("apb", "4"), ("tl-ul", "1")),
        )

        plan = plan_auto_composition(
            request,
            cpu_catalog=_executable_cpu_catalog(),
            component_catalog=component_catalog,
            root=ROOT,
        )

        self.assertTrue(plan.complete, plan.diagnostics)
        self.assertEqual(plan.dependencies, (("child0", "memory0"),))

    def test_missing_declared_dependency_is_an_incomplete_plan(self) -> None:
        source = "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_timer.sv"
        component_catalog = ComponentCatalog(
            (
                PeripheralProfile(
                    component_type="child",
                    module_name="fixture_child",
                    protocols=(("apb", "4"),),
                    address_alignment=4096,
                    default_size=4096,
                    irq_capable=True,
                    requires=("memory",),
                    source_status="implemented",
                    source_paths=(source,),
                    implemented=True,
                    parameter_limits={},
                ),
                PeripheralProfile(
                    component_type="memory",
                    module_name="fixture_memory",
                    protocols=(("tl-ul", "1"),),
                    address_alignment=4096,
                    default_size=4096,
                    irq_capable=False,
                    requires=(),
                    source_status="implemented",
                    source_paths=(source,),
                    implemented=True,
                    parameter_limits={},
                ),
            )
        )

        plan = plan_auto_composition(
            _request(component_types=("child",)),
            cpu_catalog=_executable_cpu_catalog(),
            component_catalog=component_catalog,
            root=ROOT,
        )

        self.assertFalse(plan.complete)
        self.assertIn("dependency:child0:missing:memory0", plan.diagnostics)

    def test_implemented_component_with_missing_source_is_not_selected(self) -> None:
        component_catalog = ComponentCatalog(
            (
                PeripheralProfile(
                    component_type="missing",
                    module_name="fixture_missing",
                    protocols=(("apb", "4"),),
                    address_alignment=4096,
                    default_size=4096,
                    irq_capable=False,
                    requires=(),
                    source_status="implemented",
                    source_paths=("configs/does-not-exist.sv",),
                    implemented=True,
                    parameter_limits={},
                ),
            )
        )

        plan = plan_auto_composition(
            _request(component_types=("missing",)),
            cpu_catalog=_executable_cpu_catalog(),
            component_catalog=component_catalog,
            root=ROOT,
        )

        self.assertFalse(plan.complete)
        self.assertIn("component:missing:missing-source", plan.diagnostics)

    def test_incomplete_plan_never_writes_manifest(self) -> None:
        cases = (
            ("duplicate", _request(component_types=("timer", "timer"))),
            ("missing-preferences", _request(protocol_preferences=())),
            (
                "unsupported-cpu-protocol",
                _request(protocol_preferences=(("tl-ul", "1"),)),
            ),
            ("unknown-component", _request(component_types=("unknown",))),
            ("width-mismatch", _request(data_width=64)),
            ("reference-only", _request(component_types=("dma",))),
        )
        for label, request in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                plan = self.plan(request)
                self.assertFalse(plan.complete, plan.diagnostics)
                destination = Path(directory) / "manifest.json"
                destination.write_bytes(b"previous manifest\n")
                with self.assertRaises(AutoCompositionError):
                    write_auto_composition_manifest(plan, destination)
                self.assertEqual(destination.read_bytes(), b"previous manifest\n")

    def test_non_publishable_window_size_is_incomplete(self) -> None:
        plan = self.plan(_request(window_size=0x2000))

        self.assertFalse(plan.complete, plan.diagnostics)
        self.assertTrue(
            any("manifest-size" in diagnostic or "window" in diagnostic for diagnostic in plan.diagnostics),
            plan.diagnostics,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AutoCompositionError):
                write_auto_composition_manifest(plan, Path(directory) / "manifest.json")

    def test_plan_nested_records_are_immutable(self) -> None:
        plan = self.plan(_request(component_types=("timer",)))

        with self.assertRaises(TypeError):
            plan.components[0]["protocol"]["id"] = "axi4"  # type: ignore[index]
        with self.assertRaises(TypeError):
            plan.components[0]["parameters"]["WORDS"] = 1  # type: ignore[index]

    def test_writer_rechecks_source_evidence_at_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "rtl" / "fixture.sv"
            source.parent.mkdir(parents=True)
            source.write_text("module fixture; endmodule\n", encoding="utf-8")
            cpu_catalog = CpuCatalog(
                (
                    CpuProfile(
                        cpu_id="fixture.rv32i",
                        vendor="test",
                        xlen=(32,),
                        extensions=("I",),
                        core_native_protocols=(("ready-valid-mmio", "1"),),
                        integration_protocols=(("apb", "4"),),
                        source_status="implemented",
                        source_paths=("rtl/fixture.sv",),
                        implemented=True,
                    ),
                )
            )
            component_catalog = ComponentCatalog(
                (
                    PeripheralProfile(
                        component_type="timer",
                        module_name="fixture_timer",
                        protocols=(("apb", "4"),),
                        address_alignment=4096,
                        default_size=4096,
                        irq_capable=True,
                        requires=(),
                        source_status="implemented",
                        source_paths=("rtl/fixture.sv",),
                        implemented=True,
                        parameter_limits={},
                    ),
                )
            )
            plan = plan_auto_composition(
                _request(component_types=("timer",)),
                cpu_catalog=cpu_catalog,
                component_catalog=component_catalog,
                root=root,
            )
            self.assertTrue(plan.complete, plan.diagnostics)
            source.unlink()
            destination = root / "manifest.json"
            destination.write_bytes(b"previous manifest\n")
            with self.assertRaisesRegex(AutoCompositionError, "missing"):
                write_auto_composition_manifest(plan, destination)
            self.assertEqual(destination.read_bytes(), b"previous manifest\n")

    def test_builtin_ibex_can_be_revalidated_against_planner_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_paths = set(load_builtin_cpu_catalog().require("ibex.rv32imc").source_paths)
            component_catalog = load_builtin_component_catalog()
            for component_type in ("timer", "gpio"):
                source_paths.update(component_catalog.require(component_type).source_paths)
            for relative_path in source_paths:
                destination = root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("// planner-root fixture source\n", encoding="utf-8")

            plan = plan_auto_composition(
                AutoCompositionRequest(
                    cpu_id="ibex.rv32imc",
                    component_types=("timer", "gpio"),
                    protocol_preferences=(("apb", "4"), ("axi4-lite", "1")),
                ),
                root=root,
            )

        self.assertTrue(plan.complete, plan.diagnostics)

    def test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent(self) -> None:
        request = AutoCompositionRequest(
            cpu_id="ibex.rv32imc",
            component_types=("timer", "gpio", "uart", "spi"),
            protocol_preferences=(("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
        )

        with tempfile.TemporaryDirectory(prefix="myfuzz-missing-cpu-") as temporary:
            root = Path(temporary)
            plan = plan_auto_composition(
                request,
                cpu_catalog=load_builtin_cpu_catalog(root=root),
                component_catalog=load_builtin_component_catalog(),
                root=root,
            )

        self.assertFalse(plan.complete, plan.diagnostics)
        self.assertTrue(
            any("cpu" in diagnostic and "source" in diagnostic for diagnostic in plan.diagnostics),
            plan.diagnostics,
        )

    def test_identical_plans_publish_identical_canonical_manifests(self) -> None:
        request = _request()
        first = self.plan(request)
        second = self.plan(request)

        self.assertEqual(first.components, second.components)
        self.assertEqual(first.dependencies, second.dependencies)
        self.assertEqual(first.content_hash, second.content_hash)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_path = root / "one" / "manifest.json"
            second_path = root / "two" / "manifest.json"
            write_auto_composition_manifest(first, first_path)
            write_auto_composition_manifest(second, second_path)

            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            document = json.loads(first_path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], "protocol_composition.v1")
            self.assertEqual(document["target"]["address_width"], 32)
            self.assertEqual(document["runtime"], {
                "checkpoint_seconds": 30,
                "duration_seconds": 3600,
                "seed": 7,
            })
            manifest = load_protocol_composition(first_path)
            validate_protocol_composition(
                manifest,
                load_protocol_catalog(PLUGIN_DIR),
                default_component_registry(ROOT),
            )


if __name__ == "__main__":
    unittest.main()
