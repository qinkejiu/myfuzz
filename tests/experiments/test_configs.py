from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from myfuzz.experiments import (
    ExperimentConfigurationError,
    load_experiment_config,
    load_experiment_configs,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION_PATHS = (
    ROOT / "configs" / "experiments" / "rvx_generated" / "experiment.json",
    ROOT / "configs" / "experiments" / "ibex_opentitan" / "experiment.json",
)


class ExperimentConfigurationTest(unittest.TestCase):
    def load_mutated_configuration(
        self,
        source: Path,
        mutate: Callable[[dict[str, Any]], None],
    ) -> None:
        document = json.loads(source.read_text(encoding="utf-8"))
        mutate(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            load_experiment_config(path)

    def test_checked_in_configurations_load_through_public_loaders(self) -> None:
        individual = tuple(load_experiment_config(path) for path in CONFIGURATION_PATHS)
        batch = load_experiment_configs(CONFIGURATION_PATHS)

        self.assertEqual(individual, batch)
        self.assertEqual({101, 202}, {configuration.target_id for configuration in batch})
        self.assertTrue(all(configuration.generated_candidate_count == 3 for configuration in batch))
        self.assertTrue(all(configuration.seeds == (1, 7, 19) for configuration in batch))
        self.assertTrue(all(configuration.cycle_budget == 1_000 for configuration in batch))
        self.assertTrue(all(configuration.raw_width == 512 for configuration in batch))
        self.assertTrue(all(configuration.coverage_metric == "branch" for configuration in batch))

    def test_configurations_declare_sources_components_ports_and_protocol_bindings(self) -> None:
        for configuration in load_experiment_configs(CONFIGURATION_PATHS):
            self.assertGreaterEqual(len(configuration.source_lists), 1)
            self.assertGreaterEqual(len(configuration.components), 5)
            self.assertTrue(all(component.port_ids for component in configuration.components))
            self.assertTrue(all(port.role or port.uninterpreted_external for port in configuration.ports))
            self.assertTrue(all(endpoint.field_bindings for endpoint in configuration.protocol_endpoints))
            self.assertTrue(all(endpoint.protocol_id and endpoint.version for endpoint in configuration.protocol_endpoints))

    def test_generated_configurations_are_reference_free(self) -> None:
        first, second = load_experiment_configs(CONFIGURATION_PATHS)

        self.assertIsNone(first.reference)
        self.assertIsNone(second.reference)
        self.assertNotIn("reference", first.document)
        self.assertNotIn("reference", second.document)
        self.assertNotIn("reference_top", first.document)
        self.assertNotIn("reference_top", second.document)

    def test_rejects_unsupported_protocol_identifier_and_version(self) -> None:
        for key, value in (("protocol_id", "unsupported"), ("version", "unsupported")):
            with self.subTest(key=key), self.assertRaisesRegex(
                ExperimentConfigurationError,
                "unsupported protocol version",
            ):
                self.load_mutated_configuration(
                    CONFIGURATION_PATHS[0],
                    lambda document, key=key, value=value: document["protocol_endpoints"][0].update(
                        {key: value}
                    ),
                )

    def test_rejects_incomplete_and_unknown_protocol_field_roles(self) -> None:
        with self.assertRaisesRegex(ExperimentConfigurationError, "missing required field roles"):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[0],
                lambda document: document["protocol_endpoints"][0].update(
                    field_bindings=document["protocol_endpoints"][0]["field_bindings"][:-1]
                ),
            )

        with self.assertRaisesRegex(ExperimentConfigurationError, "unsupported field role"):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[0],
                lambda document: document["protocol_endpoints"][0]["field_bindings"][0].update(
                    field_role="not_a_protocol_field"
                ),
            )

    def test_rejects_reference_top_in_every_configuration(self) -> None:
        for path in CONFIGURATION_PATHS:
            with self.subTest(path=path), self.assertRaisesRegex(
                ExperimentConfigurationError,
                "unsupported top-level fields: reference_top",
            ):
                self.load_mutated_configuration(
                    path,
                    lambda document: document.update(reference_top="reference/top.sv"),
                )

    def test_rejects_evaluator_commands_in_experiment_configuration(self) -> None:
        with self.assertRaisesRegex(
            ExperimentConfigurationError,
            "unsupported top-level fields: reference",
        ):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[0],
                lambda document: document.update(
                    reference={
                        "mode": "evaluation-only",
                        "allowed_stage": "report",
                        "comparison": "shared-stable-source-id",
                        "command": ["reference/evaluate-original-top"],
                    }
                ),
            )

    def test_rejects_other_unsupported_top_level_fields(self) -> None:
        with self.assertRaisesRegex(
            ExperimentConfigurationError,
            "unsupported top-level fields: arbitrary_metadata",
        ):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[0],
                lambda document: document.update(arbitrary_metadata={"unchecked": True}),
            )

    def test_rejects_endpoint_binding_to_another_component_port(self) -> None:
        with self.assertRaisesRegex(
            ExperimentConfigurationError,
            "field binding port must belong to endpoint component",
        ):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[0],
                lambda document: document["protocol_endpoints"][0]["field_bindings"][0].update(
                    port_id=document["protocol_endpoints"][1]["field_bindings"][0]["port_id"]
                ),
            )

    def test_rejects_generated_components_with_input_source_lists(self) -> None:
        with self.assertRaisesRegex(
            ExperimentConfigurationError,
            "generated components cannot declare source lists",
        ):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[1],
                lambda document: document["components"][4].update(source_list_ids=[21]),
            )

    def test_rejects_protocol_endpoint_direction_and_width_mismatches(self) -> None:
        with self.assertRaisesRegex(ExperimentConfigurationError, "protocol endpoint field direction"):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[1],
                lambda document: next(
                    port for port in document["ports"] if port["port_id"] == 2701
                ).update(direction="input"),
            )

        with self.assertRaisesRegex(ExperimentConfigurationError, "protocol endpoint field width"):
            self.load_mutated_configuration(
                CONFIGURATION_PATHS[1],
                lambda document: next(
                    port for port in document["ports"] if port["port_id"] == 2701
                ).update(width=2),
            )

    def test_rejects_parameterized_protocol_width_mismatches(self) -> None:
        for port_id in (2705, 3115):
            with self.subTest(port_id=port_id), self.assertRaisesRegex(
                ExperimentConfigurationError,
                "protocol endpoint field width",
            ):
                self.load_mutated_configuration(
                    CONFIGURATION_PATHS[1],
                    lambda document, port_id=port_id: next(
                        port for port in document["ports"] if port["port_id"] == port_id
                    ).update(width=31),
                )


if __name__ == "__main__":
    unittest.main()
