from __future__ import annotations

import unittest
from pathlib import Path

from myfuzz.experiments import load_experiment_config, load_experiment_configs


ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION_PATHS = (
    ROOT / "configs" / "experiments" / "rvx_generated" / "experiment.json",
    ROOT / "configs" / "experiments" / "ibex_opentitan" / "experiment.json",
)


class ExperimentConfigurationTest(unittest.TestCase):
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

    def test_reference_is_report_only_and_absent_from_reference_free_configuration(self) -> None:
        first, second = load_experiment_configs(CONFIGURATION_PATHS)

        self.assertIsNotNone(first.reference)
        self.assertEqual("evaluation-only", first.reference.mode)
        self.assertEqual("report", first.reference.allowed_stage)
        self.assertIsNotNone(first.reference.command)
        self.assertIsNone(second.reference)
        self.assertNotIn("reference_top", first.document)
        self.assertNotIn("reference_top", second.document)


if __name__ == "__main__":
    unittest.main()
