"""A physical campaign wall cut replays its semantic prefix, not elapsed time."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.integration.scenario_rfuzz_replay import (
    _wall_cut_factory, _wall_cut_mismatch, replay_scenario_rfuzz_corpus,
)


def _digest(events):
    return hashlib.sha256(json.dumps(
        events, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


class WallCutReplayTests(unittest.TestCase):
    def marker(self):
        prefix = [{"event_id": 1, "kind": "source_injection", "value": 3}]
        return prefix, {
            "event_id": 2, "kind": "budget_exhausted",
            "limit": "max_wall_time_ms", "phase": "inflight_step",
            "effect_may_have_occurred": True,
            "prefix_event_count": 1,
            "prefix_local_ticks": {"cpu": 2},
            "local_ticks": {"cpu": 3},
            "semantic_prefix_sha256": _digest(prefix),
        }

    def test_factory_arms_saved_semantic_boundary_after_budget(self):
        _, marker = self.marker()

        class Runner:
            def __init__(self):
                self._resource_budget = SimpleNamespace(max_wall_time_ms=5000)

            def set_replay_wall_cut(self, steps, phase, **kwargs):
                self.cut = (steps, phase, kwargs)

        runner = _wall_cut_factory(Runner, marker)()
        self.assertEqual((2, "inflight_step", {"prefix_event_count": 1}),
                         runner.cut)

    def test_cut_uses_all_prefix_local_ticks_not_post_cut_ticks(self):
        _, marker = self.marker()
        marker["prefix_local_ticks"] = {"cpu": 2, "gpio_a": 3,
                                        "gpio_b": 4}
        marker["local_ticks"] = {"cpu": 7, "gpio_a": 8, "gpio_b": 9}

        class Runner:
            def set_replay_wall_cut(self, steps, phase, **kwargs):
                self.cut = (steps, phase, kwargs)

        runner = _wall_cut_factory(Runner, marker)()
        self.assertEqual((9, "inflight_step", {"prefix_event_count": 1}),
                         runner.cut)

    def test_prefix_replay_accepts_same_prefix_and_rejects_changed_event(self):
        prefix, marker = self.marker()
        actual = SimpleNamespace(
            status="budget_exhausted",
            events=tuple(prefix + [{key: value for key, value in marker.items()
                                    if key != "semantic_prefix_sha256"}]),
            local_ticks={"cpu": 2})
        self.assertIsNone(_wall_cut_mismatch(marker, actual))
        changed = SimpleNamespace(**{**vars(actual),
                                     "events": ({**prefix[0], "value": 4},)
                                     + actual.events[1:]})
        self.assertIn("semantic prefix", _wall_cut_mismatch(marker, changed))

    def test_replay_rejects_missing_budget_marker(self):
        prefix, marker = self.marker()
        actual = SimpleNamespace(status="complete", events=tuple(prefix),
                                 local_ticks={"cpu": 2})
        self.assertIn("budget", _wall_cut_mismatch(marker, actual))

    def test_begin_cut_accepts_json_list_for_started_components(self):
        marker = {
            "kind": "budget_exhausted", "limit": "max_wall_time_ms",
            "phase": "inflight_begin", "effect_may_have_occurred": True,
            "failed_component": "b", "started_components": ["a"],
            "prefix_event_count": 0, "prefix_local_ticks": {"a": 0, "b": 0},
            "local_ticks": {"a": 0, "b": 0},
            "semantic_prefix_sha256": _digest([]),
        }

        class Runner:
            def __init__(self):
                self._resource_budget = SimpleNamespace(max_wall_time_ms=5000)

            def set_replay_wall_cut(self, steps, phase, **kwargs):
                self.cut = (steps, phase, kwargs)

        runner = _wall_cut_factory(Runner, marker)()
        self.assertEqual((0, "inflight_begin", {
            "prefix_event_count": 0,
            "failed_component": "b", "started_components": ("a",)}),
            runner.cut)
        actual = SimpleNamespace(status="budget_exhausted",
                                 events=({**marker,
                                          "started_components": ("a",)},))
        self.assertIsNone(_wall_cut_mismatch(marker, actual))

    def test_saved_corpus_uses_cut_factory_and_prefix_comparison(self):
        prefix, marker = self.marker()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "corpus").mkdir()
            manifest = {"decoder": "stub"}
            (output / "decoder_manifest.json").write_text(json.dumps(manifest))
            (output / "report.json").write_text(json.dumps({
                "decoder_manifest_sha256": hashlib.sha256(_digest_bytes(
                    manifest)).hexdigest()}))
            (output / "targets.json").write_text(json.dumps([{
                "target_id": "target", "component": "cpu", "port": "irq",
                "mask": 1, "value": 1}]))
            raw = bytes(8)
            (output / "corpus" / "entry_0000.json").write_text(json.dumps({
                "entry": {"inputs": list(raw)}}))
            prior = {"raw_sha256": hashlib.sha256(raw).hexdigest(),
                     "genome_sha256": "genome", "path_id": "path",
                     "manifest_sha256": "manifest", "semantic_sha256": "physical",
                     "status": "budget_exhausted", "total_local_ticks": 3,
                     "coverage_hex": "00", "wall_cut": marker}
            (output / "receipts.jsonl").write_text(json.dumps(prior) + "\n")

            class Runner:
                def set_replay_wall_cut(self, steps, phase, **kwargs):
                    self.cut = (steps, phase, kwargs)

            class Executor:
                def __init__(self, **kwargs):
                    self.factory = kwargs["factory"]
                    self.receipts = []

                def execute_batch(self, batch):
                    runner = self.factory()
                    assert runner.cut == (2, "inflight_step",
                                          {"prefix_event_count": 1})
                    replay_marker = {key: value for key, value in marker.items()
                                     if key != "semantic_prefix_sha256"}
                    trace = SimpleNamespace(status="budget_exhausted",
                                            events=tuple(prefix + [replay_marker]))
                    self.receipts.append(SimpleNamespace(
                        trace=trace, genome_sha256="genome", path_id="path",
                        manifest_sha256="manifest"))

            with patch("myfuzz.integration.scenario_rfuzz_replay."
                       "GenomeRecordDecoder.from_document",
                       return_value=SimpleNamespace(max_records=1)), \
                    patch("myfuzz.integration.scenario_rfuzz_replay."
                          "ScenarioRfuzzExecutor", Executor):
                result = replay_scenario_rfuzz_corpus(output, Runner)
            self.assertEqual((1, 1, ()), (result.total_entries,
                                          result.matched_entries,
                                          result.mismatches))


def _digest_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
