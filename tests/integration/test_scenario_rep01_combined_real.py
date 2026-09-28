"""One real RTL testcase combines the persistent replay obligations."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec, ResetAction, Trigger
from myfuzz.scenario.ledger import TransactionKey


ROOT = Path(__file__).resolve().parents[2]


def _sb(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15
            | (offset & 31) << 7 | 0x23)


def combined_genome():
    """Add an unknown RAM read and one byte store to a two IRQ round program."""
    base = GenomeCodec.decode((ROOT / "configs/scenario/"
                               "ibex_two_gpio_closed_two_rounds.json").read_bytes())
    main = base.initial_images[0]
    words = [int.from_bytes(main.data[i:i + 4], "little")
             for i in range(0, len(main.data), 4)]
    words[3:3] = [0x30002283, _sb(2, 0, 0x301)]
    images = (replace(main, data_hex=b"".join(
        word.to_bytes(4, "little") for word in words).hex()),
        *base.initial_images[1:])
    return replace(base, testcase_id="rep01-combined-ibex-gpio",
                   path_id="rep01-unknown-be-delay-irq-reset",
                   initial_images=images, max_steps=1010,
                   reset_actions=(
                       ResetAction("warm-after-two-rounds", "warm_all",
                                   Trigger("START"), delay_component="cpu",
                                   delay_ticks=110),
                       ResetAction("cold-after-four-rounds", "cold_all",
                                   Trigger("START"), delay_component="cpu",
                                   delay_ticks=220)))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class CombinedRep01RealTests(unittest.TestCase):
    def test_multi_component_material_tamper_rejected_before_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            save_evidence_bundle(combined_genome(), make_ibex_two_gpio_runner,
                                 original, gpio_check_devices=("gpio_a",))
            created = []

            def counted_factory():
                created.append(True)
                return make_ibex_two_gpio_runner()

            for name, filename, mutate, expected in (
                ("genome", "genome.bin", lambda data: data.replace(
                    b'rep01-combined-ibex-gpio', b'rep01-combined-ibex-gpiX'),
                 "genome JSON disagrees"),
                ("firmware", "images/0000.bin", lambda data:
                 bytes([data[0] ^ 1]) + data[1:],
                 "image material disagrees"),
                ("rules", "manifest.json", lambda data:
                 data.replace(b'"target_component":"gpio_a"',
                              b'"target_component":"gpio_x"', 1),
                 "manifest identity mismatch"),
                ("initial_seed", "manifest.json", lambda data:
                 data.replace(b'"initialization_seed":47',
                              b'"initialization_seed":48', 1),
                 "manifest identity mismatch"),
                ("harness", "factory_source.json", lambda data:
                 data.replace(b'make_ibex_two_gpio_runner',
                              b'make_ibex_two_gpio_runneX'),
                 "factory source identity mismatch"),
            ):
                with self.subTest(material=name):
                    changed = root / name
                    shutil.copytree(original, changed)
                    target = changed / filename
                    before = target.read_bytes()
                    after = mutate(before)
                    self.assertNotEqual(before, after)
                    target.write_bytes(after)
                    index_path = changed / "bundle_index.json"
                    index = json.loads(index_path.read_text())
                    index["files"][filename] = hashlib.sha256(after).hexdigest()
                    index_path.write_text(json.dumps(index))
                    with self.assertRaisesRegex(ValueError, expected):
                        replay_evidence_bundle(changed, counted_factory)
                    self.assertEqual([], created)

    def test_multi_component_live_output_and_resume_boundaries(self):
        def changed_live_b_factory():
            runner = make_ibex_two_gpio_runner()
            session = runner.sessions["gpio_b"]
            original_step = session.step_local
            altered = False

            def changed_step(inputs):
                nonlocal altered
                outputs = dict(original_step(inputs))
                if not altered:
                    outputs["irq"] ^= 1
                    altered = True
                return outputs

            session.step_local = changed_step
            return runner

        def missing_live_capture_factory():
            runner = make_ibex_two_gpio_runner()

            def unavailable(_inputs):
                raise RuntimeError("live GPIO B output capture unavailable")

            runner.sessions["gpio_b"].step_local = unavailable
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "combined"
            save_evidence_bundle(combined_genome(), make_ibex_two_gpio_runner,
                                 bundle, gpio_check_devices=("gpio_a",))
            changed = replay_evidence_bundle(
                bundle, changed_live_b_factory, allow_factory_mismatch=True)
            self.assertFalse(changed.matches)
            self.assertEqual("gpio_b", changed.difference_context["component"])
            self.assertEqual(1, changed.difference_context["local_tick"])
            missing = replay_evidence_bundle(
                bundle, missing_live_capture_factory,
                allow_factory_mismatch=True)
            self.assertFalse(missing.matches)
            self.assertEqual("gpio_b", missing.difference_context["component"])
            self.assertTrue(replay_evidence_bundle(
                bundle, make_ibex_two_gpio_runner).matches)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
            result = subprocess.run(
                (sys.executable, str(ROOT / "scripts/replay_scenario.py"),
                 "--evidence", str(bundle), "--factory",
                 "myfuzz.scenario.examples:make_ibex_two_gpio_runner",
                 "--resume", str(bundle / "final_state.json")),
                cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsupported_checkpoint_resume", result.stderr)

    def test_multi_component_replay_reports_first_memory_commit_divergence(self):
        def changed_first_unknown_byte_factory():
            runner = make_ibex_two_gpio_runner()
            memory = runner.sessions["cpu"].memory
            original_initial_byte = memory._initial_byte

            def changed_initial_byte(memory_id, offset):
                value = original_initial_byte(memory_id, offset)
                return value ^ 1 if (memory_id, offset) == ("ram", 0x300) else value

            memory._initial_byte = changed_initial_byte
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case"
            save_evidence_bundle(combined_genome(), make_ibex_two_gpio_runner,
                                 bundle, gpio_check_devices=("gpio_a",))
            comparison = replay_evidence_bundle(
                bundle, changed_first_unknown_byte_factory,
                allow_factory_mismatch=True)
            self.assertFalse(comparison.matches)
            self.assertIsNotNone(comparison.first_difference)
            context = comparison.difference_context
            self.assertEqual("cpu", context["component"])
            self.assertEqual("ram", context["memory_id"])
            self.assertEqual(0x300, context["byte_offset"])
            self.assertEqual("init:ram:768", context["writer_event_id"])
            self.assertNotEqual(context["expected"]["value"],
                                context["actual"]["value"])

    def test_one_continuous_real_trace_contains_all_rep01_obligations(self):
        genome = combined_genome()
        self.assertEqual(
            GenomeCodec.encode(genome),
            (ROOT / "configs/scenario/rep01_combined_ibex_two_gpio.json")
            .read_bytes().rstrip(b"\n"))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "case"
            trace = save_evidence_bundle(
                genome, make_ibex_two_gpio_runner, bundle,
                gpio_check_devices=("gpio_a",))
            events = trace.events
            self.assertEqual("complete", trace.status)
            self.assertEqual(["warm_all", "cold_all"],
                             [e["policy"] for e in events
                              if e.get("kind") == "reset_barrier"])
            materialized = [e for e in events
                            if e.get("kind") == "memory_initialization"
                            and 0x300 <= e.get("byte_offset", -1) < 0x304]
            self.assertEqual({0, 1}, {e["generation"] for e in materialized})
            self.assertEqual(8, len(materialized))
            reads = [e for e in events if e.get("kind") == "memory_read"
                     and e.get("address") == 0x300]
            self.assertEqual([0, 0, 1], [e["generation"] for e in reads])
            partial_writes = [e for e in events
                              if e.get("kind") == "memory_write"
                              and e.get("address") == 0x300
                              and e.get("byte_enable") == 0b0010]
            self.assertEqual([0, 0, 1],
                             [e["generation"] for e in partial_writes])
            self.assertEqual(str(TransactionKey(**partial_writes[0]["transaction"])),
                             reads[1]["writer_event_ids"][1])
            self.assertEqual(reads[0]["writer_event_ids"][0],
                             reads[2]["writer_event_ids"][0])
            self.assertEqual("init:ram:769", reads[2]["writer_event_ids"][1])
            self.assertNotEqual(reads[0]["value"], reads[1]["value"])
            warm_writer = str(TransactionKey(**partial_writes[0]["transaction"]))
            warm_reader = str(TransactionKey(**reads[1]["transaction"]))
            cold_reader = str(TransactionKey(**reads[2]["transaction"]))
            self.assertTrue(any(
                e.get("kind") == "state_dependency"
                and e.get("edge_kind") == "PERSIST"
                and e.get("memory_id") == "ram"
                and e.get("byte_offset") == 0x301
                and e.get("generation") == 0
                and e.get("source") == warm_writer
                and e.get("target") == warm_reader
                for e in events))
            self.assertTrue(any(
                e.get("kind") == "state_dependency"
                and e.get("edge_kind") == "PERSIST"
                and e.get("memory_id") == "ram"
                and e.get("byte_offset") == 0x301
                and e.get("generation") == 1
                and e.get("source") == "init:ram:769"
                and e.get("target") == cold_reader
                for e in events))
            self.assertFalse(any(
                e.get("kind") == "state_dependency"
                and e.get("edge_kind") in ("RAW", "PERSIST")
                and e.get("source") == warm_writer
                and e.get("target") == cold_reader
                for e in events))
            self.assertTrue(any(e.get("kind") == "state_dependency"
                                and e.get("edge_kind") == "INVALIDATE"
                                and e.get("generation") == 0
                                for e in events))
            for read in reads:
                transaction = read["transaction"]
                consumed = [e for e in events if e.get("component") == "cpu"
                            and e.get("outputs", {}).get("data_rsp_consumed") == 1
                            and e["outputs"]["data_rsp_source_epoch"] ==
                            transaction["source_epoch"]
                            and e["outputs"]["data_rsp_source_sequence"] ==
                            transaction["source_sequence"]]
                self.assertEqual(1, len(consumed))
                self.assertGreater(consumed[0]["event_id"], read["event_id"])
                producer = next(e for e in events
                                if e["event_id"] == read["producer_event_id"])
                self.assertGreater(consumed[0]["local_tick"],
                                   producer["local_tick"])
                self.assertEqual(transaction["source_epoch"],
                                 sum(e.get("kind") == "reset_barrier" and
                                     e["event_id"] < consumed[0]["event_id"]
                                     for e in events))
                self.assertEqual(read["value"],
                                 consumed[0]["outputs"]["data_rsp_rdata"])
            irq_rises = []
            irq_falls = []
            prior = 0
            for event in events:
                if event.get("component") != "gpio_b" or "outputs" not in event:
                    continue
                level = event["outputs"]["irq"]
                if level and not prior:
                    irq_rises.append(event)
                if prior and not level:
                    irq_falls.append(event)
                prior = level
            self.assertGreaterEqual(len(irq_rises), 6)
            w1c = [e for e in events if e.get("kind") == "mmio_delivery"
                   and e.get("device_id") == "gpio_b"
                   and e.get("offset") == 0 and e.get("write")]
            self.assertGreaterEqual(len(w1c), 6)
            self.assertEqual(len(w1c), len({str(e["source_transaction"]) for e in w1c}))
            taken = [e for e in events if e.get("component") == "cpu"
                     and e.get("outputs", {}).get("irq_taken_pre") == 1]
            self.assertGreaterEqual(len(taken), 6)
            for epoch in range(3):
                boundaries = [0, *(e["event_id"] for e in events
                                   if e.get("kind") == "reset_barrier"),
                              len(events) + 1]
                within = lambda e: boundaries[epoch] < e["event_id"] < boundaries[epoch + 1]
                self.assertGreaterEqual(sum(within(e) for e in irq_rises), 2)
                self.assertGreaterEqual(sum(within(e) for e in taken), 2)
                self.assertGreaterEqual(sum(within(e) for e in w1c), 2)
            for clear in w1c:
                self.assertTrue(any(fall["event_id"] > clear["event_id"]
                                    and not any(rise["event_id"] > clear["event_id"]
                                                and rise["event_id"] < fall["event_id"]
                                                for rise in irq_rises)
                                    for fall in irq_falls))
            self.assertEqual(0, [e for e in events if e.get("component") == "gpio_b"
                                 and "outputs" in e][-1]["outputs"]["irq"])
            self.assertEqual(0, [e for e in events if e.get("component") == "cpu"
                                 and "inputs" in e][-1]["inputs"]["irq"])
            compared = replay_evidence_bundle(bundle, make_ibex_two_gpio_runner)
            self.assertTrue(compared.matches, compared.difference_context)
            self.assertEqual(trace.semantic_sha256,
                             compared.actual_trace.semantic_sha256)


if __name__ == "__main__":
    unittest.main()
