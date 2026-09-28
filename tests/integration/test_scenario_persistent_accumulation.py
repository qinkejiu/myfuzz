"""Real Ibex/GPIO state must accumulate across two external IRQ rounds."""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.ip_cpu_ip_example import make_external_gpio_ibex_gpio_runner
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.replay import record_scenario


def audit_persistent_accumulation(events):
    """Audit the committed RAM chain; this consumes observations, not DUT predictions.

    The two rising external GPIO values encode increments in bits 14:8.  Each
    later CPU RAM read must observe the preceding committed Store's value and
    version before the ISR can commit its next sum.
    """
    rises = [event for event in events if event.get("kind") == "source_injection"
             and event.get("component") == "gpio_b"
             and event.get("value", 0) & 0x8000]
    writes = [event for event in events if event.get("kind") == "memory_write"
              and event.get("address") == 0x200]
    reads = [event for event in events if event.get("kind") == "memory_read"
             and event.get("address") == 0x200]
    if len(rises) != 2 or len(writes) != 2:
        return ("two_rounds_missing",)
    findings = []
    previous_value = 5
    previous_version = None
    previous_writer = None
    for index, (rise, write) in enumerate(zip(rises, writes), start=1):
        window = [event for event in reads
                  if rise["event_id"] < event["event_id"] < write["event_id"]]
        if len(window) != 1:
            findings.append(f"round_{index}:ram_read_missing_or_duplicated")
            continue
        read = window[0]
        if read["value"] != previous_value:
            findings.append(f"round_{index}:stale_prior_store")
            if previous_writer is not None and read.get("writer_event_ids") and all(
                    writer == previous_writer
                    for writer in read["writer_event_ids"]):
                findings.append(f"round_{index}:writer_value_conflict")
        if previous_version is not None and (
                not read.get("versions") or
                tuple(read["versions"][0]) != previous_version):
            findings.append(f"round_{index}:stale_prior_version")
        if previous_writer is not None and (
                not read.get("writer_event_ids") or
                any(writer != previous_writer
                    for writer in read["writer_event_ids"])):
            findings.append(f"round_{index}:stale_prior_writer")
        increment = (rise["value"] >> 8) & 0x7f
        if write["value"] != read["value"] + increment:
            findings.append(f"round_{index}:wrong_accumulated_store")
        previous_value = write["value"]
        previous_version = tuple(write["version"])
        previous_writer = str(TransactionKey(**write["transaction"]))
    tail = [event for event in reads
            if event["event_id"] > writes[-1]["event_id"]]
    if not tail or tail[0]["value"] != previous_value or (
            not tail[0].get("versions") or
            tuple(tail[0]["versions"][0]) != previous_version):
        findings.append("final_ram_read_not_last_store")
    return tuple(findings)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class PersistentAccumulationTests(unittest.TestCase):
    def test_harness_state_rebuild_after_first_store_is_detected_during_real_continuation(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario" /
                                     "external_gpio_ibex_gpio_accumulate.json").read_bytes())
        injected = []

        def faulting_factory():
            runner = make_external_gpio_ibex_gpio_runner()
            memory = runner.sessions["cpu"].memory
            actual_write = memory.write
            actual_read = memory.read
            first_store = []

            def observe_store(address, value, *, width_bytes, byte_enable,
                              writer_event_id):
                version = actual_write(address, value, width_bytes=width_bytes,
                                       byte_enable=byte_enable,
                                       writer_event_id=writer_event_id)
                if address == 0x200 and not first_store:
                    first_store.append((value, version, writer_event_id))
                return version

            def corrupt_before_next_load(address, width_bytes, *, transaction_id):
                if address == 0x200 and first_store and not injected:
                    self.assertEqual(8, first_store[0][0])
                    # Explicit harness fault: corrupt S's data bytes only.
                    # Keep the real Store's version/writer so the next actual
                    # CPU Load exposes a value/writer inconsistency. This is
                    # never represented as a DUT output or ordinary Store.
                    before = tuple(memory._bytes[("ram", 0x200 + lane)]
                                   for lane in range(4))
                    self.assertEqual((8, 0, 0, 0),
                                     tuple(cell.value for cell in before))
                    for lane, cell in enumerate(before):
                        memory._bytes[("ram", 0x200 + lane)] = replace(
                            cell, value=(5 >> (8 * lane)) & 0xff)
                    injected.append({"kind": "harness_fault_injection",
                                     "address": 0x200, "value": 5,
                                     "after_store": first_store[0],
                                     "preserved_writer": before[0].writer_event_id,
                                     "preserved_version": before[0].version})
                return actual_read(address, width_bytes,
                                   transaction_id=transaction_id)

            memory.write = observe_store
            memory.read = corrupt_before_next_load
            return runner

        trace = record_scenario(genome, faulting_factory)
        self.assertEqual("complete", trace.status,
                         [event for event in trace.events
                          if event.get("kind") in ("harness_failure", "begin_failure")])
        self.assertEqual(1, len(injected), "the harness fault must fire once")
        self.assertEqual([8, 14], [event["value"] for event in trace.events
                                   if event.get("kind") == "memory_write" and
                                   event.get("address") == 0x200])
        self.assertFalse(any(event.get("kind") == "reset_barrier"
                             for event in trace.events))
        rises = [event for event in trace.events
                 if event.get("kind") == "source_injection" and
                 event.get("component") == "gpio_b" and
                 event.get("value", 0) & 0x8000]
        writes = [event for event in trace.events
                  if event.get("kind") == "memory_write" and
                  event.get("address") == 0x200]
        second_read = next(event for event in trace.events
                           if event.get("kind") == "memory_read" and
                           event.get("address") == 0x200 and
                           rises[1]["event_id"] < event["event_id"] <
                           writes[1]["event_id"])
        self.assertEqual(5, second_read["value"])
        source_sequence = second_read["transaction"]["source_sequence"]
        source_epoch = second_read["transaction"]["source_epoch"]
        self.assertTrue(any(event.get("component") == "cpu" and
                            event.get("outputs", {}).get("data_rsp_consumed") == 1 and
                            event["outputs"].get("data_rsp_rdata") == 5 and
                            event["outputs"].get("data_rsp_source_sequence") ==
                            source_sequence and
                            event["outputs"].get("data_rsp_source_epoch") == source_epoch
                            and second_read["event_id"] < event["event_id"] <
                            writes[1]["event_id"] for event in trace.events))
        a_writes = [event for event in trace.events
                    if event.get("kind") == "mmio_delivery" and
                    event.get("device_id") == "gpio_a" and
                    event.get("offset") == 0x14 and event.get("write")]
        self.assertEqual([0x800, 0xe00],
                         [event["write_value"] for event in a_writes])
        self.assertTrue(any(event.get("component") == "gpio_a" and
                            event.get("outputs", {}).get("gpio_out") == 0xe00 and
                            a_writes[1]["event_id"] < event["event_id"]
                            for event in trace.events))
        self.assertTrue(any(event.get("kind") == "memory_read" and
                            event.get("address") == 0x200 and
                            event.get("value") == 14 and
                            event["event_id"] > writes[1]["event_id"]
                            for event in trace.events))
        findings = audit_persistent_accumulation(trace.events)
        self.assertIn("round_2:stale_prior_store", findings)
        self.assertIn("round_2:writer_value_conflict", findings)
        self.assertNotIn("round_2:stale_prior_version", findings)
        self.assertNotIn("round_2:stale_prior_writer", findings)

    def test_external_values_accumulate_in_real_cpu_ram_and_gpio_output(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario" /
                                     "external_gpio_ibex_gpio_accumulate.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            trace = save_evidence_bundle(
                genome, make_external_gpio_ibex_gpio_runner,
                Path(directory) / "bundle")
            events = trace.events
            source = [event for event in events if event.get("kind") ==
                      "source_injection" and event.get("component") == "gpio_b"]
            self.assertEqual([0x8300, 0x0300, 0x8900],
                             [event["value"] for event in source])
            self.assertFalse(any(event.get("kind") == "reset_barrier"
                                 for event in events))
            writes = [event for event in events if event.get("kind") ==
                      "memory_write" and event.get("address") == 0x200]
            self.assertEqual([8, 17], [event["value"] for event in writes])
            self.assertEqual((), audit_persistent_accumulation(events))
            # Offline fault injection: these copied records are deliberately
            # corrupted evidence, never presented as fresh RTL observations.
            reconstructed = deepcopy(events)
            second_read = next(event for event in reconstructed
                               if event.get("kind") == "memory_read" and
                               event.get("address") == 0x200 and
                               source[2]["event_id"] < event["event_id"] <
                               writes[1]["event_id"])
            second_read["value"] = 5
            second_read["versions"] = deepcopy(next(
                event["versions"] for event in reconstructed
                if event.get("kind") == "memory_read" and
                event.get("address") == 0x200 and
                source[0]["event_id"] < event["event_id"] <
                writes[0]["event_id"]))
            second_write = next(event for event in reconstructed
                                if event.get("event_id") == writes[1]["event_id"])
            second_write["value"] = 14  # Injected 5 + second increment 9.
            self.assertIn("round_2:stale_prior_store",
                          audit_persistent_accumulation(reconstructed))
            self.assertIn("round_2:stale_prior_version",
                          audit_persistent_accumulation(reconstructed))
            self.assertEqual(2, len({event["transaction"]["source_sequence"]
                                     for event in writes}))
            reads = [event for event in events if event.get("kind") ==
                     "memory_read" and event.get("address") == 0x200]
            self.assertTrue(any(event["event_id"] > writes[-1]["event_id"]
                                and event.get("value") == 17 for event in reads))
            first_read = next(event for event in reads
                              if source[0]["event_id"] < event["event_id"] <
                              writes[0]["event_id"])
            second_read = next(event for event in reads
                               if source[2]["event_id"] < event["event_id"] <
                               writes[1]["event_id"])
            self.assertEqual((5, 8), (first_read["value"], second_read["value"]))
            self.assertEqual(tuple(writes[0]["version"]),
                             tuple(second_read["versions"][0]))
            self.assertEqual(tuple(writes[1]["version"]),
                             tuple(next(event for event in reads
                                        if event["event_id"] > writes[1]["event_id"])
                                   ["versions"][0]))
            a_writes = [event for event in events if event.get("kind") ==
                        "mmio_delivery" and event.get("device_id") == "gpio_a"
                        and event.get("offset") == 0x14 and event.get("write")]
            self.assertEqual([0x800, 0x1100],
                             [event["write_value"] for event in a_writes])
            for index, output in enumerate((0x800, 0x1100)):
                lower = a_writes[index]["event_id"]
                upper = (a_writes[index + 1]["event_id"]
                         if index + 1 < len(a_writes) else float("inf"))
                self.assertTrue(any(event.get("component") == "gpio_a" and
                                    event.get("outputs", {}).get("gpio_out") == output
                                    and lower < event["event_id"] < upper
                                    for event in events))
            b_reads = [event for event in events if event.get("kind") ==
                       "mmio_delivery" and event.get("device_id") == "gpio_b"
                       and event.get("offset") == 0x10 and not event.get("write")]
            self.assertEqual([0x8300, 0x8900],
                             [event["read_value"] for event in b_reads])
            self.assertTrue(source[0]["event_id"] < b_reads[0]["event_id"] <
                            writes[0]["event_id"] < a_writes[0]["event_id"] <
                            source[1]["event_id"] < source[2]["event_id"] <
                            b_reads[1]["event_id"] < writes[1]["event_id"] <
                            a_writes[1]["event_id"])
            for read in b_reads:
                tx = read["source_transaction"]
                self.assertTrue(any(event.get("component") == "cpu" and
                                    event.get("outputs", {}).get("data_rsp_consumed") == 1
                                    and event["outputs"].get("data_rsp_rdata") ==
                                    read["read_value"] and
                                    event["outputs"].get("data_rsp_source_sequence") ==
                                    tx["source_sequence"] and
                                    event["outputs"].get("data_rsp_source_epoch") ==
                                    tx["source_epoch"]
                                    for event in events))
            irq_rises = []
            prior_irq = 0
            for event in events:
                if event.get("component") != "gpio_b" or "outputs" not in event:
                    continue
                irq = event["outputs"].get("irq")
                if irq == 1 and prior_irq == 0:
                    irq_rises.append(event)
                if irq in (0, 1):
                    prior_irq = irq
            self.assertEqual([0x8300, 0x8900],
                             [event["inputs"]["gpio_in"] for event in irq_rises])
            first_irq = irq_rises[0]
            self.assertLess(first_irq["event_id"], writes[0]["event_id"])
            self.assertTrue(any(event.get("kind") == "dataflow_delivery" and
                                event.get("producer_event_id") == first_irq["event_id"]
                                and event.get("source") == ("gpio_b", "irq") and
                                event.get("target") == ("cpu", "irq") and
                                event.get("value") == 1 for event in events))
            self.assertTrue(any(event.get("component") == "cpu" and
                                event.get("outputs", {}).get("irq_taken_pre") == 1 and
                                first_irq["event_id"] < event["event_id"] <
                                writes[0]["event_id"] for event in events))
            final = json.loads((Path(directory) / "bundle" /
                                "final_state.json").read_text())
            self.assertEqual(0, final["inputs"]["cpu"]["irq"])
            self.assertTrue(all(v == 0 for v in final["pending_responses"].values()))
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{root / 'src'}:{root}"
            replay = subprocess.run(
                (sys.executable, str(root / "scripts/replay_scenario.py"),
                 "--evidence", str(Path(directory) / "bundle"), "--factory",
                 "myfuzz.scenario.ip_cpu_ip_example:"
                 "make_external_gpio_ibex_gpio_runner", "--rebuild",
                 "--compare-trace"), cwd=root, env=environment,
                capture_output=True, text=True, timeout=180)
            self.assertEqual(0, replay.returncode, replay.stderr)
            self.assertTrue(json.loads(replay.stdout)["matches"])


if __name__ == "__main__":
    unittest.main()
