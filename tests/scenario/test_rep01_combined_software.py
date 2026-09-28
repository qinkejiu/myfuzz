"""One continuous software scene calibrates frozen response and reset state."""

import tempfile
from pathlib import Path
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class _SoftwareCpu:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 4096),),
            initialization_seed=91, max_initialized_bytes=4096)
        self.service = MemoryService(self.memory, TransactionLedger())
        self.local_ticks = 0
        self.reset_epoch = 0
        self._case_id = ""
        self._stage = 0
        self._snapshot = None

    def identity_document(self):
        return {"fixture": "rep01_software_cpu.v1"}

    @property
    def pending_responses(self):
        return int(self._snapshot is not None)

    def begin_case(self, testcase_id):
        self._case_id = testcase_id

    def reset_local(self):
        cancelled = self.pending_responses
        self._snapshot = None
        self._stage = 0
        self.reset_epoch += 1
        return {"cancelled_responses": cancelled}

    def step_local(self, inputs):
        self.local_ticks += 1
        self._stage += 1
        output = {"irq_taken_pre": int(inputs.get("irq", 0)),
                  "data_rsp_consumed": 0, "data_rsp_rdata": 0,
                  "data_rsp_source_epoch": 0,
                  "data_rsp_source_sequence": 0}
        if self._stage == 1:
            key = TransactionKey("software-execution", self._case_id, "cpu",
                                 self.reset_epoch, "data", 1)
            self._snapshot = self.service.read(key, 0x300, width_bytes=4)
        elif self._stage == 2:
            key = TransactionKey("software-execution", self._case_id, "cpu",
                                 self.reset_epoch, "data", 2)
            self.service.write(key, 0x300, 0x5500,
                               width_bytes=4, byte_enable=0b0010)
        elif self._stage == 3:
            snapshot = self._snapshot
            self._snapshot = None
            output.update(data_rsp_consumed=1,
                          data_rsp_rdata=snapshot.value,
                          data_rsp_source_epoch=self.reset_epoch,
                          data_rsp_source_sequence=1)
        self.memory.advance_step()
        return output

    def end_case(self):
        pass


class _SoftwareIrqSource:
    def __init__(self):
        self.local_ticks = 0
        self._stage = 0

    def identity_document(self):
        return {"fixture": "rep01_software_irq.v1"}

    def begin_case(self, testcase_id):
        pass

    def reset_local(self):
        self._stage = 0
        return {"cancelled_responses": 0}

    def step_local(self, inputs):
        self.local_ticks += 1
        self._stage += 1
        return {"irq": int(self._stage in (2, 4))}

    def end_case(self):
        pass


def make_software_rep01_runner():
    ownership = compile_ownership(
        (InputField("cpu", "irq", 1),),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),))
    return ScenarioRunner(sessions={"cpu": _SoftwareCpu(),
                                    "gpio": _SoftwareIrqSource()},
                          ownership=ownership,
                          bindings=(Binding("gpio", "irq", "cpu", "irq", 1),))


class CombinedSoftwareRep01Tests(unittest.TestCase):
    def test_frozen_read_survives_intervening_write_and_warm_then_cold_reset(self):
        genome = ScenarioGenome(
            testcase_id="rep01-software-combined", direction="CPU_TO_IP_TO_CPU",
            path_id="unknown-read-write-delay-irq-reset",
            schedule_order=("cpu", "gpio"), max_steps=48,
            actions=(), encoding_version=3,
            reset_actions=(
                ResetAction("warm", "warm_all", Trigger("START"),
                            delay_component="cpu", delay_ticks=8),
                ResetAction("cold", "cold_all", Trigger("START"),
                            delay_component="cpu", delay_ticks=16)))
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(genome, make_software_rep01_runner,
                                         bundle)
            self.assertEqual("complete", trace.status)
            events = trace.events
            reads = [e for e in events if e.get("kind") == "memory_read"
                     and e.get("address") == 0x300]
            writes = [e for e in events if e.get("kind") == "memory_write"
                      and e.get("address") == 0x300]
            deliveries = [e for e in events if e.get("component") == "cpu"
                          and e.get("outputs", {}).get("data_rsp_consumed") == 1]
            self.assertEqual([0, 0, 1], [e["generation"] for e in reads])
            self.assertEqual([0b0010] * 3,
                             [e["byte_enable"] for e in writes])
            self.assertEqual(3, len(deliveries))
            for read, write, delivered in zip(reads, writes, deliveries):
                self.assertLess(read["event_id"], write["event_id"])
                self.assertLess(write["event_id"], delivered["event_id"])
                self.assertEqual(read["value"],
                                 delivered["outputs"]["data_rsp_rdata"])
            self.assertEqual(writes[0]["transaction"]["source_epoch"], 0)
            self.assertEqual(["warm_all", "cold_all"],
                             [e["policy"] for e in events
                              if e.get("kind") == "reset_barrier"])
            init = [e for e in events if e.get("kind") == "memory_initialization"
                    and 0x300 <= e.get("byte_offset", -1) < 0x304]
            self.assertEqual(8, len(init))
            self.assertEqual({0, 1}, {e["generation"] for e in init})
            self.assertEqual(6, sum(e.get("component") == "gpio"
                                    and e.get("outputs", {}).get("irq") == 1
                                    for e in events))
            self.assertTrue(replay_evidence_bundle(
                bundle, make_software_rep01_runner).matches)


if __name__ == "__main__":
    unittest.main()
