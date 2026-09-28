"""CVA6 plus two OpenTitan GPIO campaign fixtures and closed-chain evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from myfuzz.scenario.cva6_gpio_example import make_cva6_two_gpio_runner
from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource, SourceBinding,
                                        SourceBindings)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner

from .scenario_campaign import CampaignBlocked, IbexTwoGpioBoundProvider


def _transaction_identity(event: Mapping) -> tuple:
    tx = event.get("source_transaction", event.get("transaction", {}))
    if not isinstance(tx, Mapping):
        return ()
    return tuple(tx.get(key) for key in (
        "execution_id", "testcase_id", "source_component", "source_epoch",
        "channel_id", "source_sequence"))


def assess_cva6_closed_chain(direction: str, events, final_state: Mapping) -> dict | None:
    """Require two ordered real RTL rounds; never infer DUT output from a schedule."""
    if direction not in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
        return None
    stream = tuple(events)
    findings: list[str] = []
    ids = [event.get("event_id") for event in stream]
    if any(type(item) is not int for item in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")

    def find(after, predicate):
        return next((event for event in stream
                     if event.get("event_id", 0) > after and predicate(event)), None)

    b_steps = [event for event in stream
               if event.get("component") == "gpio_b"
               and "irq" in event.get("outputs", {})]
    rises = {event["event_id"] for index, event in enumerate(b_steps)
             if event["outputs"]["irq"] == 1
             and (index == 0 or b_steps[index - 1]["outputs"]["irq"] == 0)}
    falls = {event["event_id"] for index, event in enumerate(b_steps)
             if event["outputs"]["irq"] == 0 and index
             and b_steps[index - 1]["outputs"]["irq"] == 1}
    previous_end = 0
    used_transactions: set[tuple] = set()
    rounds = 0
    for round_index in range(2):
        if direction == "CPU_TO_IP_TO_CPU":
            beginning = find(previous_end, lambda e:
                             e.get("kind") == "mmio_delivery"
                             and e.get("device_id") == "gpio_a"
                             and e.get("offset") == 0x14 and e.get("write") is True
                             and e.get("write_value") in (1, 3))
            if beginning is None:
                findings.append(f"round_{round_index + 1}:cpu_write_a_missing")
                break
            value = beginning["write_value"]
            a_output = find(beginning["event_id"], lambda e:
                            e.get("component") == "gpio_a"
                            and e.get("outputs", {}).get("gpio_out") == value)
            a_delivery = None if a_output is None else find(
                a_output["event_id"], lambda e:
                e.get("kind") == "dataflow_delivery"
                and tuple(e.get("source", ())) == ("gpio_a", "gpio_out")
                and tuple(e.get("target", ())) == ("gpio_b", "gpio_in")
                and e.get("producer_event_id") == a_output["event_id"]
                and e.get("value") == value)
            b_rise = None if a_delivery is None else find(
                a_delivery["event_id"], lambda e:
                e.get("event_id") in rises
                and e.get("inputs", {}).get("gpio_in", -1) & 0xff == value)
        else:
            action_id = ("first-rise", "second-rise")[round_index]
            beginning = find(previous_end, lambda e:
                             e.get("kind") == "source_injection"
                             and e.get("action_id") == action_id
                             and e.get("component") == "gpio_b"
                             and e.get("port") == "gpio_in")
            if beginning is None:
                findings.append(f"round_{round_index + 1}:source_injection_missing")
                break
            relative_value = beginning.get("value")
            bit_offset = beginning.get("bit_offset")
            if (type(relative_value) is not int or type(bit_offset) is not int
                    or bit_offset != 8):
                findings.append(f"round_{round_index + 1}:source_value_invalid")
                break
            value = relative_value << bit_offset
            if not value & 0x100:
                findings.append(f"round_{round_index + 1}:source_value_invalid")
                break
            b_rise = find(beginning["event_id"], lambda e:
                          e.get("event_id") in rises
                          and e.get("inputs", {}).get("gpio_in") == value)
        irq_delivery = None if b_rise is None else find(
            b_rise["event_id"], lambda e:
            e.get("kind") == "dataflow_delivery"
            and tuple(e.get("source", ())) == ("gpio_b", "irq")
            and tuple(e.get("target", ())) == ("cpu", "irq")
            and e.get("producer_event_id") == b_rise["event_id"]
            and e.get("value") == 1)
        cpu_irq = None if irq_delivery is None else find(
            irq_delivery["event_id"], lambda e:
            e.get("component") == "cpu" and e.get("inputs", {}).get("irq", 0) & 1)
        read_b = None if cpu_irq is None else find(
            cpu_irq["event_id"], lambda e:
            e.get("kind") == "mmio_delivery"
            and e.get("device_id") == "gpio_b"
            and e.get("offset") == 0x10 and e.get("write") is False
            and e.get("read_value", 0) & 0xffffffff == value)
        tx = read_b.get("source_transaction", {}) if read_b else {}
        response = None if read_b is None else find(
            read_b["event_id"], lambda e:
            e.get("component") == "cpu"
            and e.get("outputs", {}).get("response_consumed") == 1
            and e["outputs"].get("response_rdata") == read_b["read_value"]
            and e["outputs"].get("response_source_sequence") ==
            tx.get("source_sequence")
            and e["outputs"].get("response_source_epoch") ==
            tx.get("source_epoch"))
        if direction == "IP_TO_CPU_TO_IP":
            a_write = None if response is None else find(
                response["event_id"], lambda e:
                e.get("kind") == "mmio_delivery"
                and e.get("device_id") == "gpio_a"
                and e.get("offset") == 0x14 and e.get("write") is True
                and e.get("write_value", 0) & 0xffffffff == value)
            a_output = None if a_write is None else find(
                a_write["event_id"], lambda e:
                e.get("component") == "gpio_a"
                and e.get("outputs", {}).get("gpio_out") == value)
            ram_after = a_output
        else:
            ram_after = response
        ram = None if ram_after is None else find(
            ram_after["event_id"], lambda e:
            e.get("kind") == "memory_write"
            and e.get("component") == "cpu"
            and e.get("address") == 0x80000200
            and e.get("value", 0) & 0xffffffff == value)
        w1c = None if ram is None else find(
            ram["event_id"], lambda e:
            e.get("kind") == "mmio_delivery"
            and e.get("device_id") == "gpio_b"
            and e.get("offset") == 0 and e.get("write") is True
            and e.get("write_value", 0) & (1 if direction == "CPU_TO_IP_TO_CPU"
                                               else 0x100))
        b_fall = None if w1c is None else find(
            w1c["event_id"], lambda e: e.get("event_id") in falls)
        cpu_low = None if b_fall is None else find(
            b_fall["event_id"], lambda e:
            e.get("component") == "cpu" and not e.get("inputs", {}).get("irq", 0) & 1)
        stages = ([beginning, b_rise, irq_delivery, cpu_irq, read_b,
                   response, ram, w1c, b_fall, cpu_low]
                  if direction == "CPU_TO_IP_TO_CPU" else
                  [beginning, b_rise, irq_delivery, cpu_irq, read_b,
                   response, a_write, a_output, ram, w1c, b_fall, cpu_low])
        if any(stage is None for stage in stages):
            findings.append(f"round_{round_index + 1}:causal_stage_missing")
            break
        if direction == "CPU_TO_IP_TO_CPU" and a_delivery is None:
            findings.append(f"round_{round_index + 1}:a_to_b_missing")
            break
        for event in ([beginning, read_b, ram, w1c]
                      if direction == "CPU_TO_IP_TO_CPU" else
                      [read_b, a_write, ram, w1c]):
            identity = _transaction_identity(event)
            if not identity or any(item is None for item in identity):
                findings.append(f"round_{round_index + 1}:transaction_identity_missing")
            elif identity in used_transactions:
                findings.append(f"round_{round_index + 1}:transaction_reused")
            used_transactions.add(identity)
        previous_end = cpu_low["event_id"]
        rounds += 1
    if rounds < 2:
        findings.append("too_few_closed_rounds")
    if any(value != 0 for value in final_state.get("pending_responses", {}).values()):
        findings.append("pending_responses_at_end")
    return {"complete": not findings, "rounds": rounds, "findings": findings}


class Cva6TwoGpioBoundProvider(IbexTwoGpioBoundProvider):
    """Three strategies share one CVA6/GPIO local RTL execution pipeline."""

    @staticmethod
    def _assess_trace_chain(direction: str, events, final_state: Mapping) -> dict | None:
        return assess_cva6_closed_chain(direction, events, final_state)

    @staticmethod
    def _fixture(direction: str, bound_manifest: Path | None = None):
        if bound_manifest is None:
            root = Path(__file__).resolve().parents[3]
            bound_manifest = root / "configs/scenario/cva6_cpu_two_gpio_campaign_seed.json"
        bound_manifest = Path(bound_manifest)
        if direction == "CPU_TO_IP_TO_CPU":
            genome_path = bound_manifest
            sources = (
                FuzzableSource("cpu.program", "cpu", "cpu.main", 84, 1,
                               (direction,), "memory_image"),
                FuzzableSource("cpu.isr", "cpu", "cpu.isr", 533, 1,
                               (direction,), "memory_image"),
            )
            bindings = (
                SourceBinding("cpu.program", "memory_image", "cpu", "cpu.main",
                              84, 1, "initial_image:cpu:cpu.main", 0x80000080),
                SourceBinding("cpu.isr", "memory_image", "cpu", "cpu.isr",
                              533, 1, "initial_image:cpu:cpu.isr", 0x80000100),
            )
            target = CoverageTarget("gpio_a.out_3", "gpio_a", "gpio_out", 0xff, 3)
        elif direction == "IP_TO_CPU_TO_IP":
            genome_path = bound_manifest.parent / "cva6_external_two_gpio_campaign_seed.json"
            sources = (
                FuzzableSource("b.pin8", "gpio_b", "gpio_in", 8, 1,
                               (direction,)),
                FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                               (direction,)),
            )
            bindings = (
                SourceBinding("b.pin8", "source", "gpio_b", "gpio_in", 8, 1,
                              "external_b"),
                SourceBinding("b.pin9", "source", "gpio_b", "gpio_in", 9, 1,
                              "external_b"),
            )
            target = CoverageTarget("gpio_a.out_0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300)
        else:
            raise CampaignBlocked(f"unsupported direction: {direction}")
        if not genome_path.is_file():
            raise CampaignBlocked(f"seed genome is missing: {genome_path}")
        seed = GenomeCodec.decode(genome_path.read_bytes())
        if seed.direction != direction:
            raise CampaignBlocked("campaign seed direction mismatch")
        expected = 6000 if direction == "CPU_TO_IP_TO_CPU" else 3600
        if seed.max_steps != expected or seed.quiesce_steps != 0:
            raise CampaignBlocked("CVA6 campaign needs pinned two-round Genome shape")
        main = next((image for image in seed.initial_images
                     if image.image_id == "cpu.main"), None)
        isr = next((image for image in seed.initial_images
                    if image.image_id == "cpu.isr"), None)
        if main is None or isr is None:
            raise CampaignBlocked("CVA6 campaign source program differs")
        if direction == "CPU_TO_IP_TO_CPU":
            if main.data[8:12] != bytes.fromhex("13011000"):
                raise CampaignBlocked("CVA6 first-output source seed differs")
            if isr.data[64:68] != bytes.fromhex("13011000"):
                raise CampaignBlocked("CVA6 ISR second-output seed differs")
        if direction == "IP_TO_CPU_TO_IP" and (
                len(seed.actions) != 3 or seed.actions[0].value != 1
                or seed.actions[2].value != 1):
            raise CampaignBlocked("CVA6 external edge seed differs")
        runner = make_cva6_two_gpio_runner()
        graph = DependencyGraph(
            sources=sources,
            rules=(DependencyRule(target.target_id,
                                  tuple(source.source_id for source in sources),
                                  "DATA_BINDING"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=SourceBindings(bindings))
        return make_cva6_two_gpio_runner, decoder, (target,), seed

    @staticmethod
    def _independent_fixture(direction: str, manifest: Path):
        manifest = Path(manifest)
        if not manifest.is_file():
            raise CampaignBlocked("CVA6 independent baseline manifest is missing")
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if (document.get("schema_version") != "scenario_independent_baseline.v1"
                or document.get("local_response_model") != "persistent_shadow_registers"
                or document.get("cross_component_bindings") != []
                or document.get("cpu_irq") != "constant_zero"):
            raise CampaignBlocked("CVA6 independent baseline manifest is invalid")
        if direction == "CPU_TO_IP_TO_CPU":
            seed_name = document.get("cpu_seed")
            source = FuzzableSource("cpu.program", "cpu", "cpu.main", 84, 1,
                                    (direction,), "memory_image")
            binding = SourceBinding("cpu.program", "memory_image", "cpu", "cpu.main",
                                    84, 1, "initial_image:cpu:cpu.main", 0x80000080)
            target = CoverageTarget("gpio_b.irq_high", "gpio_b", "irq", 1, 1)
            mask = document.get("gpio_b_local_irq_setup", {}).get("cpu_group_mask")
        elif direction == "IP_TO_CPU_TO_IP":
            seed_name = document.get("reverse_seed")
            source = FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    (direction,))
            binding = SourceBinding("b.pin9", "source", "gpio_b", "gpio_in",
                                    9, 1, "external_b")
            target = CoverageTarget("gpio_a.out_0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300)
            mask = document.get("gpio_b_local_irq_setup", {}).get("ip_group_mask")
        else:
            raise CampaignBlocked(f"unsupported direction: {direction}")
        if (not isinstance(seed_name, str) or Path(seed_name).name != seed_name
                or type(mask) is not int or not 0 < mask < 1 << 32):
            raise CampaignBlocked("CVA6 independent baseline setup is invalid")
        genome_path = manifest.parent / seed_name
        if not genome_path.is_file():
            raise CampaignBlocked(f"independent seed genome is missing: {genome_path}")
        seed = GenomeCodec.decode(genome_path.read_bytes())
        if seed.direction != direction:
            raise CampaignBlocked("independent seed direction mismatch")

        class LocalRegisterModel:
            def __init__(self):
                self.words: dict[int, int] = {}

            def write_register(self, offset: int, value: int, *, be: int = 15):
                old = self.words.get(offset, 0)
                byte_mask = sum(0xff << (8 * byte) for byte in range(4)
                                if be & (1 << byte))
                self.words[offset] = ((old & ~byte_mask) | (value & byte_mask)) \
                    & 0xffffffff

            def read_register(self, offset: int) -> int:
                return self.words.get(offset, 0)

        class LocallyConfiguredGpio(OpenTitanGpioSession):
            max_final_state_growth_bytes_per_operation = 65536
            max_evidence_record_bytes = 8192

            def begin_case(self, testcase_id: str) -> None:
                super().begin_case(testcase_id)
                self.write_register(0x04, mask)
                self.write_register(0x2c, mask)

        def factory():
            memory = PersistentMemory(
                regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
                initialization_seed=24, max_initialized_bytes=0x10000)
            gpio_a = OpenTitanGpioSession()
            gpio_b = LocallyConfiguredGpio()
            router = DataflowRouter((
                DeviceWindow("gpio_a_local", 0x40001000, 0x1000,
                             LocalRegisterModel()),
                DeviceWindow("gpio_b_local", 0x40000000, 0x1000,
                             LocalRegisterModel())))
            cpu = Cva6CpuSession(memory=memory, router=router)
            ownership = compile_ownership(
                (InputField("cpu", "irq", 2),
                 InputField("gpio_a", "gpio_in", 32),
                 InputField("gpio_b", "gpio_in", 32)),
                (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
                 InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
                 InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_b")))
            return ScenarioRunner(
                sessions={"cpu": cpu, "gpio_a": gpio_a, "gpio_b": gpio_b},
                ownership=ownership, bindings=(), independent_baseline=True)

        runner = factory()
        graph = DependencyGraph(
            sources=(source,),
            rules=(DependencyRule(target.target_id, (source.source_id,),
                                  "BASELINE_GROUPING"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=SourceBindings((binding,)))
        return factory, decoder, (target,), seed
