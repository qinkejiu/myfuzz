"""Trusted RFuzz source maps for the Ibex and OpenTitan peripheral chains."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .dependency import (DependencyGraph, DependencyRule, FuzzableSource,
                         SourceBinding, SourceBindings)
from .feedback import CoverageTarget
from .genome import GenomeCodec, ScenarioGenome
from .ibex_i2c_example import make_ibex_i2c_runner
from .ibex_spi_host_example import make_ibex_spi_host_runner
from .ibex_spi_device_example import make_ibex_spi_device_runner
from .ibex_timer_example import make_ibex_timer_runner
from .rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from .runner import ScenarioRunner


_SEED_DIR = Path(__file__).resolve().parents[3] / "configs" / "scenario"

# A single immediate bit in each already legal Ibex ADDI is exposed during
# this first stage. The surrounding opcode, register fields, and program
# schedule stay pinned to the known two round testcase.
_CASES: dict[str, tuple[str, Callable[[], ScenarioRunner], str, str, int,
                        int | None, str | None]] = {
    "spi": ("spi_host", make_ibex_spi_host_runner, "spi", "IP_TO_CPU",
            84, 32, "external_spi_peer"),
    "i2c": ("i2c", make_ibex_i2c_runner, "i2c", "IP_TO_CPU",
            84, 8, "external_i2c_peer"),
    "timer": ("timer", make_ibex_timer_runner, "timer", "CPU_TO_IP_TO_CPU",
              436, None, None),
    "spi_device": ("spi_device", make_ibex_spi_device_runner, "spi_device",
                   "IP_TO_CPU_TO_IP", 84, 32, "external_spi_master"),
}
_ALIASES = {"spi_host": "spi", "rv_timer": "timer"}


def make_opentitan_mutation_bundle(component_id: str) -> tuple[
        Callable[[], ScenarioRunner], GenomeRecordDecoder,
        tuple[CoverageTarget, ...], ScenarioGenome]:
    """Return a runner and a search trusted decoder for one real chain.

    The record source selector chooses between declared peer payloads and a
    pinned CPU program bit. IRQ and MMIO response fields belong to the RTL
    route and are deliberately absent from the source graph.
    """
    try:
        seed_name, factory, device, direction, cpu_bit, peer_width, peer_owner = (
            _CASES[_ALIASES.get(component_id, component_id)])
    except (KeyError, TypeError) as exc:
        raise ValueError(f"unsupported OpenTitan component: {component_id}") from exc

    seed = GenomeCodec.decode((_SEED_DIR /
                               f"ibex_{seed_name}_two_rounds.json").read_bytes())
    if seed.direction != direction:
        raise ValueError("OpenTitan seed direction differs from source profile")
    main = next((image for image in seed.initial_images
                 if image.component == "cpu" and image.image_id == "cpu.main"), None)
    if main is None or cpu_bit >= len(main.data) * 8:
        raise ValueError("OpenTitan seed lacks the selected CPU program bit")
    instruction_offset = cpu_bit // 32 * 4
    if int.from_bytes(main.data[instruction_offset:instruction_offset + 4],
                      "little") & 0x7f != 0x13:
        raise ValueError("selected CPU source is no longer an ADDI instruction")

    sources = [FuzzableSource("cpu.program.immediate", "cpu", "cpu.main",
                              cpu_bit, 1, (direction,), "memory_image")]
    bindings = [SourceBinding("cpu.program.immediate", "memory_image",
                              "cpu", "cpu.main", cpu_bit, 1,
                              "initial_image:cpu:cpu.main", main.address)]
    if peer_width is not None:
        assert peer_owner is not None
        expected_ports = (("frame_1", "frame_2") if device == "spi_device" else
                          ("peer_payload_1", "peer_payload_2"))
        if tuple(action.port for action in seed.actions) != expected_ports or any(
                action.component != device or action.direction != direction
                for action in seed.actions):
            raise ValueError("OpenTitan seed peer actions differ from source profile")
        for port in expected_ports:
            source_id = f"{device}.{port}"
            sources.append(FuzzableSource(source_id, device, port, 0,
                                          peer_width, (direction,)))
            bindings.append(SourceBinding(source_id, "source", device, port,
                                          0, peer_width, peer_owner))
    elif seed.actions:
        raise ValueError("timer seed unexpectedly has source actions")

    target = CoverageTarget(f"{device}.cpu.irq_taken", "cpu",
                            "irq_taken_pre", 1, 1)
    cause = f"{device}.upstream"
    irq = f"{device}.irq"
    if device == "spi_device":
        # These rules describe mutation reachability and a stateful causal
        # path. They never assert that the RTL accepted configuration or
        # uploaded a frame; the runtime observes those results separately.
        rules = (
            DependencyRule("spi_device.config_state",
                           ("cpu.program.immediate",), "PERSISTENT_STATE_RULE"),
            DependencyRule("spi_device.external_frames",
                           ("spi_device.frame_1", "spi_device.frame_2"),
                           "DATA_BINDING"),
            DependencyRule("spi_device.upload_fifo_state",
                           ("spi_device.config_state", "spi_device.external_frames"),
                           "PERSISTENT_STATE_RULE"),
            DependencyRule(irq, ("spi_device.upload_fifo_state",), "EVENT_ORDER"),
            DependencyRule(target.target_id, (irq,), "EVENT_ORDER"),
        )
    else:
        rules = (DependencyRule(cause, tuple(item.source_id for item in sources),
                                "DATA_BINDING"),
                 DependencyRule(irq, (cause,), "EVENT_ORDER"),
                 DependencyRule(target.target_id, (irq,), "EVENT_ORDER"))
    graph = DependencyGraph(sources=tuple(sources), rules=rules)
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=factory().ownership,
        templates=(DecoderTemplate(target.target_id, seed),),
        source_bindings=SourceBindings(tuple(bindings)))
    return factory, decoder, (target,), seed
