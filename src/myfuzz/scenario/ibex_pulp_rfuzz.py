"""RFuzz source map for the generated Ibex and two PULP GPIO chain.

Only the CPU program's output immediate is mutable. GPIO B's pin and the
CPU interrupt are bound to observed RTL outputs by the scenario runner.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib

from .checker import check_pulp_gpio_irq_chain
from .dependency import (DependencyGraph, DependencyRule, FuzzableSource,
                         SourceBinding, SourceBindings)
from .feedback import CoverageTarget
from .genome import GenomeCodec, ScenarioGenome
from .ownership import compile_ownership
from .replay import ScenarioTrace
from .rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder


_BOOT_ADDRESS = 0x10080
_OUTPUT_INSTRUCTION_OFFSET = 60
_OUTPUT_BIT = _OUTPUT_INSTRUCTION_OFFSET * 8 + 21
_SEED_SHA256 = '433d2fc069981af4d72cadee5d90592f9a9eedece6541884c06218e614086fdd'


def _boot_image(seed: ScenarioGenome):
    images = [image for image in seed.initial_images
              if image.component == 'cpu' and image.image_id == 'boot']
    if len(images) != 1 or images[0].address != _BOOT_ADDRESS:
        raise ValueError('generated Ibex source map requires one fixed boot image')
    image = images[0]
    if len(image.data) < _OUTPUT_INSTRUCTION_OFFSET + 8:
        raise ValueError('generated Ibex boot image lacks GPIO output instruction')
    word = int.from_bytes(image.data[_OUTPUT_INSTRUCTION_OFFSET:
                                     _OUTPUT_INSTRUCTION_OFFSET + 4], 'little')
    next_word = int.from_bytes(image.data[_OUTPUT_INSTRUCTION_OFFSET + 4:
                                          _OUTPUT_INSTRUCTION_OFFSET + 8], 'little')
    if word != 0x00100113 or next_word != 0x0021a623:
        raise ValueError('generated Ibex source map needs ADDI x2,1 then GPIO A PADOUT store')
    return image


def _chain_violations(trace: ScenarioTrace) -> tuple[str, ...]:
    """Report only concrete RTL contradictions, not an incomplete path."""
    writes = [event for event in trace.events
              if event.get('kind') == 'mmio_delivery'
              and event.get('component') == 'cpu'
              and event.get('device_id') == 'gpio_a'
              and event.get('offset') == 0x0c
              and event.get('write') is True
              and event.get('byte_enable') == 15]
    if not writes:
        return ()
    value = writes[0].get('write_value')
    if type(value) is not int or value not in (1, 3):
        return ()
    report = check_pulp_gpio_irq_chain(trace.events, expected_value=value)
    return tuple(report['dut_violations'])


def make_ibex_pulp_rfuzz_bundle(seed: ScenarioGenome) -> tuple[
        GenomeRecordDecoder, tuple[CoverageTarget, ...],
        Callable[[ScenarioTrace], tuple[str, ...]]]:
    """Build a trusted one-bit CPU source decoder and a conservative checker."""
    if not isinstance(seed, ScenarioGenome) or hashlib.sha256(
            GenomeCodec.encode(seed)).hexdigest() != _SEED_SHA256:
        raise ValueError('generated Ibex/PULP seed differs from pinned search program')
    image = _boot_image(seed)
    source_id = 'cpu.program.output_bit1'
    target_id = 'cpu.b_padin_response_bit1'
    graph = DependencyGraph(
        sources=(FuzzableSource(source_id, 'cpu', 'boot', _OUTPUT_BIT, 1,
                                ('CPU_TO_IP_TO_CPU',), 'memory_image'),),
        rules=(
            DependencyRule('gpio_a.padout_state', (source_id,), 'PERSISTENT_STATE_RULE'),
            DependencyRule('gpio_a.gpio_out', ('gpio_a.padout_state',), 'DATA_BINDING'),
            DependencyRule('gpio_b.gpio_in', ('gpio_a.gpio_out',), 'DATA_BINDING'),
            DependencyRule('gpio_b.irq', ('gpio_b.gpio_in',), 'EVENT_ORDER'),
            DependencyRule('cpu.irq', ('gpio_b.irq',), 'EVENT_ORDER'),
            DependencyRule('cpu.b_padin_response', ('cpu.irq',), 'DATA_BINDING'),
            DependencyRule(target_id, ('cpu.b_padin_response',), 'EVENT_ORDER'),
        ))
    bindings = SourceBindings((SourceBinding(
        source_id, 'memory_image', 'cpu', 'boot', _OUTPUT_BIT, 1,
        'initial_image:cpu:boot', image.address),))
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=compile_ownership((), ()),
        templates=(DecoderTemplate(target_id, seed),), source_bindings=bindings)
    targets = (CoverageTarget(target_id, 'cpu', 'data_rsp_rdata', 2, 2),)
    return decoder, targets, _chain_violations
