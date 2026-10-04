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
_SEED_SHA256 = '770857f6b1840943c6e9d64d296d698a39e5f0a51b13d0d0e887485076a9abce'
_MAX_SHA256 = '050c1d1a9116128a51d245ec312da6b5c6173e89d8854527acf6f65c13179b3c'


def _boot_image(genome: ScenarioGenome):
    images = [image for image in genome.initial_images
              if image.component == 'cpu' and image.image_id == 'boot']
    if len(images) != 1 or images[0].address != _BOOT_ADDRESS:
        raise ValueError('generated Ibex source map requires one fixed boot image')
    image = images[0]
    return image


def _source_span(seed: ScenarioGenome, maximum: ScenarioGenome) -> tuple[int, int]:
    first, last = _boot_image(seed), _boot_image(maximum)
    if len(first.data) != len(last.data):
        raise ValueError('CPU GPIO boot image length differs')
    changed = [byte * 8 + bit
               for byte, (left, right) in enumerate(zip(first.data, last.data))
               for bit in range(8) if (left ^ right) & (1 << bit)]
    if (len(changed) != 7 or changed != list(range(changed[0], changed[0] + 7))
            or changed[0] % 32 != 21):
        raise ValueError('CPU GPIO output immediate is not seven contiguous high bits')
    offset = changed[0] // 32 * 4
    if offset + 8 > len(first.data):
        raise ValueError('CPU GPIO output instruction is truncated')
    words = tuple(int.from_bytes(image.data[offset:offset + 4], 'little')
                  for image in (first, last))
    next_words = tuple(int.from_bytes(image.data[offset + 4:offset + 8], 'little')
                       for image in (first, last))
    if words != (0x00100113, 0x0ff00113) or next_words != (0x0021a623,) * 2:
        raise ValueError('CPU GPIO source must be ADDI x2,1/255 then PADOUT store')
    return changed[0], len(changed)


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
    if type(value) is not int or not 1 <= value <= 0xff or not value & 1:
        return ()
    report = check_pulp_gpio_irq_chain(trace.events, expected_value=value)
    return tuple(report['dut_violations'])


def make_ibex_pulp_rfuzz_bundle(seed: ScenarioGenome,
                                maximum: ScenarioGenome) -> tuple[
        GenomeRecordDecoder, tuple[CoverageTarget, ...],
        Callable[[ScenarioTrace], tuple[str, ...]]]:
    """Build a pinned seven-bit CPU source decoder and a conservative checker."""
    if (not isinstance(seed, ScenarioGenome)
            or not isinstance(maximum, ScenarioGenome)
            or hashlib.sha256(GenomeCodec.encode(seed)).hexdigest() != _SEED_SHA256
            or hashlib.sha256(GenomeCodec.encode(maximum)).hexdigest() != _MAX_SHA256):
        raise ValueError('generated Ibex/PULP seed differs from pinned search program')
    image = _boot_image(seed)
    source_bit_offset, source_width = _source_span(seed, maximum)
    source_id = 'cpu.program.output_high_bits'
    target_id = 'cpu.b_padin_response_bit3'
    graph = DependencyGraph(
        sources=(FuzzableSource(source_id, 'cpu', 'boot', source_bit_offset, source_width,
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
        source_id, 'memory_image', 'cpu', 'boot', source_bit_offset, source_width,
        'initial_image:cpu:boot', image.address),))
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=compile_ownership((), ()),
        templates=(DecoderTemplate(target_id, seed),), source_bindings=bindings)
    targets = (CoverageTarget(target_id, 'cpu', 'data_rsp_rdata', 8, 8),)
    return decoder, targets, _chain_violations
