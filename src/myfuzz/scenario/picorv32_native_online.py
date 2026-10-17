"""Explicit bounded RV32 native/PULP online inputs; no IRQ or chain authority.

Construction renders the actual profiles; execution begins only at session.begin.
Online-only max_wait_cycles=1024 is a distinct generated artifact policy. Existing
native fixtures retain their original bound16. No terminal consumption is inferred
from decoder/path selection or from accepted instruction bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from .dependency import DependencyRule
from .genome import MemoryImage, ScenarioGenome
from .memory import MemoryRegion, PersistentMemory
from .online_case_decoder import OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource
from .session_runtime import OnlineInstruction
from .picorv32_native_cpu_example import (ROOT, CPU_PROFILE, GPIO_PROFILE,
    GPIO_BASE, GPIO_WINDOW, GPIO_COMPONENT, GPIO_INPUT, PADDIR, GPIOEN, PADIN,
    PADOUT, DeferredNativeMemorySession, gpio_ownership, _lui, _addi, _sw, _lw, _xor)
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner
from .runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract
from .rv32i_sources import MmioWindow

INSTRUCTION_START = 0x200
INSTRUCTION_END = 0xe00
CPU_TICKS_PER_CASE = 128
SCHEDULE = ('cpu', GPIO_COMPONENT)
PACKET_BYTES = 32
PACKET_COUNT = (INSTRUCTION_END - INSTRUCTION_START) // PACKET_BYTES


@dataclass(frozen=True)
class NativeOnlineBootstrap:
    template: ScenarioGenome
    instruction_start: int = INSTRUCTION_START
    instruction_end: int = INSTRUCTION_END

    @property
    def instruction_count(self):
        return PACKET_COUNT + 1

    @property
    def instruction_slots(self):
        return (*range(self.instruction_start, self.instruction_end, PACKET_BYTES),
                self.instruction_end)


def make_picorv32_native_online_bootstrap():
    # Actual CPU stores configure PADDIR/GPIOEN; no target-side setup writes.
    words = [_lui(1, GPIO_BASE >> 12), _addi(2, 0, -1),
             _sw(2, 1, PADDIR), _sw(2, 1, GPIOEN), _addi(10, 0, 0)]
    pc = len(words) * 4
    offset = INSTRUCTION_START - pc
    words.append(((offset >> 20) & 1) << 31 | ((offset >> 1) & 0x3ff) << 21
                 | ((offset >> 11) & 1) << 20 | ((offset >> 12) & 0xff) << 12 | 0x6f)
    encode = lambda seq: b''.join(word.to_bytes(4, 'little') for word in seq).hex()
    # Every packet has one source slot and seven immutable instructions. Both
    # source choices therefore reach a real PADIN load/CPU RAM store/derived
    # PADOUT store, rather than making an IP case only execute a NOP forever.
    # x1 is initialized by bootstrap and never modified by either source or
    # tail. Read actual PADOUT back before joining it with the actual PADIN
    # read: the resulting RAM/GPIO value depends on both sources, not merely
    # on a host-side copy of the CPU payload.
    tail = [_sw(10, 1, PADOUT), _lw(12, 1, PADOUT), _lw(11, 1, PADIN),
            _xor(10, 12, 11), _sw(10, 0, 0x100), _sw(10, 1, PADOUT), 0x13]
    images = (MemoryImage('native.online.bootstrap', 'cpu', 0, encode(words)),
              *(MemoryImage(f'native.online.tail.{index}', 'cpu', address + 4, encode(tail))
                for index, address in enumerate(range(INSTRUCTION_START, INSTRUCTION_END, PACKET_BYTES))))
    return NativeOnlineBootstrap(ScenarioGenome('native-pulp-online',
        'MULTI_COMPONENT_CHAIN', 'native-pulp-online', SCHEDULE,
        2 * CPU_TICKS_PER_CASE, (), initial_images=images))


class NativePacketDecoder(OnlineCaseDecoder):
    """One source word per immutable32-byte CPU packet; no mutable support."""

    def _decode_case(self, raw, *, coverage_hints=None):
        if (self.instruction_cursor >= self.instruction_end
                or (self.instruction_cursor - self.instruction_start) % PACKET_BYTES):
            raise ValueError('native online packet reservation exhausted')
        return super()._decode_case(raw, coverage_hints=coverage_hints)

    def _materialize_case(self, case_id, selected, entropy):
        if selected.kind != 'instruction':
            return super()._materialize_case(case_id, selected, entropy)
        value = entropy[0]
        source = OnlineInstruction(f'{case_id}:{selected.source_id}', 'cpu',
            self.instruction_cursor, _addi(10, 0, value).to_bytes(4, 'little').hex())
        return source, (), None

    def commit(self, case):
        cursor = self.instruction_cursor
        super().commit(case)
        # Only the single source word is reserved/submitted; immutable tails
        # are initial images, so never admit them through instruction input.
        if self.instruction_cursor != cursor + 4:
            raise ValueError('native online packet requires exactly one source word')
        self.instruction_cursor += PACKET_BYTES - 4

    def document(self):
        return {**super().document(), 'native_packet_policy': {
            'schema_version': 'native_online_packet.v1', 'stride_bytes': PACKET_BYTES,
            'source_words': 1, 'immutable_tail_words': 7,
            'cpu_source': 'ADDI x10,x0,u8', 'result_address': 0x100,
            'generic_contiguous_decoder_reconstruction_supported': False}}


def make_picorv32_native_online_decoder():
    cpu_id, pin_id = 'cpu.instructions', 'gpio0.pin_byte'
    cpu_path, pin_path = 'native.cpu_gpio_cpu', 'native.pin_cpu_gpio'
    sources = (OnlineDependencySource(cpu_id, 'instruction', 'cpu', ('CPU_TO_IP_TO_CPU',)),
        OnlineDependencySource(pin_id, 'source', GPIO_COMPONENT, ('IP_TO_CPU_TO_IP',),
                               GPIO_INPUT, 0, 8))
    rules = (DependencyRule('native.gpio.cpu_write', (cpu_id,), 'PERSISTENT_STATE_RULE'),
             DependencyRule(cpu_path, ('native.gpio.cpu_write',), 'DATA_BINDING'),
             DependencyRule('native.gpio.pin', (pin_id,), 'ENV_PRECONDITION'),
             DependencyRule('native.cpu.pin_read', ('native.gpio.pin',), 'DATA_BINDING'),
             DependencyRule(pin_path, ('native.cpu.pin_read',), 'PERSISTENT_STATE_RULE'))
    graph = OnlineDependencyGraph(sources=sources, rules=rules)
    nodes = (RuntimeNode(cpu_id, 'cpu', 'logical'),
        RuntimeNode(pin_id, GPIO_COMPONENT, 'physical', GPIO_INPUT, 0, 8),
        RuntimeNode('native.gpio.cpu_write', GPIO_COMPONENT, 'state'),
        RuntimeNode(cpu_path, 'cpu', 'logical'),
        RuntimeNode('native.gpio.pin', GPIO_COMPONENT, 'physical', GPIO_INPUT, 0, 8),
        RuntimeNode('native.cpu.pin_read', 'cpu', 'logical'),
        RuntimeNode(pin_path, GPIO_COMPONENT, 'state'))
    edges = tuple(RuntimeEdgeContract(index, 0, 'mmio_route',
        initiator_component='cpu', device_id=GPIO_COMPONENT,
        base=GPIO_BASE, size=GPIO_WINDOW) for index in (0, 1, 3, 4))
    graph_hash = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    contract = RuntimePathContract(graph_hash, nodes, edges)
    return NativePacketDecoder(sources=(
        OnlineSource(cpu_id, 'instruction', 'cpu', 'CPU_TO_IP_TO_CPU', cpu_path),
        OnlineSource(pin_id, 'source', GPIO_COMPONENT, 'IP_TO_CPU_TO_IP', pin_path,
                     port=GPIO_INPUT, width=8)), ownership=gpio_ownership(),
        schedule=SCHEDULE, instruction_start=INSTRUCTION_START,
        instruction_end=INSTRUCTION_END, advance_rounds=CPU_TICKS_PER_CASE,
        max_steps=2 * CPU_TICKS_PER_CASE, support_words=1,
        windows=(MmioWindow(GPIO_BASE + PADOUT, 4, write_widths=(4,)),
                 MmioWindow(GPIO_BASE + PADIN, 4, writable=False, write_widths=(4,))),
        allowed_mmio_operations=('LW', 'SW'), graph=graph, runtime_contract=contract)


def _online_artifact(profile, instance, base_dir, *, max_wait_cycles):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=max_wait_cycles))
    plan = plan_local_harness(request, base_dir=base_dir)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base_dir), base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


def make_picorv32_native_online_factory(*, cache_dir: Path, base_dir: Path = ROOT):
    """Each invocation makes one independent runner; no per-case pair.runner resets."""
    base_dir, cache_dir = Path(base_dir), Path(cache_dir)
    cpu_artifact = _online_artifact(CPU_PROFILE, 'cpu', base_dir, max_wait_cycles=1024)
    gpio_artifact = _online_artifact(GPIO_PROFILE, GPIO_COMPONENT, base_dir, max_wait_cycles=16)

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                                  initialization_seed=7, max_initialized_bytes=0x1000)
        gpio = GeneratedPulpGpioSession(gpio_artifact, base_dir=base_dir, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow(GPIO_COMPONENT, GPIO_BASE, GPIO_WINDOW, gpio),))
        cpu = DeferredNativeMemorySession(cpu_artifact, base_dir=base_dir,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        return ScenarioRunner(sessions={'cpu': cpu, GPIO_COMPONENT: gpio},
                              ownership=gpio_ownership(), bindings=())
    return factory
