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
from .picorv32_native_cpu_example import (ROOT, CPU_PROFILE, GPIO_PROFILE,
    GPIO_BASE, GPIO_WINDOW, GPIO_COMPONENT, GPIO_INPUT, PADDIR, GPIOEN, PADIN,
    PADOUT, DeferredNativeMemorySession, gpio_ownership, _lui, _addi, _sw)
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner
from .runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract
from .rv32i_sources import MmioWindow

INSTRUCTION_START = 0x200
INSTRUCTION_END = 0xe00
CPU_TICKS_PER_CASE = 128
SCHEDULE = ('cpu', GPIO_COMPONENT)


@dataclass(frozen=True)
class NativeOnlineBootstrap:
    template: ScenarioGenome
    instruction_start: int = INSTRUCTION_START
    instruction_end: int = INSTRUCTION_END

    @property
    def instruction_count(self):
        return (self.instruction_end - self.instruction_start) // 4


def make_picorv32_native_online_bootstrap():
    # Actual CPU stores configure PADDIR/GPIOEN; no target-side setup writes.
    words = [_lui(1, GPIO_BASE >> 12), _addi(2, 0, -1),
             _sw(2, 1, PADDIR), _sw(2, 1, GPIOEN)]
    pc = len(words) * 4
    offset = INSTRUCTION_START - pc
    words.append(((offset >> 20) & 1) << 31 | ((offset >> 1) & 0x3ff) << 21
                 | ((offset >> 11) & 1) << 20 | ((offset >> 12) & 0xff) << 12 | 0x6f)
    encode = lambda seq: b''.join(word.to_bytes(4, 'little') for word in seq).hex()
    images = (MemoryImage('native.online.bootstrap', 'cpu', 0, encode(words)),
              MemoryImage('native.online.end', 'cpu', INSTRUCTION_END, encode([0x6f])))
    return NativeOnlineBootstrap(ScenarioGenome('native-pulp-online',
        'MULTI_COMPONENT_CHAIN', 'native-pulp-online', SCHEDULE,
        2 * CPU_TICKS_PER_CASE, (), initial_images=images))


def make_picorv32_native_online_decoder():
    cpu_id, pin_id = 'cpu.instructions', 'gpio0.pin_byte'
    cpu_path, pin_path = 'native.cpu_gpio_cpu', 'native.pin_cpu_gpio'
    sources = (OnlineDependencySource(cpu_id, 'instruction', 'cpu', ('CPU_TO_IP_TO_CPU',)),
        OnlineDependencySource(pin_id, 'source', GPIO_COMPONENT, ('IP_TO_CPU_TO_IP',),
                               GPIO_INPUT, 0, 8))
    rules = (DependencyRule('native.gpio.cpu_write', (cpu_id,), 'PERSISTENT_STATE_RULE'),
             DependencyRule(cpu_path, ('native.gpio.cpu_write',), 'DATA_BINDING'),
             DependencyRule('native.gpio.pin', (pin_id,), 'ENV_PRECONDITION'),
             DependencyRule(pin_path, ('native.gpio.pin',), 'DATA_BINDING'))
    graph = OnlineDependencyGraph(sources=sources, rules=rules)
    nodes = (RuntimeNode(cpu_id, 'cpu', 'logical'),
        RuntimeNode(pin_id, GPIO_COMPONENT, 'physical', GPIO_INPUT, 0, 8),
        RuntimeNode('native.gpio.cpu_write', GPIO_COMPONENT, 'state'),
        RuntimeNode(cpu_path, 'cpu', 'logical'),
        RuntimeNode('native.gpio.pin', GPIO_COMPONENT, 'physical', GPIO_INPUT, 0, 8),
        RuntimeNode(pin_path, 'cpu', 'logical'))
    edges = tuple(RuntimeEdgeContract(index, 0, 'mmio_route',
        initiator_component='cpu', device_id=GPIO_COMPONENT,
        base=GPIO_BASE, size=GPIO_WINDOW) for index in (0, 1, 3))
    graph_hash = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    contract = RuntimePathContract(graph_hash, nodes, edges)
    return OnlineCaseDecoder(sources=(
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
