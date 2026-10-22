"""Unstarted real Ibex → ZipCPU DMA → Caliptra SHA256 assembly.

Independent generated sessions share host persistent RAM and declared register
providers. The caller installs the prepared D4 route before starting a case.
"""
from dataclasses import dataclass
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.dma_artifact_endpoint_links import (
    PROVIDER_ID, render_dma_linked_runtime,
)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow

from .caliptra_sha256_dma_paths import SHA_CTRL_OFFSET, SHA_CTRL_START_VALUE
from .ibex_dma_example import ROOT, DMA_BASE, _artifact
from .ibex_dma_caliptra_sha_example import ibex_dma_caliptra_sha_images
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

RAM_BASE = 0x10000
RAM_SIZE = 0x20000
SHA_BASE = 0x40002000
SHA_SIZE = 0x1000
SHA_START_ADDRESS = SHA_BASE + SHA_CTRL_OFFSET


@dataclass(frozen=True)
class IbexCaliptraShaDmaFixture:
    runner: ScenarioRunner
    dma_endpoint_links: dict


def make_ibex_dma_caliptra_sha_runner(*, cache_dir: Path, source_value: int = 5,
        destination_address: int = SHA_START_ADDRESS) -> IbexCaliptraShaDmaFixture:
    """Create the isolated fixture; firmware arguments never widen its policy."""
    images = ibex_dma_caliptra_sha_images(source_value=source_value,
        destination_address=destination_address)
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=17, max_initialized_bytes=RAM_SIZE)
    for address, image in images.items():
        memory.preload(address, image)

    sha_request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path='configs/peripherals/caliptra_sha256/component_profile.json',
        instance_id='sha', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16, tuning={'endpoint_policies': [dict(
            endpoint_id='sha256.bus', template_id='target.ahb-lite',
            template_version='1', variant_id='full-word-single',
            max_outstanding=1)]}))
    sha_plan = plan_local_harness(sha_request, base_dir=ROOT)
    sha_artifact = render_local_driver(render_local_runtime(sha_plan,
        render_local_harness(sha_plan),
        verify_local_source_lock(sha_plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)
    dma_request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_wbdmac/component_profile.json',
        instance_id='dma', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    dma_plan = plan_local_harness(dma_request, base_dir=ROOT)
    issued_dma = render_dma_linked_runtime(dma_plan, render_local_harness(dma_plan),
        verify_local_source_lock(dma_plan.profile, base_dir=ROOT),
        base_dir=ROOT, provider_id=PROVIDER_ID)

    created = []
    try:
        sha = GeneratedAhbLiteRegisterSession(sha_artifact, base_dir=ROOT,
            cache_dir=cache_dir, command_timeout_seconds=30)
        created.append(sha)
        window = MasterTargetWindow('sha', SHA_BASE, SHA_SIZE, sha,
            (SHA_CTRL_OFFSET,), (SHA_CTRL_START_VALUE,))
        dma = GeneratedWishboneDmaScenarioSession(issued_dma.artifact,
            base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            master_targets=(window,), command_timeout_seconds=30)
        created.append(dma)
        router = DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
            DeviceWindow('sha', SHA_BASE, SHA_SIZE, sha)))
        cpu = GeneratedCve2Session(_artifact(
            'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
            base_dir=ROOT, cache_dir=cache_dir, memory=memory, router=router,
            defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
        created.append(cpu)
        binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
        ownership = compile_ownership((InputField('cpu', 'irq', 1),),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'sha': sha},
            ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
        return IbexCaliptraShaDmaFixture(runner,
            {'dma': issued_dma.endpoint_links_document()})
    except BaseException:
        for session in reversed(created):
            session.end_case()
        raise
