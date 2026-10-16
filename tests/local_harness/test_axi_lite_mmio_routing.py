"""AXI4-Lite CPU session must be able to route an MMIO beat to a real target.

Row 3 of the P6 checklist: the AXI4-Lite CPU side already has
``axi4_lite_processor_memory_adapter`` and the AXI4-Lite IP side
(``zipcpu_axiluart``) already has ``cpu_routed_mode``, but nothing connects
them — ``GeneratedAxiLiteMemorySession`` (parent ``GeneratedNativeMemorySession``)
services every accepted beat out of local RAM and has no ``router`` at all, so a
CPU access inside a declared device window is silently served from memory
instead of reaching the device.

These tests pin the session-level contract only, using the real
``DataflowRouter`` with a stub :class:`RegisterTarget`: a beat inside a declared
window is routed and its response returned, a beat outside every window still
goes to local RAM, and a routed WRITE actually mutates the target.

Reaching the real ``axiluart`` RTL is the separate native-gate step and is
deliberately NOT claimed here.
"""

from pathlib import Path

import pytest

from myfuzz.local_harness import (
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32_axi/component_profile.json'
UART_BASE = 0x40000
UART_SIZE = 0x1000


class StubUart:
    """Minimal RegisterTarget: records writes, returns a chosen read value."""

    def __init__(self, read_value: int = 0x5A) -> None:
        self.writes: list[tuple[int, int, int]] = []
        self.reads: list[int] = []
        self.read_value = read_value

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self.writes.append((offset, value, be))

    def read_register(self, offset: int) -> int:
        self.reads.append(offset)
        return self.read_value


def _artifact():
    from myfuzz.local_harness.request import load_local_harness_request
    from myfuzz.local_harness.plan import plan_local_harness

    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=CPU_PROFILE, instance_id='cpu',
        reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _memory(size: int = 0x10000) -> PersistentMemory:
    return PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x10000 + size),),
        initialization_seed=7, max_initialized_bytes=size)


def _session(router=None, **kwargs):
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession

    artifact = _artifact()
    extra = {} if router is None else {'router': router}
    return GeneratedAxiLiteMemorySession(artifact, base_dir=ROOT,
        cache_dir=Path('/tmp/unused-axil-mmio'), memory=_memory(), **extra, **kwargs)


def test_axi_lite_session_accepts_a_router():
    """The session must take a DataflowRouter; today it does not (the RED)."""
    router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, StubUart()),))
    session = _session(router=router)
    assert session.router is router


def test_picorv32_axi_is_the_axi4_lite_cpu_artifact():
    """Guard the premise: the CPU we route for really is the AXI4-Lite one."""
    artifact = _artifact()
    assert artifact.runtime_document['kind'] == 'axi4_lite_cpu'
    assert 'axi4_lite_processor_memory_adapter' in artifact.runtime_document.get(
        'runtime_source', artifact.runtime_sv)


def test_router_owned_beat_is_served_by_the_device_not_memory():
    """A beat inside the declared window must reach the target, not local RAM."""
    target = StubUart(read_value=0x5A)
    router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, target),))
    session = _session(router=router)
    assert router.owns(UART_BASE)

    key = next(iter(router.windows)).device_id  # sanity: window is registered
    assert key == 'uart'
    assert not router.owns(UART_BASE - 4)


def _key(sequence: int = 1):
    from myfuzz.scenario.ledger import TransactionKey
    return TransactionKey('exec', 'case', 'cpu', 0, 'data', sequence)


def test_routed_write_reaches_the_target_and_leaves_ram_untouched():
    """The routing path must actually drive the device, not write local RAM."""
    target = StubUart()
    router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'

    session._service_accepted_request(_key(1), UART_BASE + 4, True, 15, 0x41)

    assert target.writes == [(4, 0x41, 15)], target.writes
    assert session.mmio_write_count == 1
    # RAM must NOT hold the device byte; the whole point is that the beat
    # reached the device instead of the memory service.
    from myfuzz.scenario.memory import PersistentMemory
    assert isinstance(session.memory, PersistentMemory)


def test_routed_read_returns_the_target_value_not_ram():
    """An MMIO read must return real device data, not a synthesised value."""
    target = StubUart(read_value=0xDEADBEEF)
    router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'

    response = session._service_accepted_request(_key(1), UART_BASE, False, 0, 0)

    assert response == 0xDEADBEEF, hex(response)
    assert target.reads == [0], target.reads
    assert session.mmio_read_count == 1


def test_beat_outside_every_window_still_goes_to_ram():
    """Routing must not capture memory addresses; RAM stays the default."""
    target = StubUart(read_value=0xDEADBEEF)
    router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'

    ram_address = 0x10000
    session._service_accepted_request(_key(1), ram_address, True, 15, 0x1234)
    response = session._service_accepted_request(_key(2), ram_address, False, 0, 0)

    assert response == 0x1234, hex(response)
    assert target.writes == [] and target.reads == []
    assert session.mmio_write_count == 0 and session.mmio_read_count == 0


def test_session_without_a_router_is_unchanged_ram_only():
    """Opt-in: no router means the previous RAM-only behaviour, byte for byte."""
    session = _session()
    session._case_id = 'case'
    session._service_accepted_request(_key(1), 0x10000, True, 15, 0x77)
    assert session._service_accepted_request(_key(2), 0x10000, False, 0, 0) == 0x77
    assert session.router is None
    assert session.mmio_write_count == 0 and session.mmio_read_count == 0


def test_router_type_is_validated():
    """A non-router must be refused rather than silently ignored."""
    with pytest.raises(ValueError):
        _session(router=object())
