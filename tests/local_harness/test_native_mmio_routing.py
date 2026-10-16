"""The native ready-valid memory CPU session must be able to route MMIO beats.

Row 5 of the P6 checklist (PicoRV32 native ``ready-valid-memory/1``): the CPU
profile declares exactly one ``memory_master`` endpoint and no MMIO window, so
the local protocol acceptance covers RAM/ROM only.  ``GeneratedNativeMemorySession``
services every accepted beat out of local RAM and has no ``router`` at all, so a
CPU access inside a declared device window can never reach a real peripheral —
outside the RAM regions it aborts the run instead, and inside them it would be
aliased into RAM.

These tests pin the session-level contract only, using the real
:class:`~myfuzz.scenario.router.DataflowRouter` with a stub
:class:`RegisterTarget`: a beat inside a declared window is routed and its
response returned, a beat outside every window still goes to local RAM, and a
routed WRITE actually drives the target.  Reaching real peripheral RTL is the
separate native-gate step (``tests/integration/test_native_cpu_pulp_gpio_chain_real.py``).
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
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32/component_profile.json'
GPIO_BASE = 0x40000000
GPIO_SIZE = 0x1000
RAM_WORD = 0x100


class StubGpio:
    """Minimal RegisterTarget: records writes, returns a chosen read value."""

    def __init__(self, read_value: int = 0x5A) -> None:
        self.writes: list[tuple[int, int, int]] = []
        self.reads: list[int] = []
        self.read_value = read_value

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        if be != 15:
            raise ValueError('PULP GPIO APB3 requires a full-word write')
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


def _memory() -> PersistentMemory:
    return PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
        initialization_seed=7, max_initialized_bytes=0x1000)


def _memory_aliasing_the_window() -> PersistentMemory:
    """RAM that deliberately also covers the device window address.

    Used to make the precedence guard sharp: if a routed beat fell through to
    RAM it would succeed silently instead of failing, so the guard cannot pass
    merely because RAM refused the address.
    """
    return PersistentMemory(
        regions=(MemoryRegion('ram', 0, 0x1000),
                 MemoryRegion('alias', GPIO_BASE, GPIO_SIZE)),
        initialization_seed=7, max_initialized_bytes=0x1000)


def _session(router=None, memory=None, **kwargs):
    from myfuzz.local_harness.native_session import GeneratedNativeMemorySession

    artifact = _artifact()
    extra = {} if router is None else {'router': router}
    return GeneratedNativeMemorySession(artifact, base_dir=ROOT,
        cache_dir=Path('/tmp/unused-native-mmio'),
        memory=_memory() if memory is None else memory, **extra, **kwargs)


def _key(sequence: int = 1):
    from myfuzz.scenario.ledger import TransactionKey
    return TransactionKey('exec', 'case', 'cpu', 0, 'data', sequence)


def test_native_session_accepts_a_router():
    """The session must take a DataflowRouter; today it does not (the RED)."""
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, StubGpio()),))
    session = _session(router=router)
    assert session.router is router


def test_picorv32_is_the_native_memory_cpu_artifact():
    """Guard the premise: the CPU we route for really is the native one."""
    artifact = _artifact()
    assert artifact.runtime_document['kind'] == 'native_memory_cpu'


def test_a_routed_beat_reserves_one_target_access_per_step():
    """The runner reads this field to bound the target's local ticks."""
    without = _session()
    assert without.max_mmio_target_accesses_per_step == 0
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, StubGpio()),))
    assert _session(router=router).max_mmio_target_accesses_per_step == 1


def test_routed_write_drives_the_target_and_not_local_ram():
    """A write inside the declared window must reach the device, not RAM."""
    target = StubGpio()
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'
    assert router.owns(GPIO_BASE + 0x0C)
    assert not router.owns(GPIO_BASE + GPIO_SIZE)

    response = session._service_accepted_request(
        _key(1), GPIO_BASE + 0x0C, True, 15, 0x5A)

    assert response == 0, response
    assert target.writes == [(0x0C, 0x5A, 15)], target.writes
    assert session.mmio_write_count == 1
    assert session.memory_write_count == 0, 'the device beat must not touch RAM'


def test_routed_read_returns_the_target_value_not_ram():
    """An MMIO read must return real device data, not a synthesized value."""
    target = StubGpio(read_value=0xDEADBEEF)
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'

    response = session._service_accepted_request(_key(1), GPIO_BASE + 0x08, False, 15, 0)

    assert response == 0xDEADBEEF, hex(response)
    assert target.reads == [0x08], target.reads
    assert session.mmio_read_count == 1


def test_beat_outside_every_window_still_goes_to_ram():
    """Routing must not capture memory addresses; RAM stays the default."""
    target = StubGpio(read_value=0xDEADBEEF)
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, target),))
    session = _session(router=router)
    session._case_id = 'case'

    assert session._service_accepted_request(
        _key(1), RAM_WORD, True, 15, 0x1234) == 0
    assert session._service_accepted_request(
        _key(2), RAM_WORD, False, 15, 0) == 0x1234
    assert target.writes == [] and target.reads == []
    assert session.mmio_write_count == 0 and session.mmio_read_count == 0
    assert session.memory_write_count == 1


def test_session_without_a_router_is_unchanged_ram_only():
    """Opt-in: no router means the previous RAM-only behaviour, byte for byte."""
    session = _session()
    session._case_id = 'case'
    assert session._service_accepted_request(_key(1), RAM_WORD, True, 15, 0x77) == 0
    assert session._service_accepted_request(_key(2), RAM_WORD, False, 15, 0) == 0x77
    assert session.router is None
    assert session.mmio_write_count == 0 and session.mmio_read_count == 0


def test_router_type_is_validated():
    """A non-router must be refused rather than silently ignored."""
    with pytest.raises(ValueError):
        _session(router=object())


def test_a_routed_partial_write_is_refused_by_a_full_word_device():
    """Fail closed: byte lanes must not be silently widened for the device.

    The RAM passed here covers the window address as well, so a beat that fell
    through to memory would be accepted silently; the refusal must come from the
    device's own full-word requirement.
    """
    target = StubGpio()
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_SIZE, target),))
    session = _session(router=router, memory=_memory_aliasing_the_window())
    session._case_id = 'case'
    assert not router.owns(GPIO_BASE + GPIO_SIZE)

    with pytest.raises(ValueError):
        session._service_accepted_request(_key(1), GPIO_BASE + 0x0C, True, 0b0001, 0x5A)
    assert target.writes == []
    assert session.memory_write_count == 0, 'the device beat must not fall through to RAM'
    assert session.mmio_write_count == 0
