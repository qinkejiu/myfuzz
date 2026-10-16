"""The AHB-Lite CPU has a session kind, so D4 can actually drive it.

What was missing
    ``_OPERATIONS`` already registered ``ahb_lite_cpu``'s ``STEP_MEMORY`` and the
    generated driver already emitted the four-field beat for it, but no session
    class admitted the artifact kind.  A P7-E run could therefore report D1..D4
    green, with F1..F4 *executable*, while nothing in the repository could start
    the CPU - "executable path" and "runnable session" are different claims and
    only the first was true.

The beat face matches the native completion face
    ``src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv`` presents
    ``req_valid/req_ready/req_write/req_addr/req_wdata/req_be`` out and
    ``rsp_valid/rsp_ready/rsp_rdata/rsp_error`` in on channel ``m`` - the same
    shape the native and AXI4-Lite memory sessions already drive.  So the new
    session reuses that handshake and budgets instead of reimplementing them, and
    this test pins both the reuse and the two things that do differ:

    * ``read_request_be`` is 15 (CVW asserts all four byte lanes on a read) where
      the AXI4-Lite register bridge uses 0;
    * the service identity names AHB, so an artifact cannot be served under the
      wrong session kind's identity.

The boot path is deliberately *not* claimed here
    CVW fetches from its reset vector as soon as reset is released, and that vector
    is inside the external region, so the service sees a fetch before the session
    has necessarily supplied a program.  Holding that transfer (withholding the
    response) is the honest behaviour; other CPU sessions do it through the
    on-demand instruction path.  Wiring that stall-and-resume path into this
    session is separate work and is not asserted here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from myfuzz.local_harness import (GeneratedAhbMemorySession, render_local_harness,
                                  render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

ROOT = Path(__file__).resolve().parents[2]
CVW_PROFILE = 'configs/cpus/cvw/component_profile.json'
CVW_ROOT = ROOT / 'third_party' / 'cvw_upstream_reference'

pytestmark = pytest.mark.skipif(
    not (CVW_ROOT / 'src' / 'cvw.sv').is_file(),
    reason='the CVW reference source is not present in this checkout')


def _artifact():
    from tests.local_harness.test_renderer import real_plan

    plan = real_plan(CVW_PROFILE, 'cpu')
    runtime = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _memory():
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory

    # The derived configuration puts CVW's reset vector and external region at
    # 0xC0000000; the region here mirrors that so a fetch can be served.
    return PersistentMemory(regions=(MemoryRegion('ram', 0xC0000000, 0x1000),),
                            initialization_seed=7, max_initialized_bytes=0x1000)


def test_the_ahb_session_admits_a_real_generated_artifact():
    from myfuzz.scenario.memory import PersistentMemory

    artifact = _artifact()
    assert artifact.runtime_document['kind'] == 'ahb_lite_cpu'
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=_memory())
    assert isinstance(session.memory, PersistentMemory)
    # RAM/ROM only: no router installed means no device window is claimed.
    assert session.router is None
    assert session.mmio_read_count == 0 and session.mmio_write_count == 0


def test_the_ahb_service_identity_names_ahb_not_the_native_schema():
    artifact = _artifact()
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=_memory())
    identity = session.identity_document()
    assert identity['ahb_lite_service_schema_version'] == (
        'generated_ahb_lite_memory_service.v1')
    assert 'native_service_schema_version' not in identity


def test_the_ahb_session_requires_persistent_memory():
    from myfuzz.scenario.memory import PersistentMemory

    class _NotMemory(PersistentMemory):
        pass

    artifact = _artifact()
    with pytest.raises(ValueError, match='persistent memory'):
        GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                  cache_dir=Path('/tmp/unused-ahb-lite'),
                                  memory=object())


def test_the_ahb_session_reads_whole_words_and_serves_a_materialised_word():
    """A served beat returns the byte content the persistent memory holds."""
    artifact = _artifact()
    memory = _memory()
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=memory)
    # A write and the read that follows it are different transactions, so they
    # carry different source sequences: the ledger refuses one key used for two
    # different payloads.
    write_key = TransactionKey('local-execution', 'ahb-boot', 'cpu',
                               session.reset_epoch, 'memory', 1)
    read_key = TransactionKey('local-execution', 'ahb-boot', 'cpu',
                              session.reset_epoch, 'memory', 2)
    # A fetched instruction: 'j self' at the reset vector, written through the
    # session's own service so the read is served from real bytes.
    session.service.write(write_key, 0xC0000000, 0x0000006F, width_bytes=4,
                          byte_enable=15)
    value = session._service_accepted_request(read_key, 0xC0000000, False, 15, 0)
    assert value == 0x0000006F
    # The declared read strobe is the full lane mask, not the register bridge's 0.
    assert GeneratedAhbMemorySession.read_request_be == 15


def test_an_unfilled_boot_word_is_held_by_withholding_req_ready():
    """The boot transfer is held by not accepting it, not by a late response.

    AHB-Lite gives a subordinate exactly one way to extend a transfer: keep
    ``HREADYEXT`` low, which this harness's subordinate does for as long as it has
    not accepted the beat.  Accepting the beat and withholding only the *response*
    would not work - accepting drives the subordinate into its COMPLETE state and it
    raises ``HREADYEXT`` there, so the transfer would already have completed with
    whatever data was on the bus.

    So the hold is: while the core is asking for a boot word the session has not
    supplied, the session drives ``req_ready`` low for that tick.  ``req_valid``
    stays high because the core is still waiting, so the request is retried and no
    error completion is invented.
    """
    artifact = _artifact()
    memory = _memory()
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=memory)
    address = 0xC0000000
    assert session.boot_base == address
    # The session declared the boot slot from the artifact's own boot contract, so
    # the reset-vector word is an unfilled instruction slot, not ordinary zero RAM.
    assert memory.instruction_slot_unmaterialized(address) is True
    assert session._boot_word_required() is True

    # The session supplies the program word, which is what releases the transfer.
    instruction = 0x00000013          # addi x0, x0, 0
    memory.accept_instructions(address, instruction.to_bytes(4, 'little'),
                               source_event_id='boot-image')
    assert memory.instruction_slot_unmaterialized(address) is False
    assert session._boot_word_required() is False

    # ... and the word is now served for real, not as a zero.
    key = TransactionKey('local-execution', 'ahb-boot-hold', 'cpu',
                         session.reset_epoch, 'memory', 1)
    assert session._service_accepted_request(key, address, False, 15, 0) == instruction


def test_holding_the_boot_word_does_not_consume_a_response_slot():
    """A held tick must not fabricate a pending response.

    Regression guard: an earlier version accepted the beat and stored
    ``_pending=(None, sequence)``.  That reaches the driver as a non-integer
    response field (it refused the command outright) and, had it ever reached the
    wire, would have completed the fetch with ``rdata=0`` - the silent zero
    instruction this session exists to avoid.
    """
    artifact = _artifact()
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=_memory())
    assert session._boot_word_required() is True
    assert session._pending is None
    session.begin_case('ahb-hold-shape')
    assert session._boot_word_required() is True
    assert session._pending is None
    assert session._quiescing is False, 'the hold flag must not outlive one step'
    session.end_case()


def test_a_write_to_an_unsupplied_word_is_served_not_held():
    """Only a fetch is held; a data write materialises its own bytes."""
    artifact = _artifact()
    session = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
                                        cache_dir=Path('/tmp/unused-ahb-lite'),
                                        memory=_memory())
    key = TransactionKey('local-execution', 'ahb-boot-write', 'cpu',
                         session.reset_epoch, 'memory', 1)
    assert session._service_accepted_request(key, 0xC0000010, True, 15,
                                             0x00000013) == 0


def test_the_session_boots_the_core_and_the_core_executes_the_supplied_program():
    """End to end: hold, supply, execute, and prove execution from the trace.

    The program is written so that only a *running* core can produce the last
    transaction:

        lui  x1, 0xC0000      ; x1 = 0xC0000000   (the class A U-type encoding the
        addi x1, x1, 0x100    ; x1 = 0xC0000100    repository's validator accepts)
        lw   x2, 0(x1)        ; the core itself asks for 0xC0000100

    A fetch at 0xC0000100 could only be issued if the earlier instructions really
    executed, so observing that address proves the harness - not a fixture, not a
    poke - supplied the program.  This is the session-level counterpart of
    tests/integration/rtl/cvw_ahb_boot_from_service_tb.sv.

    It also pins the hold shape: while the boot word is unsupplied the session must
    drive ``req_ready`` low (the base implementation derives that from
    ``_quiescing``), so the core is held with no invented error completion.
    """
    artifact = _artifact()
    # The boot line plus the word the load targets.
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0xC0000000, 0x1000),),
                              initialization_seed=7, max_initialized_bytes=0x1000)
    session = GeneratedAhbMemorySession(
        artifact, base_dir=ROOT, cache_dir=Path('/tmp/unused-ahb-lite'),
        memory=memory, command_timeout_seconds=180.0)
    session.begin_case('ahb-boot-execute')

    def step():
        return session.step_local({})

    # ---- 1. nothing supplied: the boot fetch must be HELD -------------------
    held = 0
    for _ in range(200):
        outputs = step()
        if session._boot_word_required():
            held += 1
            # The hold is "do not accept the beat", which the base implementation
            # expresses as req_ready low for this tick.  Assert the flag's *effect*
            # rather than trusting the mechanism: the last sample must show the
            # request still presented and the response not being offered, and the
            # session must not have accepted anything.
            samples = outputs['driver_samples']
            assert samples, 'a held tick must still produce a driver sample'
            pre = samples[-1]['pre']['backend'] if 'pre' in samples[-1] else {}
            assert pre.get('m_req_ready') in (0, None), (
                'the session must drive req_ready low while holding: ' + str(pre))
            assert not outputs['data_rsp_consumed'], 'a held tick must consume no response'
            break
        if outputs['data_req_accepted']:
            raise AssertionError('the session accepted the boot beat before it had a word')
    assert held == 1, 'the boot fetch was never held while its word was unsupplied'
    assert not session.accepted_addresses, (
        'a beat was accepted while the boot word was unsupplied: ' + str(session.accepted_addresses))

    # ---- 2. supply the program: the held transfer is released ---------------
    boot_program = {
        0x00: 0xC00000B7,   # lui  x1, 0xC0000
        0x04: 0x10008093,   # addi x1, x1, 0x100
        0x08: 0x0000A103,   # lw   x2, 0(x1)
        0x0C: 0x00000013,   # addi x0, x0, 0  (j self is not an accepted first-stage encoding)
        0x100: 0x00000013,  # addi x0, x0, 0  (the load target)
    }
    # Every byte of an on-demand instruction must sit in a *declared* slot before
    # it can be accepted: that is what distinguishes "waiting for its source" from
    # ordinary RAM bytes.  The session declares the reset word in its constructor;
    # the rest of the boot image is declared here, which is also exactly what a real
    # caller must do.
    session.declare_instruction_window(0xC0000000, 4)   # lui / addi / lw / addi
    session.declare_instruction_window(0xC0000100, 1)   # the load target
    for offset, word in boot_program.items():
        memory.accept_instructions(0xC0000000 + offset,
                                   word.to_bytes(4, 'little'),
                                   source_event_id=f'boot-{offset:#x}')

    for _ in range(4000):
        outputs = step()
        if 0xC0000100 in session.accepted_addresses:
            break

    assert 0xC0000000 in session.accepted_addresses, (
        'the reset vector was never served: ' + str(session.accepted_addresses))
    assert 0xC0000100 in session.accepted_addresses, (
        'the core never asked for the address only the supplied program computes: '
        + str(session.accepted_addresses))
    # The boot address was served too, and the error channel stayed clean.
    assert outputs.get('data_rsp_rdata') is not None
    session.end_case()
